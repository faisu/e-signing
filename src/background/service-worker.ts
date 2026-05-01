import {
  NATIVE_HOST_NAME,
  PROTOCOL_VERSION,
  type HostCmd,
  type HostEnvelope,
  type HostError,
  type HostResponse
} from "../shared/protocol";

type PendingRequest = {
  resolve: (value: HostResponse) => void;
  reject: (error: HostError) => void;
  timer: ReturnType<typeof setTimeout>;
};

interface NativeChunkedResult {
  resultType: "chunk";
  jobId: string;
  chunk: string;
  index: number;
  totalChunks: number;
}

interface NativeFinalResult {
  resultType: "final";
  jobId: string;
}

type NativeResult = NativeChunkedResult | NativeFinalResult | Record<string, unknown> | null;

let nativePort: chrome.runtime.Port | null = null;
const pendingById = new Map<string, PendingRequest>();
const chunkAccumulator = new Map<string, { totalChunks: number; chunks: string[] }>();
const REQUEST_TIMEOUT_MS = 30_000;

function createError(code: string, message: string): HostError {
  return { code, message };
}

function ensurePort(): chrome.runtime.Port {
  if (nativePort) {
    console.debug("[bridge:sw] reusing native port", {
      pendingCount: pendingById.size
    });
    return nativePort;
  }

  console.info("[bridge:sw] connecting native host", { host: NATIVE_HOST_NAME });
  nativePort = chrome.runtime.connectNative(NATIVE_HOST_NAME);
  nativePort.onMessage.addListener((response: HostResponse<NativeResult>) => {
    console.debug("[bridge:sw] native message received", {
      requestId: response.id,
      ok: response.ok,
      resultType:
        response.result && typeof response.result === "object"
          ? (response.result as Record<string, unknown>).resultType
          : null,
      hasError: Boolean(response.error)
    });
    const pending = pendingById.get(response.id);
    if (!pending) {
      console.warn("[bridge:sw] received native response without pending request", {
        requestId: response.id
      });
      return;
    }

    if (isChunkResult(response.result)) {
      collectChunk(response.id, response.result);
      return;
    }

    if (isFinalResult(response.result)) {
      const assembled = assembleChunks(response.result.jobId);
      response = {
        ...response,
        result: assembled
      };
    }

    clearTimeout(pending.timer);
    pendingById.delete(response.id);

    if (response.ok) {
      pending.resolve(response);
      return;
    }

    pending.reject(
      response.error ?? createError("NATIVE_ERROR", "Native host returned an unknown error.")
    );
  });

  nativePort.onDisconnect.addListener(() => {
    const message =
      chrome.runtime.lastError?.message ?? "Native host disconnected unexpectedly.";
    console.warn("[bridge:sw] native port disconnected", {
      message,
      pendingCount: pendingById.size
    });
    const error = createError("NATIVE_DISCONNECTED", message);

    for (const [id, pending] of pendingById.entries()) {
      clearTimeout(pending.timer);
      pending.reject(error);
      pendingById.delete(id);
    }

    nativePort = null;
  });

  return nativePort;
}

function isChunkResult(result: NativeResult): result is NativeChunkedResult {
  return Boolean(result && (result as NativeChunkedResult).resultType === "chunk");
}

function isFinalResult(result: NativeResult): result is NativeFinalResult {
  return Boolean(result && (result as NativeFinalResult).resultType === "final");
}

function collectChunk(requestId: string, chunkResult: NativeChunkedResult): void {
  const existing = chunkAccumulator.get(chunkResult.jobId) ?? {
    totalChunks: chunkResult.totalChunks,
    chunks: Array.from({ length: chunkResult.totalChunks }, () => "")
  };
  existing.chunks[chunkResult.index] = chunkResult.chunk;
  chunkAccumulator.set(chunkResult.jobId, existing);
  console.debug("[bridge:sw] collected native chunk", {
    requestId,
    jobId: chunkResult.jobId,
    index: chunkResult.index,
    totalChunks: chunkResult.totalChunks,
    chunkLen: chunkResult.chunk.length
  });

  // Keep request pending until final marker arrives.
  const pending = pendingById.get(requestId);
  if (!pending) {
    return;
  }
}

function assembleChunks(jobId: string): { signedPdfBase64: string; jobId: string } {
  const value = chunkAccumulator.get(jobId);
  if (!value) {
    console.warn("[bridge:sw] final marker without chunk accumulator", { jobId });
    return { signedPdfBase64: "", jobId };
  }
  chunkAccumulator.delete(jobId);
  const missingChunkCount = value.chunks.filter((chunk) => chunk.length === 0).length;
  console.debug("[bridge:sw] assembled signed PDF chunks", {
    jobId,
    totalChunks: value.totalChunks,
    missingChunkCount
  });
  return {
    jobId,
    signedPdfBase64: value.chunks.join("")
  };
}

function sendNativeMessage(cmd: HostCmd, requestId: string, payload: unknown): Promise<HostResponse> {
  const envelope: HostEnvelope = {
    v: PROTOCOL_VERSION,
    id: requestId,
    cmd,
    payload
  };

  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pendingById.delete(requestId);
      console.error("[bridge:sw] native request timeout", {
        requestId,
        cmd,
        timeoutMs: REQUEST_TIMEOUT_MS
      });
      reject(createError("NATIVE_TIMEOUT", `Timed out waiting for ${cmd} response.`));
    }, REQUEST_TIMEOUT_MS);

    pendingById.set(requestId, {
      resolve,
      reject,
      timer
    });

    try {
      console.info("[bridge:sw] sending native request", {
        requestId,
        cmd,
        payloadKeys:
          payload && typeof payload === "object" ? Object.keys(payload as Record<string, unknown>) : []
      });
      ensurePort().postMessage(envelope);
    } catch (error) {
      clearTimeout(timer);
      pendingById.delete(requestId);
      console.error("[bridge:sw] failed posting message to native host", {
        requestId,
        cmd,
        error: error instanceof Error ? error.message : String(error)
      });
      reject(
        createError(
          "NATIVE_SEND_FAILED",
          error instanceof Error ? error.message : "Could not post message to native host."
        )
      );
    }
  });
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  const requestId = typeof message?.requestId === "string" ? message.requestId : crypto.randomUUID();
  const cmd = message?.cmd as HostCmd | undefined;

  if (!cmd) {
    console.warn("[bridge:sw] invalid extension request missing cmd", {
      requestId
    });
    sendResponse({
      ok: false,
      result: null,
      error: createError("INVALID_REQUEST", "Missing cmd for native request.")
    });
    return false;
  }

  sendNativeMessage(cmd, requestId, message?.payload ?? {})
    .then((response) => {
      console.info("[bridge:sw] native request resolved", {
        requestId,
        cmd,
        ok: response.ok,
        errorCode: response.error?.code ?? null
      });
      sendResponse({
        ok: response.ok,
        result: response.result,
        error: response.error
      });
    })
    .catch((error: HostError) => {
      console.error("[bridge:sw] native request failed", {
        requestId,
        cmd,
        errorCode: error.code,
        message: error.message
      });
      sendResponse({
        ok: false,
        result: null,
        error
      });
    });

  return true;
});
