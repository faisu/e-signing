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
    return nativePort;
  }

  nativePort = chrome.runtime.connectNative(NATIVE_HOST_NAME);
  nativePort.onMessage.addListener((response: HostResponse<NativeResult>) => {
    const pending = pendingById.get(response.id);
    if (!pending) {
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

  // Keep request pending until final marker arrives.
  const pending = pendingById.get(requestId);
  if (!pending) {
    return;
  }
}

function assembleChunks(jobId: string): { signedPdfBase64: string; jobId: string } {
  const value = chunkAccumulator.get(jobId);
  if (!value) {
    return { signedPdfBase64: "", jobId };
  }
  chunkAccumulator.delete(jobId);
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
      reject(createError("NATIVE_TIMEOUT", `Timed out waiting for ${cmd} response.`));
    }, REQUEST_TIMEOUT_MS);

    pendingById.set(requestId, {
      resolve,
      reject,
      timer
    });

    try {
      ensurePort().postMessage(envelope);
    } catch (error) {
      clearTimeout(timer);
      pendingById.delete(requestId);
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
    sendResponse({
      ok: false,
      result: null,
      error: createError("INVALID_REQUEST", "Missing cmd for native request.")
    });
    return false;
  }

  sendNativeMessage(cmd, requestId, message?.payload ?? {})
    .then((response) => {
      sendResponse({
        ok: response.ok,
        result: response.result,
        error: response.error
      });
    })
    .catch((error: HostError) => {
      sendResponse({
        ok: false,
        result: null,
        error
      });
    });

  return true;
});
