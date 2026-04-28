import {
  MAX_CHUNK_BYTES,
  PROTOCOL_VERSION,
  type HostCmd,
  type HostEnvelope,
  type HostResponse,
  type SignPdfChunkPayload,
  type SignPdfEndPayload,
  type SignPdfStartPayload
} from "./shared/protocol.js";

type SignJob = {
  totalChunks: number;
  chunks: string[];
};

const signJobs = new Map<string, SignJob>();

function success(id: string, result: unknown): HostResponse {
  return {
    v: PROTOCOL_VERSION,
    id,
    ok: true,
    result,
    error: null
  };
}

function failure(id: string, code: string, message: string): HostResponse {
  return {
    v: PROTOCOL_VERSION,
    id,
    ok: false,
    result: null,
    error: { code, message }
  };
}

function toChunks(base64: string): string[] {
  const chunks: string[] = [];
  for (let i = 0; i < base64.length; i += MAX_CHUNK_BYTES) {
    chunks.push(base64.slice(i, i + MAX_CHUNK_BYTES));
  }
  return chunks;
}

function handleSignStart(id: string, payload: SignPdfStartPayload): HostResponse {
  if (!payload.jobId || payload.totalChunks <= 0) {
    return failure(id, "INVALID_PAYLOAD", "SIGN_PDF_START requires jobId and totalChunks > 0.");
  }

  signJobs.set(payload.jobId, {
    totalChunks: payload.totalChunks,
    chunks: Array.from({ length: payload.totalChunks }, () => "")
  });

  return success(id, { accepted: true, jobId: payload.jobId });
}

function handleSignChunk(id: string, payload: SignPdfChunkPayload): HostResponse {
  const job = signJobs.get(payload.jobId);
  if (!job) {
    return failure(id, "UNKNOWN_JOB", "SIGN_PDF_CHUNK received before SIGN_PDF_START.");
  }
  if (payload.index < 0 || payload.index >= job.totalChunks) {
    return failure(id, "INVALID_CHUNK_INDEX", "Chunk index is out of range.");
  }

  job.chunks[payload.index] = payload.chunkBase64;
  return success(id, { accepted: true, jobId: payload.jobId, index: payload.index });
}

function handleSignEnd(id: string, payload: SignPdfEndPayload): HostResponse[] {
  const job = signJobs.get(payload.jobId);
  if (!job) {
    return [failure(id, "UNKNOWN_JOB", "SIGN_PDF_END received before SIGN_PDF_START.")];
  }

  signJobs.delete(payload.jobId);
  const assembledBase64 = job.chunks.join("");
  const signedBase64 = assembledBase64;
  const resultChunks = toChunks(signedBase64);

  const responses: HostResponse[] = [];
  for (let index = 0; index < resultChunks.length; index += 1) {
    responses.push(
      success(id, {
        resultType: "chunk",
        jobId: payload.jobId,
        chunk: resultChunks[index],
        index,
        totalChunks: resultChunks.length
      })
    );
  }
  responses.push(success(id, { resultType: "final", jobId: payload.jobId }));
  return responses;
}

export function handleCommand(request: HostEnvelope): HostResponse[] {
  const { id, cmd, payload } = request;

  switch (cmd as HostCmd) {
    case "PING":
      return [success(id, { hostVersion: "0.1.0", tokenPresent: false, protocolVersion: 1 })];
    case "LIST_SLOTS":
      return [success(id, { slots: [], note: "Stub implementation." })];
    case "LIST_CERTS":
      return [success(id, { certs: [], note: "Stub implementation." })];
    case "SIGN_PDF_START":
      return [handleSignStart(id, payload as SignPdfStartPayload)];
    case "SIGN_PDF_CHUNK":
      return [handleSignChunk(id, payload as SignPdfChunkPayload)];
    case "SIGN_PDF_END":
      return handleSignEnd(id, payload as SignPdfEndPayload);
    default:
      return [failure(id, "UNKNOWN_CMD", `Unsupported command: ${String(cmd)}`)];
  }
}
