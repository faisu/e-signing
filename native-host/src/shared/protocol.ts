export const PROTOCOL_VERSION = 1 as const;
export const MAX_CHUNK_BYTES = 256 * 1024;
export const MAX_NATIVE_MESSAGE_BYTES = 1024 * 1024;

export type HostCmd =
  | "PING"
  | "LIST_SLOTS"
  | "LIST_CERTS"
  | "SIGN_PDF_START"
  | "SIGN_PDF_CHUNK"
  | "SIGN_PDF_END";

export interface HostEnvelope<P = unknown> {
  v: typeof PROTOCOL_VERSION;
  id: string;
  cmd: HostCmd;
  payload: P;
}

export interface HostResponse<R = unknown> {
  v: typeof PROTOCOL_VERSION;
  id: string;
  ok: boolean;
  result: R | null;
  error: { code: string; message: string } | null;
}

export interface SignPdfStartPayload {
  jobId: string;
  fileName?: string;
  totalChunks: number;
  contentType?: string;
}

export interface SignPdfChunkPayload {
  jobId: string;
  index: number;
  chunkBase64: string;
}

export interface SignPdfEndPayload {
  jobId: string;
}
