export const PROTOCOL_VERSION = 1 as const;
export const BRIDGE_SOURCE = "AUTODCR_SIGN_BRIDGE";
export const NATIVE_HOST_NAME = "com.example.autodcr.signer";
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

export interface HostError {
  code: string;
  message: string;
}

export interface HostResponse<R = unknown> {
  v: typeof PROTOCOL_VERSION;
  id: string;
  ok: boolean;
  result: R | null;
  error: HostError | null;
}

export type BridgeType = "REQUEST" | "RESPONSE";

export interface BridgeRequest<P = unknown> {
  source: typeof BRIDGE_SOURCE;
  type: "REQUEST";
  requestId: string;
  cmd: HostCmd;
  payload: P;
}

export interface BridgeResponse<R = unknown> {
  source: typeof BRIDGE_SOURCE;
  type: "RESPONSE";
  requestId: string;
  ok: boolean;
  result: R | null;
  error: HostError | null;
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
