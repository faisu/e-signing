import { stdin, stdout, stderr } from "node:process";
import { handleCommand } from "./commands.js";
import {
  MAX_NATIVE_MESSAGE_BYTES,
  PROTOCOL_VERSION,
  type HostEnvelope,
  type HostResponse
} from "./shared/protocol.js";
import { concatUint8Arrays, decodeFirstFrame, encodeFrame } from "./shared/framing.js";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

let inputBuffer: Uint8Array<ArrayBufferLike> = new Uint8Array(0);

function writeResponse(response: HostResponse): void {
  const body = textEncoder.encode(JSON.stringify(response));
  const frame = encodeFrame(body);
  stdout.write(Buffer.from(frame));
}

function writeError(id: string, code: string, message: string): void {
  writeResponse({
    v: PROTOCOL_VERSION,
    id,
    ok: false,
    result: null,
    error: { code, message }
  });
}

function parseEnvelope(raw: Uint8Array<ArrayBufferLike>): HostEnvelope | null {
  try {
    const parsed = JSON.parse(textDecoder.decode(raw)) as HostEnvelope;
    return parsed;
  } catch {
    return null;
  }
}

function processFrames(): void {
  while (true) {
    const decoded = decodeFirstFrame(inputBuffer);
    if (!decoded) {
      return;
    }

    inputBuffer = inputBuffer.subarray(decoded.bytesConsumed);
    if (decoded.message.byteLength > MAX_NATIVE_MESSAGE_BYTES) {
      writeError("unknown", "MSG_TOO_LARGE", "Message exceeded 1MB native host cap.");
      continue;
    }

    const envelope = parseEnvelope(decoded.message);
    if (!envelope) {
      writeError("unknown", "INVALID_JSON", "Could not parse incoming JSON envelope.");
      continue;
    }

    const responses = handleCommand(envelope);
    for (const response of responses) {
      writeResponse(response);
    }
  }
}

stdin.on("data", (chunk: Buffer) => {
  const chunkArray = new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength);
  inputBuffer = concatUint8Arrays([inputBuffer, chunkArray]);
  processFrames();
});

stdin.on("error", (error: Error) => {
  stderr.write(`[native-host] stdin error: ${error.message}\n`);
});

stdout.on("error", (error: Error) => {
  stderr.write(`[native-host] stdout error: ${error.message}\n`);
});
