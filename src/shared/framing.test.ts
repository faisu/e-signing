import { describe, expect, it } from "vitest";
import { concatUint8Arrays, decodeFirstFrame, encodeFrame } from "./framing";

describe("framing", () => {
  it("encodes and decodes frame roundtrip", () => {
    const payload = new TextEncoder().encode(JSON.stringify({ hello: "world" }));
    const frame = encodeFrame(payload);
    const decoded = decodeFirstFrame(frame);

    expect(decoded).not.toBeNull();
    expect(decoded?.bytesConsumed).toBe(frame.byteLength);
    expect(new TextDecoder().decode(decoded?.message)).toBe('{"hello":"world"}');
  });

  it("returns null for partial frame", () => {
    const payload = new TextEncoder().encode("abc");
    const frame = encodeFrame(payload);
    const partial = frame.subarray(0, frame.byteLength - 1);
    expect(decodeFirstFrame(partial)).toBeNull();
  });

  it("supports decoding after fragmented chunks are merged", () => {
    const payload = new TextEncoder().encode("fragmented");
    const frame = encodeFrame(payload);
    const chunks = [frame.subarray(0, 3), frame.subarray(3, 7), frame.subarray(7)];
    const merged = concatUint8Arrays(chunks);
    const decoded = decodeFirstFrame(merged);

    expect(decoded).not.toBeNull();
    expect(new TextDecoder().decode(decoded?.message)).toBe("fragmented");
  });
});
