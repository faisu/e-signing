const HEADER_BYTES = 4;
export function encodeFrame(message) {
    const frame = new Uint8Array(HEADER_BYTES + message.byteLength);
    const view = new DataView(frame.buffer);
    view.setUint32(0, message.byteLength, true);
    frame.set(message, HEADER_BYTES);
    return frame;
}
export function decodeFirstFrame(buffer) {
    if (buffer.byteLength < HEADER_BYTES) {
        return null;
    }
    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    const messageLength = view.getUint32(0, true);
    const totalLength = HEADER_BYTES + messageLength;
    if (buffer.byteLength < totalLength) {
        return null;
    }
    return {
        message: buffer.subarray(HEADER_BYTES, totalLength),
        bytesConsumed: totalLength
    };
}
export function concatUint8Arrays(chunks) {
    const total = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
        out.set(chunk, offset);
        offset += chunk.byteLength;
    }
    return out;
}
