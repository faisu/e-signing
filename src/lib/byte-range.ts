/**
 * Locates the /ByteRange and /Contents placeholders written by
 * @signpdf/placeholder-pdf-lib, patches the four ByteRange numbers,
 * and returns the two byte slices that must be hashed / signed.
 */
export function computeByteRange(pdf: Buffer): {
  pdf: Buffer;
  byteRange: [number, number, number, number];
  dataToSign: Buffer;
} {
  // Find /ByteRange placeholder — written as /ByteRange [0 9999999 9999999 9999999]
  const byteRangePos = pdf.lastIndexOf(Buffer.from('/ByteRange ['));
  if (byteRangePos === -1) throw new Error('No /ByteRange found in PDF');

  const byteRangeEnd = pdf.indexOf(Buffer.from(']'), byteRangePos);
  if (byteRangeEnd === -1) throw new Error('Malformed /ByteRange in PDF');

  // Find /Contents <hex...> — must come AFTER /ByteRange
  const contentsPos = pdf.lastIndexOf(Buffer.from('/Contents <'));
  if (contentsPos === -1) throw new Error('No /Contents placeholder found');

  const contentsValueStart = contentsPos + '/Contents <'.length;
  const contentsValueEnd = pdf.indexOf(Buffer.from('>'), contentsValueStart);
  if (contentsValueEnd === -1) throw new Error('Malformed /Contents in PDF');

  // /Contents < hex > — the actual byte positions (including < and >)
  const contentsStart = contentsPos + '/Contents '.length; // points at '<'
  const contentsEnd = contentsValueEnd + 1; // points past '>'

  // ByteRange: [0, contentsStart, contentsEnd, pdfLen - contentsEnd]
  const byteRange: [number, number, number, number] = [
    0,
    contentsStart,
    contentsEnd,
    pdf.length - contentsEnd,
  ];

  // Write the real ByteRange numbers back into the PDF buffer
  const byteRangeStr = `/ByteRange [${byteRange.join(' ')}]`;
  const originalByteRangeStr = pdf.slice(byteRangePos, byteRangeEnd + 1).toString();

  if (byteRangeStr.length > originalByteRangeStr.length) {
    throw new Error(
      `ByteRange string too long: ${byteRangeStr.length} > ${originalByteRangeStr.length}`,
    );
  }

  // Pad with spaces to preserve byte offsets
  const padded = byteRangeStr.padEnd(originalByteRangeStr.length, ' ');
  pdf.write(padded, byteRangePos);

  const dataToSign = Buffer.concat([
    pdf.slice(byteRange[0], byteRange[0] + byteRange[1]),
    pdf.slice(byteRange[2], byteRange[2] + byteRange[3]),
  ]);

  return { pdf, byteRange, dataToSign };
}
