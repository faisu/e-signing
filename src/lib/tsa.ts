/**
 * RFC 3161 timestamp client.
 *
 * Free public TSAs for development:
 *   https://freetsa.org/tsr   (no auth, sha256 supported)
 *   http://timestamp.digicert.com
 *
 * For production use eMudhra's licensed TSA (Indian Standard Time, CCA-audited):
 *   https://rfc3161timestamp.emudhra.com/tsa
 */

import * as asn1js from 'asn1js';
import { fromBER } from 'asn1js';
import { Crypto as PecularCrypto } from '@peculiar/webcrypto';
const webcrypto = new PecularCrypto();

const OID_SHA256         = '2.16.840.1.101.3.4.2.1';

function toAB(buf: Buffer): ArrayBuffer {
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
}

/** Build a minimal RFC 3161 TimeStampReq DER buffer. */
function buildTsQuery(messageImprint: Buffer): Buffer {
  // MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
  const messageImprintSeq = new asn1js.Sequence({
    value: [
      new asn1js.Sequence({
        value: [new asn1js.ObjectIdentifier({ value: OID_SHA256 })],
      }),
      new asn1js.OctetString({ valueHex: toAB(messageImprint) }),
    ],
  });

  // TimeStampReq ::= SEQUENCE { version INTEGER (1), messageImprint, certReq BOOLEAN DEFAULT FALSE, ... }
  const tsq = new asn1js.Sequence({
    value: [
      new asn1js.Integer({ value: 1 }),
      messageImprintSeq,
      new asn1js.Boolean({ value: true }), // certReq = true
    ],
  });

  return Buffer.from(tsq.toBER(false));
}

/**
 * Request a timestamp token from a TSA and return the raw TSR DER bytes.
 * The TSR is a TimeStampResp which contains the TimeStampToken (a CMS ContentInfo).
 */
export async function fetchTimestamp(
  dataToTimestamp: Buffer,
  tsaUrl: string,
): Promise<Buffer> {
  const digest = Buffer.from(
    await webcrypto.subtle.digest('SHA-256', toAB(dataToTimestamp)),
  );
  const tsq = buildTsQuery(digest);

  const resp = await fetch(tsaUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/timestamp-query' },
    body: toAB(tsq),
  });

  if (!resp.ok) {
    throw new Error(`TSA returned HTTP ${resp.status}: ${await resp.text()}`);
  }

  const tsrBytes = Buffer.from(await resp.arrayBuffer());

  // Basic sanity: parse outer TimeStampResp and check status = 0 (granted)
  const asn = fromBER(toAB(tsrBytes));
  if (asn.offset === -1) throw new Error('Invalid TSR response');
  const tsResp = asn.result as asn1js.Sequence;
  const statusSeq = (tsResp.valueBlock.value as asn1js.BaseBlock[])[0] as asn1js.Sequence;
  const statusInt = (statusSeq.valueBlock.value as asn1js.BaseBlock[])[0] as asn1js.Integer;
  if (statusInt.valueBlock.valueDec !== 0 && statusInt.valueBlock.valueDec !== 1) {
    throw new Error(`TSA returned non-granted status: ${statusInt.valueBlock.valueDec}`);
  }

  return tsrBytes;
}

/**
 * Extract the TimeStampToken (ContentInfo) from a TimeStampResp.
 * Returns the DER of the token itself (without the outer PKIStatusInfo).
 */
export function extractTokenFromTsr(tsrBytes: Buffer): Buffer {
  const asn = fromBER(toAB(tsrBytes));
  if (asn.offset === -1) throw new Error('Invalid TSR DER');
  const tsResp = asn.result as asn1js.Sequence;
  const blocks = tsResp.valueBlock.value as asn1js.BaseBlock[];
  if (blocks.length < 2) throw new Error('No TimeStampToken in TSR');
  return Buffer.from(blocks[1].toBER(false));
}
