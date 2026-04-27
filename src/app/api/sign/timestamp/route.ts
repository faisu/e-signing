/**
 * PAdES B-T: embed an RFC 3161 timestamp over the existing signature value.
 *
 * The client sends back the signed PDF as base64 and the signer cert thumbprint
 * (to locate the SignerInfo). We find the CMS, extract the SignerInfo.signature,
 * request a TSR, and insert it as an unsigned attribute.
 *
 * NOTE: This re-parses and re-writes the /Contents field in an incremental
 * update, which keeps the original byte-range signature intact.
 */

import { NextRequest, NextResponse } from 'next/server';
import { fetchTimestamp, extractTokenFromTsr } from '@/lib/tsa';
import * as asn1js from 'asn1js';
import { fromBER } from 'asn1js';
import * as pkijs from 'pkijs';

const TSA_URL = process.env.TSA_URL ?? 'https://freetsa.org/tsr';

// OID id-aa-signatureTimeStampToken
const OID_SIG_TIMESTAMP = '1.2.840.113549.1.9.16.2.14';

export async function POST(req: NextRequest) {
  try {
    const { signedPdfB64 } = await req.json();
    if (!signedPdfB64) {
      return NextResponse.json({ error: 'signedPdfB64 required' }, { status: 400 });
    }

    const pdf = Buffer.from(signedPdfB64, 'base64');

    // Locate /Contents < hex > — last occurrence is the signature
    const contentsPos = pdf.lastIndexOf(Buffer.from('/Contents <'));
    if (contentsPos === -1) {
      return NextResponse.json({ error: 'No /Contents found' }, { status: 400 });
    }

    const hexStart = contentsPos + '/Contents <'.length;
    const hexEnd = pdf.indexOf(Buffer.from('>'), hexStart);
    const cmsHex = pdf.slice(hexStart, hexEnd).toString();
    const cmsDer = Buffer.from(cmsHex.replace(/0+$/, ''), 'hex'); // strip trailing zeros

    // Parse CMS to get the signature value
    const cmsAsn = fromBER(cmsDer.buffer.slice(cmsDer.byteOffset, cmsDer.byteOffset + cmsDer.byteLength) as ArrayBuffer);
    if (cmsAsn.offset === -1) throw new Error('Cannot parse CMS DER');

    const contentInfo = new pkijs.ContentInfo({ schema: cmsAsn.result });
    const signedData = new pkijs.SignedData({ schema: contentInfo.content });
    const signerInfo = signedData.signerInfos[0];

    if (!signerInfo) throw new Error('No SignerInfo in CMS');

    const sigValue = Buffer.from(
      (signerInfo.signature as asn1js.OctetString).valueBlock.valueHexView,
    );

    // Request TSR
    const tsrDer = await fetchTimestamp(sigValue, TSA_URL);
    const tokenDer = extractTokenFromTsr(tsrDer);

    // Add unsigned attribute
    if (!signerInfo.unsignedAttrs) {
      signerInfo.unsignedAttrs = new pkijs.SignedAndUnsignedAttributes({ type: 1, attributes: [] });
    }
    const tokenAsn = fromBER(tokenDer.buffer.slice(tokenDer.byteOffset, tokenDer.byteOffset + tokenDer.byteLength) as ArrayBuffer);
    signerInfo.unsignedAttrs.attributes.push(
      new pkijs.Attribute({
        type: OID_SIG_TIMESTAMP,
        values: [tokenAsn.result],
      }),
    );

    // Re-encode CMS
    const newCmsContentInfo = new pkijs.ContentInfo({
      contentType: pkijs.ContentInfo.SIGNED_DATA,
      content: signedData.toSchema(true),
    });
    const newCmsDer = Buffer.from(newCmsContentInfo.toSchema().toBER(false));

    if (newCmsDer.length > (hexEnd - hexStart) / 2) {
      return NextResponse.json(
        { error: 'CMS with timestamp too large for /Contents slot; increase SIG_LENGTH' },
        { status: 500 },
      );
    }

    // Splice back in (same length slot)
    const newHex = newCmsDer.toString('hex').toUpperCase().padEnd(hexEnd - hexStart, '0');
    pdf.write(newHex, hexStart);

    return NextResponse.json({ signedPdfB64: pdf.toString('base64') });
  } catch (err) {
    console.error('[timestamp]', err);
    return NextResponse.json({ error: String(err) }, { status: 500 });
  }
}
