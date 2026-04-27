import { NextRequest, NextResponse } from 'next/server';
import crypto from 'node:crypto';
import { getPdf, deletePdf } from '@/lib/pdf-cache';
import { buildSignedAttrs, buildCms } from '@/lib/cms-builder';
import type { FinalizeRequest, FinalizeResponse } from '@/types/signing';

const TSA_URL =
  process.env.TSA_URL ?? 'https://freetsa.org/tsr'; // swap to eMudhra in prod

export async function POST(req: NextRequest) {
  try {
    const body: FinalizeRequest = await req.json();
    const { pdfId, signatureB64, certificateB64, chainB64 = [] } = body;

    if (!pdfId || !signatureB64 || !certificateB64) {
      return NextResponse.json(
        { error: 'pdfId, signatureB64 and certificateB64 are required' },
        { status: 400 },
      );
    }

    const cached = getPdf(pdfId);
    if (!cached) {
      return NextResponse.json(
        { error: 'PDF not found or session expired — please restart signing' },
        { status: 404 },
      );
    }

    const { pdf, byteRange } = cached;

    // Recompute the byte-range data to re-derive the digest
    const dataToSign = Buffer.concat([
      pdf.slice(byteRange[0], byteRange[0] + byteRange[1]),
      pdf.slice(byteRange[2], byteRange[2] + byteRange[3]),
    ]);
    const byteRangeDigest = Buffer.from(
      crypto.createHash('sha256').update(dataToSign).digest(),
    );

    // Build signedAttrs (with ESS signing-certificate-v2 for PAdES B-B)
    const { signedAttrsDer } = await buildSignedAttrs(
      byteRangeDigest,
      certificateB64,
      new Date(),
    );

    const signatureValue = Buffer.from(signatureB64, 'base64');

    // Assemble CMS SignedData
    const cmsDer = buildCms({
      signedAttrsDer,
      signatureValue,
      certDerB64: certificateB64,
      chainB64,
    });

    if (cmsDer.length > 16384) {
      return NextResponse.json(
        {
          error: `CMS too large (${cmsDer.length} bytes). Increase SIG_LENGTH in prepare route.`,
        },
        { status: 500 },
      );
    }

    // Splice CMS into /Contents placeholder (hex-encoded)
    const cmsHex = cmsDer.toString('hex').toUpperCase();
    const contentsStart = byteRange[2]; // '<' character
    // The placeholder is /Contents <000…0> — replace the hex digits
    // Slot length in bytes = (byteRange[2] - byteRange[1] - 2) / 2
    // but we just write into the known positions
    const hexPadded = cmsHex.padEnd(
      (byteRange[2] - byteRange[1] - 2), // length of hex field between < >
      '0',
    );

    pdf.write(hexPadded, byteRange[1] + 1); // +1 to skip '<'

    const signedPdfB64 = pdf.toString('base64');
    deletePdf(pdfId);

    // Optionally add a timestamp (PAdES B-T) — fire-and-forget; non-fatal if TSA down
    // For now we return the B-B signed PDF and the client can separately call /timestamp
    return NextResponse.json({ signedPdfB64 } satisfies FinalizeResponse);
  } catch (err) {
    console.error('[finalize]', err);
    return NextResponse.json({ error: String(err) }, { status: 500 });
  }
}
