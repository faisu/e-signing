import { NextRequest, NextResponse } from 'next/server';
import { PDFDocument, rgb, StandardFonts, degrees } from 'pdf-lib';
import { pdflibAddPlaceholder } from '@signpdf/placeholder-pdf-lib';
import { SUBFILTER_ETSI_CADES_DETACHED } from '@signpdf/utils';
import crypto from 'node:crypto';
import { cachePdf } from '@/lib/pdf-cache';
import { computeByteRange } from '@/lib/byte-range';
import { buildSignedAttrs } from '@/lib/cms-builder';
import type { PrepareRequest, PrepareResponse } from '@/types/signing';

// Reserve 16 KiB for the hex-encoded CMS (enough for RSA-2048 chain + OCSP margin)
const SIG_LENGTH = 16384;

export async function POST(req: NextRequest) {
  try {
    const body: PrepareRequest = await req.json();
    const {
      pdfBase64,
      reason = 'Digitally signed',
      location = 'India',
      signerName,
      contactInfo,
      signatureRect,
      pageNumber = 0,
    } = body;

    if (!pdfBase64 || !signerName) {
      return NextResponse.json(
        { error: 'pdfBase64 and signerName are required' },
        { status: 400 },
      );
    }

    const pdfDoc = await PDFDocument.load(Buffer.from(pdfBase64, 'base64'), {
      ignoreEncryption: true,
    });

    pdflibAddPlaceholder({
      pdfDoc,
      reason,
      location,
      name: signerName,
      contactInfo: contactInfo ?? signerName,
      signatureLength: SIG_LENGTH,
      subFilter: SUBFILTER_ETSI_CADES_DETACHED,
      ...(signatureRect
        ? {
            widgetRect: signatureRect,
            pageIndex: pageNumber,
          }
        : {}),
    });

    const pdfBytes = Buffer.from(
      await pdfDoc.save({ useObjectStreams: false }),
    );

    const { pdf: patchedPdf, byteRange, dataToSign } = computeByteRange(pdfBytes);

    const byteRangeDigest = Buffer.from(
      crypto.createHash('sha256').update(dataToSign).digest(),
    );

    const pdfId = crypto.randomUUID();
    cachePdf(pdfId, patchedPdf, byteRange);

    // We don't know the cert yet at prepare time — the client will send it
    // after selecting from the token. We return the raw digest; the client
    // sends the cert in /finalize and we build the CMS there.
    // However, to allow the helper to sign over signedAttrs (Option A — most
    // PAdES-correct path), we also accept a workflow where the client sends
    // the cert fingerprint upfront. For the first phase we return the
    // byteRangeDigest and let the helper use it directly (many Indian helpers
    // sign the raw hash). The finalize route then wraps it in CMS.

    return NextResponse.json({
      pdfId,
      digestB64: byteRangeDigest.toString('base64'),
      hashAlgo: 'SHA-256',
    } satisfies PrepareResponse);
  } catch (err) {
    console.error('[prepare]', err);
    return NextResponse.json(
      { error: String(err) },
      { status: 500 },
    );
  }
}
