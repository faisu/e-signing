'use client';

import { useEffect, useRef, useState } from 'react';
import { useDscSigner } from '@/lib/use-dsc-signer';
import InstallBanner from './InstallBanner';
import CertPicker from './CertPicker';
import StatusBadge from './StatusBadge';

interface Props {
  /** PDF bytes to sign */
  pdfBytes: Uint8Array | null;
  /** Called with the signed PDF bytes after successful signing */
  onSigned?: (signedPdf: Uint8Array, filename: string) => void;
  /** Original filename (used for the download name) */
  filename?: string;
  reason?: string;
  location?: string;
  withTimestamp?: boolean;
}

function downloadBlob(bytes: Uint8Array, name: string) {
  const blob = new Blob([bytes.buffer as ArrayBuffer], { type: 'application/pdf' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

export default function DscSigningPanel({
  pdfBytes,
  onSigned,
  filename = 'document.pdf',
  reason = 'Digitally signed',
  location = 'India',
  withTimestamp = false,
}: Props) {
  const {
    status,
    error,
    helper,
    certs,
    chosenCert,
    warning,
    detect,
    enumerate,
    chooseCert,
    sign,
    reset,
  } = useDscSigner();

  const [helperChecked, setHelperChecked] = useState(false);
  const signedRef = useRef<Uint8Array | null>(null);

  // Auto-detect helper on mount
  useEffect(() => {
    detect().finally(() => setHelperChecked(true));
  }, [detect]);

  const handleSign = async () => {
    if (!pdfBytes || !chosenCert) return;
    const signed = await sign(pdfBytes, {
      reason,
      location,
      signerName: chosenCert.subjectCN,
      withTimestamp,
    });
    if (signed) {
      signedRef.current = signed;
      const signedName = filename.replace(/\.pdf$/i, '_signed.pdf');
      onSigned?.(signed, signedName);
    }
  };

  const handleDownload = () => {
    if (signedRef.current) {
      downloadBlob(signedRef.current, filename.replace(/\.pdf$/i, '_signed.pdf'));
    }
  };

  // Not yet checked
  if (!helperChecked) {
    return (
      <div className="text-sm text-gray-500 animate-pulse">
        Detecting DSC helper…
      </div>
    );
  }

  // Helper not found
  if (helperChecked && !helper && status !== 'detecting') {
    return (
      <div className="space-y-3">
        <InstallBanner />
        <button
          onClick={() => { reset(); detect(); }}
          className="text-sm text-blue-600 underline"
        >
          Re-check after installation
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Helper info */}
      {helper && (
        <div className="text-xs text-gray-500 bg-gray-50 border rounded px-3 py-2">
          Helper: <span className="font-medium text-gray-700">{helper.vendor}</span>
          {helper.version && ` v${helper.version}`}
          {' — '}{helper.baseUrl}
        </div>
      )}

      {/* Step 1: enumerate certs */}
      {certs.length === 0 && status !== 'enumerating' && (
        <button
          onClick={enumerate}
          disabled={!pdfBytes}
          className="w-full rounded-lg bg-gray-100 hover:bg-gray-200 border border-gray-300 px-4 py-2.5 text-sm font-medium text-gray-700 disabled:opacity-50"
        >
          Plug in your DSC token and click to detect certificates
        </button>
      )}

      {/* Step 2: pick cert */}
      {certs.length > 0 && (
        <CertPicker certs={certs} chosen={chosenCert} onPick={chooseCert} />
      )}

      {/* Step 3: sign */}
      {certs.length > 0 && (
        <button
          onClick={handleSign}
          disabled={!chosenCert || !pdfBytes || status === 'signing' || status === 'preparing' || status === 'embedding' || status === 'timestamping'}
          className="w-full rounded-lg bg-blue-600 hover:bg-blue-700 disabled:opacity-50 px-4 py-2.5 text-sm font-semibold text-white transition-colors"
        >
          {status === 'signing'
            ? 'Approve PIN on helper dialog…'
            : 'Sign with DSC'}
        </button>
      )}

      {/* Status */}
      <StatusBadge status={status} error={error} />

      {warning && (
        <div className="rounded-md bg-amber-50 border border-amber-300 px-4 py-3 text-sm text-amber-900">
          <span className="font-semibold">Note: </span>
          {warning}
        </div>
      )}

      {/* Download */}
      {status === 'done' && (
        <button
          onClick={handleDownload}
          className="w-full rounded-lg bg-green-600 hover:bg-green-700 px-4 py-2.5 text-sm font-semibold text-white"
        >
          Download Signed PDF
        </button>
      )}
    </div>
  );
}
