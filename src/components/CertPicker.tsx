'use client';

import type { DscCertificate } from '@/types/signing';

interface Props {
  certs: DscCertificate[];
  chosen: DscCertificate | null;
  onPick: (cert: DscCertificate) => void;
}

function expiryClass(validTo: string): string {
  const ms = new Date(validTo).getTime() - Date.now();
  if (ms < 0) return 'text-red-600 font-semibold';
  if (ms < 30 * 24 * 60 * 60 * 1000) return 'text-amber-600 font-semibold';
  return 'text-green-700';
}

export default function CertPicker({ certs, chosen, onPick }: Props) {
  return (
    <div className="space-y-2">
      <p className="text-sm font-medium text-gray-700">Select your DSC certificate:</p>
      {certs.map(cert => {
        const isSelected = chosen?.thumbprint === cert.thumbprint;
        const expired = new Date(cert.validTo).getTime() < Date.now();
        return (
          <button
            key={cert.thumbprint}
            disabled={expired}
            onClick={() => onPick(cert)}
            className={[
              'w-full text-left rounded-lg border px-4 py-3 text-sm transition-colors',
              isSelected
                ? 'border-blue-500 bg-blue-50 ring-2 ring-blue-300'
                : 'border-gray-200 bg-white hover:border-gray-300 hover:bg-gray-50',
              expired ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer',
            ].join(' ')}
          >
            <div className="font-semibold text-gray-900">{cert.subjectCN}</div>
            <div className="text-xs text-gray-500 mt-0.5">
              Issuer: {cert.issuerCN}
            </div>
            <div className="flex gap-4 mt-1 text-xs">
              <span>Serial: {cert.serialNumber.slice(0, 16)}…</span>
              <span className={expiryClass(cert.validTo)}>
                Expires: {new Date(cert.validTo).toLocaleDateString()}
                {expired ? ' (EXPIRED)' : ''}
              </span>
            </div>
            <div className="text-xs text-gray-400 mt-0.5">
              Key usage: {cert.keyUsage.join(', ')}
            </div>
          </button>
        );
      })}
    </div>
  );
}
