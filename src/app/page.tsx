'use client';

import { useState, useCallback } from 'react';
import DscSigningPanel from '@/components/DscSigningPanel';

export default function HomePage() {
  const [pdfBytes, setPdfBytes] = useState<Uint8Array | null>(null);
  const [filename, setFilename] = useState('document.pdf');
  const [withTimestamp, setWithTimestamp] = useState(true);
  const [reason, setReason] = useState('I am the author of this document');
  const [location, setLocation] = useState('India');

  const handleFileChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (!file) return;
      setFilename(file.name);
      file.arrayBuffer().then(ab => setPdfBytes(new Uint8Array(ab)));
    },
    [],
  );

  const handleSigned = useCallback((signed: Uint8Array, name: string) => {
    const blob = new Blob([signed.buffer as ArrayBuffer], { type: 'application/pdf' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
  }, []);

  return (
    <main className="mx-auto max-w-2xl px-4 py-10 space-y-8">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">DSC e-Signing</h1>
        <p className="mt-1 text-sm text-gray-500">
          PAdES-compliant signing with Indian Class 3 USB DSC tokens.
          Your private key never leaves the token.
        </p>
      </div>

      {/* Document upload */}
      <section className="rounded-xl border bg-white p-6 shadow-sm space-y-4">
        <h2 className="font-semibold">1. Select PDF</h2>
        <label className="flex flex-col items-center justify-center border-2 border-dashed border-gray-300 rounded-lg h-32 cursor-pointer hover:border-blue-400 transition-colors bg-gray-50">
          <input
            type="file"
            accept="application/pdf"
            className="sr-only"
            onChange={handleFileChange}
          />
          {pdfBytes ? (
            <span className="text-sm text-green-700 font-medium">{filename}</span>
          ) : (
            <span className="text-sm text-gray-400">Click to upload a PDF</span>
          )}
        </label>
      </section>

      {/* Signing options */}
      <section className="rounded-xl border bg-white p-6 shadow-sm space-y-4">
        <h2 className="font-semibold">2. Signing options</h2>
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">
              Reason
            </label>
            <input
              type="text"
              value={reason}
              onChange={e => setReason(e.target.value)}
              className="w-full rounded border border-gray-300 px-3 py-2 text-sm"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">
              Location
            </label>
            <input
              type="text"
              value={location}
              onChange={e => setLocation(e.target.value)}
              className="w-full rounded border border-gray-300 px-3 py-2 text-sm"
            />
          </div>
        </div>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={withTimestamp}
            onChange={e => setWithTimestamp(e.target.checked)}
            className="rounded"
          />
          Add RFC 3161 timestamp (PAdES B-T)
        </label>
      </section>

      {/* Signing panel */}
      <section className="rounded-xl border bg-white p-6 shadow-sm space-y-4">
        <h2 className="font-semibold">3. Sign with DSC token</h2>
        <DscSigningPanel
          pdfBytes={pdfBytes}
          filename={filename}
          reason={reason}
          location={location}
          withTimestamp={withTimestamp}
          onSigned={handleSigned}
        />
      </section>

      {/* Legal note */}
      <p className="text-xs text-gray-400 text-center">
        Signatures are legally valid under IT Act 2000 §5 for Class 3 DSCs issued
        by CCA-licensed Certifying Authorities. Documents are processed in-browser;
        only the PDF hash is sent to the server.
      </p>
    </main>
  );
}
