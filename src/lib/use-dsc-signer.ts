'use client';

import { useState, useCallback, useRef } from 'react';
import { detectHelper } from './helper-detect';
import {
  listCertificates,
  filterSigningCerts,
  signHash,
} from './helper-client';
import type {
  DscCertificate,
  HelperInfo,
  SigningError,
  SigningStatus,
} from '@/types/signing';

export interface UseDscSignerReturn {
  status: SigningStatus;
  error: SigningError | null;
  helper: HelperInfo | null;
  certs: DscCertificate[];
  chosenCert: DscCertificate | null;

  detect: () => Promise<void>;
  enumerate: () => Promise<void>;
  chooseCert: (cert: DscCertificate) => void;
  sign: (pdfBytes: Uint8Array, opts: SignOpts) => Promise<Uint8Array | null>;
  reset: () => void;
}

export interface SignOpts {
  reason?: string;
  location?: string;
  signerName?: string;
  withTimestamp?: boolean;
  signatureRect?: [number, number, number, number];
  pageNumber?: number;
}

export function useDscSigner(): UseDscSignerReturn {
  const [status, setStatus] = useState<SigningStatus>('idle');
  const [error, setError] = useState<SigningError | null>(null);
  const [helper, setHelper] = useState<HelperInfo | null>(null);
  const [certs, setCerts] = useState<DscCertificate[]>([]);
  const [chosenCert, setChosenCert] = useState<DscCertificate | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const setErr = (code: SigningError['code'], message: string) => {
    setError({ code, message });
    setStatus('error');
  };

  const detect = useCallback(async () => {
    setStatus('detecting');
    setError(null);
    const found = await detectHelper();
    if (!found) {
      setErr('helper_not_found', 'No DSC helper detected on this computer. Please install emBridge or the BridgeIt DSC Helper.');
      return;
    }
    setHelper(found);
    setStatus('idle');
  }, []);

  const enumerate = useCallback(async () => {
    if (!helper) { await detect(); return; }
    setStatus('enumerating');
    setError(null);
    try {
      const all = await listCertificates(helper);
      const signing = filterSigningCerts(all);
      if (signing.length === 0) {
        setErr('no_certificates', 'No Class 3 signing certificates found on the token. Ensure the token is plugged in and drivers are installed.');
        return;
      }
      setCerts(signing);
      setStatus('idle');
    } catch (e) {
      setErr('technical_error', String(e));
    }
  }, [helper, detect]);

  const chooseCert = useCallback((cert: DscCertificate) => {
    setChosenCert(cert);
  }, []);

  const sign = useCallback(
    async (pdfBytes: Uint8Array, opts: SignOpts): Promise<Uint8Array | null> => {
      if (!helper || !chosenCert) {
        setErr('technical_error', 'No helper or certificate selected.');
        return null;
      }

      abortRef.current = new AbortController();
      setError(null);

      try {
        // 1. Prepare
        setStatus('preparing');
        const prepResp = await fetch('/api/sign/prepare', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            pdfBase64: Buffer.from(pdfBytes).toString('base64'),
            reason: opts.reason ?? 'Digitally signed',
            location: opts.location ?? 'India',
            signerName: opts.signerName ?? chosenCert.subjectCN,
            signatureRect: opts.signatureRect,
            pageNumber: opts.pageNumber,
          }),
          signal: abortRef.current.signal,
        });

        if (!prepResp.ok) {
          const { error: msg } = await prepResp.json();
          setErr('technical_error', msg);
          return null;
        }

        const { pdfId, digestB64 } = await prepResp.json();

        // 2. Sign on token (triggers PIN dialog in helper)
        setStatus('signing');
        const signatureB64 = await signHash({
          helper,
          thumbprint: chosenCert.thumbprint,
          hashB64: digestB64,
          hashAlgo: 'SHA-256',
        });

        // 3. Embed CMS
        setStatus('embedding');
        const finalResp = await fetch('/api/sign/finalize', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            pdfId,
            signatureB64,
            certificateB64: chosenCert.derB64,
            chainB64: chosenCert.chainB64 ?? [],
          }),
          signal: abortRef.current.signal,
        });

        if (!finalResp.ok) {
          const { error: msg } = await finalResp.json();
          setErr('technical_error', msg);
          return null;
        }

        let { signedPdfB64 } = await finalResp.json();

        // 4. Optional timestamp (PAdES B-T)
        if (opts.withTimestamp) {
          setStatus('timestamping');
          try {
            const tsResp = await fetch('/api/sign/timestamp', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ signedPdfB64 }),
              signal: abortRef.current.signal,
            });
            if (tsResp.ok) {
              ({ signedPdfB64 } = await tsResp.json());
            }
            // Non-fatal if TSA is down — we still return B-B signed PDF
          } catch {
            console.warn('[dsc] Timestamp failed — returning B-B signed PDF');
          }
        }

        setStatus('done');
        // Convert base64 → Uint8Array without Buffer (browser-safe)
        const binary = atob(signedPdfB64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return bytes;
      } catch (e: unknown) {
        if ((e as Error)?.name === 'AbortError') return null;
        const msg = String(e);
        if (msg.toLowerCase().includes('cancel') || msg.toLowerCase().includes('user')) {
          setErr('user_cancel', 'Signing was cancelled.');
        } else if (msg.toLowerCase().includes('pin') || msg.toLowerCase().includes('blocked')) {
          setErr('pin_blocked', 'Token PIN is blocked. Use the token management utility to unblock it.');
        } else {
          setErr('technical_error', msg);
        }
        return null;
      }
    },
    [helper, chosenCert],
  );

  const reset = useCallback(() => {
    abortRef.current?.abort();
    setStatus('idle');
    setError(null);
    setCerts([]);
    setChosenCert(null);
  }, []);

  return { status, error, helper, certs, chosenCert, detect, enumerate, chooseCert, sign, reset };
}
