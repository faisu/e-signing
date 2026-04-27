'use client';

import { useState, useCallback, useRef } from 'react';
import { detectHelper } from './helper-detect';
import {
  listCertificates,
  filterSigningCerts,
  hasIdealClass3Profile,
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
  warning: string | null;

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
  const [warning, setWarning] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const setErr = (code: SigningError['code'], message: string) => {
    setError({ code, message });
    setStatus('error');
  };

  const detect = useCallback(async () => {
    setStatus('detecting');
    setError(null);
    setWarning(null);
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
    setWarning(null);
    try {
      const all = await listCertificates(helper);
      if (all.length === 0) {
        setErr(
          'no_certificates',
          'No certificates were returned by the helper. Ensure the token is inserted, unlocked, and the vendor PKCS#11 driver is installed.',
        );
        return;
      }
      const signing = filterSigningCerts(all);
      if (signing.length === 0) {
        setErr(
          'no_certificates',
          'Certificates were detected on the token, but none are marked for digital signing. Check certificate key usage in your token utility.',
        );
        return;
      }

      const idealCount = signing.filter(hasIdealClass3Profile).length;
      if (idealCount === 0) {
        setWarning(
          'Certificates were detected and can be used for signing, but none advertise nonRepudiation/contentCommitment. This is usually a token profile quirk.',
        );
      } else if (idealCount < signing.length) {
        setWarning(
          'Some detected certificates do not advertise full Class 3 key-usage flags. Prefer a certificate that includes nonRepudiation/contentCommitment when available.',
        );
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
    setWarning(null);
    setCerts([]);
    setChosenCert(null);
  }, []);

  return { status, error, helper, certs, chosenCert, warning, detect, enumerate, chooseCert, sign, reset };
}
