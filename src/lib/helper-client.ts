/**
 * Thin client for the local DSC helper REST API.
 *
 * Supports:
 *   1. emBridge (eMudhra)  — REST on localhost.emudhra.com:26769
 *   2. BridgeIt custom     — same REST contract (open-eid-inspired JSON)
 *   3. Generic fallback    — tries the same endpoints as BridgeIt
 *
 * Wire protocol (BridgeIt / generic):
 *   GET  /version                 → {version: string}
 *   GET  /certificates            → DscCertificate[]
 *   POST /sign  {thumbprint, hashB64, hashAlgo} → {signatureB64: string}
 *
 * emBridge specifics:
 *   POST /listCertificates        → vendor-specific shape (normalised below)
 *   POST /signHash                → {signatureInBase64: string}
 */

import type { DscCertificate, HelperInfo } from '@/types/signing';

// ── emBridge normaliser ────────────────────────────────────────────────────

function normaliseEmBridgeCert(raw: Record<string, string>): DscCertificate {
  return {
    thumbprint: raw.thumbPrint ?? raw.thumbprint ?? '',
    subjectCN: raw.subjectCN ?? raw.CommonName ?? raw.cn ?? '',
    issuerCN: raw.issuerCN ?? raw.Issuer ?? '',
    serialNumber: raw.serialNumber ?? raw.SerialNumber ?? '',
    validFrom: raw.validFrom ?? raw.ValidFrom ?? '',
    validTo: raw.validTo ?? raw.ValidTo ?? '',
    keyUsage: (raw.keyUsage ?? raw.KeyUsage ?? '')
      .split(',')
      .map((s: string) => s.trim())
      .filter(Boolean),
    derB64: raw.certificate ?? raw.Certificate ?? raw.certBase64 ?? '',
    chainB64: raw.chain ? (raw.chain as unknown as string[]) : undefined,
  };
}

// ── Generic / BridgeIt normaliser ─────────────────────────────────────────

function normaliseGenericCert(raw: Record<string, unknown>): DscCertificate {
  return {
    thumbprint: String(raw.thumbprint ?? raw.id ?? ''),
    subjectCN: String(raw.subjectCN ?? raw.subject ?? ''),
    issuerCN: String(raw.issuerCN ?? raw.issuer ?? ''),
    serialNumber: String(raw.serialNumber ?? ''),
    validFrom: String(raw.validFrom ?? ''),
    validTo: String(raw.validTo ?? ''),
    keyUsage: Array.isArray(raw.keyUsage)
      ? (raw.keyUsage as string[])
      : String(raw.keyUsage ?? '').split(',').map(s => s.trim()).filter(Boolean),
    derB64: String(raw.derB64 ?? raw.certificate ?? ''),
    chainB64: Array.isArray(raw.chainB64) ? (raw.chainB64 as string[]) : undefined,
  };
}

// ── Public API ─────────────────────────────────────────────────────────────

export async function listCertificates(helper: HelperInfo): Promise<DscCertificate[]> {
  let raw: unknown[];

  if (helper.vendor === 'emBridge') {
    const resp = await fetch(`${helper.baseUrl}/listCertificates`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    if (!resp.ok) throw new Error(`emBridge listCertificates: HTTP ${resp.status}`);
    const data = await resp.json();
    raw = Array.isArray(data) ? data : data.certificates ?? data.Certificates ?? [];
    return (raw as Record<string, string>[]).map(normaliseEmBridgeCert);
  }

  // Generic / BridgeIt
  const resp = await fetch(`${helper.baseUrl}/certificates`, { mode: 'cors' });
  if (!resp.ok) throw new Error(`Helper /certificates: HTTP ${resp.status}`);
  raw = await resp.json();
  return (raw as Record<string, unknown>[]).map(normaliseGenericCert);
}

/** Filter to Class 3 signing-only certs (must have both flags). */
export function filterSigningCerts(certs: DscCertificate[]): DscCertificate[] {
  return certs.filter(c => {
    const ku = c.keyUsage.map(k => k.toLowerCase());
    return (
      ku.some(k => k.includes('digitalsignature') || k.includes('digital signature')) &&
      ku.some(k => k.includes('nonrepudiation') || k.includes('non repudiation') || k.includes('content commitment'))
    );
  });
}

export interface SignHashParams {
  helper: HelperInfo;
  thumbprint: string;
  hashB64: string;
  hashAlgo?: string;
}

export async function signHash(params: SignHashParams): Promise<string> {
  const { helper, thumbprint, hashB64, hashAlgo = 'SHA-256' } = params;

  if (helper.vendor === 'emBridge') {
    const resp = await fetch(`${helper.baseUrl}/signHash`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ certThumbprint: thumbprint, hashAlgo, hashB64 }),
    });
    if (!resp.ok) throw new Error(`emBridge signHash: HTTP ${resp.status}`);
    const data = await resp.json();
    return data.signatureInBase64 ?? data.signature ?? data.signatureB64;
  }

  // Generic / BridgeIt
  const resp = await fetch(`${helper.baseUrl}/sign`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ thumbprint, hashB64, hashAlgo }),
  });
  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`Helper /sign: HTTP ${resp.status} — ${body}`);
  }
  const data = await resp.json();
  return data.signatureB64 ?? data.signature;
}
