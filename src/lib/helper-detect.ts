/**
 * Probes well-known localhost DSC helper endpoints.
 *
 * Browser security notes:
 *   - emBridge uses localhost.emudhra.com → 127.0.0.1 with a publicly-trusted
 *     TLS cert, so no self-signed-cert friction.
 *   - emSigner uses a self-signed cert on 127.0.0.1:1585; users must visit that
 *     URL once and click "Proceed" to trust it in Chrome.
 *   - Chrome 94+ Private Network Access: the helper must return
 *     Access-Control-Allow-Private-Network: true on the preflight.
 *
 * Add your own helper's endpoint to HELPERS if you build a custom one.
 */

import type { HelperInfo } from '@/types/signing';

export const HELPERS: HelperInfo[] = [
  // BridgeIt open-source helper — checked first
  {
    vendor: 'BridgeIt DSC Helper',
    baseUrl: 'https://127.0.0.1:7777',
  },
  {
    vendor: 'emBridge',
    baseUrl: 'https://localhost.emudhra.com:26769',
  },
  {
    vendor: 'emSigner',
    baseUrl: 'https://127.0.0.1:1585',
  },
  {
    vendor: 'NICDSign',
    baseUrl: 'https://localhost:8020',
  },
  {
    vendor: 'TRACES WebSigner',
    baseUrl: 'https://127.0.0.1:1565',
  },
];

/**
 * Try each candidate in order and return the first live one.
 * Resolves to null if none respond within the timeout.
 */
export async function detectHelper(timeoutMs = 1500): Promise<HelperInfo | null> {
  for (const candidate of HELPERS) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);

      const resp = await fetch(`${candidate.baseUrl}/version`, {
        mode: 'cors',
        cache: 'no-store',
        signal: controller.signal,
      });

      clearTimeout(timer);

      if (resp.ok) {
        let version: string | undefined;
        try {
          const data = await resp.json();
          version = data.version ?? data.Version ?? undefined;
        } catch {
          // plain-text version string
          version = await resp.text().catch(() => undefined);
        }
        return { ...candidate, version };
      }
    } catch {
      // Not running or CORS blocked — try next
    }
  }
  return null;
}

/** Supported wire protocols by vendor */
export type HelperProtocol = 'embridge' | 'generic-json' | 'websocket';

export function getProtocol(vendor: string): HelperProtocol {
  if (vendor === 'emBridge') return 'embridge';
  if (vendor === 'emSigner') return 'websocket';
  return 'generic-json';
}
