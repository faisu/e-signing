/**
 * In-memory PDF cache keyed by pdfId (UUID).
 * Replace with Redis/S3 for multi-instance deployments.
 *
 * TTL: 15 minutes — long enough for a user to insert their PIN,
 * short enough to avoid accumulating large buffers in memory.
 */

interface CacheEntry {
  pdf: Buffer;
  byteRange: [number, number, number, number];
  expiresAt: number;
}

const cache = new Map<string, CacheEntry>();
const TTL_MS = 15 * 60 * 1000;

export function cachePdf(
  pdfId: string,
  pdf: Buffer,
  byteRange: [number, number, number, number],
): void {
  cache.set(pdfId, { pdf, byteRange, expiresAt: Date.now() + TTL_MS });
  // Lazy eviction of expired entries
  const now = Date.now();
  cache.forEach((entry, key) => {
    if (entry.expiresAt < now) cache.delete(key);
  });
}

export function getPdf(
  pdfId: string,
): { pdf: Buffer; byteRange: [number, number, number, number] } | null {
  const entry = cache.get(pdfId);
  if (!entry || entry.expiresAt < Date.now()) {
    cache.delete(pdfId);
    return null;
  }
  return { pdf: entry.pdf, byteRange: entry.byteRange };
}

export function deletePdf(pdfId: string): void {
  cache.delete(pdfId);
}
