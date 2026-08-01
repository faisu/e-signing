export const ALLOWED_ORIGINS = [
  "http://192.168.1.9:3000",
  "http://192.168.0.121:3000",
  "http://localhost:3000",
  "https://autodcr.vercel.app",
  "https://autodcr.bridgeit.in",
] as const;

export function isAllowedOrigin(origin: string): boolean {
  return ALLOWED_ORIGINS.includes(origin as (typeof ALLOWED_ORIGINS)[number]);
}
