export const ALLOWED_ORIGINS = [
  "http://192.168.1.8/*",
  "http://localhost:3000",
  "https://autodcr.vercel.app"
] as const;

export function isAllowedOrigin(origin: string): boolean {
  return ALLOWED_ORIGINS.includes(origin as (typeof ALLOWED_ORIGINS)[number]);
}
