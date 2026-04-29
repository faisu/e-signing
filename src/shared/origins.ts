export const ALLOWED_ORIGINS = [
  "https://app.example.com",
  "http://localhost:3000",
  "https://autodcr.vercel.app"
] as const;

export function isAllowedOrigin(origin: string): boolean {
  return ALLOWED_ORIGINS.includes(origin as (typeof ALLOWED_ORIGINS)[number]);
}
