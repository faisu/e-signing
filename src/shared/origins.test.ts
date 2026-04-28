import { describe, expect, it } from "vitest";
import { ALLOWED_ORIGINS, isAllowedOrigin } from "./origins";

describe("origin allowlist", () => {
  it("contains expected default origins", () => {
    expect(ALLOWED_ORIGINS).toContain("https://app.example.com");
    expect(ALLOWED_ORIGINS).toContain("http://localhost:3000");
  });

  it("allows only exact configured origins", () => {
    expect(isAllowedOrigin("https://app.example.com")).toBe(true);
    expect(isAllowedOrigin("http://localhost:3000")).toBe(true);
    expect(isAllowedOrigin("https://evil.example.com")).toBe(false);
    expect(isAllowedOrigin("https://app.example.com.evil.com")).toBe(false);
  });
});
