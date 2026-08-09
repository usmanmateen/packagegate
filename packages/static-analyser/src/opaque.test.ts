import { describe, expect, it } from "vitest";
import { analyseOpaqueSource } from "./opaque.js";

describe("analyseOpaqueSource", () => {
  it("flags large single-line previews without claiming malware", () => {
    const preview = `${"a".repeat(60_000)};eval(x)`;
    const result = analyseOpaqueSource({
      path: "payload.js",
      sizeBytes: 10_000_000,
      preview,
      lifecycleReachable: true,
      reason: "SOURCE_CONTENT_LIMIT_EXCEEDED",
    });
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.category).toBe("OBFUSCATION_SIGNAL");
    expect(result.signals).toContain("extreme-single-line");
    expect(result.signals.some((s) => s.startsWith("token:"))).toBe(true);
  });
});
