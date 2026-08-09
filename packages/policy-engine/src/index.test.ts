import { describe, expect, it } from "vitest";
import { decidePolicy } from "./index.js";
import type { AnalysisCompleteness } from "@packagegate/shared";

function completeness(
  status: AnalysisCompleteness["status"],
  reasons: AnalysisCompleteness["reasons"] = [],
): AnalysisCompleteness {
  return { status, reasons, coverageRatio: status === "COMPLETE" ? 1 : 0.7 };
}

describe("decidePolicy", () => {
  it("keeps ALLOW when analysis is complete", () => {
    const decision = decidePolicy({
      behaviouralRecommendation: "ALLOW",
      analysisCompleteness: completeness("COMPLETE"),
    });
    expect(decision.finalAction).toBe("ALLOW");
    expect(decision.threatIntelligence).toBe("NONE");
  });

  it("escalates ALLOW to REVIEW when lifecycle-reachable executable source was skipped", () => {
    const decision = decidePolicy({
      behaviouralRecommendation: "ALLOW",
      analysisCompleteness: completeness("DEGRADED", [
        {
          code: "SOURCE_CONTENT_LIMIT_EXCEEDED",
          path: "payload.js",
          message: "content retention budget exceeded",
          sizeBytes: 10_000_000,
          lifecycleReachable: true,
          executableSource: true,
          metadata: {},
        },
      ]),
    });
    expect(decision.finalAction).toBe("REVIEW");
    expect(decision.behaviouralRecommendation).toBe("ALLOW");
    expect(decision.reasons.some((r) => r.code === "DEGRADED_EXECUTABLE_ANALYSIS")).toBe(
      true,
    );
  });

  it("does not escalate for unrelated non-executable gaps alone", () => {
    const decision = decidePolicy({
      behaviouralRecommendation: "ALLOW",
      analysisCompleteness: completeness("DEGRADED", [
        {
          code: "UNSUPPORTED_LANGUAGE",
          path: "readme.txt",
          message: "not executable source",
          executableSource: false,
          metadata: {},
        },
      ]),
    });
    // UNSUPPORTED_LANGUAGE without executableSource — hasSecurityRelevantGap
    // returns false for this reason alone.
    expect(decision.finalAction).toBe("ALLOW");
  });

  it("BLOCKS on trusted malicious intelligence regardless of behavioural score", () => {
    const decision = decidePolicy({
      behaviouralRecommendation: "ALLOW",
      analysisCompleteness: completeness("COMPLETE"),
      threatIntelligence: "KNOWN_MALICIOUS",
    });
    expect(decision.finalAction).toBe("BLOCK");
    expect(decision.behaviouralRecommendation).toBe("ALLOW");
  });

  it("escalates INSUFFICIENT analysis to at least REVIEW", () => {
    const decision = decidePolicy({
      behaviouralRecommendation: "ALLOW",
      analysisCompleteness: completeness("INSUFFICIENT", [
        {
          code: "PARSER_FAILURE",
          message: "too many parse failures",
          executableSource: true,
          metadata: {},
        },
      ]),
    });
    expect(decision.finalAction).toBe("REVIEW");
  });
});
