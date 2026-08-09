import { describe, expect, it } from "vitest";
import {
  buildConfusionMatrix,
  classifyOutcome,
  isInterventionPositive,
  tallyMissReasons,
} from "./metrics.js";
import type { EvaluationSampleResult } from "./types.js";

describe("evaluation metrics", () => {
  it("classifies intervention outcomes", () => {
    expect(isInterventionPositive("REVIEW")).toBe(true);
    expect(isInterventionPositive("BLOCK")).toBe(true);
    expect(isInterventionPositive("ALLOW")).toBe(false);
    expect(classifyOutcome("MALICIOUS", "REVIEW")).toBe("TP");
    expect(classifyOutcome("MALICIOUS", "ALLOW")).toBe("FN");
    expect(classifyOutcome("EXPECTED_BENIGN", "ALLOW")).toBe("TN");
    expect(classifyOutcome("EXPECTED_BENIGN", "REVIEW")).toBe("FP");
    expect(classifyOutcome("UNKNOWN", "ALLOW")).toBeNull();
  });

  it("builds a confusion matrix and ignores skipped samples", () => {
    const results: EvaluationSampleResult[] = [
      {
        id: "m1",
        label: "MALICIOUS",
        status: "COMPLETED",
        finalAction: "REVIEW",
        interventionPositive: true,
      },
      {
        id: "m2",
        label: "MALICIOUS",
        status: "COMPLETED",
        finalAction: "ALLOW",
        interventionPositive: false,
        missReason: "OPAQUE_PAYLOAD",
      },
      {
        id: "b1",
        label: "EXPECTED_BENIGN",
        status: "COMPLETED",
        finalAction: "ALLOW",
        interventionPositive: false,
      },
      {
        id: "b2",
        label: "EXPECTED_BENIGN",
        status: "COMPLETED",
        finalAction: "REVIEW",
        interventionPositive: true,
      },
      {
        id: "skip",
        label: "MALICIOUS",
        status: "SKIPPED",
        skipReason: "malware root not provided",
      },
    ];

    const matrix = buildConfusionMatrix(results);
    expect(matrix).toMatchObject({ tp: 1, fn: 1, tn: 1, fp: 1, sampleCount: 4 });
    expect(matrix.precision).toBeCloseTo(0.5);
    expect(matrix.recall).toBeCloseTo(0.5);
    expect(tallyMissReasons(results)).toEqual({ OPAQUE_PAYLOAD: 1 });
  });
});
