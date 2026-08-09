import { describe, expect, it } from "vitest";
import {
  classificationStyle,
  confidenceStyle,
  containsAnsi,
  createTheme,
  recommendationStyle,
  severityStyle,
  shouldUseColor,
  stripAnsi,
} from "./theme.js";

describe("style mappings", () => {
  it("maps ALLOW to success, REVIEW to warning, BLOCK to danger", () => {
    expect(recommendationStyle("ALLOW")).toBe("success");
    expect(recommendationStyle("REVIEW")).toBe("warning");
    expect(recommendationStyle("BLOCK")).toBe("danger");
  });

  it("maps classifications without inventing score thresholds", () => {
    expect(classificationStyle("LOW_RISK")).toBe("success");
    expect(classificationStyle("SUSPICIOUS")).toBe("warning");
    expect(classificationStyle("INSUFFICIENT_EVIDENCE")).toBe("warning");
    expect(classificationStyle("HIGH_RISK_BEHAVIOUR")).toBe("danger");
    expect(classificationStyle("KNOWN_MALWARE")).toBe("danger");
  });

  it("colours severity independently of confidence", () => {
    expect(severityStyle("INFO")).toBe("info");
    expect(severityStyle("LOW")).toBe("success");
    expect(severityStyle("MEDIUM")).toBe("warning");
    expect(severityStyle("HIGH")).toBe("danger");
    expect(severityStyle("CRITICAL")).toBe("danger");

    // HIGH confidence must not share HIGH severity's danger style.
    expect(confidenceStyle("HIGH")).toBe("emphasis");
    expect(confidenceStyle("MEDIUM")).toBe("warning");
    expect(confidenceStyle("LOW")).toBe("muted");
  });
});

describe("createTheme", () => {
  it("applies success/warning/danger for recommendations when colour is on", () => {
    const theme = createTheme({ enabled: true });
    expect(containsAnsi(theme.colourRecommendation("ALLOW"))).toBe(true);
    expect(containsAnsi(theme.colourRecommendation("REVIEW"))).toBe(true);
    expect(containsAnsi(theme.colourRecommendation("BLOCK"))).toBe(true);
    expect(stripAnsi(theme.colourRecommendation("ALLOW"))).toBe("ALLOW");
    expect(stripAnsi(theme.colourRecommendation("REVIEW"))).toBe("REVIEW");
    expect(stripAnsi(theme.colourRecommendation("BLOCK"))).toBe("BLOCK");
  });

  it("colours risk score from the recommendation, not a parallel threshold", () => {
    const theme = createTheme({ enabled: true });
    const allowScore = theme.colourRiskScore(12, "ALLOW");
    const reviewScore = theme.colourRiskScore(12, "REVIEW");
    const blockScore = theme.colourRiskScore(12, "BLOCK");

    expect(stripAnsi(allowScore)).toBe("12");
    expect(stripAnsi(reviewScore)).toBe("12");
    expect(stripAnsi(blockScore)).toBe("12");
    // Same numeric score, different recommendation ⇒ different style codes.
    expect(allowScore).not.toBe(reviewScore);
    expect(reviewScore).not.toBe(blockScore);
  });

  it("renders severity badges as readable plain text when colour is off", () => {
    const theme = createTheme({ enabled: false });
    expect(theme.colourSeverity("LOW", "LOW severity")).toBe("LOW severity");
    expect(theme.colourConfidence("HIGH", "HIGH confidence")).toBe(
      "HIGH confidence",
    );
    expect(containsAnsi(theme.colourSeverity("HIGH"))).toBe(false);
  });

  it("respects NO_COLOR and non-TTY streams", () => {
    expect(
      shouldUseColor({
        env: { NO_COLOR: "1" },
        stream: { isTTY: true },
      }),
    ).toBe(false);
    expect(
      shouldUseColor({
        env: {},
        stream: { isTTY: false },
      }),
    ).toBe(false);
    expect(
      shouldUseColor({
        enabled: true,
        env: { NO_COLOR: "1" },
        stream: { isTTY: false },
      }),
    ).toBe(true);
  });
});
