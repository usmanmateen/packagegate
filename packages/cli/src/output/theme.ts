import type {
  Confidence,
  RiskClassification,
  RiskRecommendation,
  Severity,
} from "@packagegate/shared";

/**
 * Terminal styling for PackageGate CLI output.
 *
 * Domain packages never import this module. Colour maps recommendations and
 * severities for humans; it does not score packages or change verdicts.
 *
 * Colour is off when:
 *  - {@link ThemeOptions.enabled} is false
 *  - `NO_COLOR` is set (https://no-color.org/)
 *  - stdout is not a TTY (unless force-enabled for tests)
 */

const ESC = "\u001b[";
const RESET = `${ESC}0m`;

const CODES = {
  bold: "1",
  dim: "2",
  red: "31",
  green: "32",
  yellow: "33",
  cyan: "36",
  white: "37",
  brightWhite: "97",
} as const;

export type StyleKind =
  "success" | "warning" | "danger" | "info" | "muted" | "heading" | "emphasis" | "plain";

export interface ThemeOptions {
  /**
   * Force colour on or off. When omitted, follows TTY + `NO_COLOR`.
   * Pass `true` in tests that assert styled output; pass `false` for pipes.
   */
  readonly enabled?: boolean;
  /** Stream used for TTY detection. Defaults to `process.stdout`. */
  readonly stream?: { readonly isTTY?: boolean };
  /** Environment variables; defaults to `process.env`. */
  readonly env?: NodeJS.ProcessEnv;
}

export interface Theme {
  readonly enabled: boolean;
  success(text: string): string;
  warning(text: string): string;
  danger(text: string): string;
  info(text: string): string;
  muted(text: string): string;
  heading(text: string): string;
  emphasis(text: string): string;
  colourRecommendation(recommendation: RiskRecommendation): string;
  colourClassification(classification: RiskClassification): string;
  colourSeverity(severity: Severity, text?: string): string;
  colourConfidence(confidence: Confidence, text?: string): string;
  colourRiskScore(score: number, recommendation: RiskRecommendation): string;
  errorPrefix(text?: string): string;
  warningPrefix(text?: string): string;
}

function paint(enabled: boolean, codes: string[], text: string): string {
  if (!enabled || text.length === 0) return text;
  return `${ESC}${codes.join(";")}m${text}${RESET}`;
}

/**
 * Pure style mapping for recommendations. Tests assert on these kinds so they
 * do not depend on raw ANSI sequences.
 */
export function recommendationStyle(recommendation: RiskRecommendation): StyleKind {
  switch (recommendation) {
    case "ALLOW":
      return "success";
    case "REVIEW":
      return "warning";
    case "BLOCK":
      return "danger";
    default: {
      const _exhaustive: never = recommendation;
      return _exhaustive;
    }
  }
}

/**
 * Pure style mapping for classifications. Score colouring uses the machine
 * recommendation instead of duplicating risk-engine thresholds.
 */
export function classificationStyle(classification: RiskClassification): StyleKind {
  switch (classification) {
    case "LOW_RISK":
      return "success";
    case "SUSPICIOUS":
    case "INSUFFICIENT_EVIDENCE":
      return "warning";
    case "HIGH_RISK_BEHAVIOUR":
    case "KNOWN_MALWARE":
      return "danger";
    default: {
      const _exhaustive: never = classification;
      return _exhaustive;
    }
  }
}

export function severityStyle(severity: Severity): StyleKind {
  switch (severity) {
    case "INFO":
      return "info";
    case "LOW":
      return "success";
    case "MEDIUM":
      return "warning";
    case "HIGH":
      return "danger";
    case "CRITICAL":
      return "danger";
    default: {
      const _exhaustive: never = severity;
      return _exhaustive;
    }
  }
}

/**
 * Confidence is detection certainty, not danger. HIGH must not look like HIGH
 * severity.
 */
export function confidenceStyle(confidence: Confidence): StyleKind {
  switch (confidence) {
    case "HIGH":
      return "emphasis";
    case "MEDIUM":
      return "warning";
    case "LOW":
      return "muted";
    default: {
      const _exhaustive: never = confidence;
      return _exhaustive;
    }
  }
}

export function shouldUseColor(options: ThemeOptions = {}): boolean {
  if (options.enabled === true) return true;
  if (options.enabled === false) return false;

  const env = options.env ?? process.env;
  if (env["NO_COLOR"] !== undefined && env["NO_COLOR"] !== "") return false;
  if (env["FORCE_COLOR"] === "0") return false;
  if (env["FORCE_COLOR"] !== undefined && env["FORCE_COLOR"] !== "") return true;

  const stream = options.stream ?? process.stdout;
  return stream.isTTY === true;
}

function applyKind(enabled: boolean, kind: StyleKind, text: string): string {
  switch (kind) {
    case "success":
      return paint(enabled, [CODES.green], text);
    case "warning":
      return paint(enabled, [CODES.yellow], text);
    case "danger":
      return paint(enabled, [CODES.red], text);
    case "info":
      return paint(enabled, [CODES.cyan], text);
    case "muted":
      return paint(enabled, [CODES.dim], text);
    case "heading":
      return paint(enabled, [CODES.bold, CODES.brightWhite], text);
    case "emphasis":
      return paint(enabled, [CODES.bold, CODES.cyan], text);
    case "plain":
      return text;
    default: {
      const _exhaustive: never = kind;
      return _exhaustive;
    }
  }
}

/** Create a theme bound to the current terminal / explicit override. */
export function createTheme(options: ThemeOptions = {}): Theme {
  const enabled = shouldUseColor(options);

  const theme: Theme = {
    enabled,
    success: (text) => applyKind(enabled, "success", text),
    warning: (text) => applyKind(enabled, "warning", text),
    danger: (text) => applyKind(enabled, "danger", text),
    info: (text) => applyKind(enabled, "info", text),
    muted: (text) => applyKind(enabled, "muted", text),
    heading: (text) => applyKind(enabled, "heading", text),
    emphasis: (text) => applyKind(enabled, "emphasis", text),

    colourRecommendation(recommendation) {
      return applyKind(enabled, recommendationStyle(recommendation), recommendation);
    },

    colourClassification(classification) {
      const kind = classificationStyle(classification);
      if (classification === "KNOWN_MALWARE") {
        return paint(enabled, [CODES.bold, CODES.red], classification);
      }
      return applyKind(enabled, kind, classification);
    },

    colourSeverity(severity, text = severity) {
      if (severity === "INFO") {
        return paint(enabled, [CODES.dim, CODES.cyan], text);
      }
      if (severity === "CRITICAL") {
        return paint(enabled, [CODES.bold, CODES.red], text);
      }
      return applyKind(enabled, severityStyle(severity), text);
    },

    colourConfidence(confidence, text = confidence) {
      if (confidence === "MEDIUM") {
        return paint(enabled, [CODES.dim, CODES.yellow], text);
      }
      return applyKind(enabled, confidenceStyle(confidence), text);
    },

    /**
     * Score colour follows the machine recommendation so the CLI cannot
     * disagree with risk-engine thresholds by inventing its own bands.
     */
    colourRiskScore(score, recommendation) {
      return applyKind(enabled, recommendationStyle(recommendation), String(score));
    },

    errorPrefix(text = "error") {
      return applyKind(enabled, "danger", text);
    },

    warningPrefix(text = "warning") {
      return applyKind(enabled, "warning", text);
    },
  };

  return theme;
}

/** Strip ANSI SGR sequences — used by tests and any plain-text assertions. */
export function stripAnsi(text: string): string {
  // eslint-disable-next-line no-control-regex -- deliberate: remove ESC sequences
  return text.replace(/\u001b\[[0-9;]*m/g, "");
}

export function containsAnsi(text: string): boolean {
  return text.includes("\u001b[");
}
