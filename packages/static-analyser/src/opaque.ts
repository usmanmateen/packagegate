import type { Finding, SourceLocation } from "@packagegate/shared";
import { sanitiseInlineValue } from "@packagegate/shared";
import { createHash } from "node:crypto";

/**
 * Bounded triage of executable source that could not receive full AST analysis.
 *
 * Operates only on a size-capped preview buffer. Never evaluates, requires, or
 * executes the source.
 */

export interface OpaqueSourceInput {
  readonly path: string;
  readonly sizeBytes: number;
  /** First N bytes only; may be absent when even a preview was unavailable. */
  readonly preview?: Uint8Array | string;
  readonly lifecycleReachable?: boolean;
  readonly retainedBytes?: number;
  readonly reason:
    | "SOURCE_CONTENT_LIMIT_EXCEEDED"
    | "CONTENT_LIMIT_EXCEEDED"
    | "ANALYSIS_BUDGET_EXHAUSTED";
}

export interface OpaqueSourceResult {
  readonly findings: Finding[];
  readonly signals: string[];
}

const TOKEN_PATTERNS: ReadonlyArray<{ readonly name: string; readonly re: RegExp }> = [
  { name: "eval", re: /\beval\s*\(/ },
  { name: "Function", re: /\bFunction\s*\(/ },
  { name: "child_process", re: /child_process/ },
  { name: "process.env", re: /process\.env/ },
  { name: "https?", re: /https?:\/\//i },
  { name: "WebAssembly", re: /WebAssembly/ },
  { name: "Buffer.from", re: /Buffer\.from\s*\(/ },
  { name: "atob", re: /\batob\s*\(/ },
];

function shannonEntropy(sample: string): number {
  if (sample.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of sample) {
    counts.set(ch, (counts.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / sample.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function printableRatio(sample: string): number {
  if (sample.length === 0) return 0;
  let printable = 0;
  for (let i = 0; i < sample.length; i += 1) {
    const code = sample.charCodeAt(i);
    if (code === 9 || code === 10 || code === 13 || (code >= 32 && code < 127)) {
      printable += 1;
    }
  }
  return printable / sample.length;
}

/**
 * Produce opaque-source findings from a bounded preview.
 */
export function analyseOpaqueSource(input: OpaqueSourceInput): OpaqueSourceResult {
  const location: SourceLocation = {
    filePath: input.path,
    startLine: 1,
    endLine: 1,
  };
  const previewText =
    input.preview === undefined
      ? ""
      : typeof input.preview === "string"
        ? input.preview.slice(0, 65_536)
        : Buffer.from(input.preview).toString("utf8").slice(0, 65_536);

  const signals: string[] = [];
  const lineCount = previewText.length === 0 ? 0 : previewText.split(/\r\n|\n|\r/).length;
  const maxLineLength = previewText
    .split(/\r\n|\n|\r/)
    .reduce((max, line) => Math.max(max, line.length), 0);

  if (input.sizeBytes >= 1_000_000) signals.push("large-file");
  if (lineCount <= 3 && input.sizeBytes >= 100_000) signals.push("extreme-single-line");
  if (maxLineLength >= 50_000) signals.push("very-long-line");

  const entropySample = previewText.slice(0, 8_192);
  const entropy = shannonEntropy(entropySample);
  if (entropy >= 5.5) signals.push("high-entropy-preview");

  const printable = printableRatio(entropySample);
  if (printable < 0.85 && previewText.length > 0) signals.push("low-printable-ratio");

  for (const pattern of TOKEN_PATTERNS) {
    if (pattern.re.test(previewText)) signals.push(`token:${pattern.name}`);
  }

  if (/[A-Za-z0-9+/]{80,}={0,2}/.test(previewText)) {
    signals.push("base64-like-blob");
  }

  const idSeed = `${input.path}\0opaque\0${input.sizeBytes}`;
  const id = createHash("sha256").update(idSeed).digest("hex").slice(0, 32);

  const findings: Finding[] = [
    {
      id,
      ruleId: "file/opaque-executable-source",
      category: "OBFUSCATION_SIGNAL",
      title: "Large or opaque executable source not fully AST-analysed",
      description:
        `Executable JavaScript/TypeScript at \`${input.path}\` exceeded full AST ` +
        "retention/analysis limits. Bounded triage inspected a size-capped preview only. " +
        "This reduces analysis completeness; it is not by itself proof of malice. " +
        "Minification alone is not treated as behavioural risk.",
      severity: "MEDIUM",
      confidence: "HIGH",
      location,
      snippet: sanitiseInlineValue(
        previewText.slice(0, 120) || `[no preview retained; size=${input.sizeBytes}]`,
        200,
      ),
      evidence: [
        {
          kind: "FILE_METADATA",
          description: "File exceeded full-analysis content budget",
          location,
          value: `${input.sizeBytes} bytes`,
        },
        {
          kind: "MEASUREMENT",
          description: "Bounded opaque-source signals",
          location,
          value: signals.join(", ") || "size-only",
        },
      ],
      metadata: {
        opaque: true,
        sizeBytes: input.sizeBytes,
        retainedBytes: input.retainedBytes ?? 0,
        lifecycleReachable: input.lifecycleReachable === true,
        signals,
        previewEntropy: Number(entropy.toFixed(3)),
        reason: input.reason,
        // Explicitly not scored as minification-only behavioural risk.
        minifiedOnly: false,
      },
    },
  ];

  return { findings, signals };
}
