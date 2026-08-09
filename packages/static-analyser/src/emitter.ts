import { createHash } from "node:crypto";
import type { Confidence, Finding, SourceLocation } from "@packagegate/shared";
import { sanitiseSnippet } from "@packagegate/shared";
import type { AnalysisLimits } from "./limits.js";
import type { FindingDraft, LimitNotice } from "./types.js";

/**
 * The finding emitter.
 *
 * Identifier derivation, snippet extraction, sanitisation, deduplication and
 * the per-file budgets all live here rather than in the rules. That is a
 * deliberate concentration of risk: every one of these is easy to get subtly
 * wrong, and a rule that got snippet sanitisation wrong would push raw
 * attacker-controlled bytes into logs, the database and a browser. Rules
 * describe *what they saw*; they never decide how it is packaged.
 */

/** Characters of context kept either side of a match on a very long line. */
const LONG_LINE_CONTEXT = 120;

/**
 * A line long enough that quoting the whole of it is useless to a reader and
 * wasteful to store. Minified bundles routinely have single lines of hundreds
 * of kilobytes.
 */
const LONG_LINE_THRESHOLD = 400;

export interface EmitterOptions {
  readonly filePath: string;
  readonly source: string;
  readonly limits: AnalysisLimits;
  /**
   * Whether the file looks machine-generated. This **never** changes severity.
   * Its only effect is a confidence reduction, because a snippet from a
   * minified bundle is harder to attribute and often duplicates source that is
   * also present unminified — the calibration in `docs/RISK_MODEL.md` §4.3.
   */
  readonly minified: boolean;
  /** Findings already emitted for the whole package, for the global budget. */
  readonly totalBudgetRemaining: number;
}

function downgradeConfidence(confidence: Confidence): Confidence {
  if (confidence === "HIGH") return "MEDIUM";
  if (confidence === "MEDIUM") return "LOW";
  return "LOW";
}

/**
 * Deterministic finding id.
 *
 * Same tarball plus same rules must produce the same ids on every run, forever
 * — the risk model's reproducibility commitment depends on it. So the id is a
 * hash of stable facts about the observation and contains no timestamp, no
 * counter and no random component.
 */
function deriveId(draft: FindingDraft, discriminator: string): string {
  const material = [
    draft.ruleId,
    draft.location.filePath,
    String(draft.location.startLine),
    String(draft.location.startColumn ?? ""),
    discriminator,
  ].join("\0");
  return createHash("sha256").update(material).digest("hex").slice(0, 32);
}

/**
 * The value that distinguishes two findings from the same rule at the same
 * place. Taken from the first evidence value so rules get it for free and
 * cannot forget it; falls back to the title.
 */
function discriminatorFor(draft: FindingDraft): string {
  for (const evidence of draft.evidence) {
    if (evidence.value !== undefined && evidence.value.length > 0) return evidence.value;
  }
  return draft.title;
}

export class FindingEmitter {
  private readonly findings: Finding[] = [];
  private readonly notices: LimitNotice[] = [];
  private readonly seenIds = new Set<string>();
  private readonly perRuleCounts = new Map<string, number>();
  private readonly noticedLimits = new Set<string>();
  private readonly lineOffsets: number[];

  constructor(private readonly options: EmitterOptions) {
    this.lineOffsets = computeLineOffsets(options.source);
  }

  /**
   * Accept a rule's observation, or drop it against a budget.
   *
   * Returns `true` when the finding was kept. Rules may ignore the return
   * value; nothing about correctness depends on them checking it.
   */
  emit(draft: FindingDraft): boolean {
    const { limits, filePath } = this.options;

    if (this.findings.length >= limits.maxFindingsPerFile) {
      this.notice("maxFindingsPerFile", limits.maxFindingsPerFile, filePath);
      return false;
    }
    if (this.findings.length >= this.options.totalBudgetRemaining) {
      this.notice("maxFindingsTotal", limits.maxFindingsTotal, filePath);
      return false;
    }

    const ruleCount = this.perRuleCounts.get(draft.ruleId) ?? 0;
    if (ruleCount >= limits.maxFindingsPerRulePerFile) {
      this.notice(
        "maxFindingsPerRulePerFile",
        limits.maxFindingsPerRulePerFile,
        filePath,
        draft.ruleId,
      );
      return false;
    }

    const id = deriveId(draft, discriminatorFor(draft));
    if (this.seenIds.has(id)) return false;

    const confidence = this.options.minified
      ? downgradeConfidence(draft.confidence)
      : draft.confidence;

    this.seenIds.add(id);
    this.perRuleCounts.set(draft.ruleId, ruleCount + 1);
    this.findings.push({
      id,
      ruleId: draft.ruleId,
      category: draft.category,
      title: draft.title,
      description: draft.description,
      severity: draft.severity,
      confidence,
      location: draft.location,
      snippet: sanitiseSnippet(
        this.excerpt(draft.location, draft.rawSnippet),
        limits.maxSnippetLength,
      ),
      evidence: draft.evidence,
      metadata: {
        ...(draft.metadata ?? {}),
        ...(this.options.minified ? { minifiedSource: true } : {}),
      },
    });
    return true;
  }

  /**
   * Pull the real source text for a location.
   *
   * The rule's own `rawSnippet` is used only as a fallback: reading from the
   * file guarantees the snippet is genuinely what is in the package rather than
   * something a rule reconstructed, which is the difference between evidence
   * and paraphrase.
   */
  private excerpt(location: SourceLocation, fallback: string): string {
    const { source } = this.options;
    const startLine = location.startLine - 1;
    const endLine = location.endLine - 1;
    const start = this.lineOffsets[startLine];
    if (start === undefined) return fallback;

    const lineEnd = this.lineOffsets[endLine + 1];
    const end = lineEnd === undefined ? source.length : lineEnd;
    if (end <= start) return fallback;

    if (end - start <= LONG_LINE_THRESHOLD) {
      return source.slice(start, end);
    }

    // A long line: window around the reported column instead of quoting the
    // whole thing, so the excerpt still points at the observation.
    const column = location.startColumn ?? 0;
    const focus = start + column;
    const from = Math.max(start, focus - LONG_LINE_CONTEXT);
    const to = Math.min(end, focus + LONG_LINE_CONTEXT);
    return source.slice(from, to);
  }

  private notice(
    limit: LimitNotice["limit"],
    limitValue: number,
    filePath: string,
    detail?: string,
  ): void {
    const key = detail === undefined ? limit : `${limit}:${detail}`;
    if (this.noticedLimits.has(key)) return;
    this.noticedLimits.add(key);
    this.notices.push({
      filePath,
      limit,
      limitValue,
      message:
        detail === undefined
          ? `Reached the ${limit} budget of ${String(limitValue)}; further findings in this file were not recorded`
          : `Reached the ${limit} budget of ${String(limitValue)} for rule ${detail}; further matches in this file were not recorded`,
    });
  }

  /** Add a limit notice raised outside the emit path (traversal budgets). */
  recordLimit(limit: LimitNotice["limit"], limitValue: number, message: string): void {
    if (this.noticedLimits.has(limit)) return;
    this.noticedLimits.add(limit);
    this.notices.push({ filePath: this.options.filePath, limit, limitValue, message });
  }

  results(): { findings: Finding[]; notices: LimitNotice[] } {
    return { findings: this.findings, notices: this.notices };
  }

  get count(): number {
    return this.findings.length;
  }
}

/** Byte offsets of the start of every line, for O(1) excerpt extraction. */
function computeLineOffsets(source: string): number[] {
  const offsets = [0];
  for (let index = 0; index < source.length; index += 1) {
    if (source.charCodeAt(index) === 0x0a) offsets.push(index + 1);
  }
  return offsets;
}
