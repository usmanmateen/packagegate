import { z } from "zod";
import {
  ConfidenceSchema,
  FindingCategorySchema,
  SeveritySchema,
  SourceLocationSchema,
} from "./primitives.js";

/**
 * The concrete observation that justifies a finding. Every finding must carry
 * at least one piece of evidence pointing at something real in the package —
 * this is the schema-level enforcement of "evidence before verdict".
 */
export const EVIDENCE_KINDS = [
  /** A specific AST node, e.g. a CallExpression for `cp.exec(...)`. */
  "AST_NODE",
  /** A field in package.json, e.g. `scripts.postinstall`. */
  "MANIFEST_FIELD",
  /** A string literal recovered from source, e.g. a URL or a file path. */
  "STRING_LITERAL",
  /** A resolved binding, e.g. `cp` → `require("child_process")`. */
  "BINDING",
  /** A property of the file itself, e.g. it is an ELF binary or a .node addon. */
  "FILE_METADATA",
  /** A statistical property, e.g. Shannon entropy of a literal. */
  "MEASUREMENT",
] as const;
export const EvidenceKindSchema = z.enum(EVIDENCE_KINDS);
export type EvidenceKind = z.infer<typeof EvidenceKindSchema>;

export const EvidenceSchema = z.object({
  kind: EvidenceKindSchema,
  /** Human-readable statement of what was observed. No interpretation. */
  description: z.string().min(1),
  location: SourceLocationSchema.optional(),
  /**
   * The observed value, already passed through `sanitiseInlineValue`.
   * Bounded — never a whole file.
   */
  value: z.string().optional(),
});
export type Evidence = z.infer<typeof EvidenceSchema>;

export const FindingSchema = z.object({
  id: z.string().min(1),
  /** Stable rule identifier, e.g. `js/process-execution/child-process-exec`. */
  ruleId: z.string().min(1),
  category: FindingCategorySchema,
  title: z.string().min(1),
  /** What was detected and why the rule fired. Neutral, factual language. */
  description: z.string().min(1),
  severity: SeveritySchema,
  confidence: ConfidenceSchema,
  location: SourceLocationSchema,
  /** Sanitised source excerpt from the real package. Never fabricated. */
  snippet: z.string(),
  evidence: z.array(EvidenceSchema).min(1),
  /**
   * Points this finding contributed to the final risk score. Populated by the
   * risk engine *after* scoring — the analyser itself does not assign score,
   * only observations. Absent on a raw analyser result.
   */
  riskContribution: z.number().optional(),
  metadata: z.record(z.string(), z.unknown()).default({}),
});
export type Finding = z.infer<typeof FindingSchema>;

/**
 * A file the analyser could not parse. Recorded explicitly rather than
 * swallowed: a package that defeats the parser is itself worth knowing about,
 * and silently skipping files would make "no findings" dishonest.
 */
export const ParseFailureSchema = z.object({
  filePath: z.string().min(1),
  reason: z.string().min(1),
  /** Bytes of the file, useful for spotting deliberate parser exhaustion. */
  sizeBytes: z.number().int().min(0),
});
export type ParseFailure = z.infer<typeof ParseFailureSchema>;
