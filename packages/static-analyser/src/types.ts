import type {
  Confidence,
  Evidence,
  Finding,
  FindingCategory,
  LifecycleScript,
  ParseFailure,
  ScannedFile,
  Severity,
  SourceLocation,
} from "@packagegate/shared";
import type { AnalysisLimits } from "./limits.js";

/**
 * A file handed to the analyser.
 *
 * The analyser performs **no I/O**. The fetcher extracts the tarball, applies
 * its own traversal and size defences, decodes the bytes and passes the result
 * in. That is what makes this package safe to run inside a network-disabled,
 * read-only scanner process, and it is why there is no `fs` import anywhere in
 * `src/`.
 */
export interface SourceFileInput {
  /** Package-relative path, e.g. `lib/index.js`. Never an absolute host path. */
  readonly path: string;
  /** Decoded file content. Binary files arrive as lossy text and are detected as such. */
  readonly content: string;
}

/** Coarse file classification, reusing the shared vocabulary rather than forking it. */
export type FileKind = ScannedFile["kind"];

/**
 * A budget that was reached. Recorded so that "no findings" can never be
 * confused with "we stopped analysing".
 */
export interface LimitNotice {
  /** Package-relative file, or `<package>` for package-wide budgets. */
  readonly filePath: string;
  readonly limit: keyof AnalysisLimits;
  readonly limitValue: number;
  readonly message: string;
}

/** What happened to one file. Emitted for every input file, analysed or not. */
export interface FileAnalysisReport {
  readonly path: string;
  readonly kind: FileKind;
  readonly sizeBytes: number;
  /** True only when the file was parsed and traversed to completion. */
  readonly analysed: boolean;
  /** Why it was not analysed, when `analysed` is false. */
  readonly skippedReason?: string;
  readonly findingCount: number;
  /** Recoverable syntax errors Babel tolerated while still producing an AST. */
  readonly recoveredParseErrors: number;
  /**
   * True when the file looks machine-generated (very long lines, few newlines).
   * Informational only — minification is not evidence of anything, and no rule
   * raises severity because of it.
   */
  readonly minified: boolean;
}

/** Everything the static analyser produces for one package. */
export interface StaticAnalysisResult {
  readonly findings: Finding[];
  /** Files that could not be parsed, or were too large to parse. Never silently dropped. */
  readonly parseFailures: ParseFailure[];
  readonly files: FileAnalysisReport[];
  /** Lifecycle scripts recovered from the manifest, with referenced files. */
  readonly lifecycleScripts: LifecycleScript[];
  readonly limitNotices: LimitNotice[];
  readonly rulesVersion: string;
}

/**
 * A finding before the emitter turns it into a {@link Finding}: the emitter
 * owns id derivation, snippet extraction, sanitisation, deduplication and
 * per-file caps so no individual rule can get those wrong.
 */
export interface FindingDraft {
  readonly ruleId: string;
  readonly category: FindingCategory;
  readonly title: string;
  readonly description: string;
  readonly severity: Severity;
  readonly confidence: Confidence;
  readonly location: SourceLocation;
  /** Raw source excerpt; sanitised and truncated by the emitter. */
  readonly rawSnippet: string;
  readonly evidence: Evidence[];
  readonly metadata?: Record<string, unknown>;
}

/**
 * Everything the analyser needs about one package.
 *
 * Deliberately not the registry manifest type: the analyser must read the
 * **tarball's** `package.json`, not the registry's copy of it. The registry
 * does not validate that the two agree and the installer uses the tarball's,
 * so taking `scripts` from registry metadata would analyse a manifest that
 * never runs.
 */
export interface PackageAnalysisInput {
  readonly files: readonly SourceFileInput[];
  /** `scripts` from the tarball's manifest. Absent is not the same as empty. */
  readonly scripts?: Readonly<Record<string, string>>;
  /** Raw manifest text, used only to give manifest findings a line number. */
  readonly manifestText?: string;
  /** Package-relative manifest path. Defaults to `package.json`. */
  readonly manifestPath?: string;
}
