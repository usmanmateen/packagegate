/**
 * Defensive budgets.
 *
 * Every input to this package is an attacker-authored file from a public
 * registry. A package must not be able to hang, exhaust or crash the scanner,
 * so every unbounded dimension of the analysis has an explicit ceiling here
 * rather than an implicit one somewhere in a rule.
 *
 * Hitting a limit is never silent: it produces a {@link LimitNotice} (and, for
 * whole files, a `ParseFailure`) so "we found nothing" can always be
 * distinguished from "we stopped looking".
 */
export interface AnalysisLimits {
  /** Files larger than this are not parsed at all. Recorded as a parse failure. */
  readonly maxFileBytes: number;
  /** Files analysed in one package. Beyond this, remaining files are recorded, not parsed. */
  readonly maxFilesAnalysed: number;
  /** Findings kept from a single file. */
  readonly maxFindingsPerFile: number;
  /** Findings kept from the whole package. */
  readonly maxFindingsTotal: number;
  /** AST nodes visited per file before traversal is abandoned. */
  readonly maxNodesPerFile: number;
  /** Wall-clock budget for parsing plus traversing one file. */
  readonly maxFileMillis: number;
  /** Characters of a string literal considered by literal-inspection rules. */
  readonly maxLiteralScanLength: number;
  /** Maximum characters retained in a finding snippet. */
  readonly maxSnippetLength: number;
  /**
   * Findings a single high-volume literal rule may emit per file. Bundles
   * legitimately contain thousands of URLs; without this one vendored file
   * would drown every other signal.
   */
  readonly maxFindingsPerRulePerFile: number;
  /** Member-expression depth followed when resolving `a.b.c.d`. */
  readonly maxMemberDepth: number;
  /** Alias hops followed when resolving one binding through another. */
  readonly maxAliasDepth: number;
  /** Characters of a lifecycle command string parsed for referenced files. */
  readonly maxCommandLength: number;
}

export const DEFAULT_ANALYSIS_LIMITS: AnalysisLimits = {
  maxFileBytes: 2_000_000,
  maxFilesAnalysed: 5_000,
  maxFindingsPerFile: 200,
  maxFindingsTotal: 5_000,
  maxNodesPerFile: 400_000,
  maxFileMillis: 5_000,
  maxLiteralScanLength: 8_192,
  maxSnippetLength: 400,
  maxFindingsPerRulePerFile: 25,
  maxMemberDepth: 8,
  maxAliasDepth: 4,
  maxCommandLength: 4_096,
};

export function resolveLimits(overrides?: Partial<AnalysisLimits>): AnalysisLimits {
  if (overrides === undefined) return DEFAULT_ANALYSIS_LIMITS;
  return { ...DEFAULT_ANALYSIS_LIMITS, ...overrides };
}
