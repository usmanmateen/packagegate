import type {
  AnalysisCompleteness,
  AnalysisCompletenessReason,
  LifecycleScript,
  ParseFailure,
} from "@packagegate/shared";
import { COVERAGE_FLOOR } from "@packagegate/risk-engine";

const JS_TS_RE = /\.(?:[cm]?js|jsx|[cm]?ts|tsx)$/i;

export function isExecutableSourcePath(path: string): boolean {
  return JS_TS_RE.test(path);
}

export function lifecycleReachablePaths(
  scripts: readonly LifecycleScript[],
): Set<string> {
  const paths = new Set<string>();
  for (const script of scripts) {
    if (!script.runsOnInstall) continue;
    for (const ref of script.referencedFiles) paths.add(ref);
  }
  return paths;
}

export interface CompletenessInput {
  readonly coverageRatio: number;
  readonly droppedExecutable: readonly {
    readonly path: string;
    readonly sizeBytes: number;
    readonly retainedBytes?: number;
    readonly lifecycleReachable: boolean;
  }[];
  readonly parseFailures: readonly ParseFailure[];
  readonly opaquePaths?: readonly string[];
  readonly budgetExhausted?: boolean;
  /**
   * Whether a path is reachable from a declared entrypoint or an install
   * lifecycle script. Omit to treat every file as reachable, which is the
   * fail-closed default when reachability cannot be computed.
   */
  readonly isInstallReachable?: (path: string) => boolean;
}

/**
 * Build the analysis-completeness visibility record.
 *
 * This does not score malware — it records what the scanner could not fully see.
 */
export function buildAnalysisCompleteness(
  input: CompletenessInput,
): AnalysisCompleteness {
  const reasons: AnalysisCompletenessReason[] = [];

  for (const dropped of input.droppedExecutable) {
    reasons.push({
      code: "SOURCE_CONTENT_LIMIT_EXCEEDED",
      path: dropped.path,
      message: `Executable source exceeded retained-content budget (${dropped.sizeBytes} bytes)`,
      sizeBytes: dropped.sizeBytes,
      retainedBytes: dropped.retainedBytes ?? 0,
      lifecycleReachable: dropped.lifecycleReachable,
      executableSource: true,
      metadata: {},
    });
  }

  for (const failure of input.parseFailures) {
    const executable = isExecutableSourcePath(failure.filePath);
    const reachable = input.isInstallReachable?.(failure.filePath) ?? true;
    reasons.push({
      code: "PARSER_FAILURE",
      path: failure.filePath,
      message: failure.reason,
      sizeBytes: failure.sizeBytes,
      executableSource: executable,
      installReachable: reachable,
      metadata: {},
    });
  }

  for (const path of input.opaquePaths ?? []) {
    if (reasons.some((r) => r.path === path && r.code === "OPAQUE_PAYLOAD")) continue;
    reasons.push({
      code: "OPAQUE_PAYLOAD",
      path,
      message:
        "Bounded opaque-source triage ran because full AST analysis was unavailable",
      executableSource: true,
      metadata: {},
    });
  }

  if (input.budgetExhausted === true) {
    reasons.push({
      code: "ANALYSIS_BUDGET_EXHAUSTED",
      message: "An analysis budget was reached before the package was fully examined",
      executableSource: true,
      metadata: {},
    });
  }

  // A gap only degrades the verdict when it sits in code that can actually run.
  // Unreachable gaps are still recorded — they are visible in `reasons` with
  // installReachable=false — but a package that ships a deliberately invalid
  // test fixture should not be reported as partially unanalysed on that basis.
  //
  // This is deliberately not a path heuristic. Reachability is computed from
  // the manifest entrypoints, install lifecycle targets and the static import
  // graph, so a payload placed under test/ is still reachable if anything
  // declared points at it, and unreachable files are analysed in full either
  // way. See docs/REACHABILITY.md for the tradeoff.
  const degrading = (reason: AnalysisCompletenessReason): boolean =>
    reason.executableSource === true && reason.installReachable !== false;

  let status: AnalysisCompleteness["status"] = "COMPLETE";
  if (input.coverageRatio < COVERAGE_FLOOR) {
    status = "INSUFFICIENT";
  } else if (reasons.some(degrading)) {
    status = "DEGRADED";
  } else if (reasons.some((r) => r.executableSource !== true)) {
    status = "DEGRADED";
  }

  return {
    status,
    reasons,
    coverageRatio: input.coverageRatio,
  };
}
