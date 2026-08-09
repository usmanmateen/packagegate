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
    reasons.push({
      code: "PARSER_FAILURE",
      path: failure.filePath,
      message: failure.reason,
      sizeBytes: failure.sizeBytes,
      executableSource: executable,
      metadata: {},
    });
  }

  for (const path of input.opaquePaths ?? []) {
    if (reasons.some((r) => r.path === path && r.code === "OPAQUE_PAYLOAD")) continue;
    reasons.push({
      code: "OPAQUE_PAYLOAD",
      path,
      message: "Bounded opaque-source triage ran because full AST analysis was unavailable",
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

  let status: AnalysisCompleteness["status"] = "COMPLETE";
  if (input.coverageRatio < COVERAGE_FLOOR) {
    status = "INSUFFICIENT";
  } else if (reasons.some((r) => r.executableSource === true)) {
    status = "DEGRADED";
  } else if (reasons.length > 0) {
    status = "DEGRADED";
  }

  return {
    status,
    reasons,
    coverageRatio: input.coverageRatio,
  };
}
