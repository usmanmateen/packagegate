import type {
  AnalysisCompleteness,
  BehaviourChain,
  Finding,
  LifecycleScript,
  PolicyDecision,
  RiskRecommendation,
  ScannedFile,
} from "@packagegate/shared";

/**
 * Minimal investigation snapshot for security version diffing.
 * Deliberately independent of CLI types so the diff engine stays pure.
 */
export interface DiffableInvestigation {
  readonly resolved: { readonly name: string; readonly version: string };
  readonly lifecycleScripts: readonly LifecycleScript[];
  readonly findings: readonly Finding[];
  readonly behaviourChains: readonly BehaviourChain[];
  readonly analysisCompleteness: AnalysisCompleteness;
  readonly risk: {
    readonly score: number;
    readonly recommendation: RiskRecommendation;
  };
  readonly policy: PolicyDecision;
  readonly files?: readonly ScannedFile[];
}

export const VERSION_DIFF_ENGINE = "version-diff/1.0.0";
