import type {
  ArtifactInfo,
  BehaviourChain,
  Finding,
  LifecycleScript,
  PackageMetadata,
  ParseFailure,
  ResolvedPackage,
  RiskAssessment,
  ScannedFile,
} from "@packagegate/shared";
import type { ScoringBreakdown } from "@packagegate/risk-engine";

/**
 * Result of one PackageGate investigation.
 *
 * Absence of findings is not evidence of safety — it means the rules did not
 * match the code we were able to parse within the budgets we applied.
 */
export interface InvestigationResult {
  readonly requestedSpec: string;
  readonly resolved: ResolvedPackage;
  readonly metadata: PackageMetadata;
  readonly artifact: ArtifactInfo;
  readonly lifecycleScripts: readonly LifecycleScript[];
  readonly files: readonly ScannedFile[];
  readonly findings: readonly Finding[];
  readonly parseFailures: readonly ParseFailure[];
  readonly behaviourChains: readonly BehaviourChain[];
  readonly risk: RiskAssessment;
  readonly scoringBreakdown: ScoringBreakdown;
  readonly analysisCoverage: number;
  readonly startedAt: string;
  readonly completedAt: string;
  readonly durationMs: number;
  readonly scannerVersion: string;
  readonly rulesVersion: string;
  readonly disclaimer: string;
}

export const SAFETY_DISCLAIMER =
  "Absence of findings is not evidence that the package is safe. " +
  "PackageGate reports what its rules observed in the code it could parse.";
