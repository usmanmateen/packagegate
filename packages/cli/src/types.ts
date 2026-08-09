import type {
  AnalysisCompleteness,
  ArtifactInfo,
  BehaviourChain,
  Finding,
  LifecycleScript,
  PackageMetadata,
  ParseFailure,
  PolicyDecision,
  ResolvedPackage,
  RiskAssessment,
  ScannedFile,
} from "@packagegate/shared";
import type { ScoringBreakdown } from "@packagegate/risk-engine";

/**
 * How PackageGate acquired the artifact under investigation.
 *
 * Acquisition metadata is deliberately separate from behavioural risk: a local
 * preserved tarball is not automatically more (or less) malicious than a
 * registry download. Registry integrity verification is a trust statement about
 * the bytes, not a score contribution by itself.
 */
export const ACQUISITION_SOURCES = ["REGISTRY", "LOCAL", "FIXTURE"] as const;
export type AcquisitionSource = (typeof ACQUISITION_SOURCES)[number];

export const REGISTRY_INTEGRITY_STATUSES = [
  /** Compared against a registry-declared digest and matched. */
  "VERIFIED",
  /** Registry declared a digest we could not check (unsupported algorithm). */
  "UNSUPPORTED",
  /** Registry published no integrity declaration for this version. */
  "NOT_DECLARED",
  /**
   * Local/fixture artifact: there is no trusted registry digest unless the
   * caller supplied one via `--sha256`.
   */
  "NOT_APPLICABLE",
] as const;
export type RegistryIntegrityStatus = (typeof REGISTRY_INTEGRITY_STATUSES)[number];

export interface RegistryIntegrityInfo {
  readonly status: RegistryIntegrityStatus;
  readonly reason: string;
}

export interface SuppliedDigestInfo {
  /** Caller-supplied expected SHA-256, when provided. */
  readonly expectedSha256: string;
  readonly matched: boolean;
}

export interface AcquisitionInfo {
  readonly source: AcquisitionSource;
  /**
   * Caller-facing path for local artifacts. Never an extraction temp path.
   * Omitted for registry downloads.
   */
  readonly localPath?: string;
  readonly registryIntegrity: RegistryIntegrityInfo;
  readonly suppliedDigest?: SuppliedDigestInfo;
}

/**
 * Result of one PackageGate investigation.
 *
 * Absence of findings is not evidence of safety — it means the rules did not
 * match the code we were able to parse within the budgets we applied.
 *
 * Behavioural risk and final policy are separate lanes.
 */
export interface InvestigationResult {
  readonly requestedSpec: string;
  readonly resolved: ResolvedPackage;
  readonly metadata: PackageMetadata;
  readonly artifact: ArtifactInfo;
  readonly acquisition: AcquisitionInfo;
  readonly lifecycleScripts: readonly LifecycleScript[];
  readonly files: readonly ScannedFile[];
  readonly findings: readonly Finding[];
  readonly parseFailures: readonly ParseFailure[];
  readonly behaviourChains: readonly BehaviourChain[];
  readonly risk: RiskAssessment;
  readonly scoringBreakdown: ScoringBreakdown;
  /** @deprecated Prefer analysisCompleteness.coverageRatio */
  readonly analysisCoverage: number;
  readonly analysisCompleteness: AnalysisCompleteness;
  readonly policy: PolicyDecision;
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
