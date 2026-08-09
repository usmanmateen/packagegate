import type {
  ArtifactInfo,
  PackageMetadata,
} from "@packagegate/shared";
import { analyseBehaviourChains } from "@packagegate/behaviour-engine";
import {
  assessRisk,
  computeScoringBreakdown,
  WEIGHTS_VERSION,
} from "@packagegate/risk-engine";
import {
  analysePackage,
  RULES_VERSION as STATIC_RULES_VERSION,
} from "@packagegate/static-analyser";
import type { ScannedFile } from "@packagegate/shared";
import { SCANNER_VERSION } from "./pipeline.js";
import {
  SAFETY_DISCLAIMER,
  type InvestigationResult,
} from "./types.js";

export interface SourceInvestigationInput {
  readonly requestedSpec: string;
  readonly resolved: { name: string; version: string };
  readonly files: readonly { path: string; content: string }[];
  readonly scripts?: Readonly<Record<string, string>>;
  readonly manifestText?: string;
  /** Optional artifact metadata for the report. */
  readonly artifact?: Partial<ArtifactInfo>;
  readonly metadata?: Partial<PackageMetadata>;
  readonly integrityVerified?: boolean;
}

/**
 * Run static analysis → behaviour chains → risk on in-memory sources.
 *
 * Used for inert fixtures and offline demos. Never executes package code.
 */
export function investigateSources(
  input: SourceInvestigationInput,
): InvestigationResult {
  const startedAt = new Date();

  const staticResult = analysePackage({
    files: input.files,
    scripts: input.scripts ?? {},
    ...(input.manifestText === undefined ? {} : { manifestText: input.manifestText }),
    manifestPath: "package.json",
  });

  const behaviour = analyseBehaviourChains({
    files: input.files,
    findings: staticResult.findings,
  });

  const analysable = staticResult.files.filter(
    (file) => file.kind === "JAVASCRIPT" || file.kind === "TYPESCRIPT",
  );
  const analysedCount = analysable.filter((file) => file.analysed).length;
  const analysisCoverage =
    analysable.length === 0 ? 1 : analysedCount / analysable.length;

  const integrityVerified = input.integrityVerified === true;
  const riskInput = {
    findings: staticResult.findings,
    chains: behaviour.chains,
    analysisCoverage,
    integrityVerified,
    scannerVersion: SCANNER_VERSION,
    rulesVersion: `${STATIC_RULES_VERSION}+${behaviour.engineVersion}+${WEIGHTS_VERSION}`,
  };

  const risk = assessRisk(riskInput);
  const scoringBreakdown = computeScoringBreakdown(riskInput);

  const files: ScannedFile[] = staticResult.files.map((file) => ({
    path: file.path,
    sizeBytes: file.sizeBytes,
    sha256: "fixture",
    kind: file.kind,
    analysed: file.analysed,
  }));

  const artifact: ArtifactInfo = {
    tarballUrl: input.artifact?.tarballUrl ?? "fixture://local",
    compressedSizeBytes: input.artifact?.compressedSizeBytes ?? 0,
    extractedSizeBytes:
      input.artifact?.extractedSizeBytes ??
      input.files.reduce((sum, file) => sum + Buffer.byteLength(file.content, "utf8"), 0),
    fileCount: input.artifact?.fileCount ?? input.files.length,
    sha256: input.artifact?.sha256 ?? "fixture",
    skippedEntries: input.artifact?.skippedEntries ?? [],
  };

  const metadata: PackageMetadata = {
    name: input.resolved.name,
    version: input.resolved.version,
    maintainers: [],
    dependencies: {},
    devDependencies: {},
    optionalDependencies: {},
    peerDependencies: {},
    engines: {},
    scripts: { ...(input.scripts ?? {}) },
    dist: {
      tarball: artifact.tarballUrl,
    },
    ...input.metadata,
  };

  const completedAt = new Date();
  return {
    requestedSpec: input.requestedSpec,
    resolved: input.resolved,
    metadata,
    artifact,
    acquisition: {
      source: "FIXTURE",
      registryIntegrity: {
        status: "NOT_APPLICABLE",
        reason: "Inert fixture has no registry integrity reference",
      },
    },
    lifecycleScripts: staticResult.lifecycleScripts,
    files,
    findings: staticResult.findings,
    parseFailures: staticResult.parseFailures,
    behaviourChains: behaviour.chains,
    risk,
    scoringBreakdown,
    analysisCoverage,
    startedAt: startedAt.toISOString(),
    completedAt: completedAt.toISOString(),
    durationMs: completedAt.getTime() - startedAt.getTime(),
    scannerVersion: SCANNER_VERSION,
    rulesVersion: risk.rulesVersion,
    disclaimer: SAFETY_DISCLAIMER,
  };
}
