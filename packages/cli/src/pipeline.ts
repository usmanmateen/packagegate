import { createHash } from "node:crypto";
import type { ExtractedPackage } from "@packagegate/artifact-fetcher";
import { analyseBehaviourChains } from "@packagegate/behaviour-engine";
import { decidePolicy, POLICY_ENGINE_VERSION } from "@packagegate/policy-engine";
import {
  assessRisk,
  computeScoringBreakdown,
  WEIGHTS_VERSION,
} from "@packagegate/risk-engine";
import type { Finding, PackageMetadata, ScannedFile } from "@packagegate/shared";
import { disabledMlAssessment } from "@packagegate/shared";
import {
  analyseOpaqueSource,
  analysePackage,
  RULES_VERSION as STATIC_RULES_VERSION,
} from "@packagegate/static-analyser";
import {
  buildAnalysisCompleteness,
  isExecutableSourcePath,
  lifecycleReachablePaths,
} from "./completeness.js";
import { buildDecisionExplanation } from "./decision.js";
import { parsePackageManifest } from "./manifest.js";
import { getThreatIntelProvider } from "./threat-intel.js";
import {
  SAFETY_DISCLAIMER,
  type AcquisitionInfo,
  type InvestigationResult,
} from "./types.js";

export const SCANNER_VERSION = "packagegate-cli/0.2.0";

/**
 * Decode retained file bytes for the analyser.
 *
 * Source extensions use utf8. Everything else uses latin1 so executable
 * signatures survive as characters the classifier can still match. Content is
 * never executed.
 */
export function decodeContent(buffer: Buffer, path: string): string {
  const lower = path.toLowerCase();
  if (
    lower.endsWith(".js") ||
    lower.endsWith(".mjs") ||
    lower.endsWith(".cjs") ||
    lower.endsWith(".jsx") ||
    lower.endsWith(".ts") ||
    lower.endsWith(".tsx") ||
    lower.endsWith(".mts") ||
    lower.endsWith(".cts") ||
    lower.endsWith(".json") ||
    lower.endsWith(".jsonc") ||
    lower.endsWith(".map")
  ) {
    return buffer.toString("utf8");
  }
  return buffer.toString("latin1");
}

export interface InvestigateExtractedInput {
  readonly extracted: ExtractedPackage;
  readonly requestedSpec: string;
  readonly acquisition: AcquisitionInfo;
  readonly startedAt: Date;
  /**
   * Optional registry metadata used when the tarball manifest is incomplete.
   * Local scans omit this and require a valid package.json in the archive.
   */
  readonly fallbackMetadata?: PackageMetadata;
  /**
   * When true, require a parseable package.json in the extracted tree.
   * Registry scans may fall back to registry metadata; local scans must not.
   */
  readonly requireManifest: boolean;
  /**
   * Whether the risk engine may apply the M1 integrity-verified modifier.
   * Only true when a trusted digest was compared successfully (registry or
   * caller-supplied SHA-256).
   */
  readonly integrityVerifiedForRisk: boolean;
}

/**
 * Shared investigation after a package has been securely extracted.
 *
 * Registry downloads and local tarballs both converge here. Package code is
 * never executed.
 */
export function investigateExtractedPackage(
  input: InvestigateExtractedInput,
): InvestigationResult {
  const { extracted, acquisition, startedAt } = input;

  const manifestFile = extracted.files.find((file) => file.path === "package.json");
  const manifestText =
    manifestFile?.content === undefined
      ? undefined
      : manifestFile.content.toString("utf8");

  let metadata: PackageMetadata;
  let scripts: Record<string, string>;

  if (input.requireManifest) {
    const parsed = parsePackageManifest(manifestText, {
      tarballUrl: extracted.artifact.tarballUrl,
    });
    metadata = parsed.metadata;
    scripts = { ...parsed.metadata.scripts };
  } else {
    const fallback = input.fallbackMetadata;
    if (fallback === undefined) {
      throw new Error("fallbackMetadata required when requireManifest is false");
    }
    metadata = fallback;
    scripts = { ...fallback.scripts };
    if (manifestText !== undefined) {
      try {
        const recovered = parsePackageManifest(manifestText, {
          tarballUrl: extracted.artifact.tarballUrl,
          allowIdentityFallback: true,
          fallbackName: fallback.name,
          fallbackVersion: fallback.version,
        });
        metadata = {
          ...fallback,
          ...recovered.metadata,
          // Prefer tarball scripts: the installer uses the archive copy.
          scripts: recovered.metadata.scripts,
          dist: fallback.dist,
        };
        scripts = { ...recovered.metadata.scripts };
      } catch {
        // Keep registry metadata if the tarball manifest is unusable.
      }
    }
  }

  const sourceFiles = extracted.files.flatMap((file) => {
    if (file.content === undefined) return [];
    return [
      {
        path: file.path,
        content: decodeContent(file.content, file.path),
      },
    ];
  });

  const staticResult = analysePackage({
    files: sourceFiles,
    scripts,
    ...(manifestText === undefined ? {} : { manifestText }),
    manifestPath: "package.json",
  });

  const reachable = lifecycleReachablePaths(staticResult.lifecycleScripts);

  // Opaque triage for executable sources whose full content was not retained.
  const opaqueFindings: Finding[] = [];
  const droppedExecutable: {
    path: string;
    sizeBytes: number;
    retainedBytes?: number;
    lifecycleReachable: boolean;
  }[] = [];
  const opaquePaths: string[] = [];

  for (const file of extracted.files) {
    if (file.content !== undefined) continue;
    if (!isExecutableSourcePath(file.path)) continue;
    const lifecycleReachable = reachable.has(file.path);
    droppedExecutable.push({
      path: file.path,
      sizeBytes: file.sizeBytes,
      retainedBytes: file.contentPreview?.byteLength ?? 0,
      lifecycleReachable,
    });
    const opaque = analyseOpaqueSource({
      path: file.path,
      sizeBytes: file.sizeBytes,
      preview: file.contentPreview,
      lifecycleReachable,
      retainedBytes: file.contentPreview?.byteLength ?? 0,
      reason: "SOURCE_CONTENT_LIMIT_EXCEEDED",
    });
    opaqueFindings.push(...opaque.findings);
    opaquePaths.push(file.path);
  }

  const allFindings = [...staticResult.findings, ...opaqueFindings];

  const behaviour = analyseBehaviourChains({
    files: sourceFiles,
    findings: allFindings,
    lifecycleScripts: staticResult.lifecycleScripts,
  });

  // Coverage: include dropped executable JS in the denominator for honesty.
  const analysedJsTs = staticResult.files.filter(
    (file) =>
      (file.kind === "JAVASCRIPT" || file.kind === "TYPESCRIPT") && file.analysed,
  );
  const retainedAnalysable = staticResult.files.filter(
    (file) => file.kind === "JAVASCRIPT" || file.kind === "TYPESCRIPT",
  );
  const analysableCount = retainedAnalysable.length + droppedExecutable.length;
  const coverageDenominator = Math.max(analysableCount, 1);
  let analysisCoverage = analysedJsTs.length / coverageDenominator;
  if (staticResult.parseFailures.length > 0) {
    analysisCoverage = Math.min(
      analysisCoverage,
      Math.max(0, 1 - staticResult.parseFailures.length / coverageDenominator),
    );
  }

  const analysisCompleteness = buildAnalysisCompleteness({
    coverageRatio: analysisCoverage,
    droppedExecutable,
    parseFailures: staticResult.parseFailures,
    opaquePaths,
  });

  const riskInput = {
    findings: allFindings,
    chains: behaviour.chains,
    analysisCoverage,
    integrityVerified: input.integrityVerifiedForRisk,
    scannerVersion: SCANNER_VERSION,
    rulesVersion: `${STATIC_RULES_VERSION}+${behaviour.engineVersion}+${WEIGHTS_VERSION}+${POLICY_ENGINE_VERSION}`,
  };

  const risk = assessRisk(riskInput);
  const scoringBreakdown = computeScoringBreakdown(riskInput);

  const threat = getThreatIntelProvider().lookup({
    packageName: metadata.name,
    version: metadata.version,
    sha256: extracted.artifact.sha256,
  });

  // Lookup failures must not invent malware; UNKNOWN does not BLOCK.
  const threatStatus =
    threat.lookupFailed && threat.status === "UNKNOWN" ? "NONE" : threat.status;

  const policy = decidePolicy({
    behaviouralRecommendation: risk.recommendation,
    analysisCompleteness,
    threatIntelligence: threatStatus,
  });

  const threatIntelligence = {
    status: threat.status,
    provider: threat.provider,
    lookupFailed: threat.lookupFailed,
    ...(threat.failureReason === undefined ? {} : { failureReason: threat.failureReason }),
    matches: threat.matches.map((match) => ({
      source: match.source,
      classification: match.classification,
      matchedBy: match.matchedBy,
      referenceId: match.referenceId,
      confidence: match.confidence,
    })),
  };

  const files: ScannedFile[] = [
    ...staticResult.files.map((file) => {
      const extractedFile = extracted.files.find((entry) => entry.path === file.path);
      return {
        path: file.path,
        sizeBytes: file.sizeBytes,
        sha256:
          extractedFile?.sha256 ??
          createHash("sha256").update(file.path).digest("hex"),
        kind: file.kind,
        analysed: file.analysed,
      };
    }),
    ...droppedExecutable.map((dropped) => {
      const extractedFile = extracted.files.find((entry) => entry.path === dropped.path);
      return {
        path: dropped.path,
        sizeBytes: dropped.sizeBytes,
        sha256:
          extractedFile?.sha256 ??
          createHash("sha256").update(dropped.path).digest("hex"),
        kind: "JAVASCRIPT" as const,
        analysed: false,
      };
    }),
  ];

  // Local artifacts must never report registry integrityVerified=true.
  const artifact =
    acquisition.source === "LOCAL"
      ? {
          ...extracted.artifact,
          integrityVerified: undefined,
        }
      : extracted.artifact;

  // Strip accidental integrityVerified: undefined key pollution for locals.
  const artifactOut =
    acquisition.source === "LOCAL"
      ? {
          tarballUrl: artifact.tarballUrl,
          compressedSizeBytes: artifact.compressedSizeBytes,
          extractedSizeBytes: artifact.extractedSizeBytes,
          fileCount: artifact.fileCount,
          sha256: artifact.sha256,
          skippedEntries: artifact.skippedEntries,
        }
      : artifact;

  const completedAt = new Date();
  const partial: InvestigationResult = {
    requestedSpec: input.requestedSpec,
    resolved: {
      name: metadata.name,
      version: metadata.version,
    },
    metadata,
    artifact: artifactOut,
    acquisition,
    lifecycleScripts: staticResult.lifecycleScripts,
    files,
    findings: allFindings,
    parseFailures: staticResult.parseFailures,
    behaviourChains: behaviour.chains,
    risk,
    scoringBreakdown,
    analysisCoverage,
    analysisCompleteness,
    threatIntelligence,
    ml: disabledMlAssessment(),
    policy,
    decisionExplanation: [],
    startedAt: startedAt.toISOString(),
    completedAt: completedAt.toISOString(),
    durationMs: completedAt.getTime() - startedAt.getTime(),
    scannerVersion: SCANNER_VERSION,
    rulesVersion: risk.rulesVersion,
    disclaimer: SAFETY_DISCLAIMER,
  };

  return {
    ...partial,
    decisionExplanation: buildDecisionExplanation(partial),
  };
}
