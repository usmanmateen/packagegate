import { createHash } from "node:crypto";
import type { ExtractedPackage } from "@packagegate/artifact-fetcher";
import { analyseBehaviourChains } from "@packagegate/behaviour-engine";
import {
  assessRisk,
  computeScoringBreakdown,
  WEIGHTS_VERSION,
} from "@packagegate/risk-engine";
import type { PackageMetadata, ScannedFile } from "@packagegate/shared";
import {
  analysePackage,
  RULES_VERSION as STATIC_RULES_VERSION,
} from "@packagegate/static-analyser";
import { parsePackageManifest } from "./manifest.js";
import {
  SAFETY_DISCLAIMER,
  type AcquisitionInfo,
  type InvestigationResult,
} from "./types.js";

export const SCANNER_VERSION = "packagegate-cli/0.1.0";

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

  const behaviour = analyseBehaviourChains({
    files: sourceFiles,
    findings: staticResult.findings,
  });

  const analysable = staticResult.files.filter(
    (file) => file.kind === "JAVASCRIPT" || file.kind === "TYPESCRIPT",
  );
  const analysedCount = analysable.filter((file) => file.analysed).length;
  const coverageDenominator = Math.max(analysable.length, 1);
  let analysisCoverage = analysedCount / coverageDenominator;
  if (extracted.retention.truncated) {
    analysisCoverage = Math.min(analysisCoverage, 0.85);
  }
  if (staticResult.parseFailures.length > 0) {
    analysisCoverage = Math.min(
      analysisCoverage,
      Math.max(0, 1 - staticResult.parseFailures.length / coverageDenominator),
    );
  }

  const riskInput = {
    findings: staticResult.findings,
    chains: behaviour.chains,
    analysisCoverage,
    integrityVerified: input.integrityVerifiedForRisk,
    scannerVersion: SCANNER_VERSION,
    rulesVersion: `${STATIC_RULES_VERSION}+${behaviour.engineVersion}+${WEIGHTS_VERSION}`,
  };

  const risk = assessRisk(riskInput);
  const scoringBreakdown = computeScoringBreakdown(riskInput);

  const files: ScannedFile[] = staticResult.files.map((file) => {
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
  });

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
  return {
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
