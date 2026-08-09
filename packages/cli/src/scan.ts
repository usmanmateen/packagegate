import { createHash } from "node:crypto";
import { withExtractedPackage } from "@packagegate/artifact-fetcher";
import { analyseBehaviourChains } from "@packagegate/behaviour-engine";
import {
  parsePackageSpec,
  RegistryClient,
  type RegistryClientOptions,
} from "@packagegate/npm-registry";
import {
  assessRisk,
  computeScoringBreakdown,
  WEIGHTS_VERSION,
} from "@packagegate/risk-engine";
import type { ScannedFile } from "@packagegate/shared";
import { ScanError, toScanError } from "@packagegate/shared";
import {
  analysePackage,
  RULES_VERSION as STATIC_RULES_VERSION,
} from "@packagegate/static-analyser";
import { SAFETY_DISCLAIMER, type InvestigationResult } from "./types.js";

export const SCANNER_VERSION = "packagegate-cli/0.1.0";

export interface ScanOptions {
  readonly registry?: RegistryClientOptions;
}

/**
 * Decode retained file bytes for the analyser.
 *
 * Source extensions use utf8. Everything else uses latin1 so executable
 * signatures survive as characters the classifier can still match. Content is
 * never executed.
 */
function decodeContent(buffer: Buffer, path: string): string {
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

/**
 * Resolve a package from the registry, download and extract its tarball safely,
 * run static analysis → behaviour chains → risk scoring, then return an
 * inspectable investigation result. Temporary extraction always cleans up.
 *
 * The investigated package is never installed and never executed.
 */
export async function scanPackage(
  specInput: string,
  options: ScanOptions = {},
): Promise<InvestigationResult> {
  const startedAt = new Date();
  const startedIso = startedAt.toISOString();

  try {
    const spec = parsePackageSpec(specInput);
    const client = new RegistryClient(options.registry);
    const { metadata, resolution } = await client.getPackageMetadata(
      spec.name,
      spec.requestedVersion,
    );

    const dist = metadata.dist;
    if (typeof dist.tarball !== "string" || dist.tarball.length === 0) {
      throw new ScanError("NOT_FOUND", "Resolved package has no tarball URL", {
        details: { package: metadata.name, version: metadata.version },
      });
    }

    return await withExtractedPackage(
      {
        url: dist.tarball,
        ...(dist.integrity === undefined ? {} : { integrity: dist.integrity }),
      },
      (extracted) => {
        const manifestFile = extracted.files.find((file) => file.path === "package.json");
        const manifestText =
          manifestFile?.content === undefined
            ? undefined
            : manifestFile.content.toString("utf8");

        let scripts: Record<string, string> = { ...metadata.scripts };
        if (manifestText !== undefined) {
          try {
            const parsed: unknown = JSON.parse(manifestText);
            if (
              parsed !== null &&
              typeof parsed === "object" &&
              "scripts" in parsed &&
              parsed.scripts !== null &&
              typeof parsed.scripts === "object" &&
              !Array.isArray(parsed.scripts)
            ) {
              const recovered: Record<string, string> = {};
              for (const [key, value] of Object.entries(parsed.scripts)) {
                if (typeof value === "string") recovered[key] = value;
              }
              scripts = recovered;
            }
          } catch {
            // Keep registry scripts if the tarball manifest is unparseable.
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
          integrityVerified: extracted.artifact.integrityVerified === true,
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

        const completedAt = new Date();
        return Promise.resolve({
          requestedSpec: spec.raw,
          resolved: {
            name: metadata.name,
            version: resolution.version,
          },
          metadata,
          artifact: extracted.artifact,
          lifecycleScripts: staticResult.lifecycleScripts,
          files,
          findings: staticResult.findings,
          parseFailures: staticResult.parseFailures,
          behaviourChains: behaviour.chains,
          risk,
          scoringBreakdown,
          analysisCoverage,
          startedAt: startedIso,
          completedAt: completedAt.toISOString(),
          durationMs: completedAt.getTime() - startedAt.getTime(),
          scannerVersion: SCANNER_VERSION,
          rulesVersion: risk.rulesVersion,
          disclaimer: SAFETY_DISCLAIMER,
        });
      },
    );
  } catch (error) {
    throw toScanError(error, "Package investigation failed");
  }
}
