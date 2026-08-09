import { access } from "node:fs/promises";
import { join } from "node:path";
import {
  buildConfusionMatrix,
  DEFAULT_EVALUATION_MANIFEST,
  tallyMissReasons,
  type EvaluationManifest,
  type EvaluationReport,
  type EvaluationSampleResult,
  type MissReasonCode,
} from "@packagegate/evaluation";
import { investigateSources } from "./investigate.js";
import { scanPackage } from "./scan.js";
import { scanLocalTarball } from "./scan-tarball.js";
import type { InvestigationResult } from "./types.js";
import { readdirSync, readFileSync } from "node:fs";

export interface EvaluateOptions {
  readonly manifest?: EvaluationManifest;
  /** Explicit quarantine root for real malware LOCAL_TGZ samples. Never auto-fetched. */
  readonly malwareRoot?: string;
  readonly fixtureRoot?: string;
}

function loadFixtureInvestigation(
  name: string,
  fixtureRoot: string,
): InvestigationResult {
  const root = join(fixtureRoot, name);
  const manifest = readFileSync(join(root, "package.json"), "utf8");
  const parsed: unknown = JSON.parse(manifest);
  const packageName =
    parsed !== null &&
    typeof parsed === "object" &&
    "name" in parsed &&
    typeof parsed.name === "string"
      ? parsed.name
      : name;
  const version =
    parsed !== null &&
    typeof parsed === "object" &&
    "version" in parsed &&
    typeof parsed.version === "string"
      ? parsed.version
      : "0.0.0";
  const scripts =
    parsed !== null &&
    typeof parsed === "object" &&
    "scripts" in parsed &&
    parsed.scripts !== null &&
    typeof parsed.scripts === "object"
      ? Object.fromEntries(
          Object.entries(parsed.scripts as Record<string, unknown>).filter(
            (entry): entry is [string, string] => typeof entry[1] === "string",
          ),
        )
      : {};

  const files: { path: string; content: string }[] = [
    { path: "package.json", content: manifest },
  ];
  for (const entry of readdirSync(root)) {
    if (!/\.(?:[cm]?js|jsx|[cm]?ts|tsx)$/i.test(entry)) continue;
    files.push({ path: entry, content: readFileSync(join(root, entry), "utf8") });
  }

  return investigateSources({
    requestedSpec: `${packageName}@${version}`,
    resolved: { name: packageName, version },
    files,
    scripts,
    manifestText: manifest,
  });
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

/**
 * Run a repeatable evaluation pass.
 * Real malware samples are SKIPPED unless --malware-root points at a local artifact.
 */
export async function runEvaluation(
  options: EvaluateOptions = {},
): Promise<EvaluationReport> {
  const manifest = options.manifest ?? DEFAULT_EVALUATION_MANIFEST;
  const fixtureRoot =
    options.fixtureRoot ?? join(process.cwd(), "fixtures");
  const results: EvaluationSampleResult[] = [];

  for (const sample of manifest.samples) {
    const started = Date.now();
    try {
      if (sample.requiresMalwareRoot === true) {
        if (options.malwareRoot === undefined) {
          results.push({
            id: sample.id,
            label: sample.label,
            status: "SKIPPED",
            skipReason:
              "Real malware sample requires explicit --malware-root; auto-download is disabled",
          });
          continue;
        }
        const artifactPath = join(options.malwareRoot, sample.artifact);
        if (!(await pathExists(artifactPath))) {
          results.push({
            id: sample.id,
            label: sample.label,
            status: "SKIPPED",
            skipReason: `Artifact not found at ${artifactPath}`,
          });
          continue;
        }
        const investigation = await scanLocalTarball(artifactPath);
        results.push(toResult(sample.id, sample.label, investigation, started));
        continue;
      }

      if (sample.kind === "REGISTRY") {
        const investigation = await scanPackage(sample.artifact);
        results.push(toResult(sample.id, sample.label, investigation, started));
        continue;
      }

      if (sample.kind === "FIXTURE") {
        const investigation = loadFixtureInvestigation(sample.artifact, fixtureRoot);
        results.push(toResult(sample.id, sample.label, investigation, started));
        continue;
      }

      results.push({
        id: sample.id,
        label: sample.label,
        status: "SKIPPED",
        skipReason: `Unsupported sample kind ${sample.kind} without malware root`,
      });
    } catch (error) {
      results.push({
        id: sample.id,
        label: sample.label,
        status: "FAILED",
        failureReason: error instanceof Error ? error.message : "unknown error",
        durationMs: Date.now() - started,
      });
    }
  }

  return {
    results,
    matrix: buildConfusionMatrix(results),
    missReasons: tallyMissReasons(results),
    disclaimer:
      "Metrics are intervention-level (REVIEW/BLOCK = positive). Tiny corpora are not statistically meaningful.",
  };
}

function toResult(
  id: string,
  label: EvaluationSampleResult["label"],
  investigation: InvestigationResult,
  started: number,
): EvaluationSampleResult {
  const finalAction = investigation.policy.finalAction;
  const interventionPositive = finalAction === "REVIEW" || finalAction === "BLOCK";
  let missReason: MissReasonCode | undefined;
  if (
    (label === "MALICIOUS" || label === "SYNTHETIC_SUSPICIOUS") &&
    !interventionPositive
  ) {
    missReason = inferMissReason(investigation);
  }
  return {
    id,
    label,
    status: "COMPLETED",
    behaviouralScore: investigation.risk.score,
    behaviouralRecommendation: investigation.risk.recommendation,
    finalAction,
    completeness: investigation.analysisCompleteness.status,
    findingCount: investigation.findings.length,
    chainCount: investigation.behaviourChains.length,
    durationMs: Date.now() - started,
    interventionPositive,
    ...(missReason === undefined ? {} : { missReason }),
  };
}

function inferMissReason(investigation: InvestigationResult): MissReasonCode {
  if (
    investigation.analysisCompleteness.reasons.some(
      (r) => r.code === "OPAQUE_PAYLOAD" || r.code === "SOURCE_CONTENT_LIMIT_EXCEEDED",
    )
  ) {
    return "OPAQUE_PAYLOAD";
  }
  if (investigation.behaviourChains.length === 0) return "DATAFLOW_GAP";
  return "UNKNOWN";
}
