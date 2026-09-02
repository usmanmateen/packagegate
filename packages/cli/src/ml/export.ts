/**
 * Versioned PackageGate → ML feature and security-slice export.
 *
 * ML must consume structured JSON, never human terminal text.
 * Package labels and threat-intel results are excluded from model features.
 */

import { createHash } from "node:crypto";
import type {
  BehaviourChain,
  Finding,
  FindingCategory,
  LifecycleScript,
  ScannedFile,
} from "@packagegate/shared";
import { FINDING_CATEGORIES } from "@packagegate/shared";
import type { InvestigationResult } from "../types.js";

export const ML_FEATURE_SCHEMA_VERSION = 1 as const;
export const ML_EXPORT_SCHEMA_VERSION = 1 as const;

const MAX_SLICES = 64;
const SLICE_CONTEXT_LINES = 8;
const MAX_SLICE_CHARS = 2_048;

export const ML_BEHAVIOUR_LABELS = [
  "environment_access",
  "environment_enumeration",
  "credential_access",
  "sensitive_file_access",
  "home_directory_access",
  "system_information",
  "process_execution",
  "shell_execution",
  "remote_download",
  "remote_code_fetch",
  "network_access",
  "data_exfiltration",
  "dynamic_code_execution",
  "payload_decode",
  "install_time_execution",
  "package_manager_access",
  "obfuscation_or_opaque_payload",
] as const;
export type MlBehaviourLabel = (typeof ML_BEHAVIOUR_LABELS)[number];

const CATEGORY_TO_BEHAVIOURS: Partial<
  Record<FindingCategory, readonly MlBehaviourLabel[]>
> = {
  ENVIRONMENT_ACCESS: ["environment_access"],
  SYSTEM_INFORMATION_ACCESS: ["system_information"],
  CREDENTIAL_RELATED_ACCESS: ["credential_access"],
  SENSITIVE_FILE_ACCESS: ["sensitive_file_access"],
  HOME_DIRECTORY_ACCESS: ["home_directory_access"],
  PROCESS_EXECUTION: ["process_execution"],
  SHELL_COMMAND: ["shell_execution"],
  REMOTE_CODE_FETCH: ["remote_code_fetch", "remote_download"],
  DOWNLOAD_BEHAVIOUR: ["remote_download"],
  NETWORK_ACCESS: ["network_access"],
  NETWORK_DESTINATION: ["network_access"],
  DYNAMIC_CODE_EXECUTION: ["dynamic_code_execution"],
  ENCODED_PAYLOAD: ["payload_decode"],
  HIGH_ENTROPY_PAYLOAD: ["obfuscation_or_opaque_payload"],
  OBFUSCATION_SIGNAL: ["obfuscation_or_opaque_payload"],
  INSTALL_SCRIPT: ["install_time_execution"],
  PACKAGE_MANAGER_ACCESS: ["package_manager_access"],
};

export interface StructuredMlFeatures {
  readonly schemaVersion: typeof ML_FEATURE_SCHEMA_VERSION;
  readonly findingCount: number;
  readonly findingsByCategory: Record<string, number>;
  readonly findingsBySeverity: Record<string, number>;
  readonly findingsByConfidence: Record<string, number>;
  readonly chainCount: number;
  readonly chainsByType: Record<string, number>;
  readonly chainsByConfidence: Record<string, number>;
  readonly lifecycleHookCount: number;
  readonly hasPreinstall: number;
  readonly hasInstall: number;
  readonly hasPostinstall: number;
  readonly networkDestinationCount: number;
  readonly environmentAccessCount: number;
  readonly processExecutionCount: number;
  readonly remoteDownloadCount: number;
  readonly sensitiveFileCount: number;
  readonly shellCommandCount: number;
  readonly opaqueSourceCount: number;
  readonly largeSourceCount: number;
  readonly completenessStatusComplete: number;
  readonly completenessStatusDegraded: number;
  readonly completenessStatusInsufficient: number;
  readonly coverageRatio: number;
  readonly fileCount: number;
  readonly analysedExecutableBytes: number;
  readonly familyBreadth: number;
  /** Optional ablation: include deterministic behavioural score (0–100). */
  readonly behaviouralScore?: number;
}

export interface SecuritySliceRecord {
  readonly sliceId: string;
  readonly filePath: string;
  readonly fileHash: string;
  readonly startLine: number;
  readonly endLine: number;
  readonly sourceText: string;
  readonly lifecycleReachable: boolean;
  readonly lifecycleHook?: string;
  readonly deterministicFindings: readonly string[];
  readonly behaviourLabels: readonly MlBehaviourLabel[];
  readonly behaviourChainMembership: readonly string[];
  readonly priority: number;
}

export interface PackageGateMlRecordV1 {
  readonly schemaVersion: typeof ML_EXPORT_SCHEMA_VERSION;
  readonly featureSchemaVersion: typeof ML_FEATURE_SCHEMA_VERSION;
  readonly package: {
    readonly nameHash: string;
    readonly version?: string;
  };
  readonly artifact: {
    readonly sha256?: string;
  };
  readonly lifecycle: readonly {
    readonly name: string;
    readonly command: string;
  }[];
  readonly findings: readonly {
    readonly id: string;
    readonly category: string;
    readonly severity: string;
    readonly confidence: string;
    readonly filePath: string;
    readonly startLine: number;
    readonly endLine: number;
    readonly title: string;
  }[];
  readonly chains: readonly {
    readonly id: string;
    readonly source: string;
    readonly sink: string;
    readonly confidence: string;
    readonly chainType?: string;
  }[];
  readonly completeness: {
    readonly status: string;
    readonly coverageRatio: number;
  };
  readonly structuredFeatures: StructuredMlFeatures;
  readonly slices: readonly SecuritySliceRecord[];
  readonly mlInputCompleteness: {
    readonly slicesAvailable: number;
    readonly slicesUsed: number;
    readonly truncationOccurred: boolean;
  };
}

export interface ExportMlOptions {
  readonly includeBehaviouralScore?: boolean;
  readonly maxSlices?: number;
  readonly sourceByPath?: ReadonlyMap<string, string>;
}

/**
 * Hash a package name so models cannot shortcut on identity by default.
 */
export function hashPackageName(name: string): string {
  return createHash("sha256").update(name).digest("hex").slice(0, 16);
}

/**
 * Extract structured numeric features from an investigation (no verdict leakage).
 */
export function extractStructuredFeatures(
  result: Pick<
    InvestigationResult,
    | "findings"
    | "behaviourChains"
    | "lifecycleScripts"
    | "analysisCompleteness"
    | "files"
    | "risk"
  >,
  options: { readonly includeBehaviouralScore?: boolean } = {},
): StructuredMlFeatures {
  const findingsByCategory = emptyCountMap(FINDING_CATEGORIES);
  const findingsBySeverity: Record<string, number> = {
    INFO: 0,
    LOW: 0,
    MEDIUM: 0,
    HIGH: 0,
    CRITICAL: 0,
  };
  const findingsByConfidence: Record<string, number> = {
    LOW: 0,
    MEDIUM: 0,
    HIGH: 0,
  };

  for (const finding of result.findings) {
    findingsByCategory[finding.category] =
      (findingsByCategory[finding.category] ?? 0) + 1;
    findingsBySeverity[finding.severity] =
      (findingsBySeverity[finding.severity] ?? 0) + 1;
    findingsByConfidence[finding.confidence] =
      (findingsByConfidence[finding.confidence] ?? 0) + 1;
  }

  const chainsByType: Record<string, number> = {};
  const chainsByConfidence: Record<string, number> = {
    LOW: 0,
    MEDIUM: 0,
    HIGH: 0,
  };
  for (const chain of result.behaviourChains) {
    const typed =
      typeof chain.metadata.chainType === "string"
        ? chain.metadata.chainType
        : `${chain.source}->${chain.sink}`;
    chainsByType[typed] = (chainsByType[typed] ?? 0) + 1;
    chainsByConfidence[chain.confidence] =
      (chainsByConfidence[chain.confidence] ?? 0) + 1;
  }

  const hooks = new Set(
    result.lifecycleScripts.map((script: LifecycleScript) => script.name),
  );
  const opaqueSourceCount = result.findings.filter((finding: Finding) => {
    return (
      finding.category === "OBFUSCATION_SIGNAL" ||
      finding.category === "HIGH_ENTROPY_PAYLOAD" ||
      finding.ruleId.includes("opaque")
    );
  }).length;
  const largeSourceCount = result.analysisCompleteness.reasons.filter(
    (reason) =>
      reason.code === "SOURCE_CONTENT_LIMIT_EXCEEDED" ||
      reason.code === "CONTENT_LIMIT_EXCEEDED" ||
      reason.code === "OPAQUE_PAYLOAD",
  ).length;

  const analysedExecutableBytes = result.files
    .filter(
      (file: ScannedFile) =>
        file.analysed && (file.kind === "JAVASCRIPT" || file.kind === "TYPESCRIPT"),
    )
    .reduce((sum: number, file: ScannedFile) => sum + file.sizeBytes, 0);

  const familyBreadth = Object.values(findingsByCategory).filter((n) => n > 0).length;

  const base: StructuredMlFeatures = {
    schemaVersion: ML_FEATURE_SCHEMA_VERSION,
    findingCount: result.findings.length,
    findingsByCategory,
    findingsBySeverity,
    findingsByConfidence,
    chainCount: result.behaviourChains.length,
    chainsByType,
    chainsByConfidence,
    lifecycleHookCount: result.lifecycleScripts.length,
    hasPreinstall: hooks.has("preinstall") ? 1 : 0,
    hasInstall: hooks.has("install") ? 1 : 0,
    hasPostinstall: hooks.has("postinstall") ? 1 : 0,
    networkDestinationCount: countCategory(result.findings, "NETWORK_DESTINATION"),
    environmentAccessCount: countCategory(result.findings, "ENVIRONMENT_ACCESS"),
    processExecutionCount: countCategory(result.findings, "PROCESS_EXECUTION"),
    remoteDownloadCount:
      countCategory(result.findings, "REMOTE_CODE_FETCH") +
      countCategory(result.findings, "DOWNLOAD_BEHAVIOUR"),
    sensitiveFileCount: countCategory(result.findings, "SENSITIVE_FILE_ACCESS"),
    shellCommandCount: countCategory(result.findings, "SHELL_COMMAND"),
    opaqueSourceCount,
    largeSourceCount,
    completenessStatusComplete: result.analysisCompleteness.status === "COMPLETE" ? 1 : 0,
    completenessStatusDegraded: result.analysisCompleteness.status === "DEGRADED" ? 1 : 0,
    completenessStatusInsufficient:
      result.analysisCompleteness.status === "INSUFFICIENT" ? 1 : 0,
    coverageRatio: result.analysisCompleteness.coverageRatio,
    fileCount: result.files.length,
    analysedExecutableBytes,
    familyBreadth,
  };

  if (options.includeBehaviouralScore === true) {
    return { ...base, behaviouralScore: result.risk.score };
  }
  return base;
}

/**
 * Build bounded security-focused code slices centred on findings/chains.
 * Labels in training metadata must never be embedded in sourceText.
 */
export function buildSecuritySlices(
  result: Pick<InvestigationResult, "findings" | "behaviourChains" | "lifecycleScripts">,
  sourceByPath: ReadonlyMap<string, string>,
  options: { readonly maxSlices?: number } = {},
): {
  readonly slices: SecuritySliceRecord[];
  readonly slicesAvailable: number;
  readonly truncationOccurred: boolean;
} {
  const maxSlices = options.maxSlices ?? MAX_SLICES;
  const chainFiles = new Set<string>();
  const chainIdsByFile = new Map<string, string[]>();
  for (const chain of result.behaviourChains) {
    for (const link of chain.links) {
      const path = link.location?.filePath;
      if (!path) continue;
      chainFiles.add(path);
      const list = chainIdsByFile.get(path) ?? [];
      list.push(chain.id);
      chainIdsByFile.set(path, list);
    }
  }

  const lifecycleReachableFiles = resolveLifecycleFiles(
    result.lifecycleScripts,
    sourceByPath,
  );

  const candidates: SecuritySliceRecord[] = [];
  for (const finding of result.findings) {
    const path = finding.location.filePath;
    const source = sourceByPath.get(path);
    if (source === undefined) continue;
    const { startLine, endLine, text } = windowSource(
      source,
      finding.location.startLine,
      finding.location.endLine,
    );
    const behaviours: readonly MlBehaviourLabel[] =
      CATEGORY_TO_BEHAVIOURS[finding.category] ?? [];
    const priority = scoreSlicePriority({
      finding,
      inChain: chainFiles.has(path),
      lifecycleReachable: lifecycleReachableFiles.has(path),
    });
    candidates.push({
      sliceId: createHash("sha256")
        .update(`${path}:${String(startLine)}:${String(endLine)}:${finding.id}`)
        .digest("hex")
        .slice(0, 16),
      filePath: path,
      fileHash: createHash("sha256").update(source).digest("hex").slice(0, 16),
      startLine,
      endLine,
      sourceText: text,
      lifecycleReachable: lifecycleReachableFiles.has(path),
      ...(lifecycleReachableFiles.get(path)
        ? { lifecycleHook: lifecycleReachableFiles.get(path) }
        : {}),
      deterministicFindings: [finding.id],
      behaviourLabels: [...behaviours],
      behaviourChainMembership: [...new Set(chainIdsByFile.get(path) ?? [])],
      priority,
    });
  }

  candidates.sort(
    (a, b) => b.priority - a.priority || a.filePath.localeCompare(b.filePath),
  );
  const truncated = candidates.length > maxSlices;
  return {
    slices: candidates.slice(0, maxSlices),
    slicesAvailable: candidates.length,
    truncationOccurred: truncated,
  };
}

/**
 * Build a versioned ML export record from an investigation + optional sources.
 */
export function exportPackageGateMlRecord(
  result: InvestigationResult,
  options: ExportMlOptions = {},
): PackageGateMlRecordV1 {
  const sourceByPath = options.sourceByPath ?? new Map<string, string>();

  const structuredFeatures = extractStructuredFeatures(result, {
    includeBehaviouralScore: options.includeBehaviouralScore === true,
  });
  const { slices, slicesAvailable, truncationOccurred } = buildSecuritySlices(
    result,
    sourceByPath,
    { maxSlices: options.maxSlices },
  );

  return {
    schemaVersion: ML_EXPORT_SCHEMA_VERSION,
    featureSchemaVersion: ML_FEATURE_SCHEMA_VERSION,
    package: {
      nameHash: hashPackageName(result.resolved.name),
      version: result.resolved.version,
    },
    artifact: {
      ...(result.artifact.sha256 === undefined ? {} : { sha256: result.artifact.sha256 }),
    },
    lifecycle: result.lifecycleScripts.map((script: LifecycleScript) => ({
      name: script.name,
      command: script.command,
    })),
    findings: result.findings.map((finding: Finding) => ({
      id: finding.id,
      category: finding.category,
      severity: finding.severity,
      confidence: finding.confidence,
      filePath: finding.location.filePath,
      startLine: finding.location.startLine,
      endLine: finding.location.endLine,
      title: finding.title,
    })),
    chains: result.behaviourChains.map((chain: BehaviourChain) => ({
      id: chain.id,
      source: chain.source,
      sink: chain.sink,
      confidence: chain.confidence,
      ...(typeof chain.metadata.chainType === "string"
        ? { chainType: chain.metadata.chainType }
        : {}),
    })),
    completeness: {
      status: result.analysisCompleteness.status,
      coverageRatio: result.analysisCompleteness.coverageRatio,
    },
    structuredFeatures,
    slices,
    mlInputCompleteness: {
      slicesAvailable,
      slicesUsed: slices.length,
      truncationOccurred,
    },
  };
}

/**
 * Flatten structured features to a stable numeric vector for classical ML.
 */
export function flattenStructuredFeatures(features: StructuredMlFeatures): {
  readonly keys: string[];
  readonly values: number[];
} {
  const keys: string[] = [];
  const values: number[] = [];
  const push = (key: string, value: number): void => {
    keys.push(key);
    values.push(value);
  };

  push("findingCount", features.findingCount);
  for (const cat of FINDING_CATEGORIES) {
    push(`cat:${cat}`, features.findingsByCategory[cat] ?? 0);
  }
  for (const sev of ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] as const) {
    push(`sev:${sev}`, features.findingsBySeverity[sev] ?? 0);
  }
  for (const conf of ["LOW", "MEDIUM", "HIGH"] as const) {
    push(`conf:${conf}`, features.findingsByConfidence[conf] ?? 0);
  }
  push("chainCount", features.chainCount);
  push("lifecycleHookCount", features.lifecycleHookCount);
  push("hasPreinstall", features.hasPreinstall);
  push("hasInstall", features.hasInstall);
  push("hasPostinstall", features.hasPostinstall);
  push("networkDestinationCount", features.networkDestinationCount);
  push("environmentAccessCount", features.environmentAccessCount);
  push("processExecutionCount", features.processExecutionCount);
  push("remoteDownloadCount", features.remoteDownloadCount);
  push("sensitiveFileCount", features.sensitiveFileCount);
  push("shellCommandCount", features.shellCommandCount);
  push("opaqueSourceCount", features.opaqueSourceCount);
  push("largeSourceCount", features.largeSourceCount);
  push("completenessStatusComplete", features.completenessStatusComplete);
  push("completenessStatusDegraded", features.completenessStatusDegraded);
  push("completenessStatusInsufficient", features.completenessStatusInsufficient);
  push("coverageRatio", features.coverageRatio);
  push("fileCount", features.fileCount);
  push("analysedExecutableBytes", features.analysedExecutableBytes);
  push("familyBreadth", features.familyBreadth);
  if (features.behaviouralScore !== undefined) {
    push("behaviouralScore", features.behaviouralScore);
  }
  return { keys, values };
}

function countCategory(findings: readonly Finding[], category: FindingCategory): number {
  return findings.filter((f) => f.category === category).length;
}

function emptyCountMap(keys: readonly string[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const key of keys) out[key] = 0;
  return out;
}

function resolveLifecycleFiles(
  scripts: readonly LifecycleScript[],
  sourceByPath: ReadonlyMap<string, string>,
): Map<string, string> {
  const map = new Map<string, string>();
  for (const script of scripts) {
    for (const rel of script.referencedFiles) {
      const normalised = rel.replace(/^\.\//, "");
      if (sourceByPath.has(normalised)) map.set(normalised, script.name);
    }
    const match = /\bnode\s+([./\w-]+\.m?js)\b/i.exec(script.command);
    if (!match) continue;
    const rel = match[1]!.replace(/^\.\//, "");
    if (sourceByPath.has(rel)) map.set(rel, script.name);
  }
  return map;
}

function windowSource(
  source: string,
  startLine: number,
  endLine: number,
): { startLine: number; endLine: number; text: string } {
  const lines = source.split(/\r?\n/);
  const start = Math.max(1, startLine - SLICE_CONTEXT_LINES);
  const end = Math.min(lines.length, endLine + SLICE_CONTEXT_LINES);
  let text = lines.slice(start - 1, end).join("\n");
  if (text.length > MAX_SLICE_CHARS) {
    text = `${text.slice(0, MAX_SLICE_CHARS)}\n/* …truncated… */`;
  }
  return { startLine: start, endLine: end, text };
}

function scoreSlicePriority(input: {
  readonly finding: Finding;
  readonly inChain: boolean;
  readonly lifecycleReachable: boolean;
}): number {
  let score = 0;
  if (input.inChain) score += 100;
  if (input.lifecycleReachable) score += 80;
  const cat = input.finding.category;
  if (cat === "PROCESS_EXECUTION" || cat === "REMOTE_CODE_FETCH") score += 60;
  if (cat === "SHELL_COMMAND" || cat === "DOWNLOAD_BEHAVIOUR") score += 50;
  if (cat === "CREDENTIAL_RELATED_ACCESS" || cat === "SENSITIVE_FILE_ACCESS") score += 40;
  if (cat === "ENVIRONMENT_ACCESS" || cat === "DYNAMIC_CODE_EXECUTION") score += 30;
  if (input.finding.confidence === "HIGH") score += 10;
  return score;
}

/** @internal exported for tests */
export function behavioursForCategory(
  category: FindingCategory,
): readonly MlBehaviourLabel[] {
  return CATEGORY_TO_BEHAVIOURS[category] ?? [];
}

export type { BehaviourChain };
