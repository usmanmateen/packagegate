import { z } from "zod";
import { BehaviourChainSchema } from "./chain.js";
import { FindingSchema, ParseFailureSchema } from "./finding.js";
import { IntelligenceResultSchema, ProvenanceRecordSchema } from "./intelligence.js";
import {
  ArtifactInfoSchema,
  LifecycleScriptSchema,
  PackageMetadataSchema,
  ResolvedPackageSchema,
} from "./package.js";
import { RiskAssessmentSchema } from "./risk.js";
import { SCAN_ERROR_CODES } from "./errors.js";

export const SCAN_STATUSES = ["PENDING", "RUNNING", "COMPLETED", "FAILED"] as const;
export const ScanStatusSchema = z.enum(SCAN_STATUSES);
export type ScanStatus = z.infer<typeof ScanStatusSchema>;

/** A file the scanner enumerated. Content is not retained after analysis. */
export const ScannedFileSchema = z.object({
  path: z.string().min(1),
  sizeBytes: z.number().int().min(0),
  sha256: z.string().min(1),
  /** Coarse classification driving which analysers run. */
  kind: z.enum(["JAVASCRIPT", "TYPESCRIPT", "JSON", "BINARY", "NATIVE_ADDON", "OTHER"]),
  analysed: z.boolean(),
});
export type ScannedFile = z.infer<typeof ScannedFileSchema>;

export const ScanFailureSchema = z.object({
  code: z.enum(SCAN_ERROR_CODES),
  message: z.string(),
  details: z.record(z.string(), z.unknown()).default({}),
});
export type ScanFailure = z.infer<typeof ScanFailureSchema>;

/**
 * The complete result of investigating one package version.
 *
 * A `COMPLETED` scan with zero findings means "we analysed this and found
 * nothing our rules recognise". It does **not** mean the package is safe, and
 * no consumer of this type may present it that way.
 */
export const ScanResultSchema = z.object({
  scanId: z.string().min(1),
  status: ScanStatusSchema,
  requestedSpec: z.string().min(1),
  resolved: ResolvedPackageSchema.optional(),
  metadata: PackageMetadataSchema.optional(),
  artifact: ArtifactInfoSchema.optional(),

  lifecycleScripts: z.array(LifecycleScriptSchema).default([]),
  files: z.array(ScannedFileSchema).default([]),
  findings: z.array(FindingSchema).default([]),
  /** Files the parser could not read. Never silently dropped. */
  parseFailures: z.array(ParseFailureSchema).default([]),
  behaviourChains: z.array(BehaviourChainSchema).default([]),

  intelligence: IntelligenceResultSchema.optional(),
  provenance: ProvenanceRecordSchema.optional(),
  risk: RiskAssessmentSchema.optional(),

  /** Present when status is FAILED. */
  failure: ScanFailureSchema.optional(),

  startedAt: z.string().datetime(),
  completedAt: z.string().datetime().optional(),
  durationMs: z.number().int().min(0).optional(),
  scannerVersion: z.string().min(1),
  rulesVersion: z.string().min(1),
});
export type ScanResult = z.infer<typeof ScanResultSchema>;
