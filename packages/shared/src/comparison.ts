import { z } from "zod";
import { AnalysisCompletenessSchema } from "./completeness.js";
import { BehaviourChainSchema } from "./chain.js";
import { FindingSchema } from "./finding.js";
import { LifecycleScriptSchema, ResolvedPackageSchema } from "./package.js";
import { PolicyDecisionSchema } from "./policy.js";
import { RiskRecommendationSchema } from "./risk.js";

/**
 * Security-focused version comparison.
 *
 * The product question is not "what text changed" — that is what a diff tool is
 * for. It is "what can this version now do that the previous one could not".
 */

export const CHANGE_DIRECTIONS = [
  "INTRODUCED",
  "REMOVED",
  "MODIFIED",
  "UNCHANGED",
] as const;
export const ChangeDirectionSchema = z.enum(CHANGE_DIRECTIONS);
export type ChangeDirection = z.infer<typeof ChangeDirectionSchema>;

/** Significance of a *version change*, not a malware verdict. */
export const CHANGE_SIGNIFICANCES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
export const ChangeSignificanceSchema = z.enum(CHANGE_SIGNIFICANCES);
export type ChangeSignificance = z.infer<typeof ChangeSignificanceSchema>;

export const LifecycleScriptChangeSchema = z.object({
  name: z.string().min(1),
  direction: ChangeDirectionSchema,
  before: LifecycleScriptSchema.optional(),
  after: LifecycleScriptSchema.optional(),
});
export type LifecycleScriptChange = z.infer<typeof LifecycleScriptChangeSchema>;

export const BehaviourChangeSchema = z.object({
  direction: ChangeDirectionSchema,
  label: z.string().min(1),
  category: z.string().min(1),
  /** Stable semantic identity used for matching across versions. */
  identity: z.string().min(1),
  findingsBefore: z.array(FindingSchema).default([]),
  findingsAfter: z.array(FindingSchema).default([]),
});
export type BehaviourChange = z.infer<typeof BehaviourChangeSchema>;

export const ChainChangeSchema = z.object({
  direction: ChangeDirectionSchema,
  identity: z.string().min(1),
  chain: BehaviourChainSchema,
});
export type ChainChange = z.infer<typeof ChainChangeSchema>;

export const DependencyChangeSchema = z.object({
  name: z.string().min(1),
  direction: ChangeDirectionSchema,
  before: z.string().optional(),
  after: z.string().optional(),
  kind: z.enum([
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
  ]),
});
export type DependencyChange = z.infer<typeof DependencyChangeSchema>;

export const OpaqueSourceChangeSchema = z.object({
  path: z.string().min(1),
  direction: ChangeDirectionSchema,
  sizeBytes: z.number().int().min(0).optional(),
});
export type OpaqueSourceChange = z.infer<typeof OpaqueSourceChangeSchema>;

export const DestinationChangeSchema = z.object({
  destination: z.string().min(1),
  direction: ChangeDirectionSchema,
});
export type DestinationChange = z.infer<typeof DestinationChangeSchema>;

/**
 * First-class security semantic diff between two investigated versions.
 */
export const SecurityDiffSchema = z.object({
  packageName: z.string().min(1),
  fromVersion: z.string().min(1),
  toVersion: z.string().min(1),

  lifecycleAdded: z.array(LifecycleScriptSchema).default([]),
  lifecycleRemoved: z.array(LifecycleScriptSchema).default([]),

  findingsAdded: z.array(FindingSchema).default([]),
  findingsRemoved: z.array(FindingSchema).default([]),

  chainsAdded: z.array(BehaviourChainSchema).default([]),
  chainsRemoved: z.array(BehaviourChainSchema).default([]),

  destinationsAdded: z.array(z.string()).default([]),
  destinationsRemoved: z.array(z.string()).default([]),

  opaqueSourcesAdded: z.array(OpaqueSourceChangeSchema).default([]),

  completenessBefore: AnalysisCompletenessSchema,
  completenessAfter: AnalysisCompletenessSchema,

  riskBefore: z.object({
    score: z.number().min(0).max(100),
    recommendation: RiskRecommendationSchema,
  }),
  riskAfter: z.object({
    score: z.number().min(0).max(100),
    recommendation: RiskRecommendationSchema,
  }),
  riskDelta: z.number(),

  policyBefore: PolicyDecisionSchema,
  policyAfter: PolicyDecisionSchema,

  changeSignificance: ChangeSignificanceSchema,
  summary: z.string().min(1),

  /** Detailed change lists for reporting. */
  behaviourChanges: z.array(BehaviourChangeSchema).default([]),
  chainChanges: z.array(ChainChangeSchema).default([]),
  lifecycleScriptChanges: z.array(LifecycleScriptChangeSchema).default([]),
});
export type SecurityDiff = z.infer<typeof SecurityDiffSchema>;

/** Legacy comparison envelope kept for API compatibility. */
export const VersionComparisonSchema = z.object({
  comparisonId: z.string().min(1),
  base: ResolvedPackageSchema,
  target: ResolvedPackageSchema,
  baseScanId: z.string().min(1),
  targetScanId: z.string().min(1),

  baseScore: z.number().min(0).max(100),
  targetScore: z.number().min(0).max(100),
  riskDelta: z.number(),

  lifecycleScriptChanges: z.array(LifecycleScriptChangeSchema).default([]),
  behaviourChanges: z.array(BehaviourChangeSchema).default([]),
  chainChanges: z.array(ChainChangeSchema).default([]),
  dependencyChanges: z.array(DependencyChangeSchema).default([]),

  addedFiles: z.array(z.string()).default([]),
  removedFiles: z.array(z.string()).default([]),
  modifiedFiles: z.array(z.string()).default([]),

  newNetworkDestinations: z.array(z.string()).default([]),

  computedAt: z.string().datetime(),
  securityDiff: SecurityDiffSchema.optional(),
});
export type VersionComparison = z.infer<typeof VersionComparisonSchema>;
