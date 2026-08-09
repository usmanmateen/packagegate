import { z } from "zod";
import { BehaviourChainSchema } from "./chain.js";
import { FindingSchema } from "./finding.js";
import { LifecycleScriptSchema, ResolvedPackageSchema } from "./package.js";

/**
 * Security-focused version comparison.
 *
 * The product question is not "what text changed" — that is what a diff tool is
 * for. It is "what can this version now do that the previous one could not".
 * A release that reformats 40,000 lines but introduces no new capability is
 * uninteresting; a release that adds four lines and a `postinstall` is not.
 */

export const CHANGE_DIRECTIONS = [
  "INTRODUCED",
  "REMOVED",
  "MODIFIED",
  "UNCHANGED",
] as const;
export const ChangeDirectionSchema = z.enum(CHANGE_DIRECTIONS);
export type ChangeDirection = z.infer<typeof ChangeDirectionSchema>;

/** A lifecycle script that appeared, disappeared or changed between versions. */
export const LifecycleScriptChangeSchema = z.object({
  name: z.string().min(1),
  direction: ChangeDirectionSchema,
  before: LifecycleScriptSchema.optional(),
  after: LifecycleScriptSchema.optional(),
});
export type LifecycleScriptChange = z.infer<typeof LifecycleScriptChangeSchema>;

/**
 * A capability difference expressed in behavioural terms.
 *
 * Findings are matched across versions by rule and semantic location rather
 * than by line number, so that unrelated edits shifting a file do not present
 * as new behaviour.
 */
export const BehaviourChangeSchema = z.object({
  direction: ChangeDirectionSchema,
  /** Human-readable capability statement, e.g. "Process execution introduced". */
  label: z.string().min(1),
  category: z.string().min(1),
  findingsBefore: z.array(FindingSchema).default([]),
  findingsAfter: z.array(FindingSchema).default([]),
});
export type BehaviourChange = z.infer<typeof BehaviourChangeSchema>;

export const ChainChangeSchema = z.object({
  direction: ChangeDirectionSchema,
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

export const VersionComparisonSchema = z.object({
  comparisonId: z.string().min(1),
  base: ResolvedPackageSchema,
  target: ResolvedPackageSchema,
  baseScanId: z.string().min(1),
  targetScanId: z.string().min(1),

  baseScore: z.number().min(0).max(100),
  targetScore: z.number().min(0).max(100),
  /** target − base. Negative means the new version is less risky. */
  riskDelta: z.number(),

  lifecycleScriptChanges: z.array(LifecycleScriptChangeSchema).default([]),
  behaviourChanges: z.array(BehaviourChangeSchema).default([]),
  chainChanges: z.array(ChainChangeSchema).default([]),
  dependencyChanges: z.array(DependencyChangeSchema).default([]),

  /** Files present only in the target version, package-relative. */
  addedFiles: z.array(z.string()).default([]),
  removedFiles: z.array(z.string()).default([]),
  /** Files present in both but with different content hashes. */
  modifiedFiles: z.array(z.string()).default([]),

  /** Network destinations statically identifiable in target but not base. */
  newNetworkDestinations: z.array(z.string()).default([]),

  computedAt: z.string().datetime(),
});
export type VersionComparison = z.infer<typeof VersionComparisonSchema>;
