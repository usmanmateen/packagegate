import { z } from "zod";

/**
 * npm package naming rules, as enforced by the registry. Kept strict because
 * this value is interpolated into registry URLs and used as a database key —
 * a permissive name pattern is a request-forgery and injection surface.
 *
 * Unscoped: `lodash`, `some-pkg.name_1`
 * Scoped:   `@scope/name`
 */
// Uppercase is permitted because the registry still serves packages published
// before it was disallowed — `JSONStream` and friends are real and must remain
// scannable. New-package naming rules are the registry's problem, not ours; our
// job is to address anything already published.
//
// The leading character must be alphanumeric, which is what excludes the
// `.` and `_` prefixes the registry reserves.
const NAME_SEGMENT = "[A-Za-z0-9](?:[A-Za-z0-9\\-._~]*)";
export const PACKAGE_NAME_PATTERN = new RegExp(`^(?:@${NAME_SEGMENT}/)?${NAME_SEGMENT}$`);

/** Maximum npm package name length, per registry rules. */
export const MAX_PACKAGE_NAME_LENGTH = 214;

export const PackageNameSchema = z
  .string()
  .min(1)
  .max(MAX_PACKAGE_NAME_LENGTH)
  .regex(PACKAGE_NAME_PATTERN, "not a valid npm package name");

/**
 * A parsed package specifier. `requestedVersion` is absent when the user wrote
 * a bare name — the resolved version is then always surfaced explicitly to the
 * user so an investigation is never ambiguous about what was analysed.
 *
 * Local paths, git URLs, tarball URLs and other npm "specifier" forms are
 * deliberately rejected. PackageGate investigates published registry artifacts.
 */
export const PackageSpecSchema = z.object({
  name: PackageNameSchema,
  scope: z.string().optional(),
  requestedVersion: z.string().optional(),
  /** The original user input, sanitised, for display and audit. */
  raw: z.string(),
});
export type PackageSpec = z.infer<typeof PackageSpecSchema>;

/** A specifier after registry resolution. The version is now concrete. */
export const ResolvedPackageSchema = z.object({
  name: PackageNameSchema,
  version: z.string().min(1),
});
export type ResolvedPackage = z.infer<typeof ResolvedPackageSchema>;

/**
 * A lifecycle script declared in package.json.
 *
 * Presence of a lifecycle script is ordinary. Native modules compile, binaries
 * are fetched, platforms are detected. What matters is what the referenced code
 * does, which is why `referencedFiles` exists — it is the bridge from the
 * manifest into static analysis of the file that actually runs.
 */
export const LifecycleScriptSchema = z.object({
  name: z.string().min(1),
  /** Raw command, sanitised for display. Never executed, never shelled out. */
  command: z.string(),
  /** True for scripts npm runs automatically on install. */
  runsOnInstall: z.boolean(),
  /**
   * Package-relative files the command appears to invoke, recovered by parsing
   * the command string. Best-effort: a command may reference files we cannot
   * statically identify, and that limitation is documented.
   */
  referencedFiles: z.array(z.string()).default([]),
});
export type LifecycleScript = z.infer<typeof LifecycleScriptSchema>;

/**
 * Registry metadata for a specific published version.
 *
 * Almost every field is optional because the registry genuinely omits them.
 *
 * Verified against the live registry rather than assumed: `integrity` and
 * `shasum` are present even on 2010–2012 era versions — npm backfilled the
 * historical corpus — so their absence is rare rather than routine. They stay
 * optional for tolerance, not because we expect them missing. The fields that
 * really are commonly absent are `fileCount` and `unpackedSize`, missing on the
 * large majority of pre-2016 versions.
 *
 * Consumers must never default an absent numeric to zero: `unpackedSize ?? 0`
 * would render every old package as empty. Absent means unknown.
 *
 * Missing metadata is not evidence of maliciousness and must never be scored
 * as such.
 */
export const PackageMetadataSchema = z.object({
  name: PackageNameSchema,
  version: z.string().min(1),
  description: z.string().optional(),
  publishedAt: z.string().optional(),
  repositoryUrl: z.string().optional(),
  homepage: z.string().optional(),
  license: z.string().optional(),
  deprecated: z.string().optional(),
  maintainers: z
    .array(z.object({ name: z.string(), email: z.string().optional() }))
    .default([]),
  dependencies: z.record(z.string(), z.string()).default({}),
  devDependencies: z.record(z.string(), z.string()).default({}),
  optionalDependencies: z.record(z.string(), z.string()).default({}),
  peerDependencies: z.record(z.string(), z.string()).default({}),
  engines: z.record(z.string(), z.string()).default({}),
  scripts: z.record(z.string(), z.string()).default({}),
  dist: z.object({
    tarball: z.string(),
    shasum: z.string().optional(),
    integrity: z.string().optional(),
    fileCount: z.number().int().optional(),
    unpackedSize: z.number().int().optional(),
  }),
});
export type PackageMetadata = z.infer<typeof PackageMetadataSchema>;

/** Facts about the artifact we actually downloaded and extracted. */
export const ArtifactInfoSchema = z.object({
  tarballUrl: z.string(),
  /** Bytes received over the wire. */
  compressedSizeBytes: z.number().int().min(0),
  /** Bytes written after decompression. */
  extractedSizeBytes: z.number().int().min(0),
  fileCount: z.number().int().min(0),
  /** SHA-256 of the downloaded tarball, computed by us. */
  sha256: z.string().min(1),
  /** Whether the registry-declared integrity matched what we downloaded. */
  integrityVerified: z.boolean().optional(),
  /** Archive entries skipped during extraction, with the reason. */
  skippedEntries: z.array(z.object({ path: z.string(), reason: z.string() })).default([]),
});
export type ArtifactInfo = z.infer<typeof ArtifactInfoSchema>;
