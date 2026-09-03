import { z } from "zod";

/**
 * Schemas for npm registry responses.
 *
 * Registry responses are **untrusted input**. They are served by a third party,
 * and much of the corpus was published a decade ago by tooling that no longer
 * exists. Fields that are documented as strings appear as objects, arrays and
 * nulls in the historical record.
 *
 * The approach is therefore: validate the small set of fields we actually
 * depend on, tolerate anything else, and normalise the messy shapes rather than
 * rejecting real packages. A parse failure here would make a legitimate old
 * package unscannable, which is a correctness bug, not a security win.
 *
 * Unknown keys are stripped by default, which is also what keeps unexpected
 * registry fields from flowing into our persistence layer.
 */

/** `repository` is a string in old manifests and an object in modern ones. */
const RepositorySchema = z
  .union([
    z.string(),
    z.object({ url: z.string().optional(), type: z.string().optional() }),
    z.null(),
  ])
  .optional();

/**
 * `license` is a string today. Older manifests used an object, and some used
 * the `licenses[]` array shape *under the `license` key* — socket.io@0.3.8 is a
 * real example. Rejecting that form makes a very widely used package
 * unscannable, so all four shapes are accepted.
 */
const LicenseEntrySchema = z.object({
  type: z.string().optional(),
  url: z.string().optional(),
});

const LicenseSchema = z
  .union([
    z.string(),
    LicenseEntrySchema,
    z.array(z.union([z.string(), LicenseEntrySchema])),
    z.null(),
  ])
  .optional();

/**
 * `homepage` is documented as a string but appears as an array of strings in
 * the early corpus — fs-extra@0.0.1 is a real example, and 19 of its versions
 * carry that shape.
 */
const HomepageSchema = z.union([z.string(), z.array(z.string()), z.null()]).optional();

/** Maintainers appear as `"name <email>"` strings in older packuments. */
const MaintainerSchema = z.union([
  z.string(),
  z.object({ name: z.string().optional(), email: z.string().optional() }),
]);

/**
 * A record of string→string that tolerates nulls and non-string values without
 * discarding the whole manifest. Dependency maps in the historical corpus
 * contain nulls and numbers.
 */
// `.optional()` is load-bearing: in Zod 4 a bare `z.unknown()` inside an object
// is still required, so omitting it rejects every manifest that simply has no
// `dependencies` key — which is most of the early corpus.
const LooseStringRecord = z
  .unknown()
  .transform((raw) => {
    const out: Record<string, string> = {};
    if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return out;
    for (const [key, value] of Object.entries(raw)) {
      if (typeof value === "string") out[key] = value;
    }
    return out;
  })
  .optional();

/**
 * `engines` additionally appears as an array in older manifests —
 * `"engines": ["node"]` was the convention before the object form, and lodash
 * alone carries 44 versions in that shape. It means "runs on these engines"
 * with no version constraint, so an unconstrained range is a faithful
 * translation rather than invented data.
 */
const EnginesRecord = z
  .unknown()
  .transform((raw) => {
    const out: Record<string, string> = {};
    if (Array.isArray(raw)) {
      for (const entry of raw) {
        if (typeof entry === "string" && entry.length > 0) out[entry] = "*";
      }
      return out;
    }
    if (raw === null || typeof raw !== "object") return out;
    for (const [key, value] of Object.entries(raw)) {
      if (typeof value === "string") out[key] = value;
    }
    return out;
  })
  .optional();

export const DistSchema = z.object({
  tarball: z.string().min(1),
  shasum: z.string().optional(),
  integrity: z.string().optional(),
  // Absent on the large majority of pre-2016 versions. Absent means unknown —
  // never coerce to zero, which would render every old package as empty.
  fileCount: z.number().int().nonnegative().optional(),
  unpackedSize: z.number().int().nonnegative().optional(),
  attestations: z
    .object({ url: z.string().optional(), provenance: z.unknown().optional() })
    .optional(),
});
export type RegistryDist = z.infer<typeof DistSchema>;

export const VersionManifestSchema = z.object({
  name: z.string().min(1),
  version: z.string().min(1),
  description: z.string().optional(),
  repository: RepositorySchema,
  homepage: HomepageSchema,
  license: LicenseSchema,
  deprecated: z.union([z.string(), z.boolean()]).optional(),
  maintainers: z.array(MaintainerSchema).optional(),
  dependencies: LooseStringRecord,
  devDependencies: LooseStringRecord,
  optionalDependencies: LooseStringRecord,
  peerDependencies: LooseStringRecord,
  engines: EnginesRecord,
  scripts: LooseStringRecord,
  /** Present in abbreviated metadata; a cheap signal that install scripts exist. */
  hasInstallScript: z.boolean().optional(),
  dist: DistSchema,
});
export type RegistryVersionManifest = z.infer<typeof VersionManifestSchema>;

export const PackumentSchema = z.object({
  name: z.string().min(1),
  "dist-tags": z.record(z.string(), z.string()).optional(),
  versions: z.record(z.string(), VersionManifestSchema),
  /**
   * Publication timestamps. Note this key set is NOT the same as `versions`:
   * unpublished versions persist in `time` long after their manifests are gone,
   * so it must never be used as the list of available versions.
   */
  time: z.record(z.string(), z.string()).optional(),
});
export type Packument = z.infer<typeof PackumentSchema>;

/** Flatten the several historical shapes of `repository` into a URL. */
export function normaliseRepositoryUrl(
  repository: RegistryVersionManifest["repository"],
): string | undefined {
  if (repository === undefined || repository === null) return undefined;
  if (typeof repository === "string") return repository;
  return repository.url ?? undefined;
}

/** Flatten the several historical shapes of `license` into an SPDX-ish string. */
export function normaliseLicense(
  license: RegistryVersionManifest["license"],
): string | undefined {
  if (license === undefined || license === null) return undefined;
  if (typeof license === "string") return license;
  if (Array.isArray(license)) {
    // The historical `licenses[]` shape. Take the first declared licence
    // rather than inventing a composite expression the publisher never wrote.
    for (const entry of license) {
      if (typeof entry === "string" && entry.length > 0) return entry;
      if (entry !== null && typeof entry === "object" && entry.type) return entry.type;
    }
    return undefined;
  }
  return license.type ?? undefined;
}

/** Flatten the string-or-array shapes of `homepage` into a single URL. */
export function normaliseHomepage(
  homepage: RegistryVersionManifest["homepage"],
): string | undefined {
  if (homepage === undefined || homepage === null) return undefined;
  if (typeof homepage === "string") return homepage;
  return homepage.find((entry) => typeof entry === "string" && entry.length > 0);
}

/** Normalise maintainers, accepting the `"name <email>"` string form. */
export function normaliseMaintainers(
  maintainers: RegistryVersionManifest["maintainers"],
): { name: string; email?: string }[] {
  if (maintainers === undefined) return [];
  return maintainers.map((maintainer) => {
    if (typeof maintainer === "string") {
      const match = /^(.*?)\s*<([^>]*)>$/.exec(maintainer);
      if (match?.[1] !== undefined && match[2] !== undefined) {
        return { name: match[1], email: match[2] };
      }
      return { name: maintainer };
    }
    return {
      name: maintainer.name ?? "unknown",
      ...(maintainer.email === undefined ? {} : { email: maintainer.email }),
    };
  });
}

/** `deprecated` is a message string, but `true` appears in the wild. */
export function normaliseDeprecated(
  deprecated: RegistryVersionManifest["deprecated"],
): string | undefined {
  if (deprecated === undefined || deprecated === false) return undefined;
  if (deprecated === true) return "This version is deprecated";
  return deprecated;
}
