/**
 * @packagegate/npm-registry — reading the npm registry.
 *
 * Read-only by construction: there is no publish, deprecate or write path here,
 * and no credential is ever sent. Everything PackageGate needs from the registry
 * is public, which keeps a compromised scanner limited to reading public data.
 *
 * Specifier parsing is a security boundary — the parsed name reaches registry
 * URLs and database keys, so only unambiguously published packages are accepted.
 */

export { parsePackageSpec, encodePackageNameForUrl, formatPackageSpec } from "./spec.js";

export {
  RegistryClient,
  toPackageMetadata,
  DEFAULT_REGISTRY_URL,
  type FetchLike,
  type RegistryClientOptions,
} from "./client.js";

export {
  resolveVersion,
  availableVersions,
  previousPublishedVersion,
  type VersionResolution,
  type VersionResolutionSource,
} from "./resolve.js";

export {
  PackumentSchema,
  VersionManifestSchema,
  DistSchema,
  type Packument,
  type RegistryVersionManifest,
  type RegistryDist,
} from "./schemas.js";
