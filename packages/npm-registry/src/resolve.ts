import semver from "semver";
import { ScanError, sanitiseInlineValue } from "@packagegate/shared";
import type { Packument } from "./schemas.js";

/**
 * Version resolution.
 *
 * Pure and network-free so it can be tested against real packument shapes
 * without touching the registry. The resolved version is always surfaced to the
 * user explicitly — an investigation must never be ambiguous about which
 * artifact was actually analysed.
 */

export type VersionResolutionSource =
  /** No version requested; the registry's `latest` dist-tag was used. */
  | "default-latest"
  /** A named dist-tag such as `latest`, `next` or `beta`. */
  | "dist-tag"
  /** An exact semver version that exists in the packument. */
  | "exact"
  /** A semver range; the highest satisfying published version was chosen. */
  | "range";

export interface VersionResolution {
  readonly version: string;
  readonly resolvedFrom: VersionResolutionSource;
  readonly requested?: string;
}

function notFound(message: string, details: Record<string, string>): never {
  throw new ScanError("NOT_FOUND", message, { details });
}

/**
 * The list of versions that can actually be fetched.
 *
 * Deliberately derived from `versions` and never from `time`. The `time` object
 * retains entries for unpublished versions indefinitely — `express` alone
 * carries dozens of timestamps with no corresponding manifest — so using it
 * would offer users versions the registry cannot serve.
 */
export function availableVersions(packument: Packument): string[] {
  return Object.keys(packument.versions).filter((version) =>
    Boolean(semver.valid(version)),
  );
}

/**
 * Resolve a requested version specifier against a packument.
 *
 * Resolution order is dist-tag, then exact version, then semver range. Dist-tags
 * are checked first because a tag name like `latest` is not a valid semver
 * version or range and would otherwise fall through to a confusing error.
 *
 * @throws {ScanError} `NOT_FOUND` when nothing published satisfies the request.
 */
export function resolveVersion(
  packument: Packument,
  requested?: string,
): VersionResolution {
  const versions = availableVersions(packument);
  const distTags = packument["dist-tags"] ?? {};
  const safeRequested = requested === undefined ? undefined : sanitiseInlineValue(requested, 80);

  if (versions.length === 0) {
    notFound("Package has no published versions available to analyse", {
      package: sanitiseInlineValue(packument.name, 214),
    });
  }

  if (requested === undefined || requested.length === 0) {
    const latest = distTags["latest"];
    // Fall back to the highest published version when `latest` is missing or
    // points at something unpublished — both occur in the historical corpus.
    if (latest !== undefined && versions.includes(latest)) {
      return { version: latest, resolvedFrom: "default-latest" };
    }
    const highest = semver.maxSatisfying(versions, "*");
    if (highest === null) {
      notFound("Could not determine a current version for this package", {
        package: sanitiseInlineValue(packument.name, 214),
      });
    }
    return { version: highest, resolvedFrom: "default-latest" };
  }

  const taggedVersion = distTags[requested];
  if (taggedVersion !== undefined) {
    if (!versions.includes(taggedVersion)) {
      notFound(`Dist-tag "${safeRequested}" points at a version that is not published`, {
        package: sanitiseInlineValue(packument.name, 214),
        tag: safeRequested ?? "",
      });
    }
    return { version: taggedVersion, resolvedFrom: "dist-tag", requested };
  }

  if (semver.valid(requested) !== null) {
    if (!versions.includes(requested)) {
      notFound(`Version ${safeRequested} is not published for this package`, {
        package: sanitiseInlineValue(packument.name, 214),
        version: safeRequested ?? "",
      });
    }
    return { version: requested, resolvedFrom: "exact", requested };
  }

  if (semver.validRange(requested) !== null) {
    const best = semver.maxSatisfying(versions, requested);
    if (best === null) {
      notFound(`No published version satisfies "${safeRequested}"`, {
        package: sanitiseInlineValue(packument.name, 214),
        range: safeRequested ?? "",
      });
    }
    return { version: best, resolvedFrom: "range", requested };
  }

  notFound(`"${safeRequested}" is not a known dist-tag, version or version range`, {
    package: sanitiseInlineValue(packument.name, 214),
    requested: safeRequested ?? "",
  });
}

/**
 * The published version immediately preceding the given one, or undefined when
 * it is the earliest. Powers the "compare with previous published version"
 * action, which is the fastest way for an analyst to see what a release changed.
 */
export function previousPublishedVersion(
  packument: Packument,
  version: string,
): string | undefined {
  const ordered = availableVersions(packument).sort(semver.compare);
  const index = ordered.indexOf(version);
  if (index <= 0) return undefined;
  return ordered[index - 1];
}
