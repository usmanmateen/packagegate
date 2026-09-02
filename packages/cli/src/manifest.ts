import {
  PackageNameSchema,
  ScanError,
  sanitiseInlineValue,
  type PackageMetadata,
} from "@packagegate/shared";

export interface ParsedManifest {
  readonly metadata: PackageMetadata;
  readonly raw: unknown;
}

export interface ParseManifestOptions {
  readonly tarballUrl: string;
  /**
   * When true, missing/invalid name or version may fall back to supplied
   * identity (registry scans). Local tarball scans leave this false.
   */
  readonly allowIdentityFallback?: boolean;
  readonly fallbackName?: string;
  readonly fallbackVersion?: string;
}

function asStringRecord(value: unknown): Record<string, string> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  const out: Record<string, string> = {};
  for (const [key, entry] of Object.entries(value)) {
    if (typeof entry === "string") out[key] = entry;
  }
  return out;
}

/**
 * Parse an extracted package.json as data only. Never executes package code.
 */
export function parsePackageManifest(
  manifestText: string | undefined,
  options: ParseManifestOptions,
): ParsedManifest {
  if (manifestText === undefined) {
    throw new ScanError(
      "PACKAGE_MANIFEST_NOT_FOUND",
      "Extracted npm package does not contain a package.json at the package root",
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(manifestText);
  } catch {
    throw new ScanError("PACKAGE_MANIFEST_INVALID", "package.json is not valid JSON");
  }

  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new ScanError("PACKAGE_MANIFEST_INVALID", "package.json must be a JSON object");
  }

  const record = parsed as Record<string, unknown>;
  const nameResult = PackageNameSchema.safeParse(record["name"]);
  const version =
    typeof record["version"] === "string" && record["version"].length > 0
      ? record["version"]
      : undefined;

  let name: string;
  let resolvedVersion: string;

  if (nameResult.success && version !== undefined) {
    name = nameResult.data;
    resolvedVersion = version;
  } else if (
    options.allowIdentityFallback === true &&
    options.fallbackName !== undefined &&
    options.fallbackVersion !== undefined
  ) {
    name = options.fallbackName;
    resolvedVersion = options.fallbackVersion;
  } else if (!nameResult.success) {
    const rawName = record["name"];
    throw new ScanError(
      "PACKAGE_MANIFEST_INVALID",
      "package.json is missing a valid package name",
      {
        details: {
          name: sanitiseInlineValue(typeof rawName === "string" ? rawName : "", 80),
        },
      },
    );
  } else {
    throw new ScanError("PACKAGE_MANIFEST_INVALID", "package.json is missing a version");
  }

  const description =
    typeof record["description"] === "string" ? record["description"] : undefined;
  const license = typeof record["license"] === "string" ? record["license"] : undefined;
  const homepage =
    typeof record["homepage"] === "string" ? record["homepage"] : undefined;

  let repositoryUrl: string | undefined;
  const repository = record["repository"];
  if (typeof repository === "string") {
    repositoryUrl = repository;
  } else if (
    repository !== null &&
    typeof repository === "object" &&
    !Array.isArray(repository) &&
    "url" in repository &&
    typeof repository.url === "string"
  ) {
    repositoryUrl = repository.url;
  }

  const metadata: PackageMetadata = {
    name,
    version: resolvedVersion,
    ...(description === undefined ? {} : { description }),
    ...(license === undefined ? {} : { license }),
    ...(homepage === undefined ? {} : { homepage }),
    ...(repositoryUrl === undefined ? {} : { repositoryUrl }),
    maintainers: [],
    dependencies: asStringRecord(record["dependencies"]),
    devDependencies: asStringRecord(record["devDependencies"]),
    optionalDependencies: asStringRecord(record["optionalDependencies"]),
    peerDependencies: asStringRecord(record["peerDependencies"]),
    engines: asStringRecord(record["engines"]),
    scripts: asStringRecord(record["scripts"]),
    dist: {
      tarball: options.tarballUrl,
    },
  };

  return { metadata, raw: parsed };
}
