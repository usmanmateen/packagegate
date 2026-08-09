import {
  PackageMetadataSchema,
  ScanError,
  sanitiseInlineValue,
  type PackageMetadata,
} from "@packagegate/shared";
import { encodePackageNameForUrl } from "./spec.js";
import { resolveVersion, type VersionResolution } from "./resolve.js";
import {
  PackumentSchema,
  normaliseDeprecated,
  normaliseLicense,
  normaliseMaintainers,
  normaliseRepositoryUrl,
  type Packument,
  type RegistryVersionManifest,
} from "./schemas.js";

export const DEFAULT_REGISTRY_URL = "https://registry.npmjs.org";

/**
 * Registry responses can be large — a popular package's packument is hundreds
 * of kilobytes, and `@types/*` packuments run to several megabytes. This bound
 * stops a hostile or pathological response from exhausting memory.
 */
const MAX_PACKUMENT_BYTES = 64 * 1024 * 1024;

/** Injectable so tests never touch the network. */
export type FetchLike = (
  input: string,
  init?: { headers?: Record<string, string>; signal?: AbortSignal },
) => Promise<{
  ok: boolean;
  status: number;
  headers: { get(name: string): string | null };
  text(): Promise<string>;
}>;

export interface RegistryClientOptions {
  readonly registryUrl?: string;
  /**
   * npm publishes no numeric rate limit and returns no rate-limit headers, but
   * it does ban by IP *and* user-agent. Identifying ourselves honestly is both
   * good manners and the thing that keeps a shared IP from being blamed.
   */
  readonly userAgent?: string;
  readonly timeoutMs?: number;
  readonly fetchImpl?: FetchLike;
}

interface ResolvedOptions {
  readonly registryUrl: string;
  readonly userAgent: string;
  readonly timeoutMs: number;
  readonly fetchImpl: FetchLike;
}

function upstreamError(
  message: string,
  details: Record<string, string | number>,
): ScanError {
  return new ScanError("UPSTREAM_UNAVAILABLE", message, { details, retryable: true });
}

/**
 * Client for the npm registry.
 *
 * Only reads. There is no publish, deprecate or write path anywhere in this
 * package, and no credential is ever sent — everything PackageGate needs is
 * public. That keeps the blast radius of a compromised scanner limited to
 * reading public data.
 */
export class RegistryClient {
  private readonly options: ResolvedOptions;

  constructor(options: RegistryClientOptions = {}) {
    // Node 24 provides a global fetch, and it satisfies FetchLike structurally
    // with no cast needed. FetchLike is deliberately a narrow subset — only the
    // handful of members used below — which keeps the seam small enough for
    // tests to stub without reconstructing the whole Response surface.
    const fetchImpl = options.fetchImpl ?? globalThis.fetch;
    if (typeof fetchImpl !== "function") {
      throw new TypeError("No fetch implementation available");
    }
    this.options = {
      registryUrl: (options.registryUrl ?? DEFAULT_REGISTRY_URL).replace(/\/+$/, ""),
      userAgent: options.userAgent ?? "packagegate/0.1.0",
      timeoutMs: options.timeoutMs ?? 30_000,
      fetchImpl,
    };
  }

  /**
   * Fetch the full packument for a package.
   *
   * The abbreviated `application/vnd.npm.install-v1+json` representation is
   * deliberately not requested: it omits `scripts`, which is precisely the
   * field lifecycle-script analysis depends on. It also returns HTTP 406 on
   * single-version endpoints, so setting it globally on a shared client is a
   * trap.
   */
  async getPackument(name: string): Promise<Packument> {
    const url = `${this.options.registryUrl}/${encodePackageNameForUrl(name)}`;
    const body = await this.request(url, name);

    let parsed: unknown;
    try {
      parsed = JSON.parse(body);
    } catch {
      throw upstreamError("Registry returned a malformed response", {
        package: sanitiseInlineValue(name, 214),
      });
    }

    const result = PackumentSchema.safeParse(parsed);
    if (!result.success) {
      throw upstreamError("Registry response did not match the expected shape", {
        package: sanitiseInlineValue(name, 214),
        issues: result.error.issues.length,
      });
    }
    return result.data;
  }

  /**
   * Resolve a spec to a concrete version and return its metadata.
   *
   * One request, not two: the packument already contains every version
   * manifest, so resolving and reading metadata from the same response avoids a
   * second round trip and sidesteps the single-version endpoint entirely.
   */
  async getPackageMetadata(
    name: string,
    requestedVersion?: string,
  ): Promise<{
    metadata: PackageMetadata;
    resolution: VersionResolution;
    packument: Packument;
  }> {
    const packument = await this.getPackument(name);
    const resolution = resolveVersion(packument, requestedVersion);
    const manifest = packument.versions[resolution.version];

    if (manifest === undefined) {
      throw new ScanError("NOT_FOUND", "Resolved version is missing from the packument", {
        details: {
          package: sanitiseInlineValue(name, 214),
          version: sanitiseInlineValue(resolution.version, 80),
        },
      });
    }

    // Publication time lives on the packument, not the version manifest.
    const publishedAt = packument.time?.[resolution.version];

    return {
      metadata: toPackageMetadata(manifest, publishedAt),
      resolution,
      packument,
    };
  }

  private async request(url: string, name: string): Promise<string> {
    const controller = new AbortController();
    const timer = setTimeout(() => {
      controller.abort();
    }, this.options.timeoutMs);

    try {
      const response = await this.options.fetchImpl(url, {
        headers: {
          accept: "application/json",
          "accept-encoding": "gzip",
          "user-agent": this.options.userAgent,
        },
        signal: controller.signal,
      });

      if (response.status === 404) {
        throw new ScanError("NOT_FOUND", "Package not found in the registry", {
          details: { package: sanitiseInlineValue(name, 214) },
        });
      }
      if (response.status === 429) {
        throw upstreamError("Registry rate limit reached", {
          package: sanitiseInlineValue(name, 214),
          status: response.status,
        });
      }
      if (!response.ok) {
        throw upstreamError("Registry request failed", {
          package: sanitiseInlineValue(name, 214),
          status: response.status,
        });
      }

      const declaredLength = Number(response.headers.get("content-length") ?? "0");
      if (declaredLength > MAX_PACKUMENT_BYTES) {
        throw new ScanError(
          "LIMIT_EXCEEDED",
          "Registry response is too large to process",
          {
            details: {
              package: sanitiseInlineValue(name, 214),
              declaredLength,
            },
          },
        );
      }

      const text = await response.text();
      if (text.length > MAX_PACKUMENT_BYTES) {
        throw new ScanError(
          "LIMIT_EXCEEDED",
          "Registry response is too large to process",
          {
            details: { package: sanitiseInlineValue(name, 214), bytes: text.length },
          },
        );
      }
      return text;
    } catch (error) {
      if (error instanceof ScanError) throw error;
      if (error instanceof Error && error.name === "AbortError") {
        throw new ScanError("TIMEOUT", "Registry request timed out", {
          details: {
            package: sanitiseInlineValue(name, 214),
            timeoutMs: this.options.timeoutMs,
          },
          retryable: true,
        });
      }
      throw upstreamError("Could not reach the registry", {
        package: sanitiseInlineValue(name, 214),
      });
    } finally {
      clearTimeout(timer);
    }
  }
}

/**
 * Map a registry version manifest onto our domain model.
 *
 * Absent numerics stay absent. `unpackedSize ?? 0` would mark every pre-2016
 * package as empty, and a downstream rule reading "zero bytes unpacked" as
 * suspicious would then fire on a decade of legitimate history.
 */
export function toPackageMetadata(
  manifest: RegistryVersionManifest,
  publishedAt?: string,
): PackageMetadata {
  const candidate = {
    name: manifest.name,
    version: manifest.version,
    description: manifest.description,
    publishedAt,
    repositoryUrl: normaliseRepositoryUrl(manifest.repository),
    homepage: manifest.homepage ?? undefined,
    license: normaliseLicense(manifest.license),
    deprecated: normaliseDeprecated(manifest.deprecated),
    maintainers: normaliseMaintainers(manifest.maintainers),
    dependencies: manifest.dependencies ?? {},
    devDependencies: manifest.devDependencies ?? {},
    optionalDependencies: manifest.optionalDependencies ?? {},
    peerDependencies: manifest.peerDependencies ?? {},
    engines: manifest.engines ?? {},
    scripts: manifest.scripts ?? {},
    dist: {
      tarball: manifest.dist.tarball,
      shasum: manifest.dist.shasum,
      integrity: manifest.dist.integrity,
      fileCount: manifest.dist.fileCount,
      unpackedSize: manifest.dist.unpackedSize,
    },
  };

  return PackageMetadataSchema.parse(candidate);
}
