import { ArtifactInfoSchema, type ArtifactInfo } from "@packagegate/shared";
import { downloadTarball, type DownloadRequest } from "./download.js";
import { extractTarball, type ContentRetention, type ExtractedFile } from "./extract.js";
import { resolveLimits, type ArtifactLimits } from "./limits.js";
import type { SkippedEntry } from "./paths.js";
import { integrityVerifiedFlag, verifyBytes } from "./verify.js";
import { withTemporaryDirectory } from "./workspace.js";

/**
 * @packagegate/artifact-fetcher — getting a hostile tarball onto disk safely,
 * and off it again reliably.
 *
 * The package exposes exactly two ways to obtain an extracted package, both
 * scoped:
 *
 *  - {@link withExtractedPackage} downloads and extracts.
 *  - {@link withExtractedTarball} extracts bytes the caller already holds, and
 *    touches no network at all.
 *
 * The second exists for more than testing convenience. THREAT_MODEL §5 puts
 * the tar/gzip parsers on the far side of a trust boundary from the network
 * and the credentials (TB-2/TB-3), and R-ARCH-03 forbids v1 from foreclosing
 * that split. A blob-in, evidence-out entry point is what makes the split a
 * later packaging decision rather than a rewrite.
 *
 * Neither entry point returns a handle the caller has to remember to release.
 * Extraction fails on limits, traversal attempts, malformed archives and
 * timeouts as a matter of routine, and a cleanup step that is only reached on
 * the happy path is not cleanup.
 */

export { DEFAULT_ARTIFACT_LIMITS, resolveLimits, LIMIT_NAMES } from "./limits.js";
export type { ArtifactLimits, LimitName } from "./limits.js";

export {
  ArtifactDigester,
  digestMatches,
  parseIntegrity,
  SUPPORTED_INTEGRITY_ALGORITHMS,
} from "./integrity.js";
export type {
  IntegrityAlgorithm,
  IntegrityDeclaration,
  IntegrityExpectation,
} from "./integrity.js";

export { integrityVerifiedFlag, verifyBytes, verifyDigest } from "./verify.js";
export type { IntegrityReport } from "./verify.js";

export { downloadTarball } from "./download.js";
export type {
  DownloadRequest,
  DownloadedTarball,
  HttpFetch,
  HttpRequestInit,
  HttpResponseLike,
} from "./download.js";

export { extractTarball } from "./extract.js";
export type { ContentRetention, ExtractedFile, ExtractionResult } from "./extract.js";

export { classifyEntryPath, resolveWithinRoot, ENTRY_SKIP_REASONS } from "./paths.js";
export type { EntryPathDecision, EntrySkipReason, SkippedEntry } from "./paths.js";

export { withTemporaryDirectory } from "./workspace.js";

/**
 * An extracted package, valid only for the duration of the callback that
 * received it.
 */
export interface ExtractedPackage {
  /** The serialisable record of what we fetched. Safe to persist and return. */
  readonly artifact: ArtifactInfo;
  /**
   * Files in the package, with bounded contents for an analyser that performs
   * no I/O of its own (R-ANL-06: no rule may open a file relative to the
   * package).
   */
  readonly files: readonly ExtractedFile[];
  readonly retention: ContentRetention;
  /**
   * Where the files were written.
   *
   * Process-local and short-lived. It must never be serialised, logged,
   * returned through the API or embedded in evidence — a host filesystem path
   * is exactly what the threat model says must not leak. It is exposed so
   * tests can assert on the real filesystem, and so a future worker-based
   * parser can be pointed at the tree.
   */
  readonly extractionRoot: string;
}

/** What {@link withExtractedPackage} needs: everything the download needs. */
export type FetchPackageRequest = DownloadRequest;

export interface ExtractTarballRequest {
  readonly bytes: Uint8Array;
  /** Recorded in {@link ArtifactInfo}; carried across the fetcher/scanner boundary. */
  readonly tarballUrl: string;
  readonly integrity?: string;
  readonly limits?: Partial<ArtifactLimits>;
}

/**
 * Download, verify, extract, hand the result to `use`, then delete the
 * temporary directory — whatever happened.
 *
 * The extracted tree does not outlive `use`. Callers must copy out the
 * evidence they need (hashes, sizes, bounded contents) rather than holding a
 * path; everything they are meant to keep is already in the value they are
 * given.
 */
export async function withExtractedPackage<T>(
  request: FetchPackageRequest,
  use: (extracted: ExtractedPackage) => Promise<T>,
): Promise<T> {
  const downloaded = await downloadTarball(request);
  return await withExtractedTarballBytes(
    {
      bytes: downloaded.bytes,
      tarballUrl: downloaded.tarballUrl,
      limits: request.limits,
    },
    downloaded.sha256,
    integrityVerifiedFlag(downloaded.integrity),
    use,
  );
}

/**
 * Extract tarball bytes the caller already holds. No network, no credentials,
 * no registry client — see the module note on TB-3.
 */
export async function withExtractedTarball<T>(
  request: ExtractTarballRequest,
  use: (extracted: ExtractedPackage) => Promise<T>,
): Promise<T> {
  // Verified before anything is written: if the bytes are not the bytes the
  // registry vouched for, nothing downstream should have looked at them.
  const { sha256, report } = verifyBytes(request.bytes, request.integrity);
  return await withExtractedTarballBytes(
    request,
    sha256,
    integrityVerifiedFlag(report),
    use,
  );
}

async function withExtractedTarballBytes<T>(
  request: ExtractTarballRequest,
  sha256: string,
  integrityVerified: boolean | undefined,
  use: (extracted: ExtractedPackage) => Promise<T>,
): Promise<T> {
  const limits = resolveLimits(request.limits);

  return await withTemporaryDirectory(async (extractionRoot) => {
    const result = await extractTarball(request.bytes, extractionRoot, limits);

    // Validated on the way out as well as on the way in: this object is the
    // contract with the database and the API, and every string in it started
    // life inside an attacker-controlled archive.
    const artifact = ArtifactInfoSchema.parse({
      tarballUrl: request.tarballUrl,
      compressedSizeBytes: request.bytes.byteLength,
      extractedSizeBytes: result.extractedSizeBytes,
      fileCount: result.fileCount,
      sha256,
      ...(integrityVerified === undefined ? {} : { integrityVerified }),
      skippedEntries: result.skippedEntries.map((entry: SkippedEntry) => ({
        path: entry.path,
        reason: entry.reason,
      })),
    });

    return await use({
      artifact,
      files: result.files,
      retention: result.retention,
      extractionRoot,
    });
  });
}
