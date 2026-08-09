/**
 * Resource budgets for handling a hostile artifact.
 *
 * Every value here exists because the tarball is attacker-controlled. The
 * defaults are deliberately generous enough for the largest real npm packages
 * (TypeScript, aws-sdk, playwright-core and friends are all well inside them)
 * and deliberately far below what it would take to exhaust the host.
 *
 * All of these are enforced *during* streaming. A limit that is only checked
 * after the archive has been fully decompressed is not a limit — it is a
 * post-mortem.
 */

/** Names used in {@link LimitExceededError} details. Kept stable for the API. */
export const LIMIT_NAMES = [
  "compressedBytes",
  "decompressedBytes",
  "fileBytes",
  "fileCount",
  "pathLength",
  "compressionRatio",
] as const;
export type LimitName = (typeof LIMIT_NAMES)[number];

export interface ArtifactLimits {
  /** Bytes accepted over the wire, and bytes fed into the decompressor. */
  readonly maxCompressedBytes: number;
  /** Total bytes produced by decompression across the whole archive. */
  readonly maxDecompressedBytes: number;
  /** Bytes produced by decompression for any single archive entry. */
  readonly maxFileBytes: number;
  /** Number of archive entries considered, including ones we skip. */
  readonly maxFileCount: number;
  /** Length of a single archive entry name, before component stripping. */
  readonly maxPathLength: number;
  /**
   * Maximum decompressed:compressed ratio. gzip tops out around 1030:1 on
   * pathological input, so anything above ~100:1 is either a bomb or a file
   * so redundant that we lose nothing by refusing it.
   */
  readonly maxCompressionRatio: number;
  /**
   * Decompressed bytes that must be produced before the ratio is enforced.
   * Small archives have a compression ratio dominated by gzip framing noise,
   * so checking the ratio immediately would reject legitimate tiny packages.
   */
  readonly ratioCheckAfterBytes: number;
  /** Wall-clock budget for a single extraction. */
  readonly extractionTimeoutMs: number;
  /** Wall-clock budget for a single tarball download. */
  readonly downloadTimeoutMs: number;
  /**
   * Total decompressed bytes held in memory and handed to the analyser.
   * Files beyond this are still listed, sized and hashed — only their content
   * is dropped, and the result records that this happened.
   */
  readonly maxRetainedContentBytes: number;
  /** Content of any single file held in memory for the analyser. */
  readonly maxRetainedFileBytes: number;
}

const MIB = 1024 * 1024;

export const DEFAULT_ARTIFACT_LIMITS: ArtifactLimits = {
  maxCompressedBytes: 64 * MIB,
  maxDecompressedBytes: 256 * MIB,
  maxFileBytes: 32 * MIB,
  maxFileCount: 20_000,
  maxPathLength: 1024,
  maxCompressionRatio: 100,
  ratioCheckAfterBytes: 1 * MIB,
  extractionTimeoutMs: 60_000,
  downloadTimeoutMs: 30_000,
  maxRetainedContentBytes: 32 * MIB,
  maxRetainedFileBytes: 4 * MIB,
};

/**
 * Merge caller overrides over the defaults.
 *
 * Overrides are clamped to positive integers so a mis-plumbed configuration
 * value cannot silently disable a limit. A limit of zero or a negative limit
 * would mean "unbounded" in most naive implementations; here it is rejected.
 */
export function resolveLimits(overrides: Partial<ArtifactLimits> = {}): ArtifactLimits {
  const merged: ArtifactLimits = { ...DEFAULT_ARTIFACT_LIMITS, ...overrides };
  for (const [key, value] of Object.entries(merged)) {
    if (!Number.isFinite(value) || value <= 0) {
      throw new RangeError(`Artifact limit "${key}" must be a positive finite number`);
    }
  }
  return merged;
}
