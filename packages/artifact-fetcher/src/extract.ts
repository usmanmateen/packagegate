import { createHash } from "node:crypto";
import { mkdir, open, realpath } from "node:fs/promises";
import { dirname } from "node:path";
import { Readable, Transform, type TransformCallback } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createGunzip } from "node:zlib";
import { extract as tarExtract } from "tar-stream";
import type { Entry as TarEntry, Headers as TarHeaders } from "tar-stream";
import { LimitExceededError, ScanError, sanitiseInlineValue } from "@packagegate/shared";
import type { ArtifactLimits } from "./limits.js";
import {
  assertRealPathWithinRoot,
  classifyEntryPath,
  resolveWithinRoot,
  type EntrySkipReason,
  type SkippedEntry,
} from "./paths.js";

/**
 * Secure extraction of an attacker-controlled gzip tarball.
 *
 * The design rule for this file is that **every entry decision is explicit**.
 * There is no "extract the archive" call that decides things on our behalf,
 * because the interesting failures in this space are all cases where a library
 * made a reasonable-looking decision for a hostile entry: node-tar's directory
 * cache turning a symlink into a write primitive (CVE-2021-32803), its
 * unbounded decompression (CVE-2026-59873), its PAX size desynchronisation
 * (CVE-2026-53655). We use `tar-stream` purely as a *header parser* and take
 * responsibility for every filesystem effect ourselves.
 *
 * What this module will do to disk: create directories, and create regular
 * files with `O_EXCL`, mode 0600, inside one root. That is the complete list.
 * There is no `symlink`, `link`, `mknod`, `chmod` or `chown` call anywhere in
 * this package, which is what makes T-EXT-03, T-EXT-04 and T-EXT-10 structural
 * rather than a check that could be bypassed.
 */

/** Files are created owner-read/write. The archive's own mode is never honoured. */
const FILE_MODE = 0o600;
/** Directories are owner-only, so a partially extracted tree is never traversable. */
const DIRECTORY_MODE = 0o700;
/** Bytes fed to the decompressor per write, so the ratio meter tracks real consumption. */
const SOURCE_CHUNK_BYTES = 64 * 1024;
/** Cap on how much of a hostile entry name is echoed into a skip record. */
const SKIP_PATH_LIMIT = 256;

export interface ExtractedFile {
  /** Package-relative POSIX path, after the archive's leading component is stripped. */
  readonly path: string;
  readonly sizeBytes: number;
  /** SHA-256 of the file's bytes, computed whether or not the content is retained. */
  readonly sha256: string;
  /**
   * File bytes, for an analyser that performs no I/O of its own.
   *
   * Absent when the retention budget was exhausted. Absence means "we chose
   * not to hold this in memory", never "this file was empty" — a zero-byte
   * file has a zero-length `content`.
   */
  readonly content?: Buffer;
}

export interface ContentRetention {
  readonly retainedBytes: number;
  /** Files listed and hashed, whose content was dropped to stay in budget. */
  readonly droppedFileCount: number;
  /** True when any content was dropped. Analysis coverage is reduced (R-ANL-05). */
  readonly truncated: boolean;
}

export interface ExtractionResult {
  readonly files: readonly ExtractedFile[];
  readonly skippedEntries: readonly SkippedEntry[];
  /** Bytes written to disk across all regular files. */
  readonly extractedSizeBytes: number;
  /** Regular files written. */
  readonly fileCount: number;
  /** Archive entries considered, including directories and skipped entries. */
  readonly entryCount: number;
  readonly retention: ContentRetention;
}

/**
 * Extract `tarball` into `destinationRoot`, which must already exist.
 *
 * The caller owns the directory's lifetime; use {@link withTemporaryDirectory}
 * rather than calling this with a long-lived path.
 *
 * @throws {ScanError} `MALFORMED_ARCHIVE` for anything the gzip or tar parser
 * rejects, `LIMIT_EXCEEDED` for any budget, `TRAVERSAL_BLOCKED` for an entry
 * that tried to escape, `TIMEOUT` for the wall-clock budget. Never an
 * unhandled rejection, and never a partially-reported success.
 */
export async function extractTarball(
  tarball: Uint8Array,
  destinationRoot: string,
  limits: ArtifactLimits,
): Promise<ExtractionResult> {
  if (tarball.byteLength === 0) {
    throw new ScanError("MALFORMED_ARCHIVE", "Tarball is empty", { details: { reason: "empty" } });
  }
  if (tarball.byteLength > limits.maxCompressedBytes) {
    throw new LimitExceededError("compressedBytes", limits.maxCompressedBytes, tarball.byteLength);
  }

  const realRoot = await realpath(destinationRoot);
  const state = new ExtractionState(realRoot, limits);
  return await state.run(tarball);
}

/**
 * All mutable extraction state, kept in one object so the abort path has a
 * single place to look for "why did we stop".
 */
class ExtractionState {
  readonly #root: string;
  readonly #limits: ArtifactLimits;

  readonly #files: ExtractedFile[] = [];
  readonly #skipped: SkippedEntry[] = [];
  /** Absolute directory path → its verified real path. */
  readonly #directories = new Map<string, string>();

  #entryCount = 0;
  #extractedSizeBytes = 0;
  #retainedBytes = 0;
  #droppedFileCount = 0;

  #compressedSeen = 0;
  #decompressedSeen = 0;

  /**
   * The reason *we* stopped, as opposed to whatever stream error surfaced
   * first once the pipeline unwound. Recorded eagerly and preferred over
   * anything else, so a limit abort reports `LIMIT_EXCEEDED` rather than the
   * `ERR_STREAM_PREMATURE_CLOSE` it causes a moment later.
   */
  #abortReason: ScanError | undefined;

  constructor(root: string, limits: ArtifactLimits) {
    this.#root = root;
    this.#limits = limits;
  }

  async run(tarball: Uint8Array): Promise<ExtractionResult> {
    const controller = new AbortController();
    const timer = setTimeout(() => {
      this.#record(
        new ScanError("TIMEOUT", "Artifact extraction exceeded its time budget", {
          details: { limitMs: this.#limits.extractionTimeoutMs },
        }),
      );
      controller.abort();
    }, this.#limits.extractionTimeoutMs);
    timer.unref();

    const source = Readable.from(chunked(tarball), { objectMode: false });
    const consumption = new StreamMeter((byteLength) => this.#onCompressed(byteLength));
    const gunzip = createGunzip();
    const decompression = new StreamMeter((byteLength) => this.#onDecompressed(byteLength));
    const archive = tarExtract();

    // The pipeline's rejection is captured rather than awaited directly: when
    // we abort mid-archive the pipeline *will* reject, and that rejection must
    // not become an unhandled one while we are still unwinding the entry loop.
    let pipelineError: unknown;
    const pumped = pipeline(source, consumption, gunzip, decompression, archive, {
      signal: controller.signal,
    }).then(
      () => undefined,
      (error: unknown) => {
        pipelineError = error;
      },
    );

    try {
      for await (const entry of archive) {
        await this.#handleEntry(entry);
      }
      await pumped;
      if (this.#abortReason !== undefined) throw this.#abortReason;
      if (pipelineError !== undefined) throw classifyStreamError(pipelineError);
    } catch (error) {
      controller.abort();
      await pumped;
      throw this.#abortReason ?? classifyStreamError(error);
    } finally {
      clearTimeout(timer);
    }

    return {
      files: this.#files,
      skippedEntries: this.#skipped,
      extractedSizeBytes: this.#extractedSizeBytes,
      fileCount: this.#files.length,
      entryCount: this.#entryCount,
      retention: {
        retainedBytes: this.#retainedBytes,
        droppedFileCount: this.#droppedFileCount,
        truncated: this.#droppedFileCount > 0,
      },
    };
  }

  /** Remember the first reason we aborted and hand it back for throwing. */
  #record(error: ScanError): ScanError {
    this.#abortReason ??= error;
    return this.#abortReason;
  }

  #fail(error: ScanError): never {
    throw this.#record(error);
  }

  #onCompressed(byteLength: number): ScanError | undefined {
    this.#compressedSeen += byteLength;
    return undefined;
  }

  /**
   * The bomb defence (T-EXT-05), applied to the decompressor's *output* before
   * the tar parser or the filesystem ever sees it.
   *
   * Two independent bounds, because either alone is escapable: an absolute
   * ceiling stops a large archive that expands modestly, and a ratio stops a
   * tiny archive that expands catastrophically long before it reaches the
   * ceiling. The ratio is only applied once enough output exists for it to
   * mean something — on the first few kilobytes it measures gzip framing
   * overhead, not the archive.
   */
  #onDecompressed(byteLength: number): ScanError | undefined {
    this.#decompressedSeen += byteLength;

    if (this.#decompressedSeen > this.#limits.maxDecompressedBytes) {
      return this.#record(
        new LimitExceededError(
          "decompressedBytes",
          this.#limits.maxDecompressedBytes,
          this.#decompressedSeen,
        ),
      );
    }

    if (this.#decompressedSeen >= this.#limits.ratioCheckAfterBytes) {
      const consumed = Math.max(this.#compressedSeen, 1);
      const budget = consumed * this.#limits.maxCompressionRatio;
      if (this.#decompressedSeen > budget) {
        return this.#record(
          new LimitExceededError(
            "compressionRatio",
            this.#limits.maxCompressionRatio,
            Math.round(this.#decompressedSeen / consumed),
          ),
        );
      }
    }

    return undefined;
  }

  async #handleEntry(entry: TarEntry): Promise<void> {
    this.#entryCount += 1;
    if (this.#entryCount > this.#limits.maxFileCount) {
      this.#fail(
        new LimitExceededError("fileCount", this.#limits.maxFileCount, this.#entryCount),
      );
    }

    const rawName = entry.header.name;
    // Throws for anything hostile. Deliberately evaluated before the entry
    // type is consulted: an escape attempt is a finding about the archive
    // regardless of what kind of thing it claimed to be.
    const decision = classifyEntryPath(rawName, this.#limits.maxPathLength);

    if (decision.kind === "package-root") {
      await drain(entry);
      return;
    }
    if (decision.kind === "skip") {
      this.#skip(rawName, decision.reason);
      await drain(entry);
      return;
    }

    // Second, independent traversal check against the resolved path. After the
    // string rules above this should be unreachable, which is exactly why it
    // is here.
    const target = resolveWithinRoot(this.#root, decision.relativePath, rawName);
    const type = entry.header.type ?? undefined;

    if (type === "directory") {
      const created = await this.#ensureDirectory(target, rawName);
      if (!created) this.#skip(rawName, "parent-not-a-directory");
      await drain(entry);
      return;
    }

    if (type !== "file" && type !== "contiguous-file") {
      this.#skip(rawName, skipReasonForType(type));
      await drain(entry);
      return;
    }

    await this.#writeFile(entry, target, decision.relativePath, rawName);
  }

  #skip(rawName: string, reason: EntrySkipReason): void {
    this.#skipped.push({ path: sanitiseInlineValue(rawName, SKIP_PATH_LIMIT), reason });
  }

  /**
   * Create a directory and prove the operating system agrees it is inside the
   * root.
   *
   * The `realpath` call is the part that matters. String resolution says where
   * the path *should* land; `realpath` says where the kernel would actually
   * write. They diverge whenever a component is a symlink — which is precisely
   * the node-tar CVE-2021-32803 shape, and the reason a string check alone is
   * not a control.
   *
   * @returns false when a component already exists as a regular file.
   */
  async #ensureDirectory(absolutePath: string, rawName: string): Promise<boolean> {
    if (this.#directories.has(absolutePath)) return true;

    try {
      await mkdir(absolutePath, { recursive: true, mode: DIRECTORY_MODE });
    } catch (error) {
      const code = errorCode(error);
      if (code === "EEXIST" || code === "ENOTDIR") return false;
      throw new ScanError("INTERNAL", "Failed to create an extraction directory", {
        details: { code: code ?? "UNKNOWN" },
      });
    }

    const resolved = await realpath(absolutePath);
    assertRealPathWithinRoot(this.#root, resolved, rawName);
    this.#directories.set(absolutePath, resolved);
    return true;
  }

  async #writeFile(
    entry: TarEntry,
    target: string,
    relativePath: string,
    rawName: string,
  ): Promise<void> {
    const parent = dirname(target);
    if (!(await this.#ensureDirectory(parent, rawName))) {
      this.#skip(rawName, "parent-not-a-directory");
      await drain(entry);
      return;
    }

    // `wx` is O_CREAT|O_EXCL: it refuses to follow an existing symlink and
    // refuses to overwrite an earlier entry. That makes both the link-escape
    // and the case/Unicode-collision families (T-EXT-03, T-EXT-09) fail at the
    // syscall rather than depending on our bookkeeping being complete.
    let handle;
    try {
      handle = await open(target, "wx", FILE_MODE);
    } catch (error) {
      const code = errorCode(error);
      if (code === "EEXIST") {
        this.#skip(rawName, "duplicate-path");
        await drain(entry);
        return;
      }
      if (code === "ENOTDIR" || code === "EISDIR") {
        this.#skip(rawName, "parent-not-a-directory");
        await drain(entry);
        return;
      }
      throw new ScanError("INTERNAL", "Failed to create an extracted file", {
        details: { code: code ?? "UNKNOWN" },
      });
    }

    const hash = createHash("sha256");
    let sizeBytes = 0;
    // `undefined` once the retention budget has ruled this file out.
    let retained: Buffer[] | undefined = [];
    let retainedForFile = 0;

    try {
      for await (const chunk of entry) {
        sizeBytes += chunk.byteLength;
        // Enforced against bytes actually produced, not against the header's
        // declared size, because the header is attacker-supplied and PAX
        // overrides make it a poor source of truth (T-EXT-08).
        if (sizeBytes > this.#limits.maxFileBytes) {
          this.#fail(new LimitExceededError("fileBytes", this.#limits.maxFileBytes, sizeBytes));
        }
        hash.update(chunk);
        await handle.write(chunk);

        if (retained !== undefined) {
          const perFileExceeded =
            retainedForFile + chunk.byteLength > this.#limits.maxRetainedFileBytes;
          const totalExceeded =
            this.#retainedBytes + retainedForFile + chunk.byteLength >
            this.#limits.maxRetainedContentBytes;
          if (perFileExceeded || totalExceeded) {
            retained = undefined;
            retainedForFile = 0;
          } else {
            retained.push(chunk);
            retainedForFile += chunk.byteLength;
          }
        }
      }
    } finally {
      await handle.close();
    }

    this.#extractedSizeBytes += sizeBytes;

    if (retained === undefined) {
      this.#droppedFileCount += 1;
      this.#files.push({ path: relativePath, sizeBytes, sha256: hash.digest("hex") });
      return;
    }

    this.#retainedBytes += retainedForFile;
    this.#files.push({
      path: relativePath,
      sizeBytes,
      sha256: hash.digest("hex"),
      content: Buffer.concat(retained),
    });
  }
}

/**
 * A pass-through that measures the stream and can stop it.
 *
 * Limits belong here rather than after the fact: by the time a fully
 * decompressed archive can be measured, the disk is already full. Returning an
 * error from the callback destroys the pipeline with that error, so the
 * decompressor stops producing rather than merely being ignored.
 */
class StreamMeter extends Transform {
  readonly #onChunk: (byteLength: number) => ScanError | undefined;

  constructor(onChunk: (byteLength: number) => ScanError | undefined) {
    super();
    this.#onChunk = onChunk;
  }

  override _transform(
    chunk: Buffer,
    _encoding: BufferEncoding,
    callback: TransformCallback,
  ): void {
    const failure = this.#onChunk(chunk.byteLength);
    if (failure !== undefined) {
      callback(failure);
      return;
    }
    callback(null, chunk);
  }
}

/**
 * Feed the compressed bytes in bounded slices.
 *
 * Writing the whole buffer in one go would make the compression-ratio meter
 * see the entire compressed size before the first byte of output, so a bomb
 * would be measured against its final ratio instead of its running one.
 */
function* chunked(bytes: Uint8Array): Generator<Buffer> {
  for (let offset = 0; offset < bytes.byteLength; offset += SOURCE_CHUNK_BYTES) {
    const length = Math.min(SOURCE_CHUNK_BYTES, bytes.byteLength - offset);
    yield Buffer.from(bytes.buffer, bytes.byteOffset + offset, length);
  }
}

/**
 * Consume an entry we are not writing.
 *
 * Not optional: `tar-stream` reads the archive as one stream, so an
 * unconsumed entry body stalls every entry after it. Skipping an entry means
 * discarding its bytes, not ignoring them.
 */
async function drain(entry: TarEntry): Promise<void> {
  for await (const _chunk of entry) {
    // Discarded deliberately — see above.
  }
}

function skipReasonForType(type: TarHeaders["type"] | undefined): EntrySkipReason {
  switch (type) {
    case "symlink":
      return "symlink";
    case "link":
      return "hardlink";
    case "character-device":
    case "block-device":
    case "fifo":
      return "device-or-fifo";
    default:
      return "unsupported-entry-type";
  }
}

/**
 * Turn a stream failure into a structured result.
 *
 * Everything in this pipeline other than our own guards is either zlib or the
 * tar header parser, and both only fail on input they cannot make sense of, so
 * an unrecognised failure is reported as a malformed archive rather than as an
 * internal fault. Getting this backwards would file "this package is corrupt"
 * as "PackageGate is broken" and see it retried forever.
 */
function classifyStreamError(error: unknown): ScanError {
  if (error instanceof ScanError) return error;

  const code = errorCode(error);
  if (code === "ABORT_ERR" || (error instanceof Error && error.name === "AbortError")) {
    return new ScanError("TIMEOUT", "Artifact extraction was aborted", {
      details: { reason: "aborted" },
    });
  }

  // Filesystem faults are ours, not the package's.
  if (code !== undefined && FILESYSTEM_ERROR_CODES.has(code)) {
    return new ScanError("INTERNAL", "Extraction failed while writing to the workspace", {
      details: { code },
    });
  }

  const reason = error instanceof Error ? sanitiseInlineValue(error.message, 120) : "unknown";
  return new ScanError("MALFORMED_ARCHIVE", "Archive could not be read as a gzip tarball", {
    details: { reason, ...(code === undefined ? {} : { code }) },
  });
}

const FILESYSTEM_ERROR_CODES = new Set([
  "EACCES",
  "EBADF",
  "EDQUOT",
  "EEXIST",
  "EISDIR",
  "ELOOP",
  "EMFILE",
  "ENFILE",
  "ENOENT",
  "ENOSPC",
  "ENOTDIR",
  "EPERM",
  "EROFS",
]);

/** Read an errno-style code without letting the error's own path text escape. */
function errorCode(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  const code: unknown = (error as { code?: unknown }).code;
  return typeof code === "string" ? code : undefined;
}
