import { open, stat } from "node:fs/promises";
import { basename, extname, resolve } from "node:path";
import { ScanError, sanitiseInlineValue } from "@packagegate/shared";

export interface LocalArtifactPath {
  /** Absolute resolved path used for reading. Never logged into evidence. */
  readonly absolutePath: string;
  /** Caller-facing path for reports (original input, sanitised for length). */
  readonly displayPath: string;
  readonly fileName: string;
}

function hasSupportedExtension(fileName: string): boolean {
  const lower = fileName.toLowerCase();
  return lower.endsWith(".tgz") || lower.endsWith(".tar.gz");
}

/**
 * Validate a caller-supplied local tarball path before any extraction.
 *
 * Rejects missing paths, directories, and unsupported extensions. The path is
 * resolved to absolute form; existence is checked with `stat` so a symlink to
 * a regular file is accepted, while a directory link is rejected.
 */
export async function resolveLocalArtifactPath(
  inputPath: string,
): Promise<LocalArtifactPath> {
  if (typeof inputPath !== "string" || inputPath.trim().length === 0) {
    throw new ScanError("LOCAL_ARTIFACT_NOT_FOUND", "Local artifact path is required");
  }

  const displayPath = sanitiseInlineValue(inputPath.trim(), 512);
  const absolutePath = resolve(inputPath.trim());
  const fileName = basename(absolutePath);

  let info;
  try {
    info = await stat(absolutePath);
  } catch (error) {
    const code =
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      typeof error.code === "string"
        ? error.code
        : undefined;
    if (code === "ENOENT") {
      throw new ScanError(
        "LOCAL_ARTIFACT_NOT_FOUND",
        "Local artifact path does not exist",
        {
          details: { fileName: sanitiseInlineValue(fileName, 214) },
        },
      );
    }
    throw new ScanError(
      "LOCAL_ARTIFACT_NOT_FOUND",
      "Local artifact path could not be read",
      {
        details: {
          fileName: sanitiseInlineValue(fileName, 214),
          ...(code === undefined ? {} : { code }),
        },
      },
    );
  }

  if (!info.isFile()) {
    throw new ScanError(
      "LOCAL_ARTIFACT_NOT_FILE",
      "Local artifact path must be a regular file",
      {
        details: { fileName: sanitiseInlineValue(fileName, 214) },
      },
    );
  }

  if (!hasSupportedExtension(fileName)) {
    throw new ScanError(
      "UNSUPPORTED_ARTIFACT_FORMAT",
      "Local artifact must be an npm package tarball (.tgz or .tar.gz)",
      {
        details: {
          extension: sanitiseInlineValue(extname(fileName) || "(none)", 32),
          fileName: sanitiseInlineValue(fileName, 214),
        },
      },
    );
  }

  return { absolutePath, displayPath, fileName };
}

/**
 * Read the validated local artifact bytes. Caller must have validated the path.
 */
export async function readLocalArtifactBytes(absolutePath: string): Promise<Buffer> {
  const handle = await open(absolutePath, "r");
  try {
    const info = await handle.stat();
    if (!info.isFile()) {
      throw new ScanError(
        "LOCAL_ARTIFACT_NOT_FILE",
        "Local artifact path must be a regular file",
      );
    }
    return await handle.readFile();
  } finally {
    await handle.close();
  }
}

/** Validate a caller-supplied hex SHA-256 digest. */
export function parseExpectedSha256(value: string): string {
  const trimmed = value.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(trimmed)) {
    throw new ScanError(
      "INVALID_SPEC",
      "Expected SHA-256 digest must be 64 hexadecimal characters",
      {
        details: { length: trimmed.length },
      },
    );
  }
  return trimmed;
}
