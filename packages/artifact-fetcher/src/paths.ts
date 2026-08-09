import { resolve, sep } from "node:path";
import {
  LimitExceededError,
  TraversalBlockedError,
  sanitiseInlineValue,
} from "@packagegate/shared";

/**
 * Archive entry name handling — the part of extraction that gets people owned.
 *
 * Zip-slip (T-EXT-01), absolute and drive-relative paths (T-EXT-02) and the
 * component-stripping abuse that npm tarballs invite are all decided here, in
 * one place, before a single byte reaches the filesystem.
 *
 * Two rules govern everything below:
 *
 *  1. **Validate the name the archive actually declared, then strip.** npm
 *     tarballs prefix every entry with `package/`, so a naive extractor strips
 *     one component and validates the remainder. That is exactly backwards:
 *     `../etc/cron.d/x` strips to `etc/cron.d/x`, which passes every check
 *     while the archive plainly asked to escape. We validate first.
 *  2. **String checks are necessary but never sufficient.** Every accepted
 *     path is additionally resolved and compared against the real extraction
 *     root by {@link resolveWithinRoot}. The string rules exist to produce a
 *     precise, attributable error; the resolved-path check exists because the
 *     string rules might one day be wrong.
 *
 * Hostile names throw. Merely *unsupported* names are skipped and recorded, so
 * a weird-but-benign package still gets scanned rather than failing the whole
 * investigation.
 */

/**
 * Why an entry was recorded in `ArtifactInfo.skippedEntries`.
 *
 * These strings reach the database and the analyst UI, so they are a stable
 * part of the API and are deliberately machine-readable.
 */
export const ENTRY_SKIP_REASONS = [
  /** A symbolic link. Never created; the escape vector behind CVE-2021-32803. */
  "symlink",
  /** A hard link. Never created; bypasses symlink-specific checks (T-EXT-04). */
  "hardlink",
  /** Character device, block device or FIFO — never materialised (T-EXT-10). */
  "device-or-fifo",
  /** A tar type flag we do not handle. Skipped rather than guessed at. */
  "unsupported-entry-type",
  /** Name contained a backslash, which is a separator on the other OS family. */
  "windows-path-separator",
  /** Name contained control characters — a log-injection vector (T-LOG-02). */
  "control-character-in-path",
  /** Nothing remained after stripping the archive's leading component. */
  "outside-package-root",
  /** A second entry resolved to a path an earlier entry already produced. */
  "duplicate-path",
  /** A parent component already exists as a regular file. */
  "parent-not-a-directory",
] as const;
export type EntrySkipReason = (typeof ENTRY_SKIP_REASONS)[number];

export interface SkippedEntry {
  /** Sanitised for display; never the raw archive bytes. */
  readonly path: string;
  readonly reason: EntrySkipReason;
}

export type EntryPathDecision =
  /** The archive's own root directory (`package/`). Not an escape, not a file. */
  | { readonly kind: "package-root" }
  | { readonly kind: "accept"; readonly relativePath: string }
  | { readonly kind: "skip"; readonly reason: EntrySkipReason };

/** Cap on how much of a hostile name we echo back into an error field. */
const ERROR_PATH_LIMIT = 200;

/** Windows drive prefix (`C:`), checked before any separator normalisation. */
const DRIVE_PREFIX = /^[A-Za-z]:/;

/**
 * True when the name carries characters that must never reach a log line, a
 * terminal, a filename or a JSON log field.
 *
 * A linear character scan rather than a regex, deliberately: R-LOG-01 requires
 * the sanctioned control-character path to be O(n), because the canonical
 * ReDoS demonstration (`ansi-regex`, CVE-2021-3807) was a regex written to
 * strip exactly these characters.
 */
function hasControlCharacters(name: string): boolean {
  for (let index = 0; index < name.length; index += 1) {
    const code = name.charCodeAt(index);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

/**
 * Split on `/`, dropping empty and `.` components.
 *
 * Dropping `.` *before* stripping matters: `./package/x.js` would otherwise
 * lose its `.` to the strip and keep the `package/` prefix, silently writing a
 * `package/` directory inside the extraction root and mis-reporting every path
 * in the scan.
 */
function splitComponents(name: string): string[] {
  const components: string[] = [];
  for (const component of name.split("/")) {
    if (component.length === 0 || component === ".") continue;
    components.push(component);
  }
  return components;
}

/**
 * Decide what to do with one archive entry name.
 *
 * @param rawName the entry name exactly as the archive declared it
 * @param maxPathLength budget from {@link ArtifactLimits.maxPathLength}
 * @throws {TraversalBlockedError} for a name that attempts to escape the root
 * @throws {LimitExceededError} for a name longer than the path budget
 */
export function classifyEntryPath(
  rawName: string,
  maxPathLength: number,
): EntryPathDecision {
  // Checked before anything else: a NUL byte makes every downstream consumer
  // disagree about where the name ends, which is the whole point of putting
  // one there (T-LOG-01, node-tar CVE-2026-59875).
  if (rawName.includes("\0")) {
    throw new TraversalBlockedError(sanitiseInlineValue(rawName, ERROR_PATH_LIMIT));
  }

  // Length is checked on the declared name, before stripping, so that a long
  // name cannot be smuggled past the budget by hiding behind a prefix.
  if (rawName.length > maxPathLength) {
    throw new LimitExceededError("pathLength", maxPathLength, rawName.length);
  }

  if (rawName.length === 0) {
    return { kind: "skip", reason: "outside-package-root" };
  }

  // Both separators are considered when looking for traversal, because a name
  // that is harmless on Linux (`..\..\x`) is an escape on Windows and we must
  // not depend on the extracting host to be the safe one.
  const unified = rawName.replaceAll("\\", "/");

  if (
    unified.startsWith("/") ||
    DRIVE_PREFIX.test(rawName) ||
    rawName.startsWith("\\\\")
  ) {
    throw new TraversalBlockedError(sanitiseInlineValue(rawName, ERROR_PATH_LIMIT));
  }

  const declared = splitComponents(unified);
  for (const component of declared) {
    if (component === "..") {
      throw new TraversalBlockedError(sanitiseInlineValue(rawName, ERROR_PATH_LIMIT));
    }
  }

  // Not an escape on this host, but not something a real npm package contains
  // either. Recorded rather than written, so the archive's intent survives.
  if (rawName.includes("\\")) {
    return { kind: "skip", reason: "windows-path-separator" };
  }
  if (hasControlCharacters(rawName)) {
    return { kind: "skip", reason: "control-character-in-path" };
  }

  // Strip exactly one leading component. Safe only because `..` has already
  // been rejected across the whole declared name.
  const stripped = declared.slice(1);
  if (stripped.length === 0) {
    // `package/` itself. A trailing separator means the archive described the
    // root directory, which already exists; anything else was a top-level
    // entry sitting outside the package root and is not ours to write.
    return unified.endsWith("/")
      ? { kind: "package-root" }
      : { kind: "skip", reason: "outside-package-root" };
  }

  return { kind: "accept", relativePath: stripped.join("/") };
}

/**
 * Resolve a validated relative path against the extraction root and prove the
 * result is still inside it.
 *
 * `realRoot` must already be a `realpath`-resolved directory: on hosts where
 * `os.tmpdir()` is itself a symlink (macOS `/tmp` → `/private/tmp`), comparing
 * against the unresolved root makes every legitimate path look like an escape.
 *
 * @throws {TraversalBlockedError} if the resolved path is not a strict
 * descendant of the root.
 */
export function resolveWithinRoot(
  realRoot: string,
  relativePath: string,
  rawName: string,
): string {
  const resolved = resolve(realRoot, relativePath);
  const isInside = resolved === realRoot || resolved.startsWith(realRoot + sep);
  if (!isInside) {
    throw new TraversalBlockedError(sanitiseInlineValue(rawName, ERROR_PATH_LIMIT));
  }
  return resolved;
}

/**
 * Confirm a path the operating system resolved for us is still inside the
 * root — used on directories after they have been created, because between
 * our check and our write the filesystem is a shared, mutable resource.
 */
export function assertRealPathWithinRoot(
  realRoot: string,
  realPath: string,
  rawName: string,
): void {
  if (realPath !== realRoot && !realPath.startsWith(realRoot + sep)) {
    throw new TraversalBlockedError(sanitiseInlineValue(rawName, ERROR_PATH_LIMIT));
  }
}
