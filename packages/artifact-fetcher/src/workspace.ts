import { chmod, mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ScanError } from "@packagegate/shared";

/**
 * Temporary extraction workspaces.
 *
 * The only supported way to obtain one is {@link withTemporaryDirectory},
 * which owns both ends of its lifetime. There is no `createWorkspace()` that
 * hands a caller a directory and trusts them to remember: an extraction that
 * aborts on a limit, a traversal attempt, a timeout or a parser crash is the
 * *expected* case here, not the exception, and every one of those paths must
 * delete the directory. A scoped API is the only shape that makes forgetting
 * impossible.
 */

/** Prefix for our directories, so a stray one is attributable during triage. */
const WORKSPACE_PREFIX = "packagegate-artifact-";

/** Owner-only. Nothing else on the host has any business reading a hostile artifact. */
const WORKSPACE_MODE = 0o700;

/**
 * Run `use` against a fresh, private temporary directory and remove the
 * directory afterwards — on success, on a thrown error, on a limit abort and
 * on a timeout alike.
 *
 * The directory handed to `use` is `realpath`-resolved. Every traversal check
 * in this package compares against it, and on a host where `os.tmpdir()` is a
 * symlink an unresolved root would make every legitimate entry look like an
 * escape.
 *
 * If removal fails, the failure is reported *only* when `use` itself
 * succeeded. Masking a real extraction failure with a cleanup failure would
 * lose the finding that matters, and a leaked directory is the lesser harm.
 */
export async function withTemporaryDirectory<T>(
  use: (directory: string) => Promise<T>,
): Promise<T> {
  // `mkdtemp` is specified to create with mode 0700, which is also the only
  // reason it is safe to use a predictable prefix inside a world-writable
  // directory. The `chmod` restates that guarantee rather than inheriting a
  // platform default we did not choose.
  const created = await mkdtemp(join(tmpdir(), WORKSPACE_PREFIX));
  await chmod(created, WORKSPACE_MODE);
  const root = await realpath(created);

  let result: T;
  try {
    result = await use(root);
  } catch (error) {
    await removeQuietly(created);
    throw error;
  }

  await remove(created);
  return result;
}

/** Remove the workspace, reporting failure without ever naming the path. */
async function remove(directory: string): Promise<void> {
  try {
    await rm(directory, { recursive: true, force: true, maxRetries: 3 });
  } catch (error) {
    throw new ScanError("INTERNAL", "Failed to remove the temporary extraction directory", {
      details: { code: errorCode(error) ?? "UNKNOWN" },
    });
  }
}

/**
 * Removal on the failure path. The extraction error is the one the analyst
 * needs, so a cleanup failure is swallowed here — but explicitly, in a
 * function whose name says so, rather than by an empty `catch`.
 */
async function removeQuietly(directory: string): Promise<void> {
  try {
    await rm(directory, { recursive: true, force: true, maxRetries: 3 });
  } catch {
    // Intentionally not rethrown: see the doc comment above. The primary
    // failure is already propagating and must not be replaced.
  }
}

/** Extract an errno-style code without letting the error's path text escape. */
function errorCode(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  const code: unknown = (error as { code?: unknown }).code;
  return typeof code === "string" ? code : undefined;
}
