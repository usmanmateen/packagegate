import { createHash } from "node:crypto";
import {
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  LimitExceededError,
  ScanError,
  TraversalBlockedError,
} from "@packagegate/shared";
import { extractTarball } from "./extract.js";
import { resolveLimits, type ArtifactLimits } from "./limits.js";
import {
  buildBomb,
  buildNpmTarball,
  buildTar,
  buildTarball,
} from "./testing/tarballs.js";

/**
 * Extraction is tested against archives built to attack it, and every result
 * is checked against the *real filesystem* rather than against the return
 * value alone. A traversal defence that reports "blocked" while the file sits
 * in `/tmp` has failed, and only `lstat` can tell us which happened.
 *
 * The extraction root here is a subdirectory of a test-owned parent, so an
 * escape of one level lands somewhere observable. `withExtractedTarball` owns
 * its own directory and deletes it on failure, which would destroy the
 * evidence these tests exist to collect, so they call `extractTarball`
 * directly; cleanup itself is covered in `index.test.ts`.
 */

let parent: string;
let root: string;

beforeEach(async () => {
  parent = await mkdtemp(join(tmpdir(), "packagegate-extract-test-"));
  root = join(parent, "root");
  await mkdir(root, { mode: 0o700 });
});

afterEach(async () => {
  await rm(parent, { recursive: true, force: true });
});

function limits(overrides: Partial<ArtifactLimits> = {}): ArtifactLimits {
  return resolveLimits(overrides);
}

/** Every path under `dir`, relative and sorted, including directories. */
async function tree(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true, recursive: true });
  return entries
    .map((entry) => join(entry.parentPath, entry.name).slice(dir.length + 1))
    .sort();
}

async function treeBytes(dir: string): Promise<number> {
  const entries = await readdir(dir, { withFileTypes: true, recursive: true });
  let total = 0;
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    total += (await stat(join(entry.parentPath, entry.name))).size;
  }
  return total;
}

async function expectScanError(
  promise: Promise<unknown>,
  code: string,
): Promise<ScanError> {
  try {
    await promise;
    expect.unreachable(`expected a ${code} ScanError`);
  } catch (error) {
    expect(error).toBeInstanceOf(ScanError);
    expect((error as ScanError).code).toBe(code);
    return error as ScanError;
  }
}

describe("a well-formed npm tarball", () => {
  it("extracts with the `package/` prefix stripped", async () => {
    const tarball = await buildNpmTarball({
      "package.json": '{"name":"demo","version":"1.0.0"}',
      "index.js": "module.exports = 1;\n",
      "lib/deep/util.js": "export const x = 2;\n",
    });

    const result = await extractTarball(tarball, root, limits());

    expect(result.files.map((file) => file.path).sort()).toEqual([
      "index.js",
      "lib/deep/util.js",
      "package.json",
    ]);
    expect(result.fileCount).toBe(3);
    expect(result.skippedEntries).toEqual([]);
    expect(await tree(root)).toEqual([
      "index.js",
      "lib",
      "lib/deep",
      "lib/deep/util.js",
      "package.json",
    ]);
  });

  it("reports sizes, hashes and contents that match the bytes on disk", async () => {
    const source = "module.exports = 1;\n";
    const tarball = await buildNpmTarball({ "index.js": source });

    const result = await extractTarball(tarball, root, limits());
    const file = result.files[0];

    expect(file).toBeDefined();
    expect(file?.sizeBytes).toBe(Buffer.byteLength(source));
    expect(file?.sha256).toBe(createHash("sha256").update(source).digest("hex"));
    expect(file?.content?.toString("utf8")).toBe(source);
    expect(await readFile(join(root, "index.js"), "utf8")).toBe(source);
  });

  it("writes files owner-only and never honours the archive's mode", async () => {
    // A setuid bit in the archive is a request we decline (T-EXT-10).
    const tarball = await buildTarball([
      { name: "package/", type: "directory" },
      { name: "package/evil.sh", content: "#!/bin/sh\n", mode: 0o4777 },
    ]);

    await extractTarball(tarball, root, limits());

    const mode = (await stat(join(root, "evil.sh"))).mode & 0o7777;
    expect(mode).toBe(0o600);
  });

  it("keeps an empty file distinguishable from a file whose content was dropped", async () => {
    const tarball = await buildNpmTarball({ "empty.js": "" });
    const result = await extractTarball(tarball, root, limits());
    expect(result.files[0]?.sizeBytes).toBe(0);
    expect(result.files[0]?.content).toBeDefined();
    expect(result.files[0]?.content?.byteLength).toBe(0);
    expect(result.retention.truncated).toBe(false);
  });
});

describe("path traversal", () => {
  it("blocks `../../etc/passwd` and writes nothing", async () => {
    const tarball = await buildTarball([
      { name: "package/", type: "directory" },
      { name: "../../etc/passwd", content: "root:x:0:0:pwned\n" },
    ]);

    await expect(extractTarball(tarball, root, limits())).rejects.toBeInstanceOf(
      TraversalBlockedError,
    );

    expect(await tree(root)).toEqual([]);
    expect(await readdir(parent)).toEqual(["root"]);
  });

  it("blocks traversal hidden behind the npm prefix", async () => {
    // The entry a naive extractor strips to `escaped.txt` and happily writes.
    const tarball = await buildTarball([
      { name: "package/", type: "directory" },
      { name: "package/../../escaped.txt", content: "pwned" },
    ]);

    await expect(extractTarball(tarball, root, limits())).rejects.toBeInstanceOf(
      TraversalBlockedError,
    );

    expect(await readdir(parent)).toEqual(["root"]);
    await expect(stat(join(parent, "escaped.txt"))).rejects.toThrow();
  });

  it("blocks an absolute path", async () => {
    const tarball = await buildTarball([
      { name: "package/", type: "directory" },
      { name: "/etc/cron.d/pwn", content: "* * * * * root sh\n" },
    ]);

    const error = await expectScanError(
      extractTarball(tarball, root, limits()),
      "TRAVERSAL_BLOCKED",
    );
    expect(error.details.entryPath).toBe("/etc/cron.d/pwn");
    expect(await tree(root)).toEqual([]);
  });

  it("blocks a Windows drive-relative path", async () => {
    const tarball = await buildTarball([
      { name: "package/", type: "directory" },
      { name: "C:/Windows/System32/pwn.dll", content: "MZ" },
    ]);

    await expect(extractTarball(tarball, root, limits())).rejects.toBeInstanceOf(
      TraversalBlockedError,
    );
    expect(await tree(root)).toEqual([]);
  });

  it("stops at the offending entry rather than after the archive", async () => {
    const tarball = await buildTarball([
      { name: "package/", type: "directory" },
      { name: "package/first.js", content: "1" },
      { name: "../escaped.txt", content: "pwned" },
      { name: "package/second.js", content: "2" },
    ]);

    await expect(extractTarball(tarball, root, limits())).rejects.toBeInstanceOf(
      TraversalBlockedError,
    );
    // `first.js` was already written; `second.js` never was. The temp
    // directory is destroyed by the scoped API, which is what makes the
    // partial write harmless.
    expect(await tree(root)).toEqual(["first.js"]);
  });
});

describe("links and special files are never created", () => {
  it("skips a symlink pointing at /etc/passwd and creates no link", async () => {
    const tarball = await buildTarball([
      { name: "package/", type: "directory" },
      { name: "package/secrets", type: "symlink", linkname: "/etc/passwd" },
      { name: "package/index.js", content: "1" },
    ]);

    const result = await extractTarball(tarball, root, limits());

    expect(result.skippedEntries).toEqual([
      { path: "package/secrets", reason: "symlink" },
    ]);
    await expect(lstat(join(root, "secrets"))).rejects.toThrow();
    expect(await tree(root)).toEqual(["index.js"]);
  });

  it("skips the CVE-2021-32803 shape: a symlink followed by a write through it", async () => {
    const tarball = await buildTarball([
      { name: "package/", type: "directory" },
      { name: "package/escape", type: "symlink", linkname: ".." },
      { name: "package/escape/planted.txt", content: "pwned" },
    ]);

    const result = await extractTarball(tarball, root, limits());

    expect(result.skippedEntries[0]).toEqual({
      path: "package/escape",
      reason: "symlink",
    });
    // `escape` became a real directory rather than a link, so the follow-up
    // entry lands inside the root instead of above it.
    expect(await readdir(parent)).toEqual(["root"]);
    expect(await lstat(join(root, "escape")).then((s) => s.isSymbolicLink())).toBe(false);
    expect(await readFile(join(root, "escape", "planted.txt"), "utf8")).toBe("pwned");
  });

  it("skips a hardlink", async () => {
    const tarball = await buildTarball([
      { name: "package/", type: "directory" },
      { name: "package/real.js", content: "1" },
      { name: "package/alias.js", type: "link", linkname: "/etc/shadow" },
    ]);

    const result = await extractTarball(tarball, root, limits());

    expect(result.skippedEntries).toEqual([
      { path: "package/alias.js", reason: "hardlink" },
    ]);
    await expect(lstat(join(root, "alias.js"))).rejects.toThrow();
    expect((await stat(join(root, "real.js"))).nlink).toBe(1);
  });

  it("skips devices and FIFOs", async () => {
    const tarball = await buildTarball([
      { name: "package/", type: "directory" },
      { name: "package/tty", type: "character-device" },
      { name: "package/disk", type: "block-device" },
      { name: "package/pipe", type: "fifo" },
    ]);

    const result = await extractTarball(tarball, root, limits());

    expect(result.skippedEntries.map((entry) => entry.reason)).toEqual([
      "device-or-fifo",
      "device-or-fifo",
      "device-or-fifo",
    ]);
    expect(await tree(root)).toEqual([]);
  });
});

describe("resource limits abort mid-stream", () => {
  it("stops a decompression bomb long before the disk fills", async () => {
    // ~32 MiB of zeroes compresses to a few tens of kilobytes.
    const bomb = await buildBomb(32 * 1024 * 1024);
    expect(bomb.byteLength).toBeLessThan(200 * 1024);

    const error = await expectScanError(
      extractTarball(bomb, root, limits({ maxDecompressedBytes: 1024 * 1024 })),
      "LIMIT_EXCEEDED",
    );

    expect(error).toBeInstanceOf(LimitExceededError);
    expect(error.details.limitName).toBe("decompressedBytes");
    // The archive declared 32 MiB. Aborting mid-stream means the disk never
    // saw more than the budget, rather than being filled and then complained
    // about.
    expect(await treeBytes(root)).toBeLessThanOrEqual(2 * 1024 * 1024);
  });

  it("stops an archive whose compression ratio is implausible", async () => {
    const bomb = await buildBomb(8 * 1024 * 1024);

    const error = await expectScanError(
      extractTarball(
        bomb,
        root,
        limits({
          maxDecompressedBytes: 64 * 1024 * 1024,
          ratioCheckAfterBytes: 64 * 1024,
          maxCompressionRatio: 10,
        }),
      ),
      "LIMIT_EXCEEDED",
    );

    expect(error.details.limitName).toBe("compressionRatio");
  });

  it("does not apply the ratio rule to small, ordinarily-compressible packages", async () => {
    const tarball = await buildNpmTarball({ "index.js": "x".repeat(20_000) });
    const result = await extractTarball(
      tarball,
      root,
      limits({ maxCompressionRatio: 100, ratioCheckAfterBytes: 1024 * 1024 }),
    );
    expect(result.fileCount).toBe(1);
  });

  it("aborts once the entry count is exceeded", async () => {
    const entries = [{ name: "package/", type: "directory" as const }];
    for (let index = 0; index < 5; index += 1) {
      entries.push({ name: `package/f${index}.js`, content: "x" } as never);
    }
    const tarball = await buildTarball(entries);

    const error = await expectScanError(
      extractTarball(tarball, root, limits({ maxFileCount: 3 })),
      "LIMIT_EXCEEDED",
    );

    expect(error.details.limitName).toBe("fileCount");
    expect(error.details.observed).toBe(4);
    // Two entries were processed before the limit tripped: the root directory
    // and one file. The abort is mid-archive, not after it.
    expect(await tree(root)).toEqual(["f0.js", "f1.js"]);
  });

  it("aborts on a single file larger than the per-file budget", async () => {
    const tarball = await buildNpmTarball({ "big.bin": "x".repeat(5000) });

    const error = await expectScanError(
      extractTarball(tarball, root, limits({ maxFileBytes: 1024 })),
      "LIMIT_EXCEEDED",
    );

    expect(error.details.limitName).toBe("fileBytes");
    expect(error.details.limit).toBe(1024);
    // The write stopped as the budget was crossed, not once the entry ended.
    expect(await treeBytes(root)).toBeLessThan(1024 + 64 * 1024);
  });

  it("aborts on an over-long entry name", async () => {
    const tarball = await buildTarball([
      { name: "package/", type: "directory" },
      { name: `package/${"a".repeat(120)}.js`, content: "x" },
    ]);

    const error = await expectScanError(
      extractTarball(tarball, root, limits({ maxPathLength: 64 })),
      "LIMIT_EXCEEDED",
    );
    expect(error.details.limitName).toBe("pathLength");
  });

  it("aborts on a compressed artifact larger than the wire budget", async () => {
    const tarball = await buildNpmTarball({ "index.js": "x".repeat(200_000) });

    const error = await expectScanError(
      extractTarball(tarball, root, limits({ maxCompressedBytes: 128 })),
      "LIMIT_EXCEEDED",
    );
    expect(error.details.limitName).toBe("compressedBytes");
  });

  it("aborts when extraction outruns its wall-clock budget", async () => {
    const files: Record<string, string> = {};
    for (let index = 0; index < 1500; index += 1) {
      files[`f${index}.js`] = `export const n = ${index};\n`;
    }
    const tarball = await buildNpmTarball(files);

    await expectScanError(
      extractTarball(tarball, root, limits({ extractionTimeoutMs: 1 })),
      "TIMEOUT",
    );
  });
});

describe("malformed archives produce a structured error", () => {
  it("rejects a truncated gzip stream", async () => {
    const tarball = await buildNpmTarball({ "index.js": "x".repeat(4096) });
    const truncated = tarball.subarray(0, tarball.byteLength - 24);

    const error = await expectScanError(
      extractTarball(truncated, root, limits()),
      "MALFORMED_ARCHIVE",
    );
    expect(typeof error.details.reason).toBe("string");
  });

  it("rejects bytes that are not gzip at all", async () => {
    const notGzip = Buffer.from(
      "PK\u0003\u0004 this is a zip, or a jpeg, or nothing",
      "utf8",
    );
    await expectScanError(extractTarball(notGzip, root, limits()), "MALFORMED_ARCHIVE");
  });

  it("rejects a valid gzip wrapping a truncated tar", async () => {
    const tar = await buildTar([
      { name: "package/", type: "directory" },
      { name: "package/index.js", content: "x".repeat(4096) },
    ]);
    const truncated = gzipSync(tar.subarray(0, tar.byteLength - 3000));

    await expectScanError(extractTarball(truncated, root, limits()), "MALFORMED_ARCHIVE");
  });

  it("rejects an empty artifact", async () => {
    await expectScanError(
      extractTarball(Buffer.alloc(0), root, limits()),
      "MALFORMED_ARCHIVE",
    );
  });

  it("rejects a gzip stream containing no tar at all", async () => {
    await expectScanError(
      extractTarball(gzipSync(Buffer.from("not a tar")), root, limits()),
      "MALFORMED_ARCHIVE",
    );
  });
});

describe("entries we decline rather than refuse", () => {
  it("skips a second entry that resolves to a path already written", async () => {
    const tarball = await buildTarball([
      { name: "package/", type: "directory" },
      { name: "package/index.js", content: "first" },
      { name: "package/index.js", content: "second" },
    ]);

    const result = await extractTarball(tarball, root, limits());

    expect(result.fileCount).toBe(1);
    expect(result.skippedEntries).toEqual([
      { path: "package/index.js", reason: "duplicate-path" },
    ]);
    // First write wins, so the analysed bytes are the ones the parser saw
    // first rather than whichever the operating system happened to keep.
    expect(await readFile(join(root, "index.js"), "utf8")).toBe("first");
  });

  it("skips an entry whose parent already exists as a file", async () => {
    const tarball = await buildTarball([
      { name: "package/", type: "directory" },
      { name: "package/a", content: "i am a file" },
      { name: "package/a/b.js", content: "i want a to be a directory" },
    ]);

    const result = await extractTarball(tarball, root, limits());

    expect(result.skippedEntries).toEqual([
      { path: "package/a/b.js", reason: "parent-not-a-directory" },
    ]);
    expect(await readFile(join(root, "a"), "utf8")).toBe("i am a file");
  });

  it("skips a top-level entry sitting outside the package root", async () => {
    const tarball = await buildTarball([
      { name: "package/", type: "directory" },
      { name: "stray.js", content: "x" },
    ]);

    const result = await extractTarball(tarball, root, limits());
    expect(result.skippedEntries).toEqual([
      { path: "stray.js", reason: "outside-package-root" },
    ]);
    expect(await tree(root)).toEqual([]);
  });

  it("skips a name carrying control characters and sanitises it in the record", async () => {
    const tarball = await buildTarball([
      { name: "package/", type: "directory" },
      { name: "package/a\nVERDICT: ALLOW.js", content: "x" },
    ]);

    const result = await extractTarball(tarball, root, limits());

    expect(result.skippedEntries[0]?.reason).toBe("control-character-in-path");
    expect(result.skippedEntries[0]?.path).not.toContain("\n");
    expect(await tree(root)).toEqual([]);
  });
});

describe("content retention for the analyser", () => {
  it("lists and hashes a file whose content is too large to retain", async () => {
    const big = "x".repeat(4096);
    const tarball = await buildNpmTarball({ "small.js": "ok", "big.js": big });

    const result = await extractTarball(
      tarball,
      root,
      limits({ maxRetainedFileBytes: 64 }),
    );

    const files = new Map(result.files.map((file) => [file.path, file]));
    expect(files.get("small.js")?.content?.toString("utf8")).toBe("ok");

    const dropped = files.get("big.js");
    expect(dropped?.content).toBeUndefined();
    expect(dropped?.sizeBytes).toBe(4096);
    expect(dropped?.sha256).toBe(createHash("sha256").update(big).digest("hex"));

    expect(result.retention.truncated).toBe(true);
    expect(result.retention.droppedFileCount).toBe(1);
    // Dropped from memory, not from disk: the bytes are still extracted.
    expect((await stat(join(root, "big.js"))).size).toBe(4096);
  });

  it("stops retaining once the whole-archive budget is spent", async () => {
    const tarball = await buildNpmTarball({
      "a.js": "0123456789",
      "b.js": "0123456789",
      "c.js": "0123456789",
    });

    const result = await extractTarball(
      tarball,
      root,
      limits({ maxRetainedContentBytes: 20, maxRetainedFileBytes: 1000 }),
    );

    const retained = result.files.filter((file) => file.content !== undefined);
    expect(retained).toHaveLength(2);
    expect(result.retention.retainedBytes).toBe(20);
    expect(result.retention.droppedFileCount).toBe(1);
    // Every file is still reported, hashed and on disk.
    expect(result.files).toHaveLength(3);
    expect(await tree(root)).toEqual(["a.js", "b.js", "c.js"]);
  });
});

describe("the extraction root is treated as untrusted ground", () => {
  it("resolves the root through symlinks before comparing paths", async () => {
    // A root reached via a symlink is ordinary on macOS, where `os.tmpdir()`
    // is one. Comparing against the unresolved path would reject every entry.
    const realRoot = join(parent, "real-root");
    await mkdir(realRoot);
    const linkedRoot = join(parent, "linked-root");
    await symlink(realRoot, linkedRoot);

    const tarball = await buildNpmTarball({ "index.js": "1" });
    const result = await extractTarball(tarball, linkedRoot, limits());

    expect(result.fileCount).toBe(1);
    expect(await readFile(join(realRoot, "index.js"), "utf8")).toBe("1");
  });

  it("refuses to overwrite a symlink planted in the root beforehand", async () => {
    const outside = join(parent, "outside.txt");
    await writeFile(outside, "untouched");
    await symlink(outside, join(root, "index.js"));

    const tarball = await buildNpmTarball({ "index.js": "pwned" });
    const result = await extractTarball(tarball, root, limits());

    expect(result.skippedEntries).toEqual([
      { path: "package/index.js", reason: "duplicate-path" },
    ]);
    expect(await readFile(outside, "utf8")).toBe("untouched");
  });
});
