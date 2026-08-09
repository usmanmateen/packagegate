import { createHash } from "node:crypto";
import { createServer, type Server } from "node:http";
import { readdir, stat } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ScanError } from "@packagegate/shared";
import { withExtractedPackage, withExtractedTarball } from "./index.js";
import { withTemporaryDirectory } from "./workspace.js";
import { buildBomb, buildNpmTarball, buildTarball } from "./testing/tarballs.js";

/**
 * The scoped API, and the property the whole design exists to guarantee: a
 * temporary directory outlives no code path.
 *
 * Cleanup is asserted by watching `os.tmpdir()` rather than by capturing the
 * root inside the callback, because on the failure paths that matter most the
 * callback never runs. If a workspace survives a limit abort, a traversal
 * block or a malformed archive, this suite notices.
 */

const WORKSPACE_PREFIX = "packagegate-artifact-";

async function workspaces(): Promise<string[]> {
  const entries = await readdir(tmpdir());
  return entries.filter((name) => name.startsWith(WORKSPACE_PREFIX)).sort();
}

/** Run `body` and assert it left no workspace behind, whatever it did. */
async function expectNoWorkspaceLeak(body: () => Promise<unknown>): Promise<unknown> {
  const before = await workspaces();
  try {
    return await body();
  } finally {
    expect(await workspaces()).toEqual(before);
  }
}

async function expectScanError(promise: Promise<unknown>, code: string): Promise<ScanError> {
  try {
    await promise;
    expect.unreachable(`expected a ${code} ScanError`);
  } catch (error) {
    expect(error).toBeInstanceOf(ScanError);
    expect((error as ScanError).code).toBe(code);
    return error as ScanError;
  }
}

const TARBALL_URL = "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz";

describe("withExtractedTarball", () => {
  it("produces an ArtifactInfo describing what was actually extracted", async () => {
    const tarball = await buildNpmTarball({
      "package.json": '{"name":"demo","version":"1.0.0"}',
      "index.js": "module.exports = 1;\n",
    });

    const artifact = await expectNoWorkspaceLeak(async () =>
      withExtractedTarball({ bytes: tarball, tarballUrl: TARBALL_URL }, async (extracted) => {
        // The tree exists for the lifetime of the callback and no longer.
        expect((await stat(extracted.extractionRoot)).isDirectory()).toBe(true);
        expect(await readdir(extracted.extractionRoot)).toContain("index.js");
        return extracted.artifact;
      }),
    );

    expect(artifact).toMatchObject({
      tarballUrl: TARBALL_URL,
      compressedSizeBytes: tarball.byteLength,
      fileCount: 2,
      sha256: createHash("sha256").update(tarball).digest("hex"),
      skippedEntries: [],
    });
  });

  it("omits integrityVerified when the registry declared nothing", async () => {
    const tarball = await buildNpmTarball({ "index.js": "1" });
    const artifact = await withExtractedTarball(
      { bytes: tarball, tarballUrl: TARBALL_URL },
      (extracted) => Promise.resolve(extracted.artifact),
    );
    expect(artifact.integrityVerified).toBeUndefined();
    expect("integrityVerified" in artifact).toBe(false);
  });

  it("reports integrityVerified true when a declared digest matched", async () => {
    const tarball = await buildNpmTarball({ "index.js": "1" });
    const integrity = `sha512-${createHash("sha512").update(tarball).digest("base64")}`;

    const artifact = await withExtractedTarball(
      { bytes: tarball, tarballUrl: TARBALL_URL, integrity },
      (extracted) => Promise.resolve(extracted.artifact),
    );
    expect(artifact.integrityVerified).toBe(true);
  });

  it("reports integrityVerified false for a declaration it cannot check", async () => {
    const tarball = await buildNpmTarball({ "index.js": "1" });
    const artifact = await withExtractedTarball(
      { bytes: tarball, tarballUrl: TARBALL_URL, integrity: "blake3-Zm9vYmFy" },
      (extracted) => Promise.resolve(extracted.artifact),
    );
    expect(artifact.integrityVerified).toBe(false);
  });

  it("refuses to extract bytes that fail their declared integrity", async () => {
    const tarball = await buildNpmTarball({ "index.js": "1" });
    const wrong = `sha512-${createHash("sha512").update("something else").digest("base64")}`;

    await expectNoWorkspaceLeak(async () => {
      await expectScanError(
        withExtractedTarball(
          { bytes: tarball, tarballUrl: TARBALL_URL, integrity: wrong },
          () => Promise.reject(new Error("the callback must never run")),
        ),
        "INTEGRITY_MISMATCH",
      );
    });
  });

  it("records skipped entries in the artifact", async () => {
    const tarball = await buildTarball([
      { name: "package/", type: "directory" },
      { name: "package/link", type: "symlink", linkname: "/etc/passwd" },
      { name: "package/index.js", content: "1" },
    ]);

    const artifact = await withExtractedTarball(
      { bytes: tarball, tarballUrl: TARBALL_URL },
      (extracted) => Promise.resolve(extracted.artifact),
    );

    expect(artifact.skippedEntries).toEqual([{ path: "package/link", reason: "symlink" }]);
    expect(artifact.fileCount).toBe(1);
  });

  it("hands the analyser file contents so it never needs to touch the disk", async () => {
    const tarball = await buildNpmTarball({ "index.js": "module.exports = 1;\n" });

    const files = await withExtractedTarball(
      { bytes: tarball, tarballUrl: TARBALL_URL },
      (extracted) => Promise.resolve(extracted.files),
    );

    expect(files).toHaveLength(1);
    expect(files[0]?.content?.toString("utf8")).toBe("module.exports = 1;\n");
  });
});

describe("cleanup runs on every path", () => {
  it("removes the workspace after a successful scan", async () => {
    const tarball = await buildNpmTarball({ "index.js": "1" });
    let capturedRoot = "";

    await expectNoWorkspaceLeak(async () =>
      withExtractedTarball({ bytes: tarball, tarballUrl: TARBALL_URL }, (extracted) => {
        capturedRoot = extracted.extractionRoot;
        return Promise.resolve(null);
      }),
    );

    await expect(stat(capturedRoot)).rejects.toThrow();
  });

  it("removes the workspace after a traversal block", async () => {
    const tarball = await buildTarball([
      { name: "package/", type: "directory" },
      { name: "../../escaped.txt", content: "pwned" },
    ]);

    await expectNoWorkspaceLeak(async () => {
      await expectScanError(
        withExtractedTarball({ bytes: tarball, tarballUrl: TARBALL_URL }, () =>
          Promise.reject(new Error("unreachable")),
        ),
        "TRAVERSAL_BLOCKED",
      );
    });
  });

  it("removes the workspace after a limit abort", async () => {
    const bomb = await buildBomb(16 * 1024 * 1024);

    await expectNoWorkspaceLeak(async () => {
      await expectScanError(
        withExtractedTarball(
          {
            bytes: bomb,
            tarballUrl: TARBALL_URL,
            limits: { maxDecompressedBytes: 512 * 1024 },
          },
          () => Promise.reject(new Error("unreachable")),
        ),
        "LIMIT_EXCEEDED",
      );
    });
  });

  it("removes the workspace after a malformed archive", async () => {
    await expectNoWorkspaceLeak(async () => {
      await expectScanError(
        withExtractedTarball(
          { bytes: Buffer.from("definitely not gzip"), tarballUrl: TARBALL_URL },
          () => Promise.reject(new Error("unreachable")),
        ),
        "MALFORMED_ARCHIVE",
      );
    });
  });

  it("removes the workspace after an extraction timeout", async () => {
    const files: Record<string, string> = {};
    for (let index = 0; index < 1500; index += 1) {
      files[`f${index}.js`] = `export const n = ${index};\n`;
    }
    const tarball = await buildNpmTarball(files);

    await expectNoWorkspaceLeak(async () => {
      await expectScanError(
        withExtractedTarball(
          { bytes: tarball, tarballUrl: TARBALL_URL, limits: { extractionTimeoutMs: 1 } },
          () => Promise.reject(new Error("unreachable")),
        ),
        "TIMEOUT",
      );
    });
  });

  it("removes the workspace when the caller's own callback throws", async () => {
    const tarball = await buildNpmTarball({ "index.js": "1" });

    await expectNoWorkspaceLeak(async () => {
      await expect(
        withExtractedTarball({ bytes: tarball, tarballUrl: TARBALL_URL }, () =>
          Promise.reject(new Error("analysis blew up")),
        ),
      ).rejects.toThrow("analysis blew up");
    });
  });

  it("propagates the caller's error rather than a cleanup error", async () => {
    const marker = new Error("the finding that matters");
    await expect(
      withTemporaryDirectory(() => Promise.reject(marker)),
    ).rejects.toBe(marker);
  });

  it("gives the callback a private directory and deletes it afterwards", async () => {
    let observed = "";
    const mode = await withTemporaryDirectory(async (directory) => {
      observed = directory;
      return (await stat(directory)).mode & 0o777;
    });

    expect(mode).toBe(0o700);
    await expect(stat(observed)).rejects.toThrow();
  });
});

describe("withExtractedPackage — download and extract together", () => {
  let server: Server;
  let origin: string;
  let payload: Buffer;

  beforeAll(async () => {
    payload = await buildNpmTarball({
      "package.json": '{"name":"demo","version":"1.0.0"}',
      "index.js": "module.exports = 1;\n",
    });
    server = createServer((request, response) => {
      if (request.url === "/demo-1.0.0.tgz") {
        response
          .writeHead(200, {
            "content-type": "application/octet-stream",
            "content-length": String(payload.byteLength),
          })
          .end(payload);
        return;
      }
      if (request.url === "/corrupt-1.0.0.tgz") {
        const corrupt = Buffer.concat([gzipSync(Buffer.from("not a tar")), Buffer.alloc(0)]);
        response.writeHead(200, { "content-type": "application/octet-stream" }).end(corrupt);
        return;
      }
      response.writeHead(404).end();
    });
    await new Promise<void>((resolve) => {
      server.listen(0, "127.0.0.1", () => {
        resolve();
      });
    });
    origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => {
      server.close((error) => {
        if (error) reject(error);
        else resolve();
      });
    });
  });

  it("downloads, verifies, extracts and cleans up", async () => {
    const integrity = `sha512-${createHash("sha512").update(payload).digest("base64")}`;

    const artifact = await expectNoWorkspaceLeak(async () =>
      withExtractedPackage(
        { url: `${origin}/demo-1.0.0.tgz`, integrity },
        async (extracted) => {
          expect(await readdir(extracted.extractionRoot)).toContain("package.json");
          return extracted.artifact;
        },
      ),
    );

    expect(artifact).toMatchObject({
      tarballUrl: `${origin}/demo-1.0.0.tgz`,
      compressedSizeBytes: payload.byteLength,
      fileCount: 2,
      integrityVerified: true,
    });
  });

  it("cleans up when the downloaded bytes turn out to be unusable", async () => {
    await expectNoWorkspaceLeak(async () => {
      await expectScanError(
        withExtractedPackage({ url: `${origin}/corrupt-1.0.0.tgz` }, () =>
          Promise.reject(new Error("unreachable")),
        ),
        "MALFORMED_ARCHIVE",
      );
    });
  });

  it("creates no workspace at all when the download fails", async () => {
    await expectNoWorkspaceLeak(async () => {
      await expectScanError(
        withExtractedPackage({ url: `${origin}/missing.tgz` }, () =>
          Promise.reject(new Error("unreachable")),
        ),
        "NOT_FOUND",
      );
    });
  });
});

describe("nothing leaks a host path into reportable output", () => {
  it("keeps the extraction root out of the artifact record", async () => {
    const tarball = await buildTarball([
      { name: "package/", type: "directory" },
      { name: "package/link", type: "symlink", linkname: "/etc/passwd" },
    ]);

    const { artifact, root } = await withExtractedTarball(
      { bytes: tarball, tarballUrl: TARBALL_URL },
      (extracted) =>
        Promise.resolve({ artifact: extracted.artifact, root: extracted.extractionRoot }),
    );

    expect(JSON.stringify(artifact)).not.toContain(root);
    expect(JSON.stringify(artifact)).not.toContain(tmpdir());
  });

  it("keeps the extraction root out of a thrown error", async () => {
    const tarball = await buildTarball([
      { name: "package/", type: "directory" },
      { name: "../../escaped.txt", content: "pwned" },
    ]);

    const error = await expectScanError(
      withExtractedTarball({ bytes: tarball, tarballUrl: TARBALL_URL }, () =>
        Promise.reject(new Error("unreachable")),
      ),
      "TRAVERSAL_BLOCKED",
    );

    const rendered = `${error.message} ${JSON.stringify(error.details)}`;
    expect(rendered).not.toContain(tmpdir());
    expect(rendered).not.toContain(join(tmpdir(), WORKSPACE_PREFIX));
  });
});
