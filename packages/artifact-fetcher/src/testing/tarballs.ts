import { gzipSync } from "node:zlib";
import { pack as tarPack } from "tar-stream";
import type { Headers as TarHeaders } from "tar-stream";

/**
 * Hostile-archive construction for tests.
 *
 * Every adversarial fixture in this package is built here, programmatically,
 * rather than checked in as a binary. Three reasons:
 *
 *  - a reviewer can read the attack instead of hexdumping it;
 *  - a checked-in `.tgz` full of `../../etc/passwd` entries is an artefact that
 *    someone's editor, indexer or antivirus will eventually try to unpack;
 *  - the archives stay honest as `tar-stream` changes, because they are
 *    produced by the same header encoder our parser reads.
 *
 * Excluded from the build via `tsconfig.build.json`; this never ships.
 */

export interface TarEntry {
  readonly name: string;
  readonly type?: TarHeaders["type"];
  readonly content?: string | Buffer;
  readonly linkname?: string;
  readonly mode?: number;
}

/** Build an uncompressed tar. */
export async function buildTar(entries: readonly TarEntry[]): Promise<Buffer> {
  const pack = tarPack();
  const collected: Buffer[] = [];
  const drained = new Promise<Buffer>((resolve, reject) => {
    pack.on("data", (chunk: Buffer) => collected.push(chunk));
    pack.on("end", () => resolve(Buffer.concat(collected)));
    pack.on("error", reject);
  });

  for (const entry of entries) {
    const content =
      typeof entry.content === "string" ? Buffer.from(entry.content, "utf8") : entry.content;
    const header: TarHeaders = {
      name: entry.name,
      type: entry.type ?? "file",
      mode: entry.mode ?? 0o644,
      size: entry.type === "directory" || entry.type === "symlink" || entry.type === "link"
        ? 0
        : (content?.byteLength ?? 0),
      ...(entry.linkname === undefined ? {} : { linkname: entry.linkname }),
    };
    await new Promise<void>((resolve, reject) => {
      pack.entry(header, content ?? Buffer.alloc(0), (error) => {
        if (error) reject(error);
        else resolve();
      });
    });
  }

  pack.finalize();
  return await drained;
}

/** Build a gzipped tar, the shape the registry actually serves. */
export async function buildTarball(entries: readonly TarEntry[]): Promise<Buffer> {
  return gzipSync(await buildTar(entries));
}

/**
 * A well-formed npm tarball: every entry under the conventional `package/`
 * prefix.
 */
export async function buildNpmTarball(
  files: Readonly<Record<string, string>>,
): Promise<Buffer> {
  const entries: TarEntry[] = [{ name: "package/", type: "directory" }];
  for (const [path, content] of Object.entries(files)) {
    entries.push({ name: `package/${path}`, content });
  }
  return await buildTarball(entries);
}

/**
 * A decompression bomb: highly redundant content, so a small archive expands
 * enormously (T-EXT-05).
 */
export async function buildBomb(decompressedBytes: number): Promise<Buffer> {
  return await buildTarball([
    { name: "package/", type: "directory" },
    { name: "package/payload.bin", content: Buffer.alloc(decompressedBytes, 0) },
  ]);
}
