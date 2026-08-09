import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * Structural guarantees, asserted against the source itself.
 *
 * Some properties of this package are only meaningful if they hold
 * *everywhere*, not at the one call site a behavioural test happens to
 * exercise. "We never create a symlink" is one of those: a single `symlink()`
 * added later in good faith would reopen T-EXT-03 without failing any of the
 * extraction tests, because those tests only prove the archives they carry.
 *
 * Test files are excluded. They deliberately plant symlinks in order to prove
 * we refuse to follow them, which is the opposite of the thing being banned.
 */

const SOURCE_DIRECTORY = fileURLToPath(new URL(".", import.meta.url));

interface SourceFile {
  readonly name: string;
  /** The file as written, including its comments. */
  readonly text: string;
  /** The file with comments removed, so prose cannot trip a code rule. */
  readonly code: string;
}

/**
 * Comments are stripped before the bans are applied. This file's own
 * explanations mention symlinks constantly; a rule that cannot tell a
 * `symlink()` call from the word "symlink" would either fail forever or be
 * weakened until it stopped meaning anything.
 */
function stripComments(text: string): string {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .split("\n")
    .filter((line) => !/^\s*\/\//.test(line))
    .join("\n");
}

async function productionSources(): Promise<SourceFile[]> {
  const entries = await readdir(SOURCE_DIRECTORY, {
    withFileTypes: true,
    recursive: true,
  });
  const files: SourceFile[] = [];
  for (const entry of entries) {
    if (!entry.isFile() || !entry.name.endsWith(".ts")) continue;
    if (entry.name.endsWith(".test.ts")) continue;
    const path = join(entry.parentPath, entry.name);
    if (path.startsWith(join(SOURCE_DIRECTORY, "testing"))) continue;
    const text = await readFile(path, "utf8");
    files.push({
      name: path.slice(SOURCE_DIRECTORY.length),
      text,
      code: stripComments(text),
    });
  }
  return files;
}

/**
 * Calls that would materialise something other than a directory or a regular
 * file, or that would hand an attacker-chosen mode or owner to the filesystem.
 */
const BANNED_FILESYSTEM_CALLS = [
  /\bsymlink(?:Sync)?\s*\(/,
  /\blink(?:Sync)?\s*\(/,
  /\bmknod\w*\s*\(/,
  /\b[lf]?chown(?:Sync)?\s*\(/,
  /\butimes(?:Sync)?\s*\(/,
];

/** Anything that could turn analysed content into running code (R-ANL-03). */
const BANNED_EXECUTION_CALLS = [
  /\bchild_process\b/,
  /\bnode:child_process\b/,
  /\bnode:vm\b/,
  /\bexecSync\s*\(/,
  /\bspawn(?:Sync)?\s*\(/,
  /\beval\s*\(/,
  /\bnew Function\s*\(/,
];

describe("the package cannot create a link, a device or a FIFO", () => {
  it("contains no symlink, hardlink, mknod, chown or utimes call", async () => {
    const offenders: string[] = [];
    for (const file of await productionSources()) {
      for (const pattern of BANNED_FILESYSTEM_CALLS) {
        if (pattern.test(file.code)) offenders.push(`${file.name}: ${pattern.source}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("writes to disk through exactly one create path", async () => {
    // `open(..., "wx")` is O_CREAT|O_EXCL: it will not follow a symlink and
    // will not overwrite. If a plain `writeFile` appears, that guarantee is
    // gone even though every existing test would still pass.
    const sources = await productionSources();
    // The lookbehind lets a private method be called `#writeFile` while still
    // catching the `fs` function of the same name.
    const writers = sources.filter((file) =>
      /(?<![#\w])writeFile(?:Sync)?\s*\(/.test(file.code),
    );
    expect(writers.map((file) => file.name)).toEqual([]);

    const extract = sources.find((file) => file.name === "extract.ts");
    expect(extract?.text).toContain('open(target, "wx", FILE_MODE)');
  });
});

describe("the package never executes what it downloads", () => {
  it("contains no process-spawning or code-evaluating call", async () => {
    const offenders: string[] = [];
    for (const file of await productionSources()) {
      for (const pattern of BANNED_EXECUTION_CALLS) {
        if (pattern.test(file.code)) offenders.push(`${file.name}: ${pattern.source}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("keeps the HTTP client out of the extraction path", async () => {
    // TB-3: the component with the tar and gzip parsers must be able to run
    // with no network and no credentials. If `extract.ts` ever imports a
    // client, that separation is gone.
    const sources = await productionSources();
    const networkless = [
      "extract.ts",
      "paths.ts",
      "verify.ts",
      "workspace.ts",
      "limits.ts",
    ];
    for (const name of networkless) {
      const file = sources.find((candidate) => candidate.name === name);
      expect(file, `${name} should exist`).toBeDefined();
      expect(file?.code, name).not.toContain("undici");
      expect(file?.code, name).not.toContain("node:http");
    }
  });
});
