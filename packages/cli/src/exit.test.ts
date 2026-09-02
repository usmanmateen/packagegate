import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

/**
 * Regression guard for silent truncation of `--json` output.
 *
 * `process.exit()` tears the process down immediately and discards anything
 * still buffered on stdout. Writes to a pipe are asynchronous, so any consumer
 * slower to start than we are to write — `jq`, a Python script, most CI steps —
 * receives only what fitted in the pipe buffer, roughly 64KB on Linux.
 *
 * The failure is worse than a crash: the consumer gets *invalid JSON* rather
 * than an error, so automation silently reads a truncated investigation. A real
 * `scan lodash@4.17.21 --json` emits ~232KB and was reproducibly cut at 65502
 * bytes before this was fixed.
 *
 * The correct idiom is `process.exitCode = n`, letting Node terminate once
 * stdout has drained.
 *
 * This is asserted against the source rather than by spawning the binary
 * because reproducing it needs >64KB of output, which requires a network scan;
 * every offline fixture is well under the pipe buffer and would pass either way.
 */
describe("CLI process exit", () => {
  const binSource = readFileSync(join(here, "bin.ts"), "utf8");

  it("does not call process.exit, which would truncate piped JSON", () => {
    const withoutComments = binSource
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/^[ \t]*\/\/.*$/gm, "");

    expect(withoutComments).not.toMatch(/process\s*\.\s*exit\s*\(/);
  });

  it("sets process.exitCode so the exit status is still propagated", () => {
    expect(binSource).toMatch(/process\s*\.\s*exitCode\s*=/);
  });
});
