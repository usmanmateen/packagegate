import { describe, expect, it } from "vitest";
import { analyseFile } from "./analyse.js";
import { DEFAULT_ANALYSIS_LIMITS, resolveLimits } from "./limits.js";
import { parseSource } from "./parse.js";

const limits = DEFAULT_ANALYSIS_LIMITS;

/** Real ELF magic: 0x7F followed by "ELF". */
const ELF_MAGIC = String.fromCharCode(0x7f) + "ELF" + String.fromCharCode(0);

describe("parseSource — hostile input never throws", () => {
  it("parses ESM", () => {
    const outcome = parseSource(
      "a.mjs",
      `import x from "y";\nexport default x;\n`,
      limits,
    );
    expect(outcome.ok).toBe(true);
    if (outcome.ok) expect(outcome.parsed.sourceType).toBe("module");
  });

  it("parses CommonJS with a top-level return", () => {
    const outcome = parseSource(
      "a.js",
      `if (!global.x) return;\nmodule.exports = 1;\n`,
      limits,
    );
    expect(outcome.ok).toBe(true);
  });

  it("falls back to script parsing for sloppy-mode-only syntax", () => {
    // `with` is a syntax error in a module and legal in a script.
    const outcome = parseSource("a.js", `with (Math) { var y = cos(1); }\n`, limits);
    expect(outcome.ok).toBe(true);
    if (outcome.ok) expect(outcome.parsed.sourceType).toBe("script");
  });

  it("parses TypeScript", () => {
    const outcome = parseSource("a.ts", `export const x: number = 1;\n`, limits);
    expect(outcome.ok).toBe(true);
  });

  it("parses TSX with generics-looking JSX", () => {
    const outcome = parseSource(
      "a.tsx",
      `export const A = () => <div id="x" />;\n`,
      limits,
    );
    expect(outcome.ok).toBe(true);
  });

  it("returns a ParseFailure for source that cannot be parsed at all", () => {
    const outcome = parseSource("broken.js", `function ( { ] ) => ??? <<< `, limits);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.failure.filePath).toBe("broken.js");
      expect(outcome.failure.reason.length).toBeGreaterThan(0);
      expect(outcome.failure.sizeBytes).toBeGreaterThan(0);
    }
  });

  it("returns a ParseFailure rather than throwing for an empty file", () => {
    const outcome = parseSource("empty.js", "", limits);
    expect(outcome.ok).toBe(false);
  });

  it("refuses NUL-containing content as non-text", () => {
    const outcome = parseSource(
      "binary.js",
      `const a = 1;${String.fromCharCode(0)}more`,
      limits,
    );
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.failure.reason).toContain("NUL");
  });

  it("refuses files above the size budget before parsing them", () => {
    const tiny = resolveLimits({ maxFileBytes: 32 });
    const outcome = parseSource("big.js", "const a = 1;".repeat(20), tiny);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.failure.reason).toContain("parse limit");
  });

  it("recovers from a syntax error and still reports how many were forgiven", () => {
    const outcome = parseSource("recovered.js", `const a = 1;\nlet let = 2;\n`, limits);
    expect(outcome.ok).toBe(true);
    if (outcome.ok) expect(outcome.parsed.recoveredErrors).toBeGreaterThan(0);
  });
});

describe("analyseFile — unparseable files are recorded, never dropped", () => {
  it("carries the parse failure into the file report", () => {
    const analysis = analyseFile({ path: "bad.js", content: "function ( { ] ) => ???" });
    expect(analysis.report.analysed).toBe(false);
    expect(analysis.parseFailure).toBeDefined();
    expect(analysis.report.skippedReason).toBeDefined();
  });

  it("records a binary file as skipped with a reason and does not parse it", () => {
    const elf = ELF_MAGIC + "x".repeat(200);
    const analysis = analyseFile({ path: "lib/addon.node", content: elf });
    expect(analysis.report.analysed).toBe(false);
    expect(analysis.report.kind).toBe("NATIVE_ADDON");
    expect(
      analysis.findings.some((finding) => finding.category === "NATIVE_BINARY"),
    ).toBe(true);
  });

  it("flags a .js file whose content is an executable", () => {
    const elf = ELF_MAGIC + "x".repeat(200);
    const analysis = analyseFile({ path: "lib/index.js", content: elf });
    const mismatch = analysis.findings.find(
      (finding) => finding.ruleId === "file/extension-mismatch",
    );
    expect(mismatch).toBeDefined();
    expect(analysis.report.analysed).toBe(false);
  });
});
