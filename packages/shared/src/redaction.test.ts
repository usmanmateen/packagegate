import { describe, expect, it } from "vitest";
import {
  DEFAULT_SNIPPET_MAX_LENGTH,
  isSafeRelativePath,
  sanitiseInlineValue,
  sanitiseSnippet,
} from "./redaction.js";

// Control bytes are constructed rather than written as literal escapes so the
// test asserts on the real byte values regardless of source encoding.
const ESC = String.fromCharCode(0x1b);
const BEL = String.fromCharCode(0x07);
const NUL = String.fromCharCode(0x00);
const CR = String.fromCharCode(0x0d);

/** Length of "\n… [truncated by PackageGate]" appended when a snippet is cut. */
const TRUNCATION_MARKER_LENGTH = 30;

describe("sanitiseSnippet", () => {
  it("preserves ordinary source code untouched", () => {
    const source = "const arr = [1, 2, 3];\n\tconst re = /[a-z]+/g;\nexport { arr };";
    expect(sanitiseSnippet(source)).toBe(source);
  });

  it("does not mangle bracket expressions (regression: overly broad ANSI pattern)", () => {
    // An earlier pattern lacked the ESC prefix and stripped any [...] group,
    // silently corrupting the evidence shown to analysts.
    const source = "matrix[0][1] = env['PATH'];";
    expect(sanitiseSnippet(source)).toBe(source);
  });

  it("strips ANSI colour sequences that could forge terminal output", () => {
    const hostile = `${ESC}[31mHIGH RISK${ESC}[0m -> ${ESC}[32mLOW RISK${ESC}[0m`;
    expect(sanitiseSnippet(hostile)).toBe("HIGH RISK -> LOW RISK");
  });

  it("strips cursor-movement sequences used to overwrite earlier output", () => {
    const hostile = `benign line${ESC}[2A${ESC}[Kfake verdict`;
    const cleaned = sanitiseSnippet(hostile);
    expect(cleaned).toBe("benign linefake verdict");
    expect(cleaned).not.toContain(ESC);
  });

  it("strips OSC sequences without swallowing the remainder of the file", () => {
    const hostile = `${ESC}]0;window title${BEL}real code follows`;
    expect(sanitiseSnippet(hostile)).toBe("real code follows");
  });

  it("leaves text intact when an OSC sequence is never terminated", () => {
    // An unterminated OSC must not consume the rest of the snippet; the lone
    // ESC is removed by control-character stripping instead.
    const hostile = `${ESC}]0;no terminator here and then real code`;
    // Only the ESC byte is removed; the remaining characters are ordinary text
    // and are preserved verbatim rather than being consumed as a sequence.
    expect(sanitiseSnippet(hostile)).toBe("]0;no terminator here and then real code");
  });

  it("removes NUL bytes and carriage returns", () => {
    expect(sanitiseSnippet(`a${NUL}b${CR}c`)).toBe("abc");
  });

  it("keeps tabs and newlines, which carry real formatting", () => {
    expect(sanitiseSnippet("a\n\tb")).toBe("a\n\tb");
  });

  it("truncates beyond the configured maximum and marks it", () => {
    const long = "x".repeat(DEFAULT_SNIPPET_MAX_LENGTH + 500);
    const cleaned = sanitiseSnippet(long);
    expect(cleaned.length).toBeLessThan(long.length);
    expect(cleaned).toContain("truncated by PackageGate");
  });

  it("bounds output on pathologically large input", () => {
    // Input is capped before any pattern matching and the result is capped
    // again afterwards, so neither work nor memory scales with an
    // attacker-controlled snippet length.
    const huge = ("x".repeat(10) + `${ESC}[31m`).repeat(20_000);
    const cleaned = sanitiseSnippet(huge);
    expect(cleaned.length).toBeLessThanOrEqual(
      DEFAULT_SNIPPET_MAX_LENGTH + TRUNCATION_MARKER_LENGTH,
    );
    expect(cleaned).not.toContain(ESC);
  });

  it("returns empty string for empty input", () => {
    expect(sanitiseSnippet("")).toBe("");
  });
});

describe("sanitiseInlineValue", () => {
  it("collapses newlines so a value cannot forge extra log lines", () => {
    const hostile = 'node setup.js\nlevel=info msg="scan completed" risk=0';
    const cleaned = sanitiseInlineValue(hostile);
    expect(cleaned).not.toContain("\n");
    expect(cleaned).toBe('node setup.js level=info msg="scan completed" risk=0');
  });

  it("strips escapes and trims", () => {
    expect(sanitiseInlineValue(`  ${ESC}[1mpostinstall${ESC}[0m  `)).toBe("postinstall");
  });

  it("truncates with an ellipsis", () => {
    expect(sanitiseInlineValue("y".repeat(400), 100)).toBe("y".repeat(100) + "…");
  });
});

describe("isSafeRelativePath", () => {
  it.each([
    ["lib/index.js", true],
    ["package.json", true],
    ["a/b/c/d.js", true],
    ["./lib/index.js", true],
    ["", false],
    ["/etc/passwd", false],
    ["../../../etc/passwd", false],
    ["lib/../../../etc/passwd", false],
    ["C:\\Windows\\System32", false],
    ["\\\\server\\share", false],
    ["lib\\..\\..\\evil.js", false],
  ])("%s -> %s", (candidate, expected) => {
    expect(isSafeRelativePath(candidate)).toBe(expected);
  });

  it("rejects embedded NUL bytes", () => {
    expect(isSafeRelativePath(`lib/index.js${NUL}.txt`)).toBe(false);
  });
});
