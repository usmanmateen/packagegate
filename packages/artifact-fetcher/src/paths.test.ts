import { describe, expect, it } from "vitest";
import { LimitExceededError, TraversalBlockedError } from "@packagegate/shared";
import { classifyEntryPath, resolveWithinRoot } from "./paths.js";

const NUL = String.fromCharCode(0x00);
const MAX_PATH = 1024;

/**
 * Unit-level tests for the name rules. The archive-level proof that nothing
 * escapes to the real filesystem lives in `extract.test.ts`; these exist so a
 * regression names the specific rule that broke.
 */

describe("classifyEntryPath — escapes are refused outright", () => {
  const escapes = [
    ["../../etc/passwd", "parent traversal from the root"],
    ["package/../../etc/passwd", "traversal hidden behind the npm prefix"],
    ["package/../../../../home/ci/.ssh/authorized_keys", "the classic zip-slip payload"],
    ["/etc/cron.d/pwn", "absolute path"],
    ["//etc/passwd", "double-slash absolute path"],
    ["C:/Windows/System32/x", "Windows drive prefix"],
    ["C:\\Windows\\System32\\x", "Windows drive prefix, backslash form"],
    ["\\\\server\\share\\x", "UNC path"],
    ["package\\..\\..\\x", "traversal using backslash separators"],
    ["..", "bare parent"],
    ["package/sub/../../../x", "traversal that only escapes on the last component"],
  ] as const;

  for (const [name, description] of escapes) {
    it(`blocks ${description}`, () => {
      expect(() => classifyEntryPath(name, MAX_PATH)).toThrow(TraversalBlockedError);
    });
  }

  it("blocks a NUL byte, which makes consumers disagree about the name", () => {
    expect(() => classifyEntryPath(`package/a${NUL}.js`, MAX_PATH)).toThrow(
      TraversalBlockedError,
    );
  });

  it("never echoes the raw hostile name back into the error", () => {
    const hostile = `../..${NUL}/etc/passwd\n\u001b[2Jfake`;
    try {
      classifyEntryPath(hostile, MAX_PATH);
      expect.unreachable("should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(TraversalBlockedError);
      const details = (error as TraversalBlockedError).details;
      expect(String(details.entryPath)).not.toContain(NUL);
      expect(String(details.entryPath)).not.toContain("\n");
      expect(String(details.entryPath)).not.toContain("\u001b");
    }
  });

  it("enforces the path-length budget on the declared name", () => {
    const long = `package/${"a".repeat(200)}`;
    expect(() => classifyEntryPath(long, 64)).toThrow(LimitExceededError);
  });
});

describe("classifyEntryPath — the npm prefix", () => {
  it("strips exactly one leading component", () => {
    expect(classifyEntryPath("package/lib/index.js", MAX_PATH)).toEqual({
      kind: "accept",
      relativePath: "lib/index.js",
    });
  });

  it("strips a leading component whatever it is called", () => {
    // Some tarballs use a different root. One component is stripped either
    // way; what matters is that the stripping cannot be steered.
    expect(classifyEntryPath("some-root/lib/index.js", MAX_PATH)).toEqual({
      kind: "accept",
      relativePath: "lib/index.js",
    });
  });

  it("normalises a `.` component before stripping, not after", () => {
    // Stripping first would eat the `.` and leave `package/x.js`, silently
    // creating a `package/` directory inside the root.
    expect(classifyEntryPath("./package/x.js", MAX_PATH)).toEqual({
      kind: "accept",
      relativePath: "x.js",
    });
  });

  it("recognises the archive root directory", () => {
    expect(classifyEntryPath("package/", MAX_PATH)).toEqual({ kind: "package-root" });
  });

  it("skips a file that sits outside the archive root", () => {
    expect(classifyEntryPath("stray.js", MAX_PATH)).toEqual({
      kind: "skip",
      reason: "outside-package-root",
    });
  });

  it("collapses redundant separators", () => {
    expect(classifyEntryPath("package//lib///a.js", MAX_PATH)).toEqual({
      kind: "accept",
      relativePath: "lib/a.js",
    });
  });
});

describe("classifyEntryPath — names we decline to write", () => {
  it("skips names carrying a Windows separator", () => {
    expect(classifyEntryPath("package/lib\\a.js", MAX_PATH)).toEqual({
      kind: "skip",
      reason: "windows-path-separator",
    });
  });

  it("skips names carrying control characters, which forge log lines", () => {
    expect(classifyEntryPath("package/a\nVERDICT: ALLOW", MAX_PATH)).toEqual({
      kind: "skip",
      reason: "control-character-in-path",
    });
    expect(classifyEntryPath("package/a\u001b[2Kb.js", MAX_PATH)).toEqual({
      kind: "skip",
      reason: "control-character-in-path",
    });
  });

  it("accepts ordinary non-ASCII names", () => {
    expect(classifyEntryPath("package/ünïcodé/文件.js", MAX_PATH)).toEqual({
      kind: "accept",
      relativePath: "ünïcodé/文件.js",
    });
  });
});

describe("resolveWithinRoot", () => {
  it("resolves a validated path inside the root", () => {
    expect(resolveWithinRoot("/srv/root", "lib/a.js", "package/lib/a.js")).toBe(
      "/srv/root/lib/a.js",
    );
  });

  it("refuses a path that resolves out of the root even if it looks relative", () => {
    // Belt-and-braces: unreachable through classifyEntryPath, which is exactly
    // why it is asserted independently.
    expect(() => resolveWithinRoot("/srv/root", "../outside", "x")).toThrow(
      TraversalBlockedError,
    );
  });

  it("refuses a sibling directory with the root as a string prefix", () => {
    expect(() => resolveWithinRoot("/srv/root", "../root-evil/a", "x")).toThrow(
      TraversalBlockedError,
    );
  });
});
