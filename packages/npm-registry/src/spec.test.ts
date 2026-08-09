import { describe, expect, it } from "vitest";
import { ScanError } from "@packagegate/shared";
import { encodePackageNameForUrl, formatPackageSpec, parsePackageSpec } from "./spec.js";

const NUL = String.fromCharCode(0x00);

describe("parsePackageSpec — accepted forms", () => {
  it("parses a bare name with no version", () => {
    const spec = parsePackageSpec("express");
    expect(spec.name).toBe("express");
    expect(spec.requestedVersion).toBeUndefined();
    expect(spec.scope).toBeUndefined();
  });

  it("parses name@version", () => {
    const spec = parsePackageSpec("lodash@4.17.21");
    expect(spec.name).toBe("lodash");
    expect(spec.requestedVersion).toBe("4.17.21");
  });

  it("parses a scoped package with no version", () => {
    const spec = parsePackageSpec("@babel/parser");
    expect(spec.name).toBe("@babel/parser");
    expect(spec.scope).toBe("babel");
    expect(spec.requestedVersion).toBeUndefined();
  });

  it("parses a scoped package with a version", () => {
    // The classic bug: splitting on the first @ yields name "" or "scope/name".
    const spec = parsePackageSpec("@scope/package@1.2.0");
    expect(spec.name).toBe("@scope/package");
    expect(spec.scope).toBe("scope");
    expect(spec.requestedVersion).toBe("1.2.0");
  });

  it("accepts legacy uppercase names still served by the registry", () => {
    expect(parsePackageSpec("JSONStream").name).toBe("JSONStream");
  });

  it("accepts dotted and hyphenated names", () => {
    expect(parsePackageSpec("lodash.merge").name).toBe("lodash.merge");
    expect(parsePackageSpec("some-pkg_name~1").name).toBe("some-pkg_name~1");
  });

  it("accepts a dist-tag in the version position", () => {
    expect(parsePackageSpec("lodash@latest").requestedVersion).toBe("latest");
  });

  it("accepts a semver range", () => {
    expect(parsePackageSpec("lodash@^4.0.0").requestedVersion).toBe("^4.0.0");
  });

  it("trims surrounding whitespace", () => {
    expect(parsePackageSpec("  express  ").name).toBe("express");
  });
});

describe("parsePackageSpec — rejected forms", () => {
  const rejected: [string, string][] = [
    ["", "empty string"],
    ["   ", "whitespace only"],
    ["@", "bare scope sigil"],
    ["express@", "trailing separator with no version"],
    ["./local/package", "relative path"],
    ["../../etc/passwd", "parent traversal"],
    ["/absolute/path", "absolute path"],
    ["~/home/package", "home-relative path"],
    ["file:../thing", "file specifier"],
    ["npm:alias@1.0.0", "alias specifier"],
    ["git+https://example.invalid/x.git", "git specifier"],
    ["https://example.invalid/x.tgz", "tarball URL"],
    ["github:owner/repo", "github shorthand"],
    ["workspace:*", "workspace protocol"],
    ["lib\\..\\evil", "backslash separator"],
    [".hidden", "leading dot"],
    ["_private", "leading underscore"],
    ["some/package", "unscoped slash"],
    ["@scope/pkg@1.0.0/extra", "version containing a slash"],
  ];

  it.each(rejected)("rejects %s (%s)", (input) => {
    expect(() => parsePackageSpec(input)).toThrow(ScanError);
  });

  it("rejects an embedded NUL byte", () => {
    expect(() => parsePackageSpec(`express${NUL}`)).toThrow(ScanError);
  });

  it("rejects a name longer than npm's limit", () => {
    expect(() => parsePackageSpec("a".repeat(215))).toThrow(ScanError);
  });

  it("throws INVALID_SPEC with the offending input sanitised into details", () => {
    try {
      parsePackageSpec("./local");
      expect.unreachable("should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(ScanError);
      const scanError = error as ScanError;
      expect(scanError.code).toBe("INVALID_SPEC");
      expect(scanError.details.spec).toBe("./local");
    }
  });

  it("does not echo control characters back in error details", () => {
    const ESC = String.fromCharCode(0x1b);
    try {
      parsePackageSpec(`${ESC}[31m./evil`);
      expect.unreachable("should have thrown");
    } catch (error) {
      const scanError = error as ScanError;
      expect(String(scanError.details.spec)).not.toContain(ESC);
    }
  });
});

describe("encodePackageNameForUrl", () => {
  it("leaves an unscoped name unchanged", () => {
    expect(encodePackageNameForUrl("lodash")).toBe("lodash");
  });

  it("percent-encodes the scope separator but keeps the @ sigil", () => {
    // Verified against the live registry: @babel%2Fparser, %40babel%2Fparser
    // and @babel/parser all return 200, so npm is tolerant here. We emit the
    // canonical form npm itself uses rather than relying on that tolerance.
    expect(encodePackageNameForUrl("@babel/parser")).toBe("@babel%2Fparser");
  });

  it("encodes names containing dots", () => {
    expect(encodePackageNameForUrl("lodash.merge")).toBe("lodash.merge");
  });
});

describe("formatPackageSpec", () => {
  it("round-trips a versioned spec", () => {
    expect(formatPackageSpec(parsePackageSpec("@scope/pkg@1.2.0"))).toBe("@scope/pkg@1.2.0");
  });

  it("omits the version when none was requested", () => {
    expect(formatPackageSpec(parsePackageSpec("express"))).toBe("express");
  });
});
