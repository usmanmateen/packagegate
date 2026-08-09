import { describe, expect, it } from "vitest";
import { ScanError } from "@packagegate/shared";
import { PackumentSchema, type Packument } from "./schemas.js";
import {
  availableVersions,
  previousPublishedVersion,
  resolveVersion,
} from "./resolve.js";

function makePackument(
  versions: string[],
  distTags: Record<string, string> = {},
  time: Record<string, string> = {},
): Packument {
  return PackumentSchema.parse({
    name: "demo",
    "dist-tags": distTags,
    time,
    versions: Object.fromEntries(
      versions.map((version) => [
        version,
        {
          name: "demo",
          version,
          dist: { tarball: `https://registry.invalid/demo-${version}.tgz` },
        },
      ]),
    ),
  });
}

describe("availableVersions", () => {
  it("comes from versions, never from time", () => {
    // `time` retains unpublished versions indefinitely. Offering them would
    // send users to artifacts the registry cannot serve.
    const packument = makePackument(
      ["1.0.0", "1.1.0"],
      {},
      { "1.0.0": "2020-01-01T00:00:00Z", "9.9.9": "2020-06-01T00:00:00Z" },
    );
    expect(availableVersions(packument)).toEqual(["1.0.0", "1.1.0"]);
  });

  it("discards keys that are not valid semver", () => {
    const packument = makePackument(["1.0.0", "not-a-version"]);
    expect(availableVersions(packument)).toEqual(["1.0.0"]);
  });
});

describe("resolveVersion", () => {
  it("uses the latest dist-tag when no version is requested", () => {
    const packument = makePackument(["1.0.0", "2.0.0", "3.0.0"], { latest: "2.0.0" });
    expect(resolveVersion(packument)).toEqual({
      version: "2.0.0",
      resolvedFrom: "default-latest",
    });
  });

  it("falls back to the highest version when latest is missing", () => {
    const packument = makePackument(["1.0.0", "2.0.0"]);
    expect(resolveVersion(packument).version).toBe("2.0.0");
  });

  it("falls back when latest points at an unpublished version", () => {
    const packument = makePackument(["1.0.0", "2.0.0"], { latest: "9.9.9" });
    expect(resolveVersion(packument).version).toBe("2.0.0");
  });

  it("resolves a named dist-tag", () => {
    const packument = makePackument(["1.0.0", "2.0.0-beta.1"], {
      latest: "1.0.0",
      next: "2.0.0-beta.1",
    });
    expect(resolveVersion(packument, "next")).toEqual({
      version: "2.0.0-beta.1",
      resolvedFrom: "dist-tag",
      requested: "next",
    });
  });

  it("resolves an exact version", () => {
    const packument = makePackument(["1.0.0", "1.1.0"]);
    expect(resolveVersion(packument, "1.0.0")).toEqual({
      version: "1.0.0",
      resolvedFrom: "exact",
      requested: "1.0.0",
    });
  });

  it("resolves a caret range to the highest satisfying version", () => {
    const packument = makePackument(["1.0.0", "1.5.2", "2.0.0"]);
    expect(resolveVersion(packument, "^1.0.0")).toEqual({
      version: "1.5.2",
      resolvedFrom: "range",
      requested: "^1.0.0",
    });
  });

  it("excludes prereleases from a plain range", () => {
    const packument = makePackument(["1.0.0", "1.1.0", "2.0.0-beta.1"]);
    expect(resolveVersion(packument, "*").version).toBe("1.1.0");
  });

  it("throws NOT_FOUND for an unpublished exact version", () => {
    const packument = makePackument(["1.0.0"]);
    expect(() => resolveVersion(packument, "9.9.9")).toThrow(ScanError);
  });

  it("throws NOT_FOUND when no version satisfies the range", () => {
    const packument = makePackument(["1.0.0"]);
    expect(() => resolveVersion(packument, "^5.0.0")).toThrow(ScanError);
  });

  it("throws NOT_FOUND for an unknown dist-tag", () => {
    const packument = makePackument(["1.0.0"], { latest: "1.0.0" });
    expect(() => resolveVersion(packument, "nonexistent-tag")).toThrow(ScanError);
  });

  it("throws when the package has no published versions", () => {
    const packument = makePackument([]);
    expect(() => resolveVersion(packument)).toThrow(ScanError);
  });

  it("does not echo control characters from the request into the error", () => {
    const ESC = String.fromCharCode(0x1b);
    const packument = makePackument(["1.0.0"]);
    try {
      resolveVersion(packument, `${ESC}[31mbogus`);
      expect.unreachable("should have thrown");
    } catch (error) {
      expect(JSON.stringify((error as ScanError).details)).not.toContain(ESC);
    }
  });
});

describe("previousPublishedVersion", () => {
  it("returns the preceding version in semver order, not insertion order", () => {
    const packument = makePackument(["1.10.0", "1.2.0", "1.9.0"]);
    expect(previousPublishedVersion(packument, "1.10.0")).toBe("1.9.0");
  });

  it("returns undefined for the earliest version", () => {
    const packument = makePackument(["1.0.0", "2.0.0"]);
    expect(previousPublishedVersion(packument, "1.0.0")).toBeUndefined();
  });

  it("returns undefined for an unknown version", () => {
    const packument = makePackument(["1.0.0"]);
    expect(previousPublishedVersion(packument, "3.0.0")).toBeUndefined();
  });
});
