import { describe, expect, it } from "vitest";
import { PackumentSchema, VersionManifestSchema } from "./schemas.js";

/**
 * Regression tests for shapes found in the *real* registry corpus.
 *
 * Both cases below were caught by running the client against live packuments,
 * not by reasoning about the documented format. Manifests published a decade
 * ago do not match today's schema, and rejecting them would make real packages
 * unscannable.
 */

function manifest(extra: Record<string, unknown> = {}): unknown {
  return {
    name: "demo",
    version: "1.0.0",
    dist: { tarball: "https://r.invalid/demo.tgz" },
    ...extra,
  };
}

describe("VersionManifestSchema — real-corpus shapes", () => {
  it("accepts engines as an array, the pre-object convention", () => {
    // lodash carries 44 versions with `"engines": ["node"]`.
    const parsed = VersionManifestSchema.parse(manifest({ engines: ["node", "browser"] }));
    // An array means "runs on these" with no version constraint, so an
    // unconstrained range is a faithful translation rather than invented data.
    expect(parsed.engines).toEqual({ node: "*", browser: "*" });
  });

  it("accepts engines as an object", () => {
    const parsed = VersionManifestSchema.parse(manifest({ engines: { node: ">=18" } }));
    expect(parsed.engines).toEqual({ node: ">=18" });
  });

  it("accepts a manifest with no dependency keys at all", () => {
    // Most of the early corpus omits these entirely. A schema that treats an
    // absent key as invalid rejects over a hundred lodash versions.
    const parsed = VersionManifestSchema.parse(manifest());
    expect(parsed.dependencies).toBeUndefined();
    expect(parsed.devDependencies).toBeUndefined();
    expect(parsed.peerDependencies).toBeUndefined();
    expect(parsed.optionalDependencies).toBeUndefined();
    expect(parsed.scripts).toBeUndefined();
    expect(parsed.engines).toBeUndefined();
  });

  it("coerces a non-object dependencies value to an empty record", () => {
    const parsed = VersionManifestSchema.parse(manifest({ dependencies: "nonsense" }));
    expect(parsed.dependencies).toEqual({});
  });

  it("drops null dependency values without failing the manifest", () => {
    const parsed = VersionManifestSchema.parse(
      manifest({ dependencies: { good: "^1.0.0", broken: null, alsoBroken: 42 } }),
    );
    expect(parsed.dependencies).toEqual({ good: "^1.0.0" });
  });

  it("requires a tarball, which is the one field we genuinely cannot work without", () => {
    expect(() => VersionManifestSchema.parse({ name: "x", version: "1.0.0", dist: {} })).toThrow();
  });
});

describe("PackumentSchema", () => {
  it("parses a packument whose versions use mixed historical shapes", () => {
    const parsed = PackumentSchema.parse({
      name: "demo",
      "dist-tags": { latest: "2.0.0" },
      versions: {
        "1.0.0": {
          name: "demo",
          version: "1.0.0",
          engines: ["node"],
          repository: "git://github.com/example/demo.git",
          maintainers: ["Some One <someone@example.invalid>"],
          dist: { tarball: "https://r.invalid/1.tgz" },
        },
        "2.0.0": {
          name: "demo",
          version: "2.0.0",
          engines: { node: ">=20" },
          repository: { type: "git", url: "https://github.com/example/demo.git" },
          maintainers: [{ name: "Some One", email: "someone@example.invalid" }],
          dist: { tarball: "https://r.invalid/2.tgz", integrity: "sha512-x" },
        },
      },
    });
    expect(Object.keys(parsed.versions)).toEqual(["1.0.0", "2.0.0"]);
  });

  it("tolerates a packument with no dist-tags or time", () => {
    const parsed = PackumentSchema.parse({
      name: "demo",
      versions: {
        "1.0.0": { name: "demo", version: "1.0.0", dist: { tarball: "https://r.invalid/1.tgz" } },
      },
    });
    expect(parsed["dist-tags"]).toBeUndefined();
    expect(parsed.time).toBeUndefined();
  });
});
