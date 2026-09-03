import { describe, expect, it } from "vitest";
import { computeInstallReachable } from "./reachability.js";

function file(path: string, content = "") {
  return { path, content };
}

describe("computeInstallReachable", () => {
  it("treats the main entrypoint and its static imports as reachable", () => {
    const reachable = computeInstallReachable({
      manifest: { main: "lib/index.js" },
      files: [
        file("lib/index.js", "const h = require('./helper');\nmodule.exports = h;"),
        file("lib/helper.js", "module.exports = 1;"),
        file("test/fixtures/broken.mjs", "this is not valid javascript ("),
      ],
      lifecycleReferencedFiles: [],
    });
    expect(reachable?.has("lib/index.js")).toBe(true);
    expect(reachable?.has("lib/helper.js")).toBe(true);
    expect(reachable?.has("test/fixtures/broken.mjs")).toBe(false);
  });

  it("follows bin entries", () => {
    const reachable = computeInstallReachable({
      manifest: { bin: { demo: "cli/run.js" } },
      files: [file("cli/run.js", ""), file("other.js", "")],
      lifecycleReferencedFiles: [],
    });
    expect(reachable?.has("cli/run.js")).toBe(true);
    expect(reachable?.has("other.js")).toBe(false);
  });

  it("follows every string leaf of a conditional exports map", () => {
    const reachable = computeInstallReachable({
      manifest: {
        exports: { ".": { import: "./dist/index.mjs", require: "./dist/index.cjs" } },
      },
      files: [
        file("dist/index.mjs", ""),
        file("dist/index.cjs", ""),
        file("stray.js", ""),
      ],
      lifecycleReferencedFiles: [],
    });
    expect(reachable?.has("dist/index.mjs")).toBe(true);
    expect(reachable?.has("dist/index.cjs")).toBe(true);
    expect(reachable?.has("stray.js")).toBe(false);
  });

  it("treats install lifecycle script targets as reachable", () => {
    // This is the path that actually runs on `npm install`, so it must never
    // be classified as unreachable no matter where it sits in the tree.
    const reachable = computeInstallReachable({
      manifest: { main: "index.js" },
      files: [file("index.js", ""), file("scripts/postinstall.js", "")],
      lifecycleReferencedFiles: ["scripts/postinstall.js"],
    });
    expect(reachable?.has("scripts/postinstall.js")).toBe(true);
  });

  it("reaches code under test/ when the package genuinely points at it", () => {
    // The improvement must be reachability, not a path heuristic. A package
    // whose entrypoint lives under test/ is still reachable.
    const reachable = computeInstallReachable({
      manifest: { main: "test/entry.js" },
      files: [file("test/entry.js", "require('./payload')"), file("test/payload.js", "")],
      lifecycleReferencedFiles: [],
    });
    expect(reachable?.has("test/entry.js")).toBe(true);
    expect(reachable?.has("test/payload.js")).toBe(true);
  });

  it("resolves directory and extensionless specifiers", () => {
    const reachable = computeInstallReachable({
      manifest: { main: "index.js" },
      files: [
        file("index.js", "require('./lib');\nrequire('./util')"),
        file("lib/index.js", ""),
        file("util.js", ""),
      ],
      lifecycleReferencedFiles: [],
    });
    expect(reachable?.has("lib/index.js")).toBe(true);
    expect(reachable?.has("util.js")).toBe(true);
  });

  it("fails closed when there is no usable manifest", () => {
    // Without entrypoints we cannot compute reachability, and guessing would
    // let a package suppress the completeness signal by shipping a broken
    // manifest. Null means "treat everything as reachable".
    expect(
      computeInstallReachable({
        manifest: undefined,
        files: [file("a.js", "")],
        lifecycleReferencedFiles: [],
      }),
    ).toBeNull();
  });

  it("fails closed when the manifest declares no entrypoint at all", () => {
    expect(
      computeInstallReachable({
        manifest: { name: "x" },
        files: [file("a.js", "")],
        lifecycleReferencedFiles: [],
      }),
    ).toBeNull();
  });

  it("does not follow bare package specifiers out of the package", () => {
    const reachable = computeInstallReachable({
      manifest: { main: "index.js" },
      files: [file("index.js", "require('lodash')"), file("lodash.js", "")],
      lifecycleReferencedFiles: [],
    });
    // A bare specifier resolves to node_modules, not to a sibling file that
    // happens to share the name.
    expect(reachable?.has("lodash.js")).toBe(false);
  });

  it("terminates on cyclic imports", () => {
    const reachable = computeInstallReachable({
      manifest: { main: "a.js" },
      files: [file("a.js", "require('./b')"), file("b.js", "require('./a')")],
      lifecycleReferencedFiles: [],
    });
    expect(reachable?.has("a.js")).toBe(true);
    expect(reachable?.has("b.js")).toBe(true);
  });

  it("treats a dynamic import with a non-literal specifier as unresolvable", () => {
    // We cannot know the target, so the file cannot be marked reachable — but
    // this is exactly why unreachable never means inert. Documented, not hidden.
    const reachable = computeInstallReachable({
      manifest: { main: "index.js" },
      files: [file("index.js", "require(process.env.X)"), file("secret.js", "")],
      lifecycleReferencedFiles: [],
    });
    expect(reachable?.has("secret.js")).toBe(false);
    expect(reachable?.unresolvedDynamicImport).toBe(true);
  });
});
