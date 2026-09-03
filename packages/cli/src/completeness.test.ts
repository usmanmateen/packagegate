import { describe, expect, it } from "vitest";
import { buildAnalysisCompleteness } from "./completeness.js";

const failure = (filePath: string) => ({
  filePath,
  reason: 'Unexpected token, expected "{" (3:0)',
  sizeBytes: 33,
});

describe("analysis completeness and install reachability", () => {
  it("does not degrade on an unreachable invalid test fixture", () => {
    // The pino case: a deliberately invalid 33-byte fixture shipped in the
    // tarball at 99.4% coverage. Nothing the package declares points at it, so
    // it says nothing about code that can run.
    const result = buildAnalysisCompleteness({
      coverageRatio: 0.994,
      droppedExecutable: [],
      parseFailures: [failure("test/fixtures/syntax-error-esm.mjs")],
      isInstallReachable: () => false,
    });
    expect(result.status).toBe("COMPLETE");
  });

  it("still records the unreachable gap rather than hiding it", () => {
    // Relieving the verdict must not erase the evidence.
    const result = buildAnalysisCompleteness({
      coverageRatio: 0.994,
      droppedExecutable: [],
      parseFailures: [failure("test/fixtures/syntax-error-esm.mjs")],
      isInstallReachable: () => false,
    });
    expect(result.reasons).toHaveLength(1);
    expect(result.reasons[0]?.path).toBe("test/fixtures/syntax-error-esm.mjs");
    expect(result.reasons[0]?.installReachable).toBe(false);
  });

  it("degrades when the unparseable file IS reachable", () => {
    const result = buildAnalysisCompleteness({
      coverageRatio: 0.994,
      droppedExecutable: [],
      parseFailures: [failure("lib/index.js")],
      isInstallReachable: () => true,
    });
    expect(result.status).toBe("DEGRADED");
  });

  it("degrades on a reachable gap even when unreachable gaps outnumber it", () => {
    // astro's shape: many unreachable gaps plus a few reachable ones. One
    // reachable gap is enough; volume of unreachable noise must not drown it.
    const result = buildAnalysisCompleteness({
      coverageRatio: 0.971,
      droppedExecutable: [],
      parseFailures: [
        failure("dist/a.js"),
        failure("examples/x.js"),
        failure("examples/y.js"),
      ],
      isInstallReachable: (path) => path.startsWith("dist/"),
    });
    expect(result.status).toBe("DEGRADED");
  });

  it("fails closed when reachability cannot be computed", () => {
    // No predicate means the graph was unavailable — every file counts as
    // reachable, so a package cannot suppress the signal by shipping a broken
    // manifest.
    const result = buildAnalysisCompleteness({
      coverageRatio: 0.994,
      droppedExecutable: [],
      parseFailures: [failure("test/fixtures/syntax-error-esm.mjs")],
    });
    expect(result.status).toBe("DEGRADED");
  });

  it("keeps INSUFFICIENT below the coverage floor regardless of reachability", () => {
    // Reachability relieves individual gaps, never the overall coverage floor.
    const result = buildAnalysisCompleteness({
      coverageRatio: 0.1,
      droppedExecutable: [],
      parseFailures: [failure("whatever.js")],
      isInstallReachable: () => false,
    });
    expect(result.status).toBe("INSUFFICIENT");
  });

  it("a payload placed under test/ still degrades when something points at it", () => {
    // The defence against gaming: reachability is computed from the declared
    // graph, not from path shape.
    const result = buildAnalysisCompleteness({
      coverageRatio: 0.99,
      droppedExecutable: [],
      parseFailures: [failure("test/payload.js")],
      isInstallReachable: (path) => path === "test/payload.js",
    });
    expect(result.status).toBe("DEGRADED");
  });
});
