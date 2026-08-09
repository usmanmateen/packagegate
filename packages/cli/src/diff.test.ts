import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { diffInvestigations, diffPackages } from "./diff.js";
import { investigateSources } from "./investigate.js";
import {
  MemoryThreatIntelProvider,
  resetThreatIntelProvider,
  setThreatIntelProvider,
} from "./threat-intel.js";

function loadFixture(name: string) {
  const root = join(process.cwd(), "../../fixtures", name);
  const manifestText = readFileSync(join(root, "package.json"), "utf8");
  const pkg = JSON.parse(manifestText) as {
    name: string;
    version: string;
    scripts?: Record<string, string>;
  };
  const files = [{ path: "package.json", content: manifestText }];
  for (const entry of readdirSync(root)) {
    if (!entry.endsWith(".js")) continue;
    files.push({ path: entry, content: readFileSync(join(root, entry), "utf8") });
  }
  return investigateSources({
    requestedSpec: `${pkg.name}@${pkg.version}`,
    resolved: { name: pkg.name, version: pkg.version },
    files,
    scripts: pkg.scripts ?? {},
    manifestText,
  });
}

describe("security version diff", () => {
  it("flags install-time remote execution as CRITICAL", () => {
    const before = loadFixture("version-diff-benign-v1");
    const after = loadFixture("version-diff-remote-v2");
    const diff = diffInvestigations(before, after);
    expect(diff.changeSignificance).toBe("CRITICAL");
    expect(diff.lifecycleAdded.some((s) => s.name === "preinstall")).toBe(true);
    expect(diff.chainsAdded.length).toBeGreaterThanOrEqual(1);
    expect(diff.riskDelta).toBeGreaterThan(0);
  });

  it("ignores line-number-only shifts for finding identity", () => {
    const before = loadFixture("version-diff-line-shift-v1");
    const after = loadFixture("version-diff-line-shift-v2");
    const diff = diffInvestigations(before, after);
    expect(diff.findingsAdded).toHaveLength(0);
    expect(diff.findingsRemoved).toHaveLength(0);
  });

  it("resolves inert fixture names through diffPackages", async () => {
    const { diff } = await diffPackages(
      "version-diff-benign-v1",
      "version-diff-remote-v2",
    );
    expect(diff.changeSignificance).toBe("CRITICAL");
    expect(diff.packageName).toBe("version-diff-demo");
  });
});

describe("threat intel policy lane", () => {
  it("BLOCKS on exact KNOWN_MALICIOUS without rewriting behavioural score", () => {
    setThreatIntelProvider(
      new MemoryThreatIntelProvider([
        {
          packageName: "version-diff-demo",
          version: "1.0.0",
          classification: "KNOWN_MALICIOUS",
          source: "test-feed",
          referenceId: "TEST-MAL-1",
        },
      ]),
    );
    try {
      const result = loadFixture("version-diff-benign-v1");
      expect(result.risk.recommendation).toBe("ALLOW");
      expect(result.threatIntelligence.status).toBe("KNOWN_MALICIOUS");
      expect(result.policy.finalAction).toBe("BLOCK");
      expect(result.decisionExplanation.some((l) => l.includes("KNOWN_MALICIOUS"))).toBe(
        true,
      );
    } finally {
      resetThreatIntelProvider();
    }
  });
});
