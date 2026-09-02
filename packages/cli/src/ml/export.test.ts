import { describe, expect, it } from "vitest";
import { investigateSources } from "../investigate.js";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  exportPackageGateMlRecord,
  extractStructuredFeatures,
  flattenStructuredFeatures,
} from "./export.js";
import { DisabledMlProvider } from "./provider.js";
import { decidePolicy } from "@packagegate/policy-engine";

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
  const result = investigateSources({
    requestedSpec: `${pkg.name}@${pkg.version}`,
    resolved: { name: pkg.name, version: pkg.version },
    files,
    scripts: pkg.scripts ?? {},
    manifestText,
  });
  const sourceByPath = new Map(files.map((f) => [f.path, f.content]));
  return { result, sourceByPath };
}

describe("ml feature export", () => {
  it("exports structured features without final policy leakage", () => {
    const { result, sourceByPath } = loadFixture("inert-install-curl-bash");
    const features = extractStructuredFeatures(result);
    expect(features.processExecutionCount).toBeGreaterThan(0);
    expect(
      features.hasPreinstall + features.hasInstall + features.hasPostinstall,
    ).toBeGreaterThan(0);
    expect("finalAction" in features).toBe(false);
    expect(features.behaviouralScore).toBeUndefined();

    const record = exportPackageGateMlRecord(result, { sourceByPath });
    expect(record.schemaVersion).toBe(1);
    expect(record.package.nameHash).toMatch(/^[a-f0-9]{16}$/);
    expect(record.slices.length).toBeGreaterThan(0);
    expect(record.slices[0]!.sourceText.includes("MALICIOUS")).toBe(false);

    const flat = flattenStructuredFeatures(features);
    expect(flat.keys.length).toBe(flat.values.length);
    expect(flat.keys).not.toContain("finalAction");
  });

  it("disabled ML provider never escalates", async () => {
    const { result, sourceByPath } = loadFixture("version-diff-benign-v1");
    const record = exportPackageGateMlRecord(result, { sourceByPath });
    const ml = await new DisabledMlProvider().assess(record);
    expect(ml.status).toBe("DISABLED");
    expect(ml.supportsReviewEscalation).toBe(false);
  });
});

describe("ml policy escalation", () => {
  it("escalates ALLOW to REVIEW but never invents BLOCK from ML alone", () => {
    const completeness = {
      status: "COMPLETE" as const,
      reasons: [],
      coverageRatio: 1,
    };
    const withMl = decidePolicy({
      behaviouralRecommendation: "ALLOW",
      analysisCompleteness: completeness,
      threatIntelligence: "NONE",
      mlSupportsReviewEscalation: true,
    });
    expect(withMl.finalAction).toBe("REVIEW");
    expect(withMl.reasons.some((r) => r.code === "ML_REVIEW_ESCALATION")).toBe(true);

    const behaviouralBlock = decidePolicy({
      behaviouralRecommendation: "BLOCK",
      analysisCompleteness: completeness,
      threatIntelligence: "NONE",
      mlSupportsReviewEscalation: true,
    });
    expect(behaviouralBlock.finalAction).toBe("BLOCK");
  });
});
