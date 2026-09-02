import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { investigateSources } from "./investigate.js";
import { formatInvestigationReport } from "./report.js";

const FIXTURE_ROOT = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../fixtures/inert-env-exfil",
);

describe("investigateSources — inert env exfil fixture", () => {
  it("finds environment access, network access, and an evidenced chain", () => {
    const index = readFileSync(join(FIXTURE_ROOT, "index.js"), "utf8");
    const manifest = readFileSync(join(FIXTURE_ROOT, "package.json"), "utf8");

    const result = investigateSources({
      requestedSpec: "inert-env-exfil@1.0.0",
      resolved: { name: "inert-env-exfil", version: "1.0.0" },
      files: [
        { path: "index.js", content: index },
        { path: "package.json", content: manifest },
      ],
      scripts: {},
      manifestText: manifest,
    });

    const categories = new Set(result.findings.map((finding) => finding.category));
    expect(categories.has("ENVIRONMENT_ACCESS")).toBe(true);
    expect(categories.has("NETWORK_ACCESS")).toBe(true);

    expect(result.behaviourChains.length).toBeGreaterThanOrEqual(1);
    const chain = result.behaviourChains[0];
    expect(chain?.source).toBe("ENVIRONMENT_ACCESS");
    expect(chain?.sink).toBe("NETWORK_REQUEST");
    expect(chain?.transformations).toContain("JSON_SERIALIZATION");
    expect(
      chain?.links.some(
        (link) => link.kind === "ARGUMENT_FLOW" || link.kind === "SHARED_BINDING",
      ),
    ).toBe(true);

    expect(result.risk.score).toBeGreaterThan(0);
    expect(["ALLOW", "REVIEW", "BLOCK"]).toContain(result.risk.recommendation);

    const report = formatInvestigationReport(result);
    expect(report).toContain("PACKAGEGATE INVESTIGATION");
    expect(report).toContain("Behaviour chains");
    expect(report).toContain("inert-env-exfil@1.0.0");
    expect(report).toContain("Absence of findings is not evidence");
  });

  it("does not invent a chain for unrelated env + network co-occurrence", () => {
    const source = [
      "const mode = process.env.NODE_ENV;",
      'require("https").request({ hostname: "example.com" });',
      "console.log(mode);",
    ].join("\n");

    const result = investigateSources({
      requestedSpec: "benign-cooccur@1.0.0",
      resolved: { name: "benign-cooccur", version: "1.0.0" },
      files: [{ path: "index.js", content: source }],
    });

    expect(result.findings.some((f) => f.category === "ENVIRONMENT_ACCESS")).toBe(true);
    expect(result.findings.some((f) => f.category === "NETWORK_ACCESS")).toBe(true);
    expect(result.behaviourChains).toHaveLength(0);
  });
});
