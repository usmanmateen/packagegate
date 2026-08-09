import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { investigateSources } from "../investigate.js";
import { formatInvestigationReport } from "../report.js";
import { formatInvestigationJson } from "./json.js";
import { containsAnsi, createTheme, stripAnsi } from "./theme.js";

const FIXTURE_ROOT = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../fixtures/inert-env-exfil",
);

function loadFixture() {
  const index = readFileSync(join(FIXTURE_ROOT, "index.js"), "utf8");
  const manifest = readFileSync(join(FIXTURE_ROOT, "package.json"), "utf8");
  return investigateSources({
    requestedSpec: "inert-env-exfil@1.0.0",
    resolved: { name: "inert-env-exfil", version: "1.0.0" },
    files: [
      { path: "index.js", content: index },
      { path: "package.json", content: manifest },
    ],
    scripts: {},
    manifestText: manifest,
  });
}

describe("report formatting", () => {
  it("renders explicit severity · confidence badges", () => {
    const result = loadFixture();
    const plain = formatInvestigationReport(result, { color: false });
    expect(plain).toContain("severity ·");
    expect(plain).toContain("confidence]");
    expect(plain).toMatch(/\[(?:INFO|LOW|MEDIUM|HIGH|CRITICAL) severity · (?:LOW|MEDIUM|HIGH) confidence\]/);
  });

  it("keeps colour-disabled output readable and free of ANSI", () => {
    const result = loadFixture();
    const plain = formatInvestigationReport(result, { color: false });
    expect(containsAnsi(plain)).toBe(false);
    expect(plain).toContain("PACKAGEGATE INVESTIGATION");
    expect(plain).toContain("Recommendation:");
    expect(plain).toContain(result.risk.recommendation);
  });

  it("applies colour when enabled without changing plain content", () => {
    const result = loadFixture();
    const theme = createTheme({ enabled: true });
    const coloured = formatInvestigationReport(result, { theme });
    expect(containsAnsi(coloured)).toBe(true);
    expect(stripAnsi(coloured)).toContain("PACKAGEGATE INVESTIGATION");
    expect(stripAnsi(coloured)).toContain(result.risk.recommendation);
    expect(stripAnsi(coloured)).toContain("✓ Integrity verified");
  });

  it("marks absent behaviour chains as neutral success text, not safety proof", () => {
    const result = investigateSources({
      requestedSpec: "empty@1.0.0",
      resolved: { name: "empty", version: "1.0.0" },
      files: [{ path: "index.js", content: "module.exports = 1;\n" }],
    });
    const plain = formatInvestigationReport(result, { color: false });
    expect(plain).toContain("None with evidenced dataflow.");
    expect(plain).toContain("not proof the package is safe");
  });
});

describe("--json output", () => {
  it("contains zero ANSI escape sequences", () => {
    const result = loadFixture();
    const json = formatInvestigationJson(result);
    expect(containsAnsi(json)).toBe(false);
    const parsed: unknown = JSON.parse(json);
    expect(parsed).toMatchObject({
      resolved: { name: "inert-env-exfil", version: "1.0.0" },
      risk: {
        recommendation: result.risk.recommendation,
        score: result.risk.score,
      },
    });
  });
});
