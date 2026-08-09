import { describe, expect, it } from "vitest";
import { analyseFile } from "./analyse.js";
import type { Finding } from "@packagegate/shared";

/**
 * Alias resolution is the correctness centrepiece of this package, so it is
 * tested through the public analyser rather than against internals: what
 * matters is that every way of writing the same import produces the same
 * capability finding, and that a local name that merely *looks* like a
 * capability produces none.
 */

function findingsFor(content: string, path = "index.js"): Finding[] {
  return analyseFile({ path, content }).findings;
}

function processExecutionFindings(content: string): Finding[] {
  return findingsFor(content).filter(
    (finding) => finding.category === "PROCESS_EXECUTION",
  );
}

const ALIAS_FORMS: readonly { readonly name: string; readonly source: string }[] = [
  {
    name: "namespace require",
    source: `const cp = require("child_process");\ncp.exec("ls");\n`,
  },
  {
    name: "destructured require",
    source: `const { exec } = require("child_process");\nexec("ls");\n`,
  },
  {
    name: "renamed destructured require",
    source: `const { exec: run } = require("child_process");\nrun("ls");\n`,
  },
  {
    name: "named ESM import",
    source: `import { exec } from "child_process";\nexec("ls");\n`,
  },
  {
    name: "renamed ESM import",
    source: `import { exec as run } from "child_process";\nrun("ls");\n`,
  },
  {
    name: "namespace ESM import",
    source: `import * as cp from "child_process";\ncp.exec("ls");\n`,
  },
  {
    name: "default ESM import (CJS interop)",
    source: `import cp from "child_process";\ncp.exec("ls");\n`,
  },
  {
    name: "node: prefixed require",
    source: `const cp = require("node:child_process");\ncp.exec("ls");\n`,
  },
  {
    name: "node: prefixed destructured require",
    source: `const { exec } = require("node:child_process");\nexec("ls");\n`,
  },
  {
    name: "member captured into a local",
    source: `const cp = require("child_process");\nconst run = cp.exec;\nrun("ls");\n`,
  },
  {
    name: "require member without an intermediate variable",
    source: `require("child_process").exec("ls");\n`,
  },
  {
    name: "aliased namespace",
    source: `const cp = require("child_process");\nconst cp2 = cp;\ncp2.exec("ls");\n`,
  },
  {
    name: "computed member with a literal key",
    source: `const cp = require("child_process");\ncp["exec"]("ls");\n`,
  },
  {
    name: "await import",
    source: `const cp = await import("node:child_process");\ncp.exec("ls");\n`,
  },
];

describe("capability resolution — every alias form reaches the same capability", () => {
  for (const form of ALIAS_FORMS) {
    it(`resolves ${form.name}`, () => {
      const findings = processExecutionFindings(form.source);
      expect(findings).toHaveLength(1);
      const [finding] = findings;
      expect(finding?.metadata.module).toBe("child_process");
      expect(finding?.metadata.member).toBe("exec");
    });
  }
});

describe("capability resolution — shadowing", () => {
  it("does not fire on a locally declared function called exec", () => {
    const source = `function exec(command) {\n  return command.length;\n}\nexec("rm -rf /");\n`;
    expect(processExecutionFindings(source)).toHaveLength(0);
  });

  it("does not fire on a local binding that shadows a real import", () => {
    const source = [
      `import { exec } from "child_process";`,
      `export function safe(input) {`,
      `  const exec = (value) => value.toUpperCase();`,
      `  return exec(input);`,
      `}`,
      ``,
    ].join("\n");
    expect(processExecutionFindings(source)).toHaveLength(0);
  });

  it("does not fire on a parameter that shadows an import", () => {
    const source = [
      `const { exec } = require("child_process");`,
      `module.exports = function run(exec) {`,
      `  return exec("ls");`,
      `};`,
      ``,
    ].join("\n");
    expect(processExecutionFindings(source)).toHaveLength(0);
  });

  it("does not treat a locally defined require helper as Node's loader", () => {
    const source = [
      `function require(name) {`,
      `  return { exec: (command) => command };`,
      `}`,
      `const cp = require("child_process");`,
      `cp.exec("ls");`,
      ``,
    ].join("\n");
    expect(processExecutionFindings(source)).toHaveLength(0);
  });

  it("does not treat a shadowed `process` as the global", () => {
    const source = [
      `export function handler(process) {`,
      `  return process.env.NPM_TOKEN;`,
      `}`,
      ``,
    ].join("\n");
    const findings = findingsFor(source).filter(
      (finding) =>
        finding.category === "ENVIRONMENT_ACCESS" ||
        finding.category === "CREDENTIAL_RELATED_ACCESS",
    );
    expect(findings).toHaveLength(0);
  });

  it("still fires when the import is used outside the shadowed scope", () => {
    const source = [
      `import { exec } from "child_process";`,
      `function inner() {`,
      `  const exec = (value) => value;`,
      `  return exec("ignored");`,
      `}`,
      `exec("real");`,
      `inner();`,
      ``,
    ].join("\n");
    const findings = processExecutionFindings(source);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.startLine).toBe(6);
  });
});

describe("capability resolution — member paths", () => {
  it("resolves fs.promises.readFile and fs/promises.readFile identically", () => {
    const viaNamespace = findingsFor(
      `const fs = require("fs");\nfs.promises.readFile("a.txt");\n`,
    ).filter((finding) => finding.category === "FILESYSTEM_READ");
    const viaSubmodule = findingsFor(
      `const fsp = require("node:fs/promises");\nfsp.readFile("a.txt");\n`,
    ).filter((finding) => finding.category === "FILESYSTEM_READ");

    expect(viaNamespace).toHaveLength(1);
    expect(viaSubmodule).toHaveLength(1);
    expect(viaNamespace[0]?.metadata.member).toBe("readFile");
    expect(viaSubmodule[0]?.metadata.member).toBe("readFile");
  });

  it("collapses globalThis.process.env to process.env", () => {
    const findings = findingsFor(`globalThis.process.env.NPM_TOKEN;\n`);
    const credential = findings.filter(
      (finding) => finding.category === "CREDENTIAL_RELATED_ACCESS",
    );
    expect(credential).toHaveLength(1);
    expect(credential[0]?.metadata.variable).toBe("NPM_TOKEN");
  });
});
