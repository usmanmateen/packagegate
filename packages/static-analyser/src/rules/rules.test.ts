import { describe, expect, it } from "vitest";
import type { Finding, FindingCategory, Severity } from "@packagegate/shared";
import { analyseFile } from "../analyse.js";

function analyse(content: string, path = "index.js"): Finding[] {
  return analyseFile({ path, content }).findings;
}

function categories(findings: readonly Finding[]): Set<FindingCategory> {
  return new Set(findings.map((finding) => finding.category));
}

function highest(findings: readonly Finding[]): Severity {
  const order: Severity[] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
  let best = 0;
  for (const finding of findings) {
    best = Math.max(best, order.indexOf(finding.severity));
  }
  return order[best] ?? "INFO";
}

describe("environment access — the calibration test that matters most", () => {
  it("reports process.env.NODE_ENV as HIGH confidence and LOW severity", () => {
    const findings = analyse(
      `export const dev = process.env.NODE_ENV !== "production";\n`,
    );
    const env = findings.find((finding) => finding.category === "ENVIRONMENT_ACCESS");
    expect(env).toBeDefined();
    expect(env?.confidence).toBe("HIGH");
    expect(env?.severity).toBe("LOW");
    expect(env?.metadata.mundane).toBe(true);
  });

  it("separates a named credential read from an ordinary one", () => {
    const findings = analyse(`const t = process.env.NPM_TOKEN;\nexport default t;\n`);
    const credential = findings.find(
      (finding) => finding.category === "CREDENTIAL_RELATED_ACCESS",
    );
    expect(credential?.severity).toBe("HIGH");
    expect(credential?.confidence).toBe("HIGH");
    expect(credential?.metadata.variable).toBe("NPM_TOKEN");
  });

  it("does not let two hundred environment reads become anything but LOW", () => {
    const lines = Array.from(
      { length: 200 },
      (_, index) => `const v${String(index)} = process.env.SOME_VAR_${String(index)};`,
    ).join("\n");
    const findings = analyse(`${lines}\n`);
    expect(highest(findings)).toBe("LOW");
  });

  it("reports whole-environment enumeration separately", () => {
    const findings = analyse(
      `const all = Object.keys(process.env);\nexport default all;\n`,
    );
    const enumeration = findings.find(
      (finding) => finding.ruleId === "js/environment/env-enumeration",
    );
    expect(enumeration?.severity).toBe("MEDIUM");
  });

  it("reports environment spread as enumeration", () => {
    const findings = analyse(`const copy = { ...process.env };\nexport default copy;\n`);
    expect(
      findings.some((finding) => finding.ruleId === "js/environment/env-enumeration"),
    ).toBe(true);
  });
});

describe("process execution", () => {
  it("keeps a literal build command at LOW", () => {
    const findings = analyse(
      `const { execSync } = require("child_process");\nexecSync("tsc -p tsconfig.json");\n`,
    );
    const execution = findings.find(
      (finding) => finding.category === "PROCESS_EXECUTION",
    );
    expect(execution?.severity).toBe("LOW");
    expect(execution?.metadata.commandIsLiteral).toBe(true);
  });

  it("raises a shell command built at runtime to MEDIUM", () => {
    const findings = analyse(
      [
        `const { exec } = require("child_process");`,
        `export function run(input) {`,
        `  return exec("git " + input);`,
        `}`,
        ``,
      ].join("\n"),
    );
    const execution = findings.find(
      (finding) => finding.category === "PROCESS_EXECUTION",
    );
    expect(execution?.severity).toBe("MEDIUM");
    expect(execution?.metadata.commandIsLiteral).toBe(false);
  });
});

describe("network", () => {
  it("records outbound capability as inventory", () => {
    const findings = analyse(`const https = require("https");\nhttps.get("x");\n`);
    const capability = findings.find((finding) => finding.category === "NETWORK_ACCESS");
    expect(capability?.severity).toBe("LOW");
  });

  it("records an ordinary destination at INFO", () => {
    const findings = analyse(`export const url = "https://registry.npmjs.org/lodash";\n`);
    const destination = findings.find(
      (finding) => finding.category === "NETWORK_DESTINATION",
    );
    expect(destination?.severity).toBe("INFO");
    expect(destination?.metadata.host).toBe("registry.npmjs.org");
  });

  it("raises a public collector destination to HIGH", () => {
    const findings = analyse(
      `export const url = "https://discord.com/api/webhooks/1/abcdef";\n`,
    );
    const destination = findings.find(
      (finding) => finding.category === "NETWORK_DESTINATION",
    );
    expect(destination?.severity).toBe("HIGH");
    expect(destination?.metadata.collectorMarker).toBe("discord.com/api/webhooks");
  });

  it("raises a hardcoded public IP to MEDIUM but not a public resolver", () => {
    const bare = analyse(`export const a = "http://203.0.113.10/collect";\n`);
    expect(
      bare.find((finding) => finding.category === "NETWORK_DESTINATION")?.severity,
    ).toBe("MEDIUM");

    const resolver = analyse(`export const b = "https://1.1.1.1/dns-query";\n`);
    expect(
      resolver.find((finding) => finding.category === "NETWORK_DESTINATION")?.severity,
    ).toBe("INFO");
  });

  it("ignores XML namespace URLs and localhost", () => {
    const findings = analyse(
      [
        `export const ns = "http://www.w3.org/2000/svg";`,
        `export const dev = "http://127.0.0.1:3000/api";`,
        ``,
      ].join("\n"),
    );
    expect(findings.filter((f) => f.category === "NETWORK_DESTINATION")).toHaveLength(0);
  });
});

describe("filesystem and sensitive paths", () => {
  it("keeps an ordinary read at LOW", () => {
    const findings = analyse(
      `const fs = require("fs");\nfs.readFileSync("package.json", "utf8");\n`,
    );
    const read = findings.find((finding) => finding.category === "FILESYSTEM_READ");
    expect(read?.severity).toBe("LOW");
  });

  it("reports an .npmrc reference as package-manager credential access", () => {
    const findings = analyse(
      [
        `const fs = require("fs");`,
        `const os = require("os");`,
        `const path = require("path");`,
        `fs.readFileSync(path.join(os.homedir(), ".npmrc"), "utf8");`,
        ``,
      ].join("\n"),
    );
    const credential = findings.find(
      (finding) => finding.category === "PACKAGE_MANAGER_ACCESS",
    );
    expect(credential?.severity).toBe("HIGH");
    expect(credential?.metadata.matched).toBe(".npmrc");
  });

  it("reports SSH keys, AWS credentials and shell history", () => {
    const findings = analyse(
      [
        `export const targets = [`,
        `  "~/.ssh/id_rsa",`,
        `  "~/.aws/credentials",`,
        `  "~/.bash_history",`,
        `];`,
        ``,
      ].join("\n"),
    );
    const found = categories(findings);
    expect(found.has("CREDENTIAL_RELATED_ACCESS")).toBe(true);
    expect(found.has("SENSITIVE_FILE_ACCESS")).toBe(true);
  });

  it("reports a write to a shell profile at MEDIUM", () => {
    const findings = analyse(
      `const fs = require("fs");\nfs.appendFileSync("/home/u/.bashrc", "x");\n`,
    );
    const write = findings.find((finding) => finding.category === "FILESYSTEM_WRITE");
    expect(write?.severity).toBe("MEDIUM");
  });

  it("reports chmod with an execute bit as an executable write", () => {
    const findings = analyse(
      `const fs = require("fs");\nfs.chmodSync("bin/run", 0o755);\n`,
    );
    expect(findings.some((finding) => finding.category === "EXECUTABLE_WRITE")).toBe(
      true,
    );
  });
});

describe("dynamic execution and encoded payloads", () => {
  it("keeps a bare eval at MEDIUM", () => {
    const findings = analyse(`export function run(code) {\n  return eval(code);\n}\n`);
    const dynamic = findings.find(
      (finding) => finding.category === "DYNAMIC_CODE_EXECUTION",
    );
    expect(dynamic?.severity).toBe("MEDIUM");
  });

  it("raises decoded-then-executed content to HIGH", () => {
    const findings = analyse(
      `const blob = "aGVsbG8=";\nexport const out = eval(Buffer.from(blob, "base64").toString());\n`,
    );
    const dynamic = findings.find(
      (finding) => finding.ruleId === "js/dynamic-execution/encoded-code",
    );
    expect(dynamic?.severity).toBe("HIGH");
  });

  it("raises fetched-then-executed content to a remote code fetch", () => {
    const findings = analyse(
      [
        `export async function boot(url) {`,
        `  return eval(await fetch(url));`,
        `}`,
        ``,
      ].join("\n"),
    );
    const remote = findings.find((finding) => finding.category === "REMOTE_CODE_FETCH");
    expect(remote?.severity).toBe("HIGH");
  });

  it("records a plain base64 decode at LOW", () => {
    const findings = analyse(
      `export const bytes = Buffer.from(process.argv[2], "base64");\n`,
    );
    const decode = findings.find((finding) => finding.category === "ENCODED_PAYLOAD");
    expect(decode?.severity).toBe("LOW");
  });

  it("reports vm execution", () => {
    const findings = analyse(
      `const vm = require("vm");\nexport const r = vm.runInNewContext("1 + 1");\n`,
    );
    expect(
      findings.some((finding) => finding.category === "DYNAMIC_CODE_EXECUTION"),
    ).toBe(true);
  });

  it("reports require with a computed specifier", () => {
    const findings = analyse(
      `export function load(name) {\n  return require("./" + name);\n}\n`,
    );
    expect(
      findings.some(
        (finding) => finding.ruleId === "js/dynamic-execution/dynamic-require",
      ),
    ).toBe(true);
  });
});

describe("obfuscation signals", () => {
  it("reports the obfuscator.io identifier fingerprint", () => {
    const names = Array.from(
      { length: 10 },
      (_, index) => `const _0x${(0x1000 + index).toString(16)} = ${String(index)};`,
    ).join("\n");
    const findings = analyse(`${names}\n`);
    const fingerprint = findings.find(
      (finding) => finding.ruleId === "js/obfuscation/obfuscator-fingerprint",
    );
    expect(fingerprint?.severity).toBe("MEDIUM");
  });

  it("does not report the fingerprint for a couple of coincidental names", () => {
    const findings = analyse(`const _0x1234 = 1;\nconst _0x5678 = 2;\n`);
    expect(
      findings.some(
        (finding) => finding.ruleId === "js/obfuscation/obfuscator-fingerprint",
      ),
    ).toBe(false);
  });

  it("reports a bidi control character inside a string literal", () => {
    const rlo = String.fromCharCode(0x202e);
    const findings = analyse(`export const label = "admin${rlo}resu";\n`);
    expect(
      findings.some((finding) => finding.ruleId === "js/obfuscation/bidi-or-invisible"),
    ).toBe(true);
  });

  it("reports computed dispatch on a sensitive global", () => {
    const findings = analyse(
      `export function get(key) {\n  return globalThis[key];\n}\n`,
    );
    expect(
      findings.some((finding) => finding.ruleId === "js/obfuscation/dynamic-dispatch"),
    ).toBe(true);
  });

  it("reports a key assembled from fragments at HIGH confidence", () => {
    const findings = analyse(`export const e = process["e" + "nv"];\n`);
    const dispatch = findings.find(
      (finding) => finding.ruleId === "js/obfuscation/dynamic-dispatch",
    );
    expect(dispatch?.confidence).toBe("HIGH");
    expect(dispatch?.metadata.keyFolded).toBe(true);
  });
});

describe("system information and native code", () => {
  it("keeps platform detection at LOW and host fingerprinting at MEDIUM", () => {
    const platform = analyse(
      `const os = require("os");\nexport const p = os.platform();\n`,
    );
    expect(
      platform.find((finding) => finding.category === "SYSTEM_INFORMATION_ACCESS")
        ?.severity,
    ).toBe("LOW");

    const recon = analyse(`const os = require("os");\nexport const h = os.hostname();\n`);
    expect(
      recon.find((finding) => finding.category === "SYSTEM_INFORMATION_ACCESS")?.severity,
    ).toBe("MEDIUM");
  });

  it("reports a required .node addon", () => {
    const findings = analyse(`module.exports = require("./build/Release/addon.node");\n`);
    expect(findings.some((finding) => finding.category === "NATIVE_BINARY")).toBe(true);
  });

  it("reports a native loader package", () => {
    const findings = analyse(
      `const gyp = require("node-gyp-build");\nmodule.exports = gyp(__dirname);\n`,
    );
    expect(findings.some((finding) => finding.category === "NATIVE_BINARY")).toBe(true);
  });
});

describe("high-entropy literals", () => {
  it("reports a long random-looking base64 literal at LOW severity", () => {
    const blob =
      "aZ9kQ2xmP7vNbT4rYuI8oPqWeRtYuIoP1aSdFgHjKlZxCvBnM3qWeRtY5uIoPaSdFgHjKlZxCvBnMqWeRtY7uIoPaSdFgHjKl";
    const findings = analyse(`export const key = "${blob}";\n`);
    const entropy = findings.find(
      (finding) => finding.category === "HIGH_ENTROPY_PAYLOAD",
    );
    expect(entropy?.severity).toBe("LOW");
    expect(entropy?.confidence).toBe("MEDIUM");
  });

  it("does not report ordinary long prose", () => {
    const prose =
      "the quick brown fox jumps over the lazy dog and then keeps on running for a while longer";
    const findings = analyse(`export const message = "${prose}";\n`);
    expect(findings.filter((f) => f.category === "HIGH_ENTROPY_PAYLOAD")).toHaveLength(0);
  });
});

describe("locations", () => {
  it("points findings at the line the code is actually on", () => {
    const source = [
      `// line 1`,
      `// line 2`,
      `const { exec } = require("child_process");`,
      `// line 4`,
      `exec("ls");`,
      ``,
    ].join("\n");
    const findings = analyse(source);
    const execution = findings.find(
      (finding) => finding.category === "PROCESS_EXECUTION",
    );
    expect(execution?.location.startLine).toBe(5);
    expect(execution?.location.startColumn).toBe(0);
    expect(execution?.snippet).toContain(`exec("ls");`);
  });

  it("reports the correct line for a finding deep in a file", () => {
    const padding = Array.from({ length: 50 }, (_, i) => `// filler ${String(i)}`).join(
      "\n",
    );
    const source = `${padding}\nconst t = process.env.NPM_TOKEN;\n`;
    const findings = analyse(source);
    const credential = findings.find(
      (finding) => finding.category === "CREDENTIAL_RELATED_ACCESS",
    );
    expect(credential?.location.startLine).toBe(51);
  });
});
