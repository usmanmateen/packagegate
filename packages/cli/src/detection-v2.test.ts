import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { investigateSources } from "./investigate.js";

function loadFixture(name: string): {
  files: { path: string; content: string }[];
  scripts: Record<string, string>;
  manifestText: string;
  name: string;
  version: string;
} {
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
    files.push({
      path: entry,
      content: readFileSync(join(root, entry), "utf8"),
    });
  }
  return {
    files,
    scripts: pkg.scripts ?? {},
    manifestText,
    name: pkg.name,
    version: pkg.version,
  };
}

describe("detection engine v2 fixtures", () => {
  it("install curl|bash produces install-time remote execution chain", () => {
    const fixture = loadFixture("inert-install-curl-bash");
    const result = investigateSources({
      requestedSpec: `${fixture.name}@${fixture.version}`,
      resolved: { name: fixture.name, version: fixture.version },
      files: fixture.files,
      scripts: fixture.scripts,
      manifestText: fixture.manifestText,
    });

    expect(
      result.findings.some((f) => f.ruleId === "js/shell/remote-content-to-shell"),
    ).toBe(true);
    expect(result.behaviourChains.length).toBeGreaterThanOrEqual(1);
    const chain = result.behaviourChains[0]!;
    expect(chain.source).toBe("REMOTE_DOWNLOAD");
    expect(chain.sink).toBe("PROCESS_EXECUTION");
    expect(chain.metadata.installTimeRooted).toBe(true);
    expect(result.risk.recommendation).toBe("REVIEW");
    expect(result.policy.finalAction).toBe("REVIEW");
  });

  it("does not chain unused curl string with unrelated execSync", () => {
    const fixture = loadFixture("inert-shell-cooccurrence-negative");
    const result = investigateSources({
      requestedSpec: `${fixture.name}@${fixture.version}`,
      resolved: { name: fixture.name, version: fixture.version },
      files: fixture.files,
      scripts: fixture.scripts,
      manifestText: fixture.manifestText,
    });

    expect(
      result.behaviourChains.some(
        (c) =>
          c.metadata.chainType === "REMOTE_CONTENT_TO_SHELL" ||
          c.metadata.chainType === "INSTALL_TIME_REMOTE_EXECUTION",
      ),
    ).toBe(false);
    expect(
      result.findings.some((f) => f.ruleId === "js/shell/remote-content-to-shell"),
    ).toBe(false);
  });

  it("detects PowerShell irm|iex pipeline", () => {
    const fixture = loadFixture("inert-powershell-irm-iex");
    const result = investigateSources({
      requestedSpec: `${fixture.name}@${fixture.version}`,
      resolved: { name: fixture.name, version: fixture.version },
      files: fixture.files,
      scripts: fixture.scripts,
      manifestText: fixture.manifestText,
    });
    expect(
      result.findings.some((f) => f.ruleId === "js/shell/remote-content-to-shell"),
    ).toBe(true);
  });

  it("keeps a normal local installer from becoming a remote-exec chain", () => {
    const fixture = loadFixture("inert-normal-installer");
    const result = investigateSources({
      requestedSpec: `${fixture.name}@${fixture.version}`,
      resolved: { name: fixture.name, version: fixture.version },
      files: fixture.files,
      scripts: fixture.scripts,
      manifestText: fixture.manifestText,
    });
    expect(
      result.behaviourChains.some(
        (c) => c.source === "REMOTE_DOWNLOAD" && c.sink === "PROCESS_EXECUTION",
      ),
    ).toBe(false);
  });
});
