#!/usr/bin/env node
/**
 * PackageGate CLI — investigate a published npm package without executing it.
 *
 * Usage:
 *   packagegate scan <package[@version]>
 *   packagegate fixture <name>
 *   packagegate --help
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ScanError } from "@packagegate/shared";
import { investigateSources } from "./investigate.js";
import { formatInvestigationReport } from "./report.js";
import { scanPackage } from "./scan.js";

function print(message: string): void {
  process.stdout.write(`${message}\n`);
}

function printError(message: string): void {
  process.stderr.write(`${message}\n`);
}

function usage(): string {
  return [
    "PackageGate — npm package Trust & Safety investigation",
    "",
    "Usage:",
    "  packagegate scan <package[@version]>",
    "  packagegate fixture <name>",
    "",
    "Examples:",
    "  packagegate scan lodash@4.17.21",
    "  packagegate scan express@^4.0.0",
    "  packagegate scan @babel/parser",
    "  packagegate fixture inert-env-exfil",
    "",
    "The package under investigation is never installed or executed.",
    "Absence of findings is not evidence of safety.",
  ].join("\n");
}

function repoRoot(): string {
  // dist/bin.js → packages/cli/dist → packages/cli → packages → repo root
  return join(dirname(fileURLToPath(import.meta.url)), "../../..");
}

function runFixture(name: string): void {
  const root = join(repoRoot(), "fixtures", name);
  const indexPath = join(root, "index.js");
  const manifestPath = join(root, "package.json");
  const index = readFileSync(indexPath, "utf8");
  const manifest = readFileSync(manifestPath, "utf8");
  const parsed: unknown = JSON.parse(manifest);
  const packageName =
    parsed !== null &&
    typeof parsed === "object" &&
    "name" in parsed &&
    typeof parsed.name === "string"
      ? parsed.name
      : name;
  const version =
    parsed !== null &&
    typeof parsed === "object" &&
    "version" in parsed &&
    typeof parsed.version === "string"
      ? parsed.version
      : "0.0.0";

  print(
    `Investigating fixture ${name} (static analysis only; never executed)…\n`,
  );
  const result = investigateSources({
    requestedSpec: `${packageName}@${version}`,
    resolved: { name: packageName, version },
    files: [
      { path: "index.js", content: index },
      { path: "package.json", content: manifest },
    ],
    scripts: {},
    manifestText: manifest,
  });
  print(formatInvestigationReport(result));
}

async function main(argv: string[]): Promise<number> {
  const args = argv.slice(2);
  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    print(usage());
    return args.length === 0 ? 1 : 0;
  }

  const [command, target, ...rest] = args;
  if (rest.length > 0 || target === undefined) {
    printError(usage());
    return 1;
  }

  try {
    if (command === "scan") {
      print(
        `Investigating ${target} (static analysis only; package is not executed)…\n`,
      );
      const result = await scanPackage(target);
      print(formatInvestigationReport(result));
      return 0;
    }

    if (command === "fixture") {
      runFixture(target);
      return 0;
    }

    printError(usage());
    return 1;
  } catch (error) {
    if (error instanceof ScanError) {
      printError(`Scan failed [${error.code}]: ${error.message}`);
      return 2;
    }
    const message = error instanceof Error ? error.message : "Unknown error";
    printError(`Scan failed: ${message}`);
    return 2;
  }
}

const exitCode = await main(process.argv);
process.exit(exitCode);
