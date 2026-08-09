#!/usr/bin/env node
/**
 * PackageGate CLI — investigate a published npm package without executing it.
 *
 * Usage:
 *   packagegate scan <package[@version]> [--json] [--no-color]
 *   packagegate fixture <name> [--json] [--no-color]
 *   packagegate --help
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ScanError } from "@packagegate/shared";
import { investigateSources } from "./investigate.js";
import { formatInvestigationJson } from "./output/json.js";
import { createTheme, shouldUseColor } from "./output/theme.js";
import { formatInvestigationReport } from "./report.js";
import { scanPackage } from "./scan.js";
import type { InvestigationResult } from "./types.js";

interface CliFlags {
  readonly json: boolean;
  readonly color: boolean | undefined;
}

function print(message: string): void {
  process.stdout.write(`${message}\n`);
}

function printRaw(message: string): void {
  process.stdout.write(message);
}

function printError(message: string): void {
  process.stderr.write(`${message}\n`);
}

function usage(): string {
  return [
    "PackageGate — npm package Trust & Safety investigation",
    "",
    "Usage:",
    "  packagegate scan <package[@version]> [--json] [--no-color]",
    "  packagegate fixture <name> [--json] [--no-color]",
    "",
    "Examples:",
    "  packagegate scan lodash@4.17.21",
    "  packagegate scan express@^4.0.0",
    "  packagegate scan @babel/parser --json",
    "  packagegate fixture inert-env-exfil",
    "",
    "Flags:",
    "  --json       Machine-readable JSON (never includes ANSI colour)",
    "  --no-color   Disable ANSI colour even on a TTY",
    "  --color      Force ANSI colour (useful when piping through a pager)",
    "",
    "The package under investigation is never installed or executed.",
    "Absence of findings is not evidence of safety.",
  ].join("\n");
}

function parseFlags(args: string[]): { positional: string[]; flags: CliFlags } {
  const positional: string[] = [];
  let json = false;
  let color: boolean | undefined;

  for (const arg of args) {
    if (arg === "--json") {
      json = true;
      continue;
    }
    if (arg === "--no-color" || arg === "--no-colour") {
      color = false;
      continue;
    }
    if (arg === "--color" || arg === "--colour") {
      color = true;
      continue;
    }
    if (arg.startsWith("-")) {
      throw new Error(`Unknown flag: ${arg}`);
    }
    positional.push(arg);
  }

  return { positional, flags: { json, color } };
}

function resolveThemeEnabled(flag: boolean | undefined): boolean {
  if (flag === false) return false;
  if (flag === true) return true;
  return shouldUseColor({ stream: process.stdout, env: process.env });
}

function emitResult(result: InvestigationResult, flags: CliFlags): void {
  if (flags.json) {
    printRaw(formatInvestigationJson(result));
    return;
  }
  print(
    formatInvestigationReport(result, {
      color: resolveThemeEnabled(flags.color),
    }),
  );
}

function formatCliError(error: unknown): string {
  const theme = createTheme({
    enabled: shouldUseColor({ stream: process.stderr, env: process.env }),
    stream: process.stderr,
  });
  const prefix = theme.errorPrefix("error");

  if (error instanceof ScanError) {
    return `${prefix}: Scan failed [${error.code}]: ${error.message}`;
  }
  const message = error instanceof Error ? error.message : "Unknown error";
  return `${prefix}: Scan failed: ${message}`;
}

function repoRoot(): string {
  // dist/bin.js → packages/cli/dist → packages/cli → packages → repo root
  return join(dirname(fileURLToPath(import.meta.url)), "../../..");
}

function runFixture(name: string): InvestigationResult {
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

  return investigateSources({
    requestedSpec: `${packageName}@${version}`,
    resolved: { name: packageName, version },
    files: [
      { path: "index.js", content: index },
      { path: "package.json", content: manifest },
    ],
    scripts: {},
    manifestText: manifest,
  });
}

async function main(argv: string[]): Promise<number> {
  const args = argv.slice(2);
  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    print(usage());
    return args.length === 0 ? 1 : 0;
  }

  try {
    const { positional, flags } = parseFlags(args);
    const [command, target] = positional;

    if (command === undefined || target === undefined || positional.length !== 2) {
      printError(usage());
      return 1;
    }

    if (command === "scan") {
      if (!flags.json) {
        print(
          `Investigating ${target} (static analysis only; package is not executed)…\n`,
        );
      }
      const result = await scanPackage(target);
      emitResult(result, flags);
      return 0;
    }

    if (command === "fixture") {
      if (!flags.json) {
        print(
          `Investigating fixture ${target} (static analysis only; never executed)…\n`,
        );
      }
      emitResult(runFixture(target), flags);
      return 0;
    }

    printError(usage());
    return 1;
  } catch (error) {
    printError(formatCliError(error));
    return 2;
  }
}

const exitCode = await main(process.argv);
process.exit(exitCode);
