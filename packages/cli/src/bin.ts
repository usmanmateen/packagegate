#!/usr/bin/env node
/**
 * PackageGate CLI — investigate published npm packages without executing them.
 *
 * Usage:
 *   packagegate scan <package[@version]> [--json] [--no-color] [--color]
 *   packagegate scan-tarball <path> [--sha256 <digest>] [--json] [--no-color] [--color]
 *   packagegate fixture <name> [--json] [--no-color] [--color]
 *   packagegate diff <package@old> <package@new> [--json] [--no-color] [--color]
 *   packagegate evaluate [--malware-root <path>] [--json]
 *   packagegate --help
 */

import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ScanError } from "@packagegate/shared";
import { diffPackages } from "./diff.js";
import { formatSecurityDiffReport } from "./diff-report.js";
import { runEvaluation } from "./evaluate.js";
import { loadNamedFixture } from "./fixtures.js";
import { formatInvestigationJson } from "./output/json.js";
import { createTheme, shouldUseColor } from "./output/theme.js";
import { formatInvestigationReport } from "./report.js";
import { scanPackage } from "./scan.js";
import { scanLocalTarball } from "./scan-tarball.js";
import type { InvestigationResult } from "./types.js";

interface CliFlags {
  readonly json: boolean;
  readonly color: boolean | undefined;
  readonly expectedSha256: string | undefined;
  readonly malwareRoot: string | undefined;
  readonly ml: boolean;
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
    "  packagegate scan <package[@version]> [--json] [--ml] [--no-color] [--color]",
    "  packagegate scan-tarball <path> [--sha256 <digest>] [--json] [--ml] [--no-color] [--color]",
    "  packagegate fixture <name> [--json] [--ml] [--no-color] [--color]",
    "  packagegate diff <package@old> <package@new> [--json] [--no-color] [--color]",
    "  packagegate evaluate [--malware-root <path>] [--json]",
    "  packagegate ml-export <fixture-or-report-path> [--json]",
    "",
    "Examples:",
    "  packagegate scan lodash@4.17.21",
    "  packagegate scan lodash@4.17.21 --ml",
    "  packagegate diff express@4.20.0 express@4.21.2",
    "  packagegate diff version-diff-benign-v1 version-diff-remote-v2",
    "  packagegate fixture inert-install-curl-bash --color",
    "  packagegate evaluate --malware-root /tmp/packagegate-malware-eval",
    "",
    "Flags:",
    "  --json                 Machine-readable JSON (never includes ANSI colour)",
    "  --ml                   Enable optional ML assessment (PACKAGEGATE_ML=local)",
    "  --sha256 <digest>      Expected SHA-256 for scan-tarball (mismatch aborts)",
    "  --malware-root <path>  Explicit quarantine root for real-malware eval samples",
    "  --no-color             Disable ANSI colour even on a TTY",
    "  --color                Force ANSI colour (useful when piping through a pager)",
    "",
    "STATIC ANALYSIS ONLY. Package code is never executed.",
    "Real malware is never auto-downloaded.",
    "ML is disabled by default and cannot independently BLOCK.",
    "Absence of findings is not evidence of safety.",
  ].join("\n");
}

function parseFlags(args: string[]): { positional: string[]; flags: CliFlags } {
  const positional: string[] = [];
  let json = false;
  let color: boolean | undefined;
  let expectedSha256: string | undefined;
  let malwareRoot: string | undefined;
  let ml = false;

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]!;
    if (arg === "--json") {
      json = true;
      continue;
    }
    if (arg === "--ml") {
      ml = true;
      continue;
    }
    if (arg === "--no-color") {
      color = false;
      continue;
    }
    if (arg === "--color") {
      color = true;
      continue;
    }
    if (arg === "--sha256") {
      expectedSha256 = args[index + 1];
      index += 1;
      continue;
    }
    if (arg.startsWith("--sha256=")) {
      expectedSha256 = arg.slice("--sha256=".length);
      continue;
    }
    if (arg === "--malware-root") {
      malwareRoot = args[index + 1];
      index += 1;
      continue;
    }
    if (arg.startsWith("--malware-root=")) {
      malwareRoot = arg.slice("--malware-root=".length);
      continue;
    }
    if (arg.startsWith("-")) {
      throw new Error(`Unknown flag: ${arg}`);
    }
    positional.push(arg);
  }

  return {
    positional,
    flags: { json, color, expectedSha256, malwareRoot, ml },
  };
}

function resolveColor(
  forceColor: boolean | undefined,
  stream: { isTTY?: boolean },
): boolean {
  if (forceColor === true) return true;
  if (forceColor === false) return false;
  return shouldUseColor({
    stream,
    env: process.env,
  });
}

function emitResult(result: InvestigationResult, flags: CliFlags): void {
  if (flags.json) {
    printRaw(formatInvestigationJson(result));
    return;
  }
  const color = resolveColor(flags.color, process.stdout);
  print(formatInvestigationReport(result, { color }));
}

function formatCliError(error: unknown): string {
  const theme = createTheme({
    enabled: resolveColor(undefined, process.stderr),
  });
  const prefix = theme.errorPrefix("error");

  if (error instanceof ScanError) {
    return `${prefix}: Scan failed [${error.code}]: ${error.message}`;
  }
  const message = error instanceof Error ? error.message : "Unknown error";
  return `${prefix}: Scan failed: ${message}`;
}

function repoRoot(): string {
  return join(dirname(fileURLToPath(import.meta.url)), "../../..");
}

function runFixture(name: string): InvestigationResult {
  return loadNamedFixture(name);
}

async function main(argv: string[]): Promise<number> {
  const args = argv.slice(2);
  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    print(usage());
    return args.length === 0 ? 1 : 0;
  }

  try {
    const { positional, flags } = parseFlags(args);
    const [command, target, target2] = positional;

    if (command === undefined) {
      printError(usage());
      return 1;
    }

    if (command === "evaluate") {
      if (positional.length !== 1) {
        printError(usage());
        return 1;
      }
      if (flags.expectedSha256 !== undefined) {
        throw new Error("--sha256 is only valid with scan-tarball");
      }
      const report = await runEvaluation({
        ...(flags.malwareRoot === undefined ? {} : { malwareRoot: flags.malwareRoot }),
        fixtureRoot: join(repoRoot(), "fixtures"),
      });
      if (flags.json) {
        printRaw(`${JSON.stringify(report, null, 2)}\n`);
      } else {
        print(themeEvaluate(report, flags.color));
      }
      return 0;
    }

    if (command === "diff") {
      if (target === undefined || target2 === undefined || positional.length !== 3) {
        printError(usage());
        return 1;
      }
      if (flags.expectedSha256 !== undefined) {
        throw new Error("--sha256 is only valid with scan-tarball");
      }
      if (!flags.json) {
        print(
          `Comparing ${target} → ${target2} (static analysis only; never executed)…\n`,
        );
      }
      const { diff } = await diffPackages(target, target2);
      if (flags.json) {
        printRaw(`${JSON.stringify(diff, null, 2)}\n`);
      } else {
        const color = resolveColor(flags.color, process.stdout);
        print(formatSecurityDiffReport(diff, { color }));
      }
      return 0;
    }

    if (target === undefined || positional.length !== 2) {
      printError(usage());
      return 1;
    }

    if (command === "scan") {
      if (flags.expectedSha256 !== undefined) {
        throw new Error("--sha256 is only valid with scan-tarball");
      }
      if (!flags.json) {
        print(
          `Investigating ${target} (static analysis only; package is not executed)…\n`,
        );
      }
      const result = await scanPackage(target, { ml: flags.ml });
      emitResult(result, flags);
      return 0;
    }

    if (command === "scan-tarball") {
      if (!flags.json) {
        print(
          `Investigating local tarball ${target} (static analysis only; never executed)…\n`,
        );
      }
      const result = await scanLocalTarball(target, {
        ...(flags.expectedSha256 === undefined
          ? {}
          : { expectedSha256: flags.expectedSha256 }),
        ml: flags.ml,
      });
      emitResult(result, flags);
      return 0;
    }

    if (command === "fixture") {
      if (flags.expectedSha256 !== undefined) {
        throw new Error("--sha256 is only valid with scan-tarball");
      }
      if (!flags.json) {
        print(
          `Investigating fixture ${target} (static analysis only; never executed)…\n`,
        );
      }
      let result = runFixture(target);
      if (flags.ml) {
        const { withMlAssessment } = await import("./ml/apply.js");
        const { loadNamedFixtureSources } = await import("./fixtures.js");
        const sources = loadNamedFixtureSources(target);
        result = await withMlAssessment(result, {
          enabled: true,
          sourceByPath: sources,
        });
      }
      emitResult(result, flags);
      return 0;
    }

    if (command === "ml-export") {
      if (target === undefined || positional.length !== 2) {
        printError(usage());
        return 1;
      }
      const { exportPackageGateMlRecord } = await import("./ml/export.js");
      const { loadNamedFixtureSources } = await import("./fixtures.js");
      const result = runFixture(target);
      const record = exportPackageGateMlRecord(result, {
        sourceByPath: loadNamedFixtureSources(target),
      });
      printRaw(`${JSON.stringify(record, null, 2)}\n`);
      return 0;
    }

    printError(usage());
    return 1;
  } catch (error) {
    printError(formatCliError(error));
    return 2;
  }
}

function themeEvaluate(
  report: Awaited<ReturnType<typeof runEvaluation>>,
  forceColor: boolean | undefined,
): string {
  const theme = createTheme({
    enabled: resolveColor(forceColor, process.stdout),
  });
  const lines: string[] = [];
  lines.push(theme.heading("PACKAGEGATE EVALUATION"));
  lines.push(theme.muted("======================"));
  lines.push("");
  for (const result of report.results) {
    const status =
      result.status === "COMPLETED"
        ? theme.success(result.status)
        : result.status === "SKIPPED"
          ? theme.warning(result.status)
          : theme.danger(result.status);
    const action =
      result.finalAction === undefined
        ? ""
        : ` → ${theme.colourRecommendation(result.finalAction)}`;
    lines.push(`  ${result.id} [${result.label}] ${status}${action}`);
    if (result.skipReason) lines.push(`    ${theme.muted(result.skipReason)}`);
    if (result.failureReason) lines.push(`    ${theme.danger(result.failureReason)}`);
  }
  lines.push("");
  lines.push(theme.heading("Intervention matrix"));
  lines.push(
    `  TP=${String(report.matrix.tp)} TN=${String(report.matrix.tn)} FP=${String(report.matrix.fp)} FN=${String(report.matrix.fn)} (n=${String(report.matrix.sampleCount)})`,
  );
  if (report.matrix.sampleCount > 0) {
    lines.push(
      `  precision=${fmt(report.matrix.precision)} recall=${fmt(report.matrix.recall)}`,
    );
  }
  lines.push("");
  lines.push(theme.muted(report.disclaimer));
  return lines.join("\n");
}

function fmt(value: number | null): string {
  return value === null ? "n/a" : value.toFixed(2);
}

const exitCode = await main(process.argv);

// Set the exit code and let Node terminate once stdout has drained, rather
// than calling process.exit().
//
// Writing to a pipe is asynchronous. process.exit() tears the process down
// immediately and discards anything still buffered, which silently truncates
// output at the pipe capacity (~64KB on Linux) whenever the consumer is slower
// to start than we are to write. `packagegate scan --json | jq` would then
// receive invalid JSON — the worst possible failure for output whose whole
// purpose is automation, because it corrupts rather than errors.
process.exitCode = exitCode;
