import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { investigateSources } from "./investigate.js";
import type { InvestigationResult } from "./types.js";

/**
 * Resolve the monorepo fixtures directory from the CLI package location.
 */
export function fixturesRoot(): string {
  return join(dirname(fileURLToPath(import.meta.url)), "../../../fixtures");
}

/**
 * Load an inert fixture by directory name under `fixtures/`.
 * Never executes package code.
 */
export function loadNamedFixture(name: string): InvestigationResult {
  const root = join(fixturesRoot(), name);
  const manifestPath = join(root, "package.json");
  if (!existsSync(manifestPath)) {
    throw new Error(`Unknown fixture: ${name}`);
  }
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
  const scripts: Record<string, string> =
    parsed !== null &&
    typeof parsed === "object" &&
    "scripts" in parsed &&
    parsed.scripts !== null &&
    typeof parsed.scripts === "object"
      ? Object.fromEntries(
          Object.entries(parsed.scripts as Record<string, unknown>).filter(
            (entry): entry is [string, string] => typeof entry[1] === "string",
          ),
        )
      : {};

  const files = [{ path: "package.json", content: manifest }];
  for (const entry of readdirSync(root)) {
    if (!/\.(?:[cm]?js|jsx|[cm]?ts|tsx)$/i.test(entry)) continue;
    files.push({
      path: entry,
      content: readFileSync(join(root, entry), "utf8"),
    });
  }

  return investigateSources({
    requestedSpec: `${packageName}@${version}`,
    resolved: { name: packageName, version },
    files,
    scripts,
    manifestText: manifest,
  });
}

/**
 * Source map for a fixture — used for ML slice export without re-reading labels.
 */
export function loadNamedFixtureSources(
  name: string,
): Map<string, string> {
  const root = join(fixturesRoot(), name);
  const manifestPath = join(root, "package.json");
  if (!existsSync(manifestPath)) {
    throw new Error(`Unknown fixture: ${name}`);
  }
  const files = new Map<string, string>();
  files.set("package.json", readFileSync(manifestPath, "utf8"));
  for (const entry of readdirSync(root)) {
    if (!/\.(?:[cm]?js|jsx|[cm]?ts|tsx)$/i.test(entry)) continue;
    files.set(entry, readFileSync(join(root, entry), "utf8"));
  }
  return files;
}

/**
 * Resolve a diff/scan target: `fixture:<name>`, bare fixture directory name,
 * or a published package spec via the registry pipeline.
 */
export function resolveFixtureSpec(spec: string): string | undefined {
  if (spec.startsWith("fixture:")) {
    return spec.slice("fixture:".length);
  }
  if (existsSync(join(fixturesRoot(), spec, "package.json"))) {
    return spec;
  }
  return undefined;
}
