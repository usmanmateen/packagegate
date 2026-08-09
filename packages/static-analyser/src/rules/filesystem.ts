import * as t from "@babel/types";
import type { Evidence, FindingCategory, Severity } from "@packagegate/shared";
import { sanitiseInlineValue } from "@packagegate/shared";
import {
  FILESYSTEM_MODULES,
  FILESYSTEM_READ_MEMBERS,
  FILESYSTEM_WRITE_MEMBERS,
  HOME_DIRECTORY_MEMBERS,
  OS_MODULE,
  PERMISSION_MEMBERS,
  SENSITIVE_PATH_PATTERNS,
  type SensitivePathClass,
} from "./catalogue.js";
import {
  argumentPaths,
  calleePath,
  effectiveMember,
  isModule,
  staticStringValue,
} from "./helpers.js";
import {
  bindingEvidenceText,
  confidenceFor,
  emitAt,
  locationOf,
  type Rule,
  type RuleContext,
} from "./types.js";

/**
 * Filesystem access, and the much more interesting question of *which files*.
 *
 * Reading and writing files is inventory: `docs/RISK_MODEL.md` puts the bare
 * capability at one point. Naming a credential file is not inventory — it is
 * purposeful, because the package told us which file it wants. So the path
 * argument is inspected whenever it is a literal, and the finding's category
 * and severity follow the path, not the call.
 */

const RULE_PREFIX = "js/filesystem";

/** Paths that make a written file executable on the next run. */
const EXECUTABLE_SUFFIXES = [".sh", ".bash", ".command", ".bat", ".cmd", ".ps1", ".exe"];

/** Locations outside the package that a write would affect the host through. */
const HOST_WRITE_MARKERS = [
  ".bashrc",
  ".zshrc",
  ".profile",
  ".zprofile",
  ".bash_profile",
  "/etc/",
  "crontab",
  "/launchagents/",
  "/systemd/",
  "startup/",
  ".git/hooks/",
];

function categoryForPathClass(pathClass: SensitivePathClass): FindingCategory {
  switch (pathClass) {
    case "PACKAGE_MANAGER_CREDENTIAL":
      return "PACKAGE_MANAGER_ACCESS";
    case "SSH_KEY":
    case "CLOUD_CREDENTIAL":
    case "GENERIC_CREDENTIAL":
      return "CREDENTIAL_RELATED_ACCESS";
    case "SHELL_HISTORY":
    case "BROWSER_OR_WALLET":
      return "SENSITIVE_FILE_ACCESS";
  }
}

/**
 * The first sensitive path pattern this literal matches.
 *
 * Substring matching inside an already-parsed literal, as the charter permits:
 * the AST established that this is a string the code uses, and only the
 * question "which file does it name" is left to pattern matching.
 */
function matchSensitivePath(
  value: string,
): (typeof SENSITIVE_PATH_PATTERNS)[number] | undefined {
  const lowered = value.toLowerCase();
  for (const pattern of SENSITIVE_PATH_PATTERNS) {
    if (lowered.includes(pattern.needle)) return pattern;
  }
  return undefined;
}

/**
 * Sensitive paths are detected wherever a literal appears, not only inside an
 * `fs` call. A credential path handed to a helper, stored in a constant or
 * pushed into an array is the same statement of intent, and requiring the
 * literal to be a direct argument would be defeated by one variable.
 */
export const sensitivePathRule: Rule = {
  id: `${RULE_PREFIX}/sensitive-path`,
  visitors: {
    StringLiteral(path, ctx) {
      inspectPathLiteral(path.node.value, path.node, ctx);
    },
    TemplateLiteral(path, ctx) {
      for (const quasi of path.node.quasis) {
        const text = quasi.value.cooked;
        if (text === null || text === undefined || text.length === 0) continue;
        inspectPathLiteral(text, quasi, ctx);
      }
    },
  },
};

function inspectPathLiteral(value: string, node: t.Node, ctx: RuleContext): void {
  if (value.length === 0 || value.length > ctx.limits.maxLiteralScanLength) return;
  const match = matchSensitivePath(value);
  if (match === undefined) return;

  emitAt(ctx, node, {
    ruleId: `${RULE_PREFIX}/sensitive-path`,
    category: categoryForPathClass(match.class),
    title: `Reference to a credential-bearing path: ${match.needle}`,
    description:
      `A string literal names ${match.description}. Naming such a file is purposeful — ` +
      "credential-chain libraries, package-manager helpers and SSH tooling do it " +
      "legitimately — and it is the most common first half of a real exfiltration payload.",
    // Serious *if* malicious; the confidence axis carries how sure we are.
    severity: "HIGH",
    confidence: "HIGH",
    evidence: [
      {
        kind: "STRING_LITERAL",
        description: `Literal naming ${match.description}`,
        location: locationOf(node, ctx.filePath),
        value: sanitiseInlineValue(value, 200),
      },
    ],
    metadata: { pathClass: match.class, matched: match.needle },
  });
}

export const filesystemRule: Rule = {
  id: RULE_PREFIX,
  visitors: {
    CallExpression(path, ctx) {
      const target = ctx.resolver.resolve(calleePath(path), ctx.limits);
      if (target === undefined) return;

      const member = effectiveMember(target);

      if (
        target.kind === "module" &&
        target.module === OS_MODULE &&
        member !== undefined &&
        HOME_DIRECTORY_MEMBERS.has(member)
      ) {
        emitAt(ctx, path.node, {
          ruleId: `${RULE_PREFIX}/home-directory`,
          category: "HOME_DIRECTORY_ACCESS",
          title: "Home directory located via os.homedir()",
          description:
            "The package resolves the current user's home directory. Dotfile tooling, cache " +
            "directories and config lookup all do this; it is recorded because it is the " +
            "root of most credential paths.",
          severity: "LOW",
          confidence: confidenceFor(target),
          evidence: [
            {
              kind: "AST_NODE",
              description: "Call to `os.homedir()`",
              location: locationOf(path.node, ctx.filePath),
            },
          ],
          metadata: { module: target.module, member },
        });
        return;
      }

      if (!isModule(target, FILESYSTEM_MODULES) || member === undefined) return;

      const reads = FILESYSTEM_READ_MEMBERS.has(member);
      const writes = FILESYSTEM_WRITE_MEMBERS.has(member);
      if (!reads && !writes) return;

      const args = argumentPaths(path);
      const firstNode = args[0]?.node;
      const literalPath =
        firstNode === undefined ? undefined : staticStringValue(firstNode);

      const evidence: Evidence[] = [
        {
          kind: "AST_NODE",
          description: `Call to \`${target.module}.${member}\``,
          location: locationOf(path.node, ctx.filePath),
        },
        {
          kind: "BINDING",
          description: bindingEvidenceText(target),
          ...(target.declaration === undefined ? {} : { location: target.declaration }),
        },
      ];
      if (literalPath !== undefined) {
        evidence.push({
          kind: "STRING_LITERAL",
          description: "Path operand, taken verbatim from the source",
          location: locationOf(firstNode ?? path.node, ctx.filePath),
          value: sanitiseInlineValue(literalPath, 200),
        });
      }

      let severity: Severity = "LOW";
      let category: FindingCategory = reads ? "FILESYSTEM_READ" : "FILESYSTEM_WRITE";
      let title = reads
        ? `Filesystem read via ${target.module}.${member}`
        : `Filesystem write via ${target.module}.${member}`;
      let description = reads
        ? "The package reads from the filesystem. Recorded as a capability; nearly every " +
          "package does this."
        : "The package writes to the filesystem. Recorded as a capability; build tooling, " +
          "caches and generated output all write files.";

      const loweredPath = literalPath?.toLowerCase() ?? "";

      if (writes && HOST_WRITE_MARKERS.some((marker) => loweredPath.includes(marker))) {
        severity = "MEDIUM";
        title = `Write to a host configuration path via ${target.module}.${member}`;
        description =
          "The write target is a shell profile, service definition, cron table or git hook — " +
          "a location that changes the behaviour of the machine rather than the package. " +
          "Version-manager installers and git-hook tooling do exactly this.";
      } else if (
        writes &&
        EXECUTABLE_SUFFIXES.some((suffix) => loweredPath.endsWith(suffix))
      ) {
        severity = "MEDIUM";
        category = "EXECUTABLE_WRITE";
        title = `Executable file written via ${target.module}.${member}`;
        description =
          "The package writes a file whose extension makes it directly executable. This is " +
          "the last step of a dropper and also how platform shims are installed.";
      } else if (writes && PERMISSION_MEMBERS.has(member)) {
        const mode = args[1]?.node;
        const executable = mode !== undefined && isExecutableMode(mode);
        if (executable) {
          severity = "MEDIUM";
          category = "EXECUTABLE_WRITE";
          title = "File made executable via chmod";
          description =
            "The package sets an executable permission bit on a file. Native-module builds " +
            "and CLI installers do this; so does a dropper immediately before running its " +
            "payload.";
        }
      }

      emitAt(ctx, path.node, {
        ruleId: reads ? `${RULE_PREFIX}/read` : `${RULE_PREFIX}/write`,
        category,
        title,
        description,
        severity,
        confidence: confidenceFor(target),
        evidence,
        metadata: {
          module: target.module,
          member,
          pathIsLiteral: literalPath !== undefined,
          ...(literalPath === undefined
            ? {}
            : { path: sanitiseInlineValue(literalPath, 200) }),
        },
      });
    },
  },
};

/** Does this mode operand grant execute permission to anyone? */
function isExecutableMode(node: t.Node): boolean {
  if (t.isNumericLiteral(node)) {
    // 0o111 is the union of the three execute bits.
    return (node.value & 0o111) !== 0;
  }
  const literal = staticStringValue(node);
  if (literal === undefined) return false;
  const parsed = Number.parseInt(literal, 8);
  return Number.isFinite(parsed) && (parsed & 0o111) !== 0;
}
