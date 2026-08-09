import type {
  Finding,
  LifecycleScript,
  Severity,
  SourceLocation,
} from "@packagegate/shared";
import {
  INSTALL_LIFECYCLE_SCRIPTS,
  isSafeRelativePath,
  sanitiseInlineValue,
} from "@packagegate/shared";
import { FindingEmitter } from "./emitter.js";
import type { AnalysisLimits } from "./limits.js";
import type { LimitNotice } from "./types.js";

/**
 * Lifecycle script analysis.
 *
 * npm runs these commands during `npm install`, unattended, before any human
 * has read the code, with the installing user's full privileges — and
 * `--ignore-scripts` defaults to false. That is why the location factor for
 * install scripts is the highest in `docs/RISK_MODEL.md`.
 *
 * It is emphatically **not** why their presence is scored highly. Install
 * scripting is a designed npm feature: native modules compile, prebuilt
 * binaries are fetched, git hooks are installed, platform shims are written.
 * Presence is LOW severity inventory. What the command *does* is what varies.
 *
 * The second job here is the bridge into the rest of the analyser:
 * `referencedFiles` recovers the package-relative files a command invokes so
 * the pipeline can go and analyse the code that actually runs. A `postinstall`
 * of `node scripts/install.js` tells us almost nothing; `scripts/install.js`
 * tells us everything.
 */

const RULE_PREFIX = "manifest/lifecycle";

const INSTALL_SCRIPT_NAMES: ReadonlySet<string> = new Set(INSTALL_LIFECYCLE_SCRIPTS);

/** Interpreters whose next non-flag argument is a script file. */
const INTERPRETERS: ReadonlySet<string> = new Set([
  "node",
  "nodejs",
  "npx",
  "ts-node",
  "tsx",
  "bun",
  "deno",
  "sh",
  "bash",
  "zsh",
  "python",
  "python3",
  "ruby",
  "perl",
  "pwsh",
  "powershell",
]);

/** Extensions that make a token a plausible script reference. */
const SCRIPT_EXTENSIONS = [
  ".js",
  ".cjs",
  ".mjs",
  ".ts",
  ".mts",
  ".cts",
  ".sh",
  ".bash",
  ".py",
  ".rb",
  ".pl",
  ".ps1",
  ".bat",
  ".cmd",
];

/** Downloaders whose output commonly becomes executable content. */
const DOWNLOADERS = ["curl", "wget", "fetch ", "iwr ", "invoke-webrequest"];

/**
 * Command-string parsing is the one place in this package where a real parser
 * is not available. There is no maintained, safe, cross-shell command parser
 * that models bash, sh, cmd and PowerShell quoting, and writing one would be a
 * far larger correctness risk than the bounded string handling below.
 *
 * The mitigations are: the command is never executed and never passed to a
 * shell; parsing is bounded by `limits.maxCommandLength`; every recovered path
 * is validated with `isSafeRelativePath`, so nothing absolute and nothing
 * containing `..` can escape into the pipeline as a file to open.
 *
 * The splitter recognises the shell operators that separate commands. It does
 * not model quoting of those operators, so `echo "a && b"` is treated as two
 * commands. That over-splits, which costs a little precision and no safety.
 */
const COMMAND_SEPARATOR = /\s*(?:&&|\|\||;|\||&)\s*/;

/** Whitespace splitting for tokens inside one command. */
const TOKEN_SEPARATOR = /\s+/;

function stripQuotes(token: string): string {
  if (token.length < 2) return token;
  const first = token[0];
  const last = token[token.length - 1];
  if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
    return token.slice(1, -1);
  }
  return token;
}

/** Normalise `./scripts/x.js` → `scripts/x.js` for comparison against paths. */
function normaliseReference(candidate: string): string | undefined {
  let value = stripQuotes(candidate.trim());
  if (value.length === 0) return undefined;
  // Strip a `./` prefix; deeper normalisation is deliberately not attempted,
  // and anything that is not already package-relative is rejected outright.
  while (value.startsWith("./")) value = value.slice(2);
  if (value.length === 0) return undefined;
  if (!isSafeRelativePath(value)) return undefined;
  return value;
}

function looksLikeScriptPath(token: string): boolean {
  const lowered = token.toLowerCase();
  return SCRIPT_EXTENSIONS.some((extension) => lowered.endsWith(extension));
}

/**
 * Package-relative files a command appears to invoke.
 *
 * Best-effort by construction, and documented as such: a command can name a
 * file this cannot see (`node -e`, a path built from a variable, a binary from
 * `node_modules/.bin`). Missing a reference costs coverage; inventing one would
 * cost correctness, so only literal, package-relative, script-shaped tokens are
 * returned.
 */
export function referencedFilesOf(command: string, limits: AnalysisLimits): string[] {
  const bounded = command.slice(0, limits.maxCommandLength);
  const found: string[] = [];
  const seen = new Set<string>();

  const segments = bounded.split(COMMAND_SEPARATOR);
  // Bounded on both axes so a crafted command cannot produce unbounded work.
  for (const segment of segments.slice(0, 64)) {
    const tokens = segment.trim().split(TOKEN_SEPARATOR).slice(0, 64);
    if (tokens.length === 0) continue;

    const head = stripQuotes(tokens[0] ?? "").toLowerCase();
    const headIsInterpreter = INTERPRETERS.has(head) || head.endsWith("/node");

    for (let index = 0; index < tokens.length; index += 1) {
      const raw = tokens[index];
      if (raw === undefined) continue;
      const token = stripQuotes(raw);
      if (token.startsWith("-")) continue;
      if (index === 0 && !headIsInterpreter && !looksLikeScriptPath(token)) continue;
      if (index === 0 && headIsInterpreter) continue;
      if (!looksLikeScriptPath(token)) continue;

      const reference = normaliseReference(token);
      if (reference === undefined || seen.has(reference)) continue;
      seen.add(reference);
      found.push(reference);
      if (found.length >= 16) return found;
    }
  }

  return found;
}

export interface LifecycleAnalysisInput {
  /** The `scripts` object from the tarball's `package.json`. */
  readonly scripts: Readonly<Record<string, string>>;
  /** Raw manifest text, used only to report a line number. Optional. */
  readonly manifestText?: string;
  /** Manifest path for evidence. Defaults to `package.json`. */
  readonly manifestPath?: string;
}

export interface LifecycleAnalysisResult {
  readonly lifecycleScripts: LifecycleScript[];
  readonly findings: Finding[];
  readonly limitNotices: LimitNotice[];
}

/**
 * Best-effort line number of a script entry inside the manifest text.
 *
 * Reported so a finding points at something a human can open. When the manifest
 * text is unavailable or the key cannot be found, line 1 is used — honest and
 * bounded, rather than omitting the location the schema requires.
 */
function locateScript(
  name: string,
  manifestPath: string,
  manifestText: string | undefined,
): SourceLocation {
  if (manifestText === undefined) {
    return { filePath: manifestPath, startLine: 1, endLine: 1 };
  }
  const scriptsAt = manifestText.indexOf('"scripts"');
  const searchFrom = scriptsAt === -1 ? 0 : scriptsAt;
  const keyAt = manifestText.indexOf(`"${name}"`, searchFrom);
  if (keyAt === -1) return { filePath: manifestPath, startLine: 1, endLine: 1 };

  let line = 1;
  for (let index = 0; index < keyAt; index += 1) {
    if (manifestText.charCodeAt(index) === 0x0a) line += 1;
  }
  return { filePath: manifestPath, startLine: line, endLine: line };
}

interface CommandShape {
  readonly pipesToInterpreter: boolean;
  readonly downloads: boolean;
  readonly inlineCode: boolean;
  readonly decodesBase64: boolean;
  readonly chained: boolean;
}

/**
 * Structural facts about a command string. Each is a plain substring test on a
 * bounded string — no interpretation, no execution.
 */
function shapeOf(command: string): CommandShape {
  const lowered = command.toLowerCase();
  const downloads = DOWNLOADERS.some((tool) => lowered.includes(tool));
  const piped = lowered.includes("|");
  const pipesToInterpreter =
    piped &&
    downloads &&
    /\|\s*(?:sudo\s+)?(?:sh|bash|zsh|node|python3?|ruby|perl|pwsh)\b/.test(lowered);

  return {
    pipesToInterpreter,
    downloads,
    // `node -e`, `node --eval`, `python -c`: code that exists only in the
    // manifest and therefore in no file a reviewer would open.
    inlineCode:
      /\b(?:node|nodejs|deno|bun)\s+(?:-e|--eval)\b/.test(lowered) ||
      /\bpython3?\s+-c\b/.test(lowered) ||
      lowered.includes("eval("),
    decodesBase64:
      lowered.includes("base64 -d") ||
      lowered.includes("base64 --decode") ||
      lowered.includes("frombase64string"),
    chained: /&&|\|\||;/.test(command),
  };
}

/**
 * Analyse the manifest's `scripts`.
 *
 * Produces one {@link LifecycleScript} per entry — including scripts that do
 * not run on install, because `prepare`, `prepublishOnly` and friends still
 * matter to a reviewer — and findings only for the ones npm runs automatically
 * plus any script whose *content* is notable.
 */
export function analyseLifecycleScripts(
  input: LifecycleAnalysisInput,
  limits: AnalysisLimits,
): LifecycleAnalysisResult {
  const manifestPath = input.manifestPath ?? "package.json";
  const emitter = new FindingEmitter({
    filePath: manifestPath,
    source: input.manifestText ?? "",
    limits,
    minified: false,
    totalBudgetRemaining: limits.maxFindingsTotal,
  });

  const lifecycleScripts: LifecycleScript[] = [];
  const entries = Object.entries(input.scripts);

  // Bounded: a manifest is attacker-controlled and can declare any number of
  // scripts.
  for (const [name, rawCommand] of entries.slice(0, 200)) {
    if (typeof rawCommand !== "string") continue;
    const command = rawCommand.slice(0, limits.maxCommandLength);
    const runsOnInstall = INSTALL_SCRIPT_NAMES.has(name);
    const referencedFiles = referencedFilesOf(command, limits);

    lifecycleScripts.push({
      name,
      command: sanitiseInlineValue(command, 1_000),
      runsOnInstall,
      referencedFiles,
    });

    const location = locateScript(name, manifestPath, input.manifestText);
    const shape = shapeOf(command);

    if (runsOnInstall) {
      emitter.emit({
        ruleId: `${RULE_PREFIX}/install-script`,
        category: "INSTALL_SCRIPT",
        title: `Install lifecycle script declared: ${name}`,
        description:
          `The manifest declares a \`${name}\` script, which npm runs automatically during ` +
          "installation with the installing user's privileges. Install scripting is a " +
          "designed npm feature used by native modules, binary fetchers and git-hook " +
          "installers; its presence is recorded as context, not as a problem.",
        severity: "LOW",
        confidence: "HIGH",
        location,
        rawSnippet: command,
        evidence: [
          {
            kind: "MANIFEST_FIELD",
            description: `scripts.${name}`,
            location,
            value: sanitiseInlineValue(command, 300),
          },
        ],
        metadata: { script: name, runsOnInstall, referencedFiles },
      });
    }

    emitCommandShapeFindings({
      emitter,
      name,
      command,
      shape,
      location,
      runsOnInstall,
    });
  }

  const { findings, notices } = emitter.results();
  return { lifecycleScripts, findings, limitNotices: notices };
}

function emitCommandShapeFindings(args: {
  emitter: FindingEmitter;
  name: string;
  command: string;
  shape: CommandShape;
  location: SourceLocation;
  runsOnInstall: boolean;
}): void {
  const { emitter, name, command, shape, location, runsOnInstall } = args;
  const value = sanitiseInlineValue(command, 300);
  const context = runsOnInstall ? "an install-time script" : "a lifecycle script";

  const evidence = [
    {
      kind: "MANIFEST_FIELD" as const,
      description: `scripts.${name}`,
      location,
      value,
    },
  ];

  if (shape.pipesToInterpreter) {
    // Fetching and executing in one command is the canonical dropper shape —
    // and also, honestly, how several legitimate install scripts still work.
    emitter.emit({
      ruleId: `${RULE_PREFIX}/fetch-and-execute`,
      category: "REMOTE_CODE_FETCH",
      title: `Downloaded content piped to an interpreter in ${context}`,
      description:
        `The \`${name}\` script downloads content and pipes it straight into a shell or ` +
        "interpreter, so the code that runs is never present in the package and cannot be " +
        "reviewed. Some legitimate installers still do this; nothing about the artefact is " +
        "verifiable when they do.",
      severity: "HIGH",
      confidence: "HIGH",
      location,
      rawSnippet: command,
      evidence,
      metadata: { script: name, runsOnInstall },
    });
  } else if (shape.downloads) {
    emitter.emit({
      ruleId: `${RULE_PREFIX}/downloads`,
      category: "DOWNLOAD_BEHAVIOUR",
      title: `Network download in ${context}`,
      description:
        `The \`${name}\` script downloads a file. Prebuilt-binary distribution works exactly ` +
        "this way across the ecosystem; whether the artefact's integrity is checked is what " +
        "separates it from a dropper.",
      severity: runsOnInstall ? "MEDIUM" : "LOW",
      confidence: "HIGH",
      location,
      rawSnippet: command,
      evidence,
      metadata: { script: name, runsOnInstall },
    });
  }

  if (shape.inlineCode || shape.decodesBase64) {
    const severity: Severity = runsOnInstall ? "MEDIUM" : "LOW";
    emitter.emit({
      ruleId: `${RULE_PREFIX}/inline-code`,
      category: shape.decodesBase64 ? "ENCODED_PAYLOAD" : "SHELL_COMMAND",
      title: `Executable code embedded in ${context}`,
      description:
        `The \`${name}\` script ${
          shape.decodesBase64
            ? "decodes base64 content before running it"
            : "passes code inline to an interpreter"
        }, so the logic that runs lives in the manifest rather than in a file the ` +
        "repository can show a reviewer.",
      severity,
      confidence: "HIGH",
      location,
      rawSnippet: command,
      evidence,
      metadata: { script: name, runsOnInstall, inlineCode: shape.inlineCode },
    });
  }
}
