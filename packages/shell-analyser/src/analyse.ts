import { sanitiseInlineValue } from "@packagegate/shared";
import { splitSegments, stripQuotes, tokeniseCommand } from "./tokenise.js";
import type {
  ShellAnalyseInput,
  ShellAnalyseResult,
  ShellFindingDraft,
  ShellOperation,
  ShellOperationKind,
} from "./types.js";

const DEFAULT_MAX_COMMAND = 4_096;
const DEFAULT_MAX_TOKENS = 128;

const DOWNLOAD_TOOLS = new Set([
  "curl",
  "wget",
  "invoke-webrequest",
  "iwr",
  "invoke-restmethod",
  "irm",
  "certutil",
  "bitsadmin",
]);

const INTERPRETERS = new Set([
  "sh",
  "bash",
  "zsh",
  "dash",
  "cmd",
  "cmd.exe",
  "powershell",
  "powershell.exe",
  "pwsh",
  "pwsh.exe",
]);

const DECODE_TOOLS = new Set(["base64", "tar", "unzip", "gzip", "certutil"]);

function basenameTool(token: string): string {
  const bare = stripQuotes(token);
  const slash = Math.max(bare.lastIndexOf("/"), bare.lastIndexOf("\\"));
  const name = slash === -1 ? bare : bare.slice(slash + 1);
  return name.toLowerCase();
}

function looksLikeUrl(token: string): boolean {
  const value = stripQuotes(token).toLowerCase();
  return (
    value.startsWith("http://") ||
    value.startsWith("https://") ||
    value.startsWith("ftp://")
  );
}

function isVersionOnlyCurl(args: string[]): boolean {
  return args.some((a) => a === "--version" || a === "-V");
}

function classifySegment(args: readonly string[], start: number, end: number): ShellOperation | null {
  if (args.length === 0) return null;
  const tool = basenameTool(args[0]!);
  const rest = args.slice(1).map(stripQuotes);

  if (DOWNLOAD_TOOLS.has(tool)) {
    if (tool === "curl" && isVersionOnlyCurl(rest)) {
      return {
        kind: "UNKNOWN",
        tool,
        tokenStart: start,
        tokenEnd: end,
        summary: "curl version probe (not a download)",
      };
    }

    let outputPath: string | undefined;
    let destinationUrl: string | undefined;
    for (let i = 0; i < rest.length; i += 1) {
      const arg = rest[i]!;
      if (arg === "-o" || arg === "--output" || arg === "-O") {
        const next = rest[i + 1];
        if (next !== undefined && arg !== "-O") outputPath = next;
        continue;
      }
      if (arg.startsWith("-o") && arg.length > 2) {
        outputPath = arg.slice(2);
        continue;
      }
      if (looksLikeUrl(arg)) destinationUrl = stripQuotes(arg);
    }

    // PowerShell irm/iwr without URL still counts as download capability only
    // when a URL is statically present.
    if (destinationUrl === undefined && !["certutil", "bitsadmin"].includes(tool)) {
      // wget/curl without URL — still a download tool invocation but weak.
      return {
        kind: "REMOTE_DOWNLOAD",
        tool,
        tokenStart: start,
        tokenEnd: end,
        summary: `${tool} invoked without a static URL`,
      };
    }

    return {
      kind: "REMOTE_DOWNLOAD",
      tool,
      destinationUrl,
      outputPath,
      tokenStart: start,
      tokenEnd: end,
      summary:
        destinationUrl === undefined
          ? `${tool} remote download`
          : `${tool} download from ${sanitiseInlineValue(destinationUrl, 80)}`,
    };
  }

  if (INTERPRETERS.has(tool) || tool === "iex" || tool === "invoke-expression") {
    return {
      kind: "SHELL_INTERPRETER",
      tool,
      interpreter: tool,
      tokenStart: start,
      tokenEnd: end,
      summary: `shell interpreter ${tool}`,
    };
  }

  if (tool === "chmod") {
    const mode = rest[0];
    const target = rest[1];
    const executable =
      mode !== undefined &&
      (mode.includes("+x") || /^[0-7]*[1357]$/.test(mode) || mode === "755" || mode === "775");
    if (executable) {
      return {
        kind: "PERMISSION_CHANGE",
        tool,
        outputPath: target,
        tokenStart: start,
        tokenEnd: end,
        summary: `chmod executable ${target ?? ""}`.trim(),
      };
    }
  }

  if (DECODE_TOOLS.has(tool)) {
    const decode =
      tool === "base64" && rest.some((a) => a === "-d" || a === "--decode" || a === "-D");
    if (decode || tool === "tar" || tool === "unzip") {
      return {
        kind: "ARCHIVE_DECODE",
        tool,
        tokenStart: start,
        tokenEnd: end,
        summary: `${tool} decode/extract`,
      };
    }
  }

  // ./path or /tmp/path style invocation
  const first = stripQuotes(args[0]!);
  if (
    first.startsWith("./") ||
    first.startsWith("/") ||
    first.startsWith(".\\") ||
    /^[A-Za-z]:\\/.test(first)
  ) {
    return {
      kind: "EXECUTABLE_INVOCATION",
      tool: first,
      outputPath: first,
      tokenStart: start,
      tokenEnd: end,
      summary: `execute ${sanitiseInlineValue(first, 80)}`,
    };
  }

  if (["node", "bun", "python", "python3", "deno"].includes(tool) && rest[0]) {
    const script = rest.find((a) => !a.startsWith("-"));
    if (script !== undefined) {
      return {
        kind: "EXECUTABLE_INVOCATION",
        tool,
        outputPath: script,
        tokenStart: start,
        tokenEnd: end,
        summary: `${tool} ${sanitiseInlineValue(script, 80)}`,
      };
    }
  }

  return null;
}

function findingForOperation(
  op: ShellOperation,
  sink: string,
): ShellFindingDraft | null {
  const evidenceValue = sanitiseInlineValue(op.summary, 200);
  if (op.kind === "REMOTE_DOWNLOAD") {
    const hasUrl = op.destinationUrl !== undefined;
    return {
      ruleId: "js/shell/remote-download",
      category: hasUrl ? "REMOTE_CODE_FETCH" : "DOWNLOAD_BEHAVIOUR",
      title: hasUrl
        ? `Shell remote download via ${op.tool ?? "downloader"}`
        : `Shell download tool invoked (${op.tool ?? "downloader"})`,
      description:
        `A process-execution sink (\`${sink}\`) runs a shell command that invokes ` +
        `${op.tool ?? "a download tool"}. The command string is analysed as data only — ` +
        "PackageGate never executes it. Remote download at install or runtime is common " +
        "for binary installers; piping into an interpreter is what elevates concern.",
      severity: hasUrl ? "MEDIUM" : "LOW",
      confidence: hasUrl ? "HIGH" : "MEDIUM",
      evidenceValue,
      metadata: {
        shellOperation: op.kind,
        tool: op.tool,
        destinationUrl: op.destinationUrl,
        outputPath: op.outputPath,
        executionSink: sink,
      },
    };
  }

  if (op.kind === "SHELL_INTERPRETER") {
    return {
      ruleId: "js/shell/interpreter",
      category: "SHELL_COMMAND",
      title: `Shell interpreter invoked (${op.interpreter ?? op.tool})`,
      description:
        `The command executed via \`${sink}\` launches a shell/interpreter. Alone this is ` +
        "ordinary for install scripts; combined with a remote download in the same " +
        "pipeline it becomes download-and-execute evidence.",
      severity: "LOW",
      confidence: "HIGH",
      evidenceValue,
      metadata: {
        shellOperation: op.kind,
        interpreter: op.interpreter,
        executionSink: sink,
      },
    };
  }

  if (op.kind === "PERMISSION_CHANGE") {
    return {
      ruleId: "js/shell/chmod-executable",
      category: "EXECUTABLE_WRITE",
      title: "Shell marks a path executable",
      description:
        `The command run via \`${sink}\` uses chmod to set an executable mode. ` +
        "This is inventory unless linked to a prior download of the same path.",
      severity: "LOW",
      confidence: "HIGH",
      evidenceValue,
      metadata: {
        shellOperation: op.kind,
        outputPath: op.outputPath,
        executionSink: sink,
      },
    };
  }

  if (op.kind === "EXECUTABLE_INVOCATION") {
    return {
      ruleId: "js/shell/executable-invocation",
      category: "PROCESS_EXECUTION",
      title: "Shell invokes a local executable path",
      description:
        `The command run via \`${sink}\` starts a local path or runtime against a script. ` +
        "Recorded as capability context for download→execute composition.",
      severity: "LOW",
      confidence: "MEDIUM",
      evidenceValue,
      metadata: {
        shellOperation: op.kind,
        outputPath: op.outputPath,
        executionSink: sink,
      },
    };
  }

  if (op.kind === "ARCHIVE_DECODE") {
    return {
      ruleId: "js/shell/archive-decode",
      category: "ENCODED_PAYLOAD",
      title: `Shell decode/extract via ${op.tool}`,
      description:
        `The command run via \`${sink}\` decodes or extracts an archive/payload. ` +
        "This is common in installers and is recorded as context.",
      severity: "LOW",
      confidence: "MEDIUM",
      evidenceValue,
      metadata: { shellOperation: op.kind, tool: op.tool, executionSink: sink },
    };
  }

  return null;
}

/**
 * Analyse a shell command string recovered from a process-execution sink.
 *
 * NEVER executes the command.
 */
export function analyseShellCommand(input: ShellAnalyseInput): ShellAnalyseResult {
  const maxCommandLength = input.maxCommandLength ?? DEFAULT_MAX_COMMAND;
  const maxTokens = input.maxTokens ?? DEFAULT_MAX_TOKENS;
  const bounded = input.command.slice(0, maxCommandLength);
  const truncatedByLength = input.command.length > maxCommandLength;

  const { tokens, truncated: truncatedTokens } = tokeniseCommand(bounded, maxTokens);
  const segments = splitSegments(tokens);

  const operations: ShellOperation[] = [];
  const pipeIndexes: number[] = [];

  for (const segment of segments) {
    if (segment.length === 1 && segment[0]?.text === "|") {
      pipeIndexes.push(operations.length);
      continue;
    }
    const args = segment.map((t) => t.text);
    const start = segment[0]?.start ?? 0;
    const end = segment[segment.length - 1]?.end ?? start;
    const op = classifySegment(args, start, end);
    if (op !== null) operations.push(op);
    if (operations.length >= 32) break;
  }

  const findings: ShellFindingDraft[] = [];
  for (const op of operations) {
    const draft = findingForOperation(op, input.executionSink);
    if (draft !== null) findings.push(draft);
  }

  const chainHints = [];

  // curl/wget/irm … | bash/sh/iex
  for (let i = 0; i < operations.length - 1; i += 1) {
    const left = operations[i]!;
    const right = operations[i + 1]!;
    if (left.kind === "REMOTE_DOWNLOAD" && right.kind === "SHELL_INTERPRETER") {
      // Require a pipe between them in the original command for HIGH confidence.
      const between = bounded.slice(left.tokenEnd, right.tokenStart);
      if (between.includes("|")) {
        chainHints.push({
          type: "REMOTE_CONTENT_TO_SHELL" as const,
          confidence: "HIGH" as const,
          rationale:
            `Remote download (${left.tool ?? "downloader"}) is piped to ` +
            `${right.interpreter ?? "a shell interpreter"} in the same command string.`,
          operationIndexes: [i, i + 1],
        });
      }
    }
  }

  // download -o path … chmod +x path … ./path  (same path, same command string)
  const downloads = operations
    .map((op, index) => ({ op, index }))
    .filter((x) => x.op.kind === "REMOTE_DOWNLOAD" && x.op.outputPath);
  for (const { op: dl, index: di } of downloads) {
    const path = dl.outputPath!;
    const chmod = operations.findIndex(
      (op, idx) =>
        idx > di && op.kind === "PERMISSION_CHANGE" && op.outputPath === path,
    );
    const exec = operations.findIndex(
      (op, idx) =>
        idx > di &&
        op.kind === "EXECUTABLE_INVOCATION" &&
        (op.outputPath === path || op.outputPath?.endsWith(`/${path}`)),
    );
    if (chmod !== -1 && exec !== -1) {
      chainHints.push({
        type: "DOWNLOAD_WRITE_EXECUTE" as const,
        confidence: "HIGH" as const,
        rationale: `Downloaded file ${path} is marked executable and then invoked.`,
        operationIndexes: [di, chmod, exec],
      });
    }
  }

  // PowerShell: irm URL | iex  already covered by REMOTE_DOWNLOAD + SHELL_INTERPRETER
  // when iex is classified as interpreter. Also treat trailing iex after irm.
  void pipeIndexes;

  return {
    operations,
    findings,
    chainHints,
    truncated: truncatedByLength || truncatedTokens,
  };
}

export type { ShellOperationKind };
