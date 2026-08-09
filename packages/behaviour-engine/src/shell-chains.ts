import { createHash } from "node:crypto";
import type {
  BehaviourChain,
  ChainLink,
  Finding,
  LifecycleScript,
  SourceLocation,
} from "@packagegate/shared";
import { maxConfidenceForLinks } from "@packagegate/shared";

/**
 * Build evidenced chains from shell-semantic findings at process-execution sinks.
 *
 * A REMOTE_CODE_FETCH finding with metadata.shellChainType produced beside a
 * PROCESS_EXECUTION finding at the same sink is linked by ARGUMENT_FLOW /
 * SHELL_PIPELINE — the command string is the literal argument to exec/execSync.
 */

function findingIdHash(parts: string[]): string {
  return createHash("sha256").update(parts.join("\0")).digest("hex").slice(0, 32);
}

function sameSink(a: Finding, b: Finding): boolean {
  return (
    a.location.filePath === b.location.filePath &&
    a.location.startLine === b.location.startLine
  );
}

function lifecycleForFile(
  filePath: string,
  scripts: readonly LifecycleScript[],
): LifecycleScript | undefined {
  return scripts.find(
    (script) =>
      script.runsOnInstall &&
      script.referencedFiles.some(
        (ref) => ref === filePath || ref.endsWith(`/${filePath}`),
      ),
  );
}

export function analyseShellBehaviourChains(args: {
  readonly findings: readonly Finding[];
  readonly lifecycleScripts?: readonly LifecycleScript[];
}): BehaviourChain[] {
  const scripts = args.lifecycleScripts ?? [];
  const remote = args.findings.filter(
    (f) =>
      f.category === "REMOTE_CODE_FETCH" &&
      (f.metadata.shellChainType === "REMOTE_CONTENT_TO_SHELL" ||
        f.ruleId === "js/shell/remote-content-to-shell"),
  );
  const processFindings = args.findings.filter(
    (f) => f.category === "PROCESS_EXECUTION" && f.metadata.shellInterpreted === true,
  );

  const chains: BehaviourChain[] = [];

  for (const remoteFinding of remote) {
    const processFinding =
      processFindings.find((p) => sameSink(p, remoteFinding)) ??
      args.findings.find(
        (f) =>
          f.category === "PROCESS_EXECUTION" &&
          f.location.filePath === remoteFinding.location.filePath &&
          Math.abs(f.location.startLine - remoteFinding.location.startLine) <= 2,
      );

    if (processFinding === undefined) continue;

    const lifecycle = lifecycleForFile(remoteFinding.location.filePath, scripts);
    const installTimeRooted =
      lifecycle !== undefined ||
      remoteFinding.metadata.installReachable === true ||
      processFinding.metadata.installReachable === true;

    const links: ChainLink[] = [
      {
        kind: "ARGUMENT_FLOW",
        via: "command",
        description:
          "Statically recovered shell command string is the argument to a process-execution sink",
        location: processFinding.location,
      },
      {
        kind: "SHELL_PIPELINE",
        via: "|",
        description:
          "Remote download tool output is piped to a shell interpreter in the same command",
        location: remoteFinding.location,
      },
    ];

    if (lifecycle !== undefined) {
      const lifecycleLocation: SourceLocation = {
        filePath: "package.json",
        startLine: 1,
        endLine: 1,
      };
      links.unshift({
        kind: "LIFECYCLE_INVOCATION",
        via: lifecycle.name,
        description: `Install lifecycle script \`${lifecycle.name}\` statically invokes ${remoteFinding.location.filePath}`,
        location: lifecycleLocation,
      });
    }

    const confidence = maxConfidenceForLinks(links);
    const id = findingIdHash([
      "shell-chain",
      remoteFinding.id,
      processFinding.id,
      installTimeRooted ? "install" : "runtime",
    ]);

    chains.push({
      id,
      source: "REMOTE_DOWNLOAD",
      transformations: [],
      sink: "PROCESS_EXECUTION",
      confidence,
      links,
      supportingFindingIds: [remoteFinding.id, processFinding.id],
      filePaths: [
        ...new Set([
          remoteFinding.location.filePath,
          processFinding.location.filePath,
          ...(lifecycle !== undefined ? ["package.json"] : []),
        ]),
      ],
      rationale: installTimeRooted
        ? `Install-time remote content is downloaded and piped to a shell interpreter via ${processFinding.location.filePath}.`
        : `Remote content is downloaded and piped to a shell interpreter via ${processFinding.location.filePath}.`,
      metadata: {
        chainType: installTimeRooted
          ? "INSTALL_TIME_REMOTE_EXECUTION"
          : "REMOTE_CONTENT_TO_SHELL",
        installTimeRooted,
        runsOnInstall: installTimeRooted,
        lifecycleScript: lifecycle?.name,
        shellChainType: remoteFinding.metadata.shellChainType,
      },
    });
  }

  // DOWNLOAD_WRITE_EXECUTE hints carried on findings
  const dwe = args.findings.filter(
    (f) => f.metadata.shellChainType === "DOWNLOAD_WRITE_EXECUTE",
  );
  for (const finding of dwe) {
    const id = findingIdHash(["dwe-chain", finding.id]);
    chains.push({
      id,
      source: "REMOTE_DOWNLOAD",
      transformations: [],
      sink: "PROCESS_EXECUTION",
      confidence: "HIGH",
      links: [
        {
          kind: "SHELL_PIPELINE",
          description:
            "Download, permission change, and execution reference the same static path in one command",
          location: finding.location,
        },
      ],
      supportingFindingIds: [finding.id],
      filePaths: [finding.location.filePath],
      rationale:
        "A shell command downloads a file, marks it executable, and runs it — analysed as data only.",
      metadata: {
        chainType: "DOWNLOAD_WRITE_EXECUTE",
        installTimeRooted: finding.metadata.installReachable === true,
        runsOnInstall: finding.metadata.installReachable === true,
      },
    });
  }

  return chains;
}
