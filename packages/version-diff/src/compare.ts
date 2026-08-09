import type {
  BehaviourChange,
  ChangeSignificance,
  ChainChange,
  LifecycleScriptChange,
  SecurityDiff,
} from "@packagegate/shared";
import { chainIdentity, destinationFromFinding, findingIdentity } from "./identity.js";
import type { DiffableInvestigation } from "./types.js";
import { VERSION_DIFF_ENGINE } from "./types.js";

/**
 * Compare two investigations as a security semantic diff.
 * Never executes package code; operates only on prior investigation evidence.
 */
export function compareInvestigations(
  before: DiffableInvestigation,
  after: DiffableInvestigation,
): SecurityDiff {
  if (before.resolved.name !== after.resolved.name) {
    throw new Error(
      `Cannot diff different packages: ${before.resolved.name} vs ${after.resolved.name}`,
    );
  }

  const beforeFindings = indexBy(before.findings, findingIdentity);
  const afterFindings = indexBy(after.findings, findingIdentity);

  const findingsAdded = [...afterFindings.entries()]
    .filter(([id]) => !beforeFindings.has(id))
    .flatMap(([, findings]) => findings);
  const findingsRemoved = [...beforeFindings.entries()]
    .filter(([id]) => !afterFindings.has(id))
    .flatMap(([, findings]) => findings);

  const behaviourChanges: BehaviourChange[] = [];
  for (const [id, findings] of afterFindings) {
    if (beforeFindings.has(id)) continue;
    const representative = findings[0]!;
    behaviourChanges.push({
      direction: "INTRODUCED",
      identity: id,
      category: representative.category,
      label: representative.title,
      findingsBefore: [],
      findingsAfter: findings,
    });
  }
  for (const [id, findings] of beforeFindings) {
    if (afterFindings.has(id)) continue;
    const representative = findings[0]!;
    behaviourChanges.push({
      direction: "REMOVED",
      identity: id,
      category: representative.category,
      label: representative.title,
      findingsBefore: findings,
      findingsAfter: [],
    });
  }

  const beforeChains = indexBy(before.behaviourChains, chainIdentity);
  const afterChains = indexBy(after.behaviourChains, chainIdentity);
  const chainsAdded = [...afterChains.entries()]
    .filter(([id]) => !beforeChains.has(id))
    .flatMap(([, chains]) => chains);
  const chainsRemoved = [...beforeChains.entries()]
    .filter(([id]) => !afterChains.has(id))
    .flatMap(([, chains]) => chains);

  const chainChanges: ChainChange[] = [
    ...chainsAdded.map((chain) => ({
      direction: "INTRODUCED" as const,
      identity: chainIdentity(chain),
      chain,
    })),
    ...chainsRemoved.map((chain) => ({
      direction: "REMOVED" as const,
      identity: chainIdentity(chain),
      chain,
    })),
  ];

  const beforeLifecycle = new Map(
    before.lifecycleScripts.filter((s) => s.runsOnInstall).map((s) => [s.name, s]),
  );
  const afterLifecycle = new Map(
    after.lifecycleScripts.filter((s) => s.runsOnInstall).map((s) => [s.name, s]),
  );
  const lifecycleAdded = [...afterLifecycle.entries()]
    .filter(([name]) => !beforeLifecycle.has(name))
    .map(([, script]) => script);
  const lifecycleRemoved = [...beforeLifecycle.entries()]
    .filter(([name]) => !afterLifecycle.has(name))
    .map(([, script]) => script);

  const lifecycleScriptChanges: LifecycleScriptChange[] = [
    ...lifecycleAdded.map((script) => ({
      name: script.name,
      direction: "INTRODUCED" as const,
      after: script,
    })),
    ...lifecycleRemoved.map((script) => ({
      name: script.name,
      direction: "REMOVED" as const,
      before: script,
    })),
  ];
  for (const [name, afterScript] of afterLifecycle) {
    const beforeScript = beforeLifecycle.get(name);
    if (beforeScript === undefined) continue;
    if (beforeScript.command === afterScript.command) continue;
    lifecycleScriptChanges.push({
      name,
      direction: "MODIFIED",
      before: beforeScript,
      after: afterScript,
    });
  }

  const beforeDest = new Set(
    before.findings.map(destinationFromFinding).filter((d): d is string => d !== undefined),
  );
  const afterDest = new Set(
    after.findings.map(destinationFromFinding).filter((d): d is string => d !== undefined),
  );
  const destinationsAdded = [...afterDest].filter((d) => !beforeDest.has(d)).sort();
  const destinationsRemoved = [...beforeDest].filter((d) => !afterDest.has(d)).sort();

  const beforeOpaque = opaquePaths(before);
  const afterOpaque = opaquePaths(after);
  const opaqueSourcesAdded = [...afterOpaque.entries()]
    .filter(([path]) => !beforeOpaque.has(path))
    .map(([path, sizeBytes]) => ({
      path,
      direction: "INTRODUCED" as const,
      sizeBytes,
    }));

  const riskDelta = after.risk.score - before.risk.score;
  const changeSignificance = classifyChangeSignificance({
    lifecycleAdded: lifecycleAdded.length,
    chainsAdded,
    findingsAdded,
    opaqueAdded: opaqueSourcesAdded.length,
    riskDelta,
    policyEscalated:
      actionRank(after.policy.finalAction) > actionRank(before.policy.finalAction),
  });

  const summary = buildSummary({
    packageName: before.resolved.name,
    fromVersion: before.resolved.version,
    toVersion: after.resolved.version,
    lifecycleAdded,
    chainsAdded,
    findingsAdded,
    opaqueSourcesAdded: opaqueSourcesAdded.length,
    riskBefore: before.risk.score,
    riskAfter: after.risk.score,
    policyBefore: before.policy.finalAction,
    policyAfter: after.policy.finalAction,
    changeSignificance,
  });

  return {
    packageName: before.resolved.name,
    fromVersion: before.resolved.version,
    toVersion: after.resolved.version,
    lifecycleAdded,
    lifecycleRemoved,
    findingsAdded,
    findingsRemoved,
    chainsAdded,
    chainsRemoved,
    destinationsAdded,
    destinationsRemoved,
    opaqueSourcesAdded,
    completenessBefore: before.analysisCompleteness,
    completenessAfter: after.analysisCompleteness,
    riskBefore: {
      score: before.risk.score,
      recommendation: before.risk.recommendation,
    },
    riskAfter: {
      score: after.risk.score,
      recommendation: after.risk.recommendation,
    },
    riskDelta,
    policyBefore: before.policy,
    policyAfter: after.policy,
    changeSignificance,
    summary,
    behaviourChanges,
    chainChanges,
    lifecycleScriptChanges,
  };
}

function indexBy<T>(items: readonly T[], keyFn: (item: T) => string): Map<string, T[]> {
  const map = new Map<string, T[]>();
  for (const item of items) {
    const key = keyFn(item);
    const list = map.get(key);
    if (list === undefined) map.set(key, [item]);
    else list.push(item);
  }
  return map;
}

function opaquePaths(inv: DiffableInvestigation): Map<string, number> {
  const map = new Map<string, number>();
  for (const finding of inv.findings) {
    if (
      finding.ruleId === "file/opaque-executable-source" ||
      finding.metadata.opaque === true
    ) {
      const size =
        typeof finding.metadata.sizeBytes === "number" ? finding.metadata.sizeBytes : 0;
      map.set(finding.location.filePath, size);
    }
  }
  for (const reason of inv.analysisCompleteness.reasons) {
    if (
      reason.path !== undefined &&
      (reason.code === "SOURCE_CONTENT_LIMIT_EXCEEDED" ||
        reason.code === "OPAQUE_PAYLOAD")
    ) {
      map.set(reason.path, reason.sizeBytes ?? map.get(reason.path) ?? 0);
    }
  }
  return map;
}

function actionRank(action: string): number {
  if (action === "BLOCK") return 2;
  if (action === "REVIEW") return 1;
  return 0;
}

export function classifyChangeSignificance(input: {
  lifecycleAdded: number;
  chainsAdded: DiffableInvestigation["behaviourChains"];
  findingsAdded: DiffableInvestigation["findings"];
  opaqueAdded: number;
  riskDelta: number;
  policyEscalated: boolean;
}): ChangeSignificance {
  const installRemote = input.chainsAdded.some(
    (chain) =>
      chain.metadata.chainType === "INSTALL_TIME_REMOTE_EXECUTION" ||
      (chain.source === "REMOTE_DOWNLOAD" &&
        chain.sink === "PROCESS_EXECUTION" &&
        chain.metadata.installTimeRooted === true),
  );
  if (installRemote) return "CRITICAL";

  const remoteFetch = input.findingsAdded.some(
    (f) => f.category === "REMOTE_CODE_FETCH" || f.ruleId.includes("remote-content-to-shell"),
  );
  const installExec = input.findingsAdded.some(
    (f) =>
      f.category === "PROCESS_EXECUTION" &&
      (f.metadata.installReachable === true || input.lifecycleAdded > 0),
  );
  if (remoteFetch && installExec) return "HIGH";
  if (input.lifecycleAdded > 0 && installExec) return "HIGH";
  if (input.policyEscalated && input.riskDelta >= 20) return "HIGH";
  if (input.lifecycleAdded > 0 || input.opaqueAdded > 0) return "MEDIUM";
  if (input.findingsAdded.length > 0 || input.riskDelta !== 0) return "LOW";
  return "LOW";
}

function buildSummary(args: {
  packageName: string;
  fromVersion: string;
  toVersion: string;
  lifecycleAdded: DiffableInvestigation["lifecycleScripts"];
  chainsAdded: DiffableInvestigation["behaviourChains"];
  findingsAdded: DiffableInvestigation["findings"];
  opaqueSourcesAdded: number;
  riskBefore: number;
  riskAfter: number;
  policyBefore: string;
  policyAfter: string;
  changeSignificance: ChangeSignificance;
}): string {
  const parts: string[] = [
    `${args.packageName}@${args.fromVersion} → ${args.toVersion} (${args.changeSignificance} change significance).`,
  ];
  if (args.lifecycleAdded.length > 0) {
    parts.push(
      `New install lifecycle: ${args.lifecycleAdded.map((s) => s.name).join(", ")}.`,
    );
  }
  if (args.chainsAdded.length > 0) {
    parts.push(
      `New behaviour chains: ${args.chainsAdded
        .map((c) => {
          const typed = c.metadata.chainType;
          return typeof typed === "string" ? typed : `${c.source}→${c.sink}`;
        })
        .join(", ")}.`,
    );
  } else if (args.findingsAdded.length > 0) {
    parts.push(`New findings introduced (${String(args.findingsAdded.length)}).`);
  } else {
    parts.push("No new high-value security behaviour detected.");
  }
  if (args.opaqueSourcesAdded > 0) {
    parts.push("New opaque/large executable source exceeded full AST analysis.");
  }
  parts.push(
    `Risk ${String(args.riskBefore)} ${args.policyBefore} → ${String(args.riskAfter)} ${args.policyAfter}.`,
  );
  parts.push("This change significance is not by itself proof of malware.");
  return parts.join(" ");
}

export { VERSION_DIFF_ENGINE };
