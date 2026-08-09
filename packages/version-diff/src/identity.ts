import type { BehaviourChain, Finding } from "@packagegate/shared";

/**
 * Stable semantic identities for matching findings/chains across versions.
 * Line numbers are intentionally excluded so reformats do not look like new behaviour.
 */

export function findingIdentity(finding: Finding): string {
  const dest =
    typeof finding.metadata.destinationUrl === "string"
      ? finding.metadata.destinationUrl
      : typeof finding.metadata.host === "string"
        ? finding.metadata.host
        : "";
  const script =
    typeof finding.metadata.script === "string" ? finding.metadata.script : "";
  const shellOp =
    typeof finding.metadata.shellOperation === "string"
      ? finding.metadata.shellOperation
      : typeof finding.metadata.shellChainType === "string"
        ? finding.metadata.shellChainType
        : "";
  return [
    finding.ruleId,
    finding.category,
    finding.location.filePath,
    script,
    shellOp,
    dest,
  ].join("|");
}

export function chainIdentity(chain: BehaviourChain): string {
  const chainType =
    typeof chain.metadata.chainType === "string" ? chain.metadata.chainType : "";
  const files = [...chain.filePaths].sort().join(",");
  return [chain.source, chain.sink, chainType, files, chain.confidence].join("|");
}

export function destinationFromFinding(finding: Finding): string | undefined {
  if (finding.category !== "NETWORK_DESTINATION" && finding.category !== "REMOTE_CODE_FETCH") {
    return undefined;
  }
  if (typeof finding.metadata.destinationUrl === "string") {
    return finding.metadata.destinationUrl;
  }
  if (typeof finding.metadata.host === "string") {
    return finding.metadata.host;
  }
  const match = finding.title.match(/:\s*(.+)$/);
  return match?.[1]?.trim();
}
