import type { BehaviourChain, ChainLink } from "@packagegate/shared";
import {
  CHAIN_PATTERNS,
  INSTALL_TIME_CHAIN_MULTIPLIER,
  RULE_WEIGHTS,
} from "./weights.js";
import { confidenceToNumeric } from "./factors.js";

export interface ResolvedChain {
  readonly chain: BehaviourChain;
  readonly patternId: string;
  readonly patternWeight: number;
  readonly patternLabel: string;
  readonly linkageFactor: number;
  readonly isEvidenced: boolean;
  readonly confidenceNumeric: number;
  readonly installTimeRooted: boolean;
  readonly rawContribution: number;
}

const STRONG_LINK_KINDS: ReadonlySet<ChainLink["kind"]> = new Set([
  "SHARED_BINDING",
  "ARGUMENT_FLOW",
]);

const MEDIUM_LINK_KINDS: ReadonlySet<ChainLink["kind"]> = new Set([
  "RETURN_VALUE",
  "PROPERTY_ACCESS",
]);

/**
 * Linkage tier factors from §4.4 mapped onto shared ChainLink kinds.
 */
export function linkageFactorForLinks(links: readonly ChainLink[]): {
  factor: number;
  isEvidenced: boolean;
} {
  if (links.length === 0) {
    return { factor: 0, isEvidenced: false };
  }

  const onlyCooccurrence = links.every(
    (link) => link.kind === "SEQUENTIAL_IN_SCOPE",
  );
  if (onlyCooccurrence) {
    return { factor: 0.25, isEvidenced: false };
  }

  if (links.every((link) => STRONG_LINK_KINDS.has(link.kind))) {
    return { factor: 1, isEvidenced: true };
  }

  if (links.some((link) => MEDIUM_LINK_KINDS.has(link.kind))) {
    return { factor: 0.75, isEvidenced: true };
  }

  if (links.some((link) => STRONG_LINK_KINDS.has(link.kind))) {
    return { factor: 0.75, isEvidenced: true };
  }

  return { factor: 0.5, isEvidenced: true };
}

/**
 * Map a behaviour chain onto J-pattern weights (§5 chain patterns).
 */
export function resolveChainPattern(chain: BehaviourChain): {
  patternId: string;
  weight: number;
  label: string;
} | null {
  const { source, sink, transformations } = chain;
  const installRooted = isInstallTimeRooted(chain);

  if (
    (source === "ENVIRONMENT_ACCESS" ||
      source === "SENSITIVE_FILE_READ" ||
      source === "FILESYSTEM_READ") &&
    sink === "NETWORK_REQUEST"
  ) {
    return pattern("J1");
  }

  if (source === "SYSTEM_INFORMATION" && sink === "NETWORK_REQUEST") {
    const encoded = transformations.some((step) =>
      ["BASE64_ENCODE", "HEX_ENCODE", "JSON_SERIALIZATION"].includes(step),
    );
    return encoded ? pattern("J2") : pattern("J1");
  }

  if (
    source === "REMOTE_DOWNLOAD" &&
    (sink === "DYNAMIC_EVALUATION" || sink === "PROCESS_EXECUTION")
  ) {
    return pattern("J3");
  }

  if (
    (source === "SENSITIVE_FILE_READ" || source === "FILESYSTEM_READ") &&
    sink === "NETWORK_REQUEST" &&
    transformations.includes("OBJECT_COLLECTION")
  ) {
    return pattern("J4");
  }

  if (
    source === "ENVIRONMENT_ACCESS" &&
    sink === "PROCESS_EXECUTION" &&
    chain.metadata.publishOrModifyPackages === true
  ) {
    return pattern("J5");
  }

  if (installRooted && sink === "NETWORK_REQUEST") {
    return pattern("J6");
  }

  if (sink === "NETWORK_REQUEST") {
    return pattern("J1");
  }

  return null;
}

function pattern(id: keyof typeof CHAIN_PATTERNS): {
  patternId: string;
  weight: number;
  label: string;
} {
  const entry = CHAIN_PATTERNS[id];
  if (entry === undefined) {
    throw new Error(`Unknown chain pattern ${id}`);
  }
  return {
    patternId: entry.id,
    weight: entry.weight,
    label: entry.label,
  };
}

function isInstallTimeRooted(chain: BehaviourChain): boolean {
  if (chain.metadata.installTimeRooted === true) return true;
  if (chain.metadata.runsOnInstall === true) return true;
  return false;
}

/**
 * Resolve all chains into scored contributions and co-occurrence fallbacks.
 */
export function resolveChains(chains: readonly BehaviourChain[]): {
  evidenced: ResolvedChain[];
  cooccurrenceFindingIds: string[];
} {
  const evidenced: ResolvedChain[] = [];
  const cooccurrenceFindingIds: string[] = [];

  for (const chain of chains) {
    const pattern = resolveChainPattern(chain);
    if (pattern === null) continue;

    const linkage = linkageFactorForLinks(chain.links);
    const confidenceNumeric =
      confidenceToNumeric(chain.confidence) * linkage.factor;
    const installTimeRooted = isInstallTimeRooted(chain);
    const installMultiplier = installTimeRooted ? INSTALL_TIME_CHAIN_MULTIPLIER : 1;

    if (!linkage.isEvidenced) {
      cooccurrenceFindingIds.push(...chain.supportingFindingIds);
      continue;
    }

    const rawContribution =
      pattern.weight * confidenceNumeric * installMultiplier;

    evidenced.push({
      chain,
      patternId: pattern.patternId,
      patternWeight: pattern.weight,
      patternLabel: pattern.label,
      linkageFactor: linkage.factor,
      isEvidenced: true,
      confidenceNumeric,
      installTimeRooted,
      rawContribution,
    });
  }

  return { evidenced, cooccurrenceFindingIds };
}

/** K1 co-occurrence without dataflow (§4.4 L4). */
export function cooccurrenceRule() {
  return RULE_WEIGHTS.K1;
}
