import type { BehaviourChain, Finding, LifecycleScript } from "@packagegate/shared";
import type { BehaviourAnalysisInput, BehaviourAnalysisResult } from "./types.js";
import { ENGINE_VERSION } from "./version.js";
import { hasSourceFinding, hasSinkFinding } from "./categories.js";
import { groupFindingsByFile, indexFiles } from "./findings.js";
import { analyseFileForChains } from "./dataflow.js";
import { analyseShellBehaviourChains } from "./shell-chains.js";
import { analyseCrossFileChains } from "./cross-file.js";

/**
 * Analyse static findings and source together to detect evidenced behaviour chains.
 *
 * Only files that already contain both a source-like and a sink-like finding
 * are re-parsed for env→network dataflow. Shell semantic chains and limited
 * cross-file summaries are composed separately. Co-occurrence alone is never
 * enough.
 */
export function analyseBehaviourChains(
  input: BehaviourAnalysisInput,
): BehaviourAnalysisResult {
  const filesByPath = indexFiles(input.files);
  const findingsByFile = groupFindingsByFile(input.findings);
  const chains: BehaviourChain[] = [];

  for (const [filePath, fileFindings] of findingsByFile) {
    if (!hasSourceFinding(fileFindings) || !hasSinkFinding(fileFindings)) {
      continue;
    }

    const content = filesByPath.get(filePath);
    if (content === undefined) {
      continue;
    }

    chains.push(...analyseFileForChains(filePath, content, fileFindings));
  }

  chains.push(
    ...analyseShellBehaviourChains({
      findings: input.findings,
      lifecycleScripts: input.lifecycleScripts,
    }),
  );

  chains.push(
    ...analyseCrossFileChains({
      files: input.files,
      findings: input.findings,
    }),
  );

  // Deduplicate by id
  const seen = new Set<string>();
  const unique = chains.filter((chain) => {
    if (seen.has(chain.id)) return false;
    seen.add(chain.id);
    return true;
  });

  return {
    chains: unique,
    engineVersion: ENGINE_VERSION,
  };
}

export type { Finding, LifecycleScript };
