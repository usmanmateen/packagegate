import type { BehaviourAnalysisInput, BehaviourAnalysisResult } from "./types.js";
import { ENGINE_VERSION } from "./version.js";
import { hasSourceFinding, hasSinkFinding } from "./categories.js";
import { groupFindingsByFile, indexFiles } from "./findings.js";
import { analyseFileForChains } from "./dataflow.js";

/**
 * Analyse static findings and source together to detect evidenced behaviour chains.
 *
 * Only files that already contain both a source-like and a sink-like finding
 * are re-parsed. Chains require SHARED_BINDING and/or ARGUMENT_FLOW links —
 * co-occurrence alone is never enough.
 */
export function analyseBehaviourChains(
  input: BehaviourAnalysisInput,
): BehaviourAnalysisResult {
  const filesByPath = indexFiles(input.files);
  const findingsByFile = groupFindingsByFile(input.findings);
  const chains = [];

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

  return {
    chains,
    engineVersion: ENGINE_VERSION,
  };
}
