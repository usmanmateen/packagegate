/**
 * @packagegate/behaviour-engine — conservative intra-file behaviour-chain analysis.
 *
 * Combines static analyser findings with AST dataflow to detect evidenced
 * source-to-sink chains. Co-occurrence alone never produces a chain.
 */

export { analyseBehaviourChains } from "./analyse.js";
export { ENGINE_VERSION } from "./version.js";
export type {
  BehaviourAnalysisInput,
  BehaviourAnalysisResult,
  SourceFileInput,
} from "./types.js";
