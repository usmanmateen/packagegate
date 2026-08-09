import type { BehaviourChain, Finding } from "@packagegate/shared";

/** One source file supplied for behaviour analysis. */
export interface SourceFileInput {
  readonly path: string;
  readonly content: string;
}

/** Input to {@link analyseBehaviourChains}. */
export interface BehaviourAnalysisInput {
  readonly files: readonly SourceFileInput[];
  readonly findings: readonly Finding[];
}

/** Result of behaviour-chain analysis. */
export interface BehaviourAnalysisResult {
  readonly chains: readonly BehaviourChain[];
  readonly engineVersion: string;
}
