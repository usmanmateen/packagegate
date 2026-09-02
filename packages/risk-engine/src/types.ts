import type { BehaviourChain, Finding } from "@packagegate/shared";

export type IntelligenceTier =
  "AUTHORITATIVE_MALWARE" | "CORROBORATED_MALWARE" | "VULNERABILITY" | "CONTEXT";

/**
 * Input to the deterministic risk engine.
 */
export interface RiskEngineInput {
  findings: readonly Finding[];
  chains?: readonly BehaviourChain[];
  /** 0..1; default 1.0 when omitted. */
  analysisCoverage?: number;
  /** Lane I — when true, force BLOCK / KNOWN_MALWARE. */
  knownMalware?: boolean;
  intelligenceTier?: IntelligenceTier[];
  scannerVersion?: string;
  rulesVersion?: string;
  weightsVersion?: string;
  /** When true, enables modifier M1 if no high-confidence chain blocks it. */
  integrityVerified?: boolean;
}

export interface RuleOccurrenceContribution {
  readonly ruleId: string;
  readonly family: string;
  readonly findingIds: readonly string[];
  readonly perOccurrenceTotal: number;
  readonly saturated: number;
}

export interface FamilyBreakdownEntry {
  readonly family: string;
  readonly rawFamilyScore: number;
  readonly decayRank: number;
  readonly decayFactor: number;
  readonly decayedPoints: number;
  readonly ruleScores: readonly RuleOccurrenceContribution[];
}

export interface ScoringBreakdown {
  readonly breadthRaw: number;
  readonly chainRaw: number;
  readonly chainSaturated: number;
  readonly modifierTotal: number;
  readonly rawTotal: number;
  readonly structuralCap: number;
  readonly score: number;
  readonly familyBreakdown: readonly FamilyBreakdownEntry[];
  readonly evidencedChainCount: number;
  readonly maxChainConfidence: number;
}
