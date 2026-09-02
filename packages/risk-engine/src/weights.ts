/**
 * Risk model weight table — authoritative values from `docs/RISK_MODEL.md` §5.
 *
 * Discrepancies between worked examples in the doc and these constants are noted
 * inline where they affect tests; the formulas in §4 are preferred over prose
 * rounding in §7 tables.
 */

export const WEIGHTS_VERSION = "risk-weights/1.0.0";
export const ENGINE_VERSION = "risk-engine/1.0.0";

export const COVERAGE_FLOOR = 0.6;
export const CROSS_FAMILY_DECAY = 0.75;
export const CHAIN_SATURATION_CAP = 65;
export const MODIFIER_FLOOR = -20;
export const MODIFIER_CEILING = 0;

export const CONFIDENCE_NUMERIC = {
  HIGH: 0.95,
  MEDIUM: 0.8,
  LOW: 0.55,
} as const;

/** Findings below this numeric confidence contribute zero (§4.1). */
export const CONFIDENCE_HARD_GATE = 0.3;

export const FAMILY_IDS = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "K"] as const;
export type FamilyId = (typeof FAMILY_IDS)[number];

export interface RuleWeight {
  readonly id: string;
  readonly family: FamilyId;
  readonly weight: number;
  /** When true, κ = weight and occurrences aggregate by max(c), not sum. */
  readonly presence: boolean;
  /** Per-rule saturation cap; defaults to weight for non-presence rules. */
  readonly kappa?: number;
}

export const FAMILY_CAPS: Readonly<Record<FamilyId, number>> = {
  A: 12,
  B: 14,
  C: 16,
  D: 15,
  E: 10,
  F: 12,
  G: 10,
  H: 12,
  I: 12,
  K: 18,
};

export const RULE_WEIGHTS: Readonly<Record<string, RuleWeight>> = {
  A1: { id: "A1", family: "A", weight: 3, presence: true },
  A2: { id: "A2", family: "A", weight: 9, presence: true },
  A3: { id: "A3", family: "A", weight: 14, presence: true },
  A4: { id: "A4", family: "A", weight: 4, presence: true },
  A5: { id: "A5", family: "A", weight: 8, presence: true },
  A6: { id: "A6", family: "A", weight: 5, presence: true },

  B1: { id: "B1", family: "B", weight: 4, presence: true },
  B2: { id: "B2", family: "B", weight: 8, kappa: 12, presence: false },
  B3: { id: "B3", family: "B", weight: 1, kappa: 4, presence: false },
  B4: { id: "B4", family: "B", weight: 6, kappa: 9, presence: false },
  B5: { id: "B5", family: "B", weight: 9, kappa: 14, presence: false },
  B6: { id: "B6", family: "B", weight: 3, kappa: 6, presence: false },
  B7: { id: "B7", family: "B", weight: 4, presence: true },

  C1: { id: "C1", family: "C", weight: 2, presence: true },
  C2: { id: "C2", family: "C", weight: 7, kappa: 10, presence: false },
  C3: { id: "C3", family: "C", weight: 12, kappa: 10, presence: false },
  C4: { id: "C4", family: "C", weight: 11, kappa: 10, presence: false },
  C5: { id: "C5", family: "C", weight: 13, kappa: 12, presence: false },
  C6: { id: "C6", family: "C", weight: 6, presence: true },
  C7: { id: "C7", family: "C", weight: 5, kappa: 8, presence: false },

  D1: { id: "D1", family: "D", weight: 1, kappa: 3, presence: false },
  D2: { id: "D2", family: "D", weight: 11, kappa: 18, presence: false },
  D3: { id: "D3", family: "D", weight: 8, kappa: 12, presence: false },
  D4: { id: "D4", family: "D", weight: 9, kappa: 12, presence: false },
  D5: { id: "D5", family: "D", weight: 7, kappa: 10, presence: false },
  D6: { id: "D6", family: "D", weight: 7, kappa: 8, presence: false },

  E1: { id: "E1", family: "E", weight: 0, presence: true },
  E2: { id: "E2", family: "E", weight: 13, kappa: 12, presence: false },
  E3: { id: "E3", family: "E", weight: 9, presence: true },
  E4: { id: "E4", family: "E", weight: 6, kappa: 8, presence: false },
  E5: { id: "E5", family: "E", weight: 4, kappa: 8, presence: false },

  F1: { id: "F1", family: "F", weight: 5, kappa: 8, presence: false },
  F2: { id: "F2", family: "F", weight: 8, kappa: 10, presence: false },
  F3: { id: "F3", family: "F", weight: 10, kappa: 10, presence: false },

  G1: { id: "G1", family: "G", weight: 9, presence: true },
  G2: { id: "G2", family: "G", weight: 5, presence: true },
  G3: { id: "G3", family: "G", weight: 7, presence: true },
  G4: { id: "G4", family: "G", weight: 2, presence: true },
  G5: { id: "G5", family: "G", weight: 12, presence: true },
  G6: { id: "G6", family: "G", weight: 10, kappa: 8, presence: false },

  H1: { id: "H1", family: "H", weight: 12, kappa: 10, presence: false },
  H2: { id: "H2", family: "H", weight: 10, kappa: 10, presence: false },
  H3: { id: "H3", family: "H", weight: 8, kappa: 10, presence: false },
  H4: { id: "H4", family: "H", weight: 11, kappa: 10, presence: false },

  I1: { id: "I1", family: "I", weight: 12, kappa: 10, presence: false },
  I2: { id: "I2", family: "I", weight: 7, kappa: 8, presence: false },
  I3: { id: "I3", family: "I", weight: 8, kappa: 8, presence: false },
  I4: { id: "I4", family: "I", weight: 9, kappa: 10, presence: false },

  K1: { id: "K1", family: "K", weight: 7, kappa: 18, presence: false },
};

export interface ChainPatternWeight {
  readonly id: string;
  readonly weight: number;
  readonly label: string;
}

export const CHAIN_PATTERNS: Readonly<Record<string, ChainPatternWeight>> = {
  J1: {
    id: "J1",
    weight: 38,
    label: "Secret or credential source → network sink",
  },
  J2: {
    id: "J2",
    weight: 32,
    label: "Host recon → encode → network sink",
  },
  J3: {
    id: "J3",
    weight: 36,
    label: "Remote fetch → dynamic execution",
  },
  J4: {
    id: "J4",
    weight: 45,
    label: "Credential read → stage → archive → network sink",
  },
  J5: {
    id: "J5",
    weight: 50,
    label: "Registry token read → publish or modify packages",
  },
  J6: {
    id: "J6",
    weight: 34,
    label: "Install trigger → egress of local data",
  },
};

export const INSTALL_TIME_CHAIN_MULTIPLIER = 1.4;
export const CHAIN_COUNT_BONUS = 0.08;
export const MAX_CHAIN_COUNT_BONUS = 3;

export const MODIFIER_VALUES = {
  M1: -8,
  M2: -5,
  M3: -4,
  M4: -6,
} as const;

/** Resolve κ for a rule — presence rules use weight as cap. */
export function kappaForRule(rule: RuleWeight): number {
  if (rule.weight === 0) return 0;
  return rule.kappa ?? rule.weight;
}
