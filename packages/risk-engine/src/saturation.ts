/**
 * Core saturating arithmetic from `docs/RISK_MODEL.md` §4.5–§4.6.
 */

/** Stage 2 — per-rule saturation: S = κ · (1 − exp(−Σc / κ)). */
export function saturateRule(totalContribution: number, kappa: number): number {
  if (kappa <= 0 || totalContribution <= 0) return 0;
  return kappa * (1 - Math.exp(-totalContribution / kappa));
}

/** Stage 3 — family saturation: S_f = C_f · (1 − exp(−Σ S_rule / C_f)). */
export function saturateFamily(ruleTotal: number, familyCap: number): number {
  if (familyCap <= 0 || ruleTotal <= 0) return 0;
  return familyCap * (1 - Math.exp(-ruleTotal / familyCap));
}

/** Stage 4 — chain term inner saturation with optional multi-chain bonus. */
export function saturateChains(
  rawChainTotal: number,
  chainCap: number,
  evidencedChainCount: number,
): number {
  if (chainCap <= 0 || rawChainTotal <= 0) return 0;
  const base = chainCap * (1 - Math.exp(-rawChainTotal / chainCap));
  const bonus = 1 + 0.08 * Math.min(Math.max(evidencedChainCount - 1, 0), 3);
  return base * bonus;
}

/** Positional cross-family decay (§4.6). Rank is 1-based. */
export function decayFactorForRank(rank: number, gamma: number): number {
  if (rank <= 1) return 1;
  return gamma ** (rank - 1);
}

/** Structural score cap from evidenced chain count (§4.9). */
export function structuralCap(evidencedChainCount: number): number {
  if (evidencedChainCount >= 2) return 100;
  if (evidencedChainCount === 1) return 89;
  return 74;
}

/** Final clamped score after structural cap (§4.9). */
export function applyStructuralCap(
  rawTotal: number,
  evidencedChainCount: number,
): number {
  const cap = structuralCap(evidencedChainCount);
  const clamped = Math.max(0, Math.min(100, Math.min(rawTotal, cap)));
  return Math.round(clamped);
}

/** Clamp modifier sum to model bounds (§4.8). */
export function clampModifiers(total: number, floor: number, ceiling: number): number {
  return Math.max(floor, Math.min(ceiling, total));
}

/**
 * Reference B3 rule saturation table from §4.5 (w=1, κ=4, confidence=1.0).
 * Used by unit tests; doc rounds to two decimal places.
 */
export const B3_RULE_SATURATION_TABLE: Readonly<Record<number, number>> = {
  1: 0.89,
  2: 1.57,
  5: 2.85,
  10: 3.67,
  20: 3.97,
  50: 4.0,
  200: 4.0,
};
