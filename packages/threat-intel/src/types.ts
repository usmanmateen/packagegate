import type { Confidence, ThreatIntelligenceStatus } from "@packagegate/shared";

export const THREAT_INTEL_VERSION = "threat-intel/1.0.0";

export interface ThreatIntelLookup {
  readonly packageName: string;
  readonly version: string;
  readonly sha256?: string;
}

export interface ThreatIntelMatch {
  readonly source: string;
  readonly classification: ThreatIntelligenceStatus;
  readonly matchedBy: "NAME_VERSION" | "SHA256";
  readonly referenceId: string;
  readonly confidence: Confidence;
  readonly observedAt?: string;
}

export interface ThreatIntelResult {
  readonly status: ThreatIntelligenceStatus;
  readonly matches: readonly ThreatIntelMatch[];
  readonly lookupFailed: boolean;
  readonly failureReason?: string;
  readonly provider: string;
}

export interface ThreatIntelProvider {
  readonly name: string;
  lookup(query: ThreatIntelLookup): ThreatIntelResult;
}

export function emptyThreatIntelResult(provider: string): ThreatIntelResult {
  return {
    status: "NONE",
    matches: [],
    lookupFailed: false,
    provider,
  };
}

/** Aggregate multiple matches into a single status (malware > compromised > vulnerable). */
export function aggregateThreatStatus(
  matches: readonly ThreatIntelMatch[],
): ThreatIntelligenceStatus {
  if (matches.some((m) => m.classification === "KNOWN_MALICIOUS")) {
    return "KNOWN_MALICIOUS";
  }
  if (matches.some((m) => m.classification === "KNOWN_COMPROMISED")) {
    return "KNOWN_COMPROMISED";
  }
  if (matches.some((m) => m.classification === "KNOWN_VULNERABLE")) {
    return "KNOWN_VULNERABLE";
  }
  if (matches.some((m) => m.classification === "UNKNOWN")) {
    return "UNKNOWN";
  }
  return "NONE";
}
