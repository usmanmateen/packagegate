import type { ThreatIntelligenceStatus } from "@packagegate/shared";

/**
 * Offline threat-intelligence provider.
 *
 * Detection Engine v2 wires the interface and a none/offline implementation.
 * Behavioural evaluation must not be poisoned by hard-coded package labels.
 */

export interface ThreatIntelLookup {
  readonly name: string;
  readonly version: string;
  readonly sha256?: string;
}

export interface ThreatIntelResult {
  readonly status: ThreatIntelligenceStatus;
  readonly source?: string;
  readonly matchedBy?: "NAME_VERSION" | "SHA256";
  readonly reference?: string;
}

export interface ThreatIntelProvider {
  lookupPackageVersion(query: ThreatIntelLookup): ThreatIntelResult;
}

/** Always returns NONE — safe default for offline scanner operation. */
export class NoneThreatIntelProvider implements ThreatIntelProvider {
  lookupPackageVersion(_query: ThreatIntelLookup): ThreatIntelResult {
    return { status: "NONE" };
  }
}

export const defaultThreatIntelProvider: ThreatIntelProvider =
  new NoneThreatIntelProvider();
