import type {
  ThreatIntelLookup,
  ThreatIntelMatch,
  ThreatIntelProvider,
  ThreatIntelResult,
} from "./types.js";
import { aggregateThreatStatus, emptyThreatIntelResult } from "./types.js";

/** Always-offline provider. Scanner works with no external intel. */
export class NoneThreatIntelProvider implements ThreatIntelProvider {
  readonly name = "none";

  lookup(_query: ThreatIntelLookup): ThreatIntelResult {
    return emptyThreatIntelResult(this.name);
  }
}

export interface MemoryThreatRecord {
  readonly packageName: string;
  readonly version: string;
  readonly sha256?: string;
  readonly classification: ThreatIntelMatch["classification"];
  readonly source: string;
  readonly referenceId: string;
  readonly confidence?: ThreatIntelMatch["confidence"];
}

/**
 * Deterministic in-memory provider for tests and offline fixtures.
 * Never fetches the network.
 */
export class MemoryThreatIntelProvider implements ThreatIntelProvider {
  readonly name = "memory";

  constructor(private readonly records: readonly MemoryThreatRecord[]) {}

  lookup(query: ThreatIntelLookup): ThreatIntelResult {
    const matches: ThreatIntelMatch[] = [];
    for (const record of this.records) {
      if (
        record.packageName === query.packageName &&
        record.version === query.version
      ) {
        matches.push({
          source: record.source,
          classification: record.classification,
          matchedBy: "NAME_VERSION",
          referenceId: record.referenceId,
          confidence: record.confidence ?? "HIGH",
        });
      }
      if (
        query.sha256 !== undefined &&
        record.sha256 !== undefined &&
        record.sha256.toLowerCase() === query.sha256.toLowerCase()
      ) {
        matches.push({
          source: record.source,
          classification: record.classification,
          matchedBy: "SHA256",
          referenceId: record.referenceId,
          confidence: record.confidence ?? "HIGH",
        });
      }
    }

    // Deduplicate by referenceId+matchedBy
    const seen = new Set<string>();
    const unique = matches.filter((m) => {
      const key = `${m.referenceId}|${m.matchedBy}|${m.classification}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    return {
      status: aggregateThreatStatus(unique),
      matches: unique,
      lookupFailed: false,
      provider: this.name,
    };
  }
}

/**
 * Provider that fails the lookup without throwing — behavioural scan must continue.
 */
export class FailingThreatIntelProvider implements ThreatIntelProvider {
  readonly name = "failing";

  lookup(_query: ThreatIntelLookup): ThreatIntelResult {
    return {
      status: "UNKNOWN",
      matches: [],
      lookupFailed: true,
      failureReason: "Threat intelligence provider unavailable",
      provider: this.name,
    };
  }
}

export function createThreatIntelProviderFromEnv(
  records: readonly MemoryThreatRecord[] = [],
): ThreatIntelProvider {
  const mode = (process.env["PACKAGEGATE_THREAT_INTEL"] ?? "none").toLowerCase();
  if (mode === "memory") return new MemoryThreatIntelProvider(records);
  if (mode === "fail") return new FailingThreatIntelProvider();
  return new NoneThreatIntelProvider();
}
