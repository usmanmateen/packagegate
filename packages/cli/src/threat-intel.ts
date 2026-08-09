/**
 * CLI threat-intelligence wiring.
 *
 * Defaults to the offline `none` provider. Set PACKAGEGATE_THREAT_INTEL=memory
 * only in controlled test environments with an explicit record set.
 */

export type {
  MemoryThreatRecord,
  ThreatIntelLookup,
  ThreatIntelMatch,
  ThreatIntelProvider,
  ThreatIntelResult,
} from "@packagegate/threat-intel";
export {
  createThreatIntelProviderFromEnv,
  FailingThreatIntelProvider,
  MemoryThreatIntelProvider,
  NoneThreatIntelProvider,
  THREAT_INTEL_VERSION,
} from "@packagegate/threat-intel";

import {
  createThreatIntelProviderFromEnv,
  type ThreatIntelProvider,
} from "@packagegate/threat-intel";

let activeProvider: ThreatIntelProvider = createThreatIntelProviderFromEnv();

export function getThreatIntelProvider(): ThreatIntelProvider {
  return activeProvider;
}

/** Test-only override. Production CLI uses env-selected provider. */
export function setThreatIntelProvider(provider: ThreatIntelProvider): void {
  activeProvider = provider;
}

export function resetThreatIntelProvider(): void {
  activeProvider = createThreatIntelProviderFromEnv();
}
