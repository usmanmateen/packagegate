import { lookupOsv, type ThreatIntelResult } from "@packagegate/threat-intel";

/**
 * Resolve known-malware intelligence for a package version before analysis.
 *
 * Lives in the async CLI layer on purpose. The analysis stage runs with no
 * network and no credentials, and adding an await inside it would put an I/O
 * seam inside the trust boundary. Here we are already online to fetch the
 * tarball, so the lookup costs nothing architecturally.
 *
 * Disabled by default. A scanner that silently phones a third party on every
 * run is not something a security team can drop into CI without asking, so the
 * network lane is opt-in via `PACKAGEGATE_THREAT_INTEL=osv`.
 */
export async function resolveThreatIntel(
  packageName: string,
  version: string,
): Promise<ThreatIntelResult | undefined> {
  const mode = (process.env["PACKAGEGATE_THREAT_INTEL"] ?? "none").toLowerCase();
  if (mode !== "osv") return undefined;
  return lookupOsv(packageName, version);
}
