import type { ThreatIntelMatch, ThreatIntelResult } from "./types.js";
import { aggregateThreatStatus } from "./types.js";

/**
 * Live lookups against the OSV database (https://osv.dev).
 *
 * This is an **async client**, not a `ThreatIntelProvider`. Providers are
 * synchronous on purpose: the analysis core runs with no network and no
 * credentials, and making it async would put an I/O seam inside the trust
 * boundary. Callers in the CLI layer — which is already doing network work to
 * fetch the tarball — resolve intelligence first and hand the result into the
 * synchronous pipeline.
 *
 * OSV is used rather than the GitHub advisory API because the npm
 * malicious-package corpus lives predominantly in OSV `MAL-` records, most of
 * which carry no GHSA alias. Consulting only GitHub advisories would produce a
 * large blind spot for exactly the class of thing this tool is looking for.
 */

export const OSV_DEFAULT_API_URL = "https://api.osv.dev";

/** Bound the response so a hostile or pathological reply cannot exhaust memory. */
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

export type OsvFetch = (
  input: string,
  init: {
    method: string;
    headers: Record<string, string>;
    body: string;
    signal?: AbortSignal;
  },
) => Promise<{ ok: boolean; status: number; text(): Promise<string> }>;

export interface OsvLookupOptions {
  readonly apiUrl?: string;
  readonly timeoutMs?: number;
  readonly fetchImpl?: OsvFetch;
  readonly userAgent?: string;
}

interface OsvVulnerability {
  id?: unknown;
  summary?: unknown;
  withdrawn?: unknown;
  affected?: unknown;
}

/**
 * An OSV id beginning `MAL-` asserts the package itself is malicious. Anything
 * else (GHSA, CVE) asserts a defect in otherwise legitimate code.
 *
 * These are different claims that lead to different analyst actions, so they
 * are never merged into a single "advisory count".
 */
function classifyOsvId(id: string): ThreatIntelMatch["classification"] {
  return id.startsWith("MAL-") ? "KNOWN_MALICIOUS" : "KNOWN_VULNERABLE";
}

/**
 * True when the record explicitly lists this exact version.
 *
 * Deliberately conservative: only the enumerated `versions` array counts.
 * Evaluating OSV range events correctly requires ecosystem-specific semver
 * comparison, and a wrong range interpretation would either invent a hit on a
 * clean version or silently miss a real one. A record that applies by range but
 * does not enumerate this version is reported by the caller as context, never
 * as a confirmed hit on the scanned artifact.
 */
function affectsExactVersion(vulnerability: OsvVulnerability, version: string): boolean {
  const affected = vulnerability.affected;
  if (!Array.isArray(affected)) return false;
  for (const entry of affected) {
    if (entry === null || typeof entry !== "object") continue;
    const versions = (entry as { versions?: unknown }).versions;
    if (Array.isArray(versions) && versions.some((v) => v === version)) return true;
  }
  return false;
}

/**
 * Look up one package version in OSV.
 *
 * A failed lookup returns `lookupFailed: true` and is never reported as "no
 * advisories found" — those are different facts, and conflating them would let
 * an outage read as a clean result.
 */
export async function lookupOsv(
  packageName: string,
  version: string,
  options: OsvLookupOptions = {},
): Promise<ThreatIntelResult> {
  const provider = "osv";
  const fetchImpl = options.fetchImpl ?? (globalThis.fetch as unknown as OsvFetch);
  if (typeof fetchImpl !== "function") {
    return {
      status: "UNKNOWN",
      matches: [],
      lookupFailed: true,
      failureReason: "No fetch implementation available",
      provider,
    };
  }

  const apiUrl = (options.apiUrl ?? OSV_DEFAULT_API_URL).replace(/\/+$/, "");
  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort();
  }, options.timeoutMs ?? 15_000);

  try {
    const response = await fetchImpl(`${apiUrl}/v1/query`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "user-agent": options.userAgent ?? "packagegate/0.1.0",
      },
      body: JSON.stringify({ package: { name: packageName, ecosystem: "npm" }, version }),
      signal: controller.signal,
    });

    if (!response.ok) {
      return {
        status: "UNKNOWN",
        matches: [],
        lookupFailed: true,
        failureReason: `OSV responded with HTTP ${String(response.status)}`,
        provider,
      };
    }

    const body = await response.text();
    if (body.length > MAX_RESPONSE_BYTES) {
      return {
        status: "UNKNOWN",
        matches: [],
        lookupFailed: true,
        failureReason: "OSV response exceeded the size limit",
        provider,
      };
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(body);
    } catch {
      return {
        status: "UNKNOWN",
        matches: [],
        lookupFailed: true,
        failureReason: "OSV returned a malformed response",
        provider,
      };
    }

    const vulns = (parsed as { vulns?: unknown }).vulns;
    if (!Array.isArray(vulns)) {
      // A query with no results legitimately omits `vulns` entirely.
      return { status: "NONE", matches: [], lookupFailed: false, provider };
    }

    const matches: ThreatIntelMatch[] = [];
    for (const raw of vulns) {
      if (raw === null || typeof raw !== "object") continue;
      const vulnerability = raw as OsvVulnerability;
      const id = typeof vulnerability.id === "string" ? vulnerability.id : undefined;
      if (id === undefined) continue;

      // Withdrawn records are retracted claims and must not drive a verdict.
      if (typeof vulnerability.withdrawn === "string") continue;

      if (!affectsExactVersion(vulnerability, version)) continue;

      matches.push({
        source: provider,
        classification: classifyOsvId(id),
        matchedBy: "NAME_VERSION",
        referenceId: id,
        confidence: "HIGH",
      });
    }

    return {
      status: aggregateThreatStatus(matches),
      matches,
      lookupFailed: false,
      provider,
    };
  } catch (error) {
    const aborted = error instanceof Error && error.name === "AbortError";
    return {
      status: "UNKNOWN",
      matches: [],
      lookupFailed: true,
      failureReason: aborted ? "OSV lookup timed out" : "Could not reach OSV",
      provider,
    };
  } finally {
    clearTimeout(timer);
  }
}
