import { ScanError } from "@packagegate/shared";
import {
  ArtifactDigester,
  digestMatches,
  parseIntegrity,
  type IntegrityAlgorithm,
} from "./integrity.js";

/**
 * Turning a registry integrity declaration into a verdict about bytes.
 *
 * This module is deliberately free of I/O so that both halves of the intended
 * fetcher/scanner split (THREAT_MODEL §5, TB-2/TB-3) can use it: the networked
 * downloader verifies while streaming, and a network-disabled scanner handed
 * an opaque blob can re-verify the same way with no HTTP client in its
 * dependency graph.
 */

/**
 * Outcome of comparing what the registry declared against what we received.
 *
 * `not-declared` and `unsupported` are separate states on purpose. Both mean
 * "we did not verify", but only the second means the registry *expected*
 * verification to be possible and we could not deliver it — which is a
 * materially different fact for the risk engine.
 */
export type IntegrityReport =
  | { readonly status: "not-declared" }
  | { readonly status: "verified"; readonly algorithm: IntegrityAlgorithm }
  | { readonly status: "unsupported"; readonly declaredAlgorithms: readonly string[] };

/**
 * Map an {@link IntegrityReport} onto `ArtifactInfo.integrityVerified`.
 *
 * Tri-state, because a boolean would force us to lie about pre-SSRI packages:
 *
 *  - `true`  — declared and matched
 *  - `false` — declared in an algorithm we cannot check
 *  - absent  — the registry declared nothing
 *
 * A *mismatch* never reaches this function; it aborts the scan instead.
 *
 * On `unsupported` we report `false` rather than throwing. Refusing to scan
 * would let anyone who can influence a registry response make a package
 * permanently unscannable by declaring a future algorithm; reporting the
 * artifact as unverified instead pushes the decision to the risk engine, where
 * "unverified" must not be able to reach `ALLOW`. That is where failing closed
 * actually has to happen.
 */
export function integrityVerifiedFlag(report: IntegrityReport): boolean | undefined {
  switch (report.status) {
    case "verified":
      return true;
    case "unsupported":
      return false;
    case "not-declared":
      return undefined;
  }
}

/**
 * Compare a finished {@link ArtifactDigester} against a declared integrity
 * string.
 *
 * @throws {ScanError} `INTEGRITY_MISMATCH` when a supported algorithm was
 * declared and the digest does not match. The error carries the algorithm and
 * the observed SHA-256 — never the tarball bytes, never a host path.
 */
export function verifyDigest(
  digester: ArtifactDigester,
  declaredIntegrity: string | undefined,
): IntegrityReport {
  const declaration = parseIntegrity(declaredIntegrity);

  if (declaration.kind === "none") return { status: "not-declared" };
  if (declaration.kind === "unsupported") {
    return { status: "unsupported", declaredAlgorithms: declaration.declaredAlgorithms };
  }

  const { expectation } = declaration;
  const actual = digester.digestFor(expectation.algorithm);
  if (actual === undefined) {
    // Only reachable if a digester was built without the expectation it is now
    // being asked about. That is a wiring fault in our own code, not a
    // statement about the package, so it must not be reported as tampering.
    throw new ScanError("INTERNAL", "Integrity digest was not computed for the declared algorithm", {
      details: { algorithm: expectation.algorithm },
    });
  }

  if (!digestMatches(expectation, actual)) {
    throw new ScanError("INTEGRITY_MISMATCH", "Downloaded tarball did not match the integrity declared by the registry", {
      details: { algorithm: expectation.algorithm, sha256: digester.sha256Hex() },
    });
  }

  return { status: "verified", algorithm: expectation.algorithm };
}

/** Convenience wrapper for callers that already hold the complete artifact. */
export function verifyBytes(
  bytes: Uint8Array,
  declaredIntegrity: string | undefined,
): { readonly sha256: string; readonly report: IntegrityReport } {
  const declaration = parseIntegrity(declaredIntegrity);
  const digester = new ArtifactDigester(
    declaration.kind === "expectation" ? declaration.expectation : undefined,
  );
  digester.update(bytes);
  return { sha256: digester.sha256Hex(), report: verifyDigest(digester, declaredIntegrity) };
}
