import { z } from "zod";

/**
 * Known security intelligence from authoritative external feeds.
 *
 * The central rule: **malware and vulnerability are different claims** and are
 * never merged. "This package is malware" and "this package has a known CVE"
 * lead to completely different analyst actions. Collapsing them into a generic
 * "advisory" count is the single most common way supply-chain tools mislead
 * their users, so the distinction is carried in the type system.
 */

export const ADVISORY_KINDS = [
  /** The package itself is malicious. An assertion about intent. */
  "KNOWN_MALWARE",
  /** The package contains an exploitable defect. An assertion about a bug. */
  "KNOWN_VULNERABILITY",
] as const;
export const AdvisoryKindSchema = z.enum(ADVISORY_KINDS);
export type AdvisoryKind = z.infer<typeof AdvisoryKindSchema>;

export const ADVISORY_SEVERITIES = [
  "LOW",
  "MODERATE",
  "HIGH",
  "CRITICAL",
  "UNKNOWN",
] as const;
export const AdvisorySeveritySchema = z.enum(ADVISORY_SEVERITIES);
export type AdvisorySeverity = z.infer<typeof AdvisorySeveritySchema>;

export const AdvisorySchema = z.object({
  kind: AdvisoryKindSchema,
  /** Feed that made the claim, e.g. "GitHub Advisories", "OSV". Always shown. */
  source: z.string().min(1),
  /** Feed-native identifier, e.g. a GHSA or OSV id. */
  identifier: z.string().min(1),
  aliases: z.array(z.string()).default([]),
  summary: z.string(),
  severity: AdvisorySeveritySchema,
  /** Range the advisory applies to, verbatim from the feed. */
  vulnerableVersionRange: z.string().optional(),
  firstPatchedVersion: z.string().optional(),
  url: z.string().optional(),
  publishedAt: z.string().optional(),
  /**
   * True when the feed's range covers the exact version we analysed. A feed
   * entry for a *different* version of the same package is context, not a hit.
   */
  affectsScannedVersion: z.boolean(),
});
export type Advisory = z.infer<typeof AdvisorySchema>;

/**
 * Result of consulting the intelligence feeds. `lookupFailed` matters: an
 * advisory lookup that errored is not the same as a package with no advisories,
 * and the UI must not present the two identically.
 */
export const IntelligenceResultSchema = z.object({
  advisories: z.array(AdvisorySchema).default([]),
  sourcesConsulted: z.array(z.string()).default([]),
  lookupFailed: z.boolean().default(false),
  failureReason: z.string().optional(),
});
export type IntelligenceResult = z.infer<typeof IntelligenceResultSchema>;

/**
 * Provenance / attestation context.
 *
 * Provenance attests to *where and how* an artifact was built. It does not
 * attest that the code behaves safely — a maliciously authored package built
 * transparently in CI has perfect provenance. Equally, the absence of
 * provenance is unremarkable: most of the registry predates the feature.
 *
 * Both directions of over-claiming are wrong, so the states are explicit and
 * the UI is required to render them honestly.
 */
/**
 * Note the deliberate absence of a `VERIFIED` state. PackageGate does not
 * perform Sigstore bundle or certificate-chain verification in v1, so claiming
 * "provenance verified" would be a lie of exactly the kind this product exists
 * to avoid. `ATTESTATION_PUBLISHED` says precisely what we checked: the
 * registry served an attestation for this version.
 *
 * `NOT_FOUND` is also weaker than it looks — the attestations endpoint returns
 * an identical 404 for "this version has no provenance" and "this package does
 * not exist", so the state is corroborated against the packument rather than
 * inferred from the 404 alone.
 */
export const PROVENANCE_STATES = [
  "ATTESTATION_PUBLISHED",
  "NOT_FOUND",
  "LOOKUP_FAILED",
  "NOT_CHECKED",
] as const;
export const ProvenanceStateSchema = z.enum(PROVENANCE_STATES);
export type ProvenanceState = z.infer<typeof ProvenanceStateSchema>;

export const ProvenanceRecordSchema = z.object({
  state: ProvenanceStateSchema,
  /** Attestation predicate types returned by the registry, if any. */
  predicateTypes: z.array(z.string()).default([]),
  /** Source repository asserted by the attestation, if present. */
  sourceRepository: z.string().optional(),
  /** Build workflow/runner asserted by the attestation, if present. */
  buildWorkflow: z.string().optional(),
  /**
   * True when the attestation's subject digest matches the artifact we actually
   * downloaded. This is a genuine check we can perform without Sigstore
   * verification: it binds the bytes we analysed to the bytes the attestation
   * describes. It does **not** establish that the attestation is authentic —
   * only that it refers to this artifact.
   */
  subjectDigestMatchesArtifact: z.boolean().optional(),
  failureReason: z.string().optional(),
});
export type ProvenanceRecord = z.infer<typeof ProvenanceRecordSchema>;
