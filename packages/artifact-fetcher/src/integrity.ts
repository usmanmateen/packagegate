import { createHash, timingSafeEqual } from "node:crypto";

/**
 * Subresource-integrity handling for registry-declared tarball digests.
 *
 * npm publishes two different things, and both have to be handled honestly:
 *
 *  - `dist.integrity` — an SSRI string such as `sha512-<base64>`, possibly
 *    several whitespace-separated entries, possibly with `?options` suffixes.
 *  - `dist.shasum` — a bare hex SHA-1, which is all that exists for versions
 *    published before SSRI was introduced.
 *
 * Versions published in the early 2010s have neither in a usable form. That is
 * *not* evidence of tampering and must never be reported as a failed check —
 * it is reported as "not declared", which is why {@link IntegrityOutcome} has
 * three states rather than a boolean.
 */

/** Digest algorithms we will verify, strongest first. */
export const SUPPORTED_INTEGRITY_ALGORITHMS = ["sha512", "sha384", "sha256", "sha1"] as const;
export type IntegrityAlgorithm = (typeof SUPPORTED_INTEGRITY_ALGORITHMS)[number];

const SUPPORTED = new Set<string>(SUPPORTED_INTEGRITY_ALGORITHMS);

/** `<algorithm>-<base64>` with an optional `?opts` suffix, per the SSRI spec. */
const SSRI_ENTRY = /^([a-z0-9]+)-([A-Za-z0-9+/=]+)(?:\?[\x21-\x7e]*)?$/;
/** A bare hex SHA-1, the shape of the legacy `dist.shasum` field. */
const HEX_SHA1 = /^[0-9a-f]{40}$/i;

export interface IntegrityExpectation {
  readonly algorithm: IntegrityAlgorithm;
  /** Expected digest as raw bytes, so base64 padding variance cannot matter. */
  readonly digest: Buffer;
}

export type IntegrityDeclaration =
  /** The registry declared nothing we can check against. */
  | { readonly kind: "none" }
  /**
   * Something was declared, but in no algorithm we support. Callers must fail
   * closed: an unverifiable declaration is weaker than no declaration, because
   * it means the registry expected verification to be possible.
   */
  | { readonly kind: "unsupported"; readonly declaredAlgorithms: readonly string[] }
  | { readonly kind: "expectation"; readonly expectation: IntegrityExpectation };

/**
 * Parse a `dist.integrity` / `dist.shasum` value into something checkable.
 *
 * Unknown algorithms are collected rather than ignored so the caller can say
 * *why* it could not verify. When several supported algorithms are present the
 * strongest one wins, matching npm's own selection rule.
 */
export function parseIntegrity(raw: string | undefined): IntegrityDeclaration {
  if (raw === undefined) return { kind: "none" };
  const trimmed = raw.trim();
  if (trimmed.length === 0) return { kind: "none" };

  const candidates = new Map<IntegrityAlgorithm, Buffer>();
  const declared: string[] = [];

  for (const token of trimmed.split(/\s+/)) {
    if (HEX_SHA1.test(token)) {
      declared.push("sha1");
      if (!candidates.has("sha1")) candidates.set("sha1", Buffer.from(token, "hex"));
      continue;
    }

    const match = SSRI_ENTRY.exec(token);
    if (match === null) continue;
    const algorithm = match[1];
    const encoded = match[2];
    if (algorithm === undefined || encoded === undefined) continue;

    declared.push(algorithm);
    if (!SUPPORTED.has(algorithm)) continue;

    const digest = Buffer.from(encoded, "base64");
    if (digest.byteLength === 0) continue;
    const supported = algorithm as IntegrityAlgorithm;
    if (!candidates.has(supported)) candidates.set(supported, digest);
  }

  for (const algorithm of SUPPORTED_INTEGRITY_ALGORITHMS) {
    const digest = candidates.get(algorithm);
    if (digest !== undefined) {
      return { kind: "expectation", expectation: { algorithm, digest } };
    }
  }

  if (declared.length === 0) return { kind: "unsupported", declaredAlgorithms: [] };
  return { kind: "unsupported", declaredAlgorithms: declared };
}

/**
 * Streaming digest accumulator.
 *
 * SHA-256 is always computed — it is our own identifier for the artifact and
 * is reported regardless of what the registry declared. A second hash is only
 * created when an expectation actually needs it, so we do not pay for three
 * passes over every tarball.
 */
export class ArtifactDigester {
  readonly #sha256 = createHash("sha256");
  readonly #extra: { algorithm: IntegrityAlgorithm; hash: ReturnType<typeof createHash> } | undefined;

  constructor(expectation?: IntegrityExpectation) {
    if (expectation !== undefined && expectation.algorithm !== "sha256") {
      this.#extra = {
        algorithm: expectation.algorithm,
        hash: createHash(expectation.algorithm),
      };
    }
  }

  update(chunk: Uint8Array): void {
    this.#sha256.update(chunk);
    this.#extra?.hash.update(chunk);
  }

  /** Hex SHA-256 of everything fed in. This is what we report as the artifact id. */
  sha256Hex(): string {
    return this.#sha256.copy().digest("hex");
  }

  digestFor(algorithm: IntegrityAlgorithm): Buffer | undefined {
    if (algorithm === "sha256") return this.#sha256.copy().digest();
    if (this.#extra?.algorithm === algorithm) return this.#extra.hash.copy().digest();
    return undefined;
  }
}

/** Constant-time comparison of a computed digest against a declared one. */
export function digestMatches(expectation: IntegrityExpectation, actual: Buffer): boolean {
  if (actual.byteLength !== expectation.digest.byteLength) return false;
  return timingSafeEqual(actual, expectation.digest);
}
