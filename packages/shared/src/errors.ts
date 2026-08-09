/**
 * Structured error types.
 *
 * Scanner failures are first-class results, not exceptions to be swallowed.
 * A scan that hit an extraction limit is a *finding about the package*, not an
 * internal fault, and the difference must survive all the way to the API and
 * the analyst. Silently returning an empty result would report a hostile
 * package as clean — the worst possible failure mode for this product.
 */

export const SCAN_ERROR_CODES = [
  /** Spec was malformed, or referenced something other than a registry package. */
  "INVALID_SPEC",
  /** Package or version does not exist in the registry. */
  "NOT_FOUND",
  /** Registry or advisory feed was unreachable or returned an error. */
  "UPSTREAM_UNAVAILABLE",
  /** A declared size, file-count or time budget was exceeded. */
  "LIMIT_EXCEEDED",
  /** Archive entry attempted to escape the extraction root. */
  "TRAVERSAL_BLOCKED",
  /** Archive was truncated, corrupt, or not a gzip tarball at all. */
  "MALFORMED_ARCHIVE",
  /** Integrity declared by the registry did not match the bytes received. */
  "INTEGRITY_MISMATCH",
  /** The scan exceeded its overall wall-clock budget. */
  "TIMEOUT",
  /** An unexpected internal fault. Always logged with the scan id. */
  "INTERNAL",
] as const;
export type ScanErrorCode = (typeof SCAN_ERROR_CODES)[number];

export interface ScanErrorDetails {
  /** Machine-readable context. Must never contain host filesystem paths. */
  readonly [key: string]: string | number | boolean | undefined;
}

/**
 * Base error for everything the scanning pipeline can fail with.
 *
 * `message` is safe to show a user. Host paths, credentials and raw package
 * bytes must never be interpolated into it.
 */
export class ScanError extends Error {
  readonly code: ScanErrorCode;
  readonly details: ScanErrorDetails;
  /** True when the same request could plausibly succeed if retried later. */
  readonly retryable: boolean;

  constructor(
    code: ScanErrorCode,
    message: string,
    options: { details?: ScanErrorDetails; retryable?: boolean; cause?: unknown } = {},
  ) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = "ScanError";
    this.code = code;
    this.details = options.details ?? {};
    this.retryable = options.retryable ?? false;
  }
}

/** A defensive limit was hit while handling a hostile artifact. */
export class LimitExceededError extends ScanError {
  constructor(limitName: string, limit: number, observed: number) {
    super("LIMIT_EXCEEDED", `Artifact exceeded the ${limitName} limit`, {
      details: { limitName, limit, observed },
    });
    this.name = "LimitExceededError";
  }
}

/** An archive entry tried to write outside the extraction root. */
export class TraversalBlockedError extends ScanError {
  constructor(entryPath: string) {
    super("TRAVERSAL_BLOCKED", "Archive entry attempted to escape the extraction root", {
      details: { entryPath },
    });
    this.name = "TraversalBlockedError";
  }
}

/** Narrow an unknown catch value to a ScanError without losing information. */
export function toScanError(error: unknown, fallbackMessage = "Scan failed"): ScanError {
  if (error instanceof ScanError) return error;
  if (error instanceof Error) {
    return new ScanError("INTERNAL", fallbackMessage, { cause: error });
  }
  return new ScanError("INTERNAL", fallbackMessage, {
    details: { raw: typeof error },
  });
}
