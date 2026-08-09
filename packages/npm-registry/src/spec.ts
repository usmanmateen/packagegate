import {
  MAX_PACKAGE_NAME_LENGTH,
  PACKAGE_NAME_PATTERN,
  ScanError,
  sanitiseInlineValue,
  type PackageSpec,
} from "@packagegate/shared";

/**
 * Parsing of user-supplied package specifiers.
 *
 * This is a security boundary, not a convenience helper. The parsed name is
 * interpolated into registry URLs and used as a database key, so anything that
 * is not unambiguously a published registry package is rejected outright.
 *
 * Accepted:
 *   express
 *   lodash@4.17.21
 *   @scope/package
 *   @scope/package@1.2.0
 *   lodash@latest          (dist-tag)
 *
 * Rejected: local paths, git URLs, tarball URLs, `file:` specifiers, aliases
 * (`npm:`), anything containing a path separator outside a scope, and anything
 * failing npm's own name rules.
 */

/** Specifier forms npm itself accepts but PackageGate deliberately does not. */
const REJECTED_PREFIXES = [
  "file:",
  "npm:",
  "git:",
  "git+",
  "http:",
  "https:",
  "github:",
  "gitlab:",
  "bitbucket:",
  "workspace:",
  "link:",
  "portal:",
];

function reject(raw: string, reason: string): never {
  throw new ScanError("INVALID_SPEC", reason, {
    details: { spec: sanitiseInlineValue(raw, 120) },
  });
}

/**
 * Split a specifier into name and version.
 *
 * The subtlety is scoped packages: `@scope/name@1.0.0` contains two `@`, and
 * only the second one separates the version. Splitting on the first `@`, or on
 * every `@`, is the classic bug here — it turns `@scope/name` into a request
 * for package `scope/name` at no version.
 */
function splitNameAndVersion(spec: string): { name: string; version?: string } {
  const isScoped = spec.startsWith("@");
  const searchFrom = isScoped ? 1 : 0;
  const separatorIndex = spec.indexOf("@", searchFrom);

  if (separatorIndex === -1) return { name: spec };

  return {
    name: spec.slice(0, separatorIndex),
    version: spec.slice(separatorIndex + 1),
  };
}

/**
 * Parse and validate a package specifier.
 *
 * @throws {ScanError} with code `INVALID_SPEC` for anything not a published
 * registry package. The error message is safe to show a user and never echoes
 * unsanitised input.
 */
export function parsePackageSpec(input: string): PackageSpec {
  if (typeof input !== "string") {
    reject(String(input), "Package specifier must be a string");
  }

  const trimmed = input.trim();

  if (trimmed.length === 0) reject(input, "Package specifier is empty");
  if (trimmed.includes("\0")) reject(input, "Package specifier contains a NUL byte");
  // A generous ceiling: 214 for the name, plus room for a version range.
  if (trimmed.length > MAX_PACKAGE_NAME_LENGTH + 100) {
    reject(input, "Package specifier is too long");
  }

  const lowered = trimmed.toLowerCase();
  for (const prefix of REJECTED_PREFIXES) {
    if (lowered.startsWith(prefix)) {
      reject(
        input,
        "Only published npm registry packages can be investigated; URLs, git references and local paths are not accepted",
      );
    }
  }

  // Relative and absolute paths. Checked explicitly so the error is useful
  // rather than a generic name-pattern failure.
  if (trimmed.startsWith(".") || trimmed.startsWith("/") || trimmed.startsWith("~")) {
    reject(input, "Local paths cannot be investigated; supply a published package name");
  }
  if (trimmed.includes("\\")) {
    reject(input, "Package specifier contains an invalid path separator");
  }

  const { name, version } = splitNameAndVersion(trimmed);

  if (name.length === 0) reject(input, "Package name is missing");
  if (name.length > MAX_PACKAGE_NAME_LENGTH) {
    reject(
      input,
      `Package name exceeds npm's ${MAX_PACKAGE_NAME_LENGTH} character limit`,
    );
  }
  if (!PACKAGE_NAME_PATTERN.test(name)) {
    reject(input, "Not a valid npm package name");
  }

  // An empty version after a separator means the user typed a trailing `@`.
  if (version !== undefined && version.trim().length === 0) {
    reject(input, "Version is empty; omit the @ to resolve the current version");
  }
  if (version !== undefined && version.includes("/")) {
    reject(input, "Version contains an invalid character");
  }

  const scope = name.startsWith("@") ? name.slice(1, name.indexOf("/")) : undefined;

  return {
    name,
    ...(scope === undefined ? {} : { scope }),
    ...(version === undefined ? {} : { requestedVersion: version }),
    raw: sanitiseInlineValue(trimmed, MAX_PACKAGE_NAME_LENGTH + 100),
  };
}

/**
 * Encode a package name for use in a registry URL path.
 *
 * Scoped names contain a `/` that must be percent-encoded — `@scope/name`
 * becomes `@scope%2Fname`. The `@` itself is left as-is, which is what the
 * registry expects. Using `encodeURIComponent` on the whole name would also
 * escape the `@` and produce a 404.
 */
export function encodePackageNameForUrl(name: string): string {
  if (!name.startsWith("@")) return encodeURIComponent(name);

  const separatorIndex = name.indexOf("/");
  if (separatorIndex === -1) return encodeURIComponent(name);

  // Slice past the leading `@` so encodeURIComponent cannot turn it into %40.
  const scope = name.slice(1, separatorIndex);
  const rest = name.slice(separatorIndex + 1);
  return `@${encodeURIComponent(scope)}%2F${encodeURIComponent(rest)}`;
}

/** Render a spec back to its canonical string form, for display and audit. */
export function formatPackageSpec(spec: PackageSpec): string {
  return spec.requestedVersion === undefined
    ? spec.name
    : `${spec.name}@${spec.requestedVersion}`;
}
