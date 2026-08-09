import { createHash, timingSafeEqual } from "node:crypto";
import { withExtractedTarball } from "@packagegate/artifact-fetcher";
import { ScanError, toScanError } from "@packagegate/shared";
import {
  parseExpectedSha256,
  readLocalArtifactBytes,
  resolveLocalArtifactPath,
} from "./local-artifact.js";
import { investigateExtractedPackage } from "./pipeline.js";
import type { InvestigationResult } from "./types.js";

export interface ScanTarballOptions {
  /** Optional expected SHA-256 of the artifact bytes. Mismatch aborts. */
  readonly expectedSha256?: string;
}

function digestsEqual(actualHex: string, expectedHex: string): boolean {
  const actual = Buffer.from(actualHex, "hex");
  const expected = Buffer.from(expectedHex, "hex");
  if (actual.byteLength !== expected.byteLength) return false;
  return timingSafeEqual(actual, expected);
}

/**
 * Investigate a caller-supplied local npm `.tgz` through the same secure
 * extraction → analysis → risk pipeline as registry scans.
 *
 * The tarball is hostile input. It is never installed or executed.
 */
export async function scanLocalTarball(
  pathInput: string,
  options: ScanTarballOptions = {},
): Promise<InvestigationResult> {
  const startedAt = new Date();

  try {
    const local = await resolveLocalArtifactPath(pathInput);
    const expectedSha256 =
      options.expectedSha256 === undefined
        ? undefined
        : parseExpectedSha256(options.expectedSha256);

    const bytes = await readLocalArtifactBytes(local.absolutePath);
    const sha256 = createHash("sha256").update(bytes).digest("hex");

    if (expectedSha256 !== undefined && !digestsEqual(sha256, expectedSha256)) {
      throw new ScanError(
        "INTEGRITY_MISMATCH",
        "Local tarball SHA-256 did not match the supplied expected digest",
        {
          details: {
            algorithm: "sha256",
            sha256,
          },
        },
      );
    }

    const suppliedMatched = expectedSha256 !== undefined;

    return await withExtractedTarball(
      {
        bytes,
        // file:// display marker — not opened as a URL by the extractor.
        tarballUrl: `file://${local.fileName}`,
        // No registry integrity string: local artifacts are unverified unless
        // the caller supplied --sha256 (checked above before extraction work
        // beyond hashing). Passing undefined keeps integrityVerified absent.
      },
      (extracted) =>
        Promise.resolve(
          investigateExtractedPackage({
            extracted: {
              ...extracted,
              artifact: {
                ...extracted.artifact,
                sha256,
              },
            },
            requestedSpec: `file:${local.displayPath}`,
            acquisition: {
              source: "LOCAL",
              localPath: local.displayPath,
              registryIntegrity: {
                status: "NOT_APPLICABLE",
                reason:
                  "Local artifact has no trusted registry integrity reference",
              },
              ...(suppliedMatched
                ? {
                    suppliedDigest: {
                      expectedSha256: expectedSha256,
                      matched: true,
                    },
                  }
                : {}),
            },
            startedAt,
            requireManifest: true,
            // M1 only when the caller supplied a digest that matched.
            integrityVerifiedForRisk: suppliedMatched,
          }),
        ),
    );
  } catch (error) {
    throw toScanError(error, "Local tarball investigation failed");
  }
}
