import { withExtractedPackage } from "@packagegate/artifact-fetcher";
import {
  parsePackageSpec,
  RegistryClient,
  type RegistryClientOptions,
} from "@packagegate/npm-registry";
import { ScanError, toScanError } from "@packagegate/shared";
import { investigateExtractedPackage, SCANNER_VERSION } from "./pipeline.js";
import type { InvestigationResult } from "./types.js";

export { SCANNER_VERSION };

export interface ScanOptions {
  readonly registry?: RegistryClientOptions;
  /** Enable optional ML assessment lane (PACKAGEGATE_ML=local or --ml). */
  readonly ml?: boolean;
}

/**
 * Resolve a package from the registry, download and extract its tarball safely,
 * then run the shared investigation pipeline. Temporary extraction always
 * cleans up.
 *
 * The investigated package is never installed and never executed.
 */
export async function scanPackage(
  specInput: string,
  options: ScanOptions = {},
): Promise<InvestigationResult> {
  const startedAt = new Date();

  try {
    const spec = parsePackageSpec(specInput);
    const client = new RegistryClient(options.registry);
    const { metadata, resolution } = await client.getPackageMetadata(
      spec.name,
      spec.requestedVersion,
    );

    const dist = metadata.dist;
    if (typeof dist.tarball !== "string" || dist.tarball.length === 0) {
      throw new ScanError("NOT_FOUND", "Resolved package has no tarball URL", {
        details: { package: metadata.name, version: metadata.version },
      });
    }

    const fallbackMetadata = {
      ...metadata,
      version: resolution.version,
    };

    return await withExtractedPackage(
      {
        url: dist.tarball,
        ...(dist.integrity === undefined ? {} : { integrity: dist.integrity }),
      },
      async (extracted) => {
        const integrityVerified = extracted.artifact.integrityVerified === true;
        let registryIntegrity;
        if (integrityVerified) {
          registryIntegrity = {
            status: "VERIFIED" as const,
            reason: "Artifact matched the integrity declared by the npm registry",
          };
        } else if (extracted.artifact.integrityVerified === false) {
          registryIntegrity = {
            status: "UNSUPPORTED" as const,
            reason: "Registry declared an integrity algorithm PackageGate cannot verify",
          };
        } else {
          registryIntegrity = {
            status: "NOT_DECLARED" as const,
            reason: "Registry did not declare an integrity digest for this version",
          };
        }

        const result = investigateExtractedPackage({
          extracted,
          requestedSpec: spec.raw,
          acquisition: {
            source: "REGISTRY",
            registryIntegrity,
          },
          startedAt,
          fallbackMetadata,
          requireManifest: false,
          integrityVerifiedForRisk: integrityVerified,
        });

        if (options.ml !== true) return result;

        const { withMlAssessment } = await import("./ml/apply.js");
        const { decodeContent } = await import("./pipeline.js");
        const sourceByPath = new Map(
          extracted.files.flatMap((file) => {
            if (file.content === undefined) return [];
            return [[file.path, decodeContent(file.content, file.path)] as const];
          }),
        );
        return withMlAssessment(result, { enabled: true, sourceByPath });
      },
    );
  } catch (error) {
    throw toScanError(error, "Package investigation failed");
  }
}
