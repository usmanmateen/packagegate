import { z } from "zod";

/**
 * Severity describes how serious a finding would be *if* it represents
 * malicious intent. It deliberately says nothing about likelihood — that is
 * what {@link Confidence} is for. Keeping the two axes separate is what stops
 * "this package reads process.env" from being reported as a high-severity event.
 */
export const SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
export const SeveritySchema = z.enum(SEVERITIES);
export type Severity = z.infer<typeof SeveritySchema>;

/**
 * Confidence describes how certain the analyser is that the detection is real
 * and correctly attributed — not how bad it is. A perfectly-detected
 * `process.env` read is HIGH confidence and LOW severity.
 */
export const CONFIDENCES = ["LOW", "MEDIUM", "HIGH"] as const;
export const ConfidenceSchema = z.enum(CONFIDENCES);
export type Confidence = z.infer<typeof ConfidenceSchema>;

/**
 * Finding categories. These describe *observed behaviour*, never a verdict.
 * `PROCESS_EXECUTION` means the package can execute a process — an entirely
 * normal thing for a build tool to do. Interpretation belongs to the risk
 * engine, and only in combination with other evidence.
 */
export const FINDING_CATEGORIES = [
  "PROCESS_EXECUTION",
  "ENVIRONMENT_ACCESS",
  "NETWORK_ACCESS",
  "NETWORK_DESTINATION",
  "SENSITIVE_FILE_ACCESS",
  "FILESYSTEM_READ",
  "FILESYSTEM_WRITE",
  "DYNAMIC_CODE_EXECUTION",
  "ENCODED_PAYLOAD",
  "HIGH_ENTROPY_PAYLOAD",
  "INSTALL_SCRIPT",
  "NATIVE_BINARY",
  "OBFUSCATION_SIGNAL",
  "REMOTE_CODE_FETCH",
  "SYSTEM_INFORMATION_ACCESS",
  "CREDENTIAL_RELATED_ACCESS",
  "SHELL_COMMAND",
  "CRYPTOGRAPHIC_OPERATION",
  "DOWNLOAD_BEHAVIOUR",
  "EXECUTABLE_WRITE",
  "PACKAGE_MANAGER_ACCESS",
  "HOME_DIRECTORY_ACCESS",
] as const;
export const FindingCategorySchema = z.enum(FINDING_CATEGORIES);
export type FindingCategory = z.infer<typeof FindingCategorySchema>;

/** npm lifecycle scripts that run automatically on install. */
export const INSTALL_LIFECYCLE_SCRIPTS = [
  "preinstall",
  "install",
  "postinstall",
  "prepare",
] as const;
export type InstallLifecycleScript = (typeof INSTALL_LIFECYCLE_SCRIPTS)[number];

/**
 * A source location inside an analysed package. `filePath` is always relative
 * to the package root — absolute host paths must never escape into evidence,
 * persistence or API responses.
 */
export const SourceLocationSchema = z.object({
  filePath: z.string().min(1),
  startLine: z.number().int().min(1),
  endLine: z.number().int().min(1),
  startColumn: z.number().int().min(0).optional(),
  endColumn: z.number().int().min(0).optional(),
});
export type SourceLocation = z.infer<typeof SourceLocationSchema>;
