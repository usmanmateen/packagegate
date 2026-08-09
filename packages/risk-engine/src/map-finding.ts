import type { Finding } from "@packagegate/shared";
import { RULE_WEIGHTS, type RuleWeight } from "./weights.js";

/**
 * Pragmatic mapping from static-analyser findings onto risk-model rules A–K.
 *
 * Unmapped or intentionally-zero categories return null and contribute nothing.
 */
export function mapFindingToRule(finding: Finding): RuleWeight | null {
  const { category, ruleId } = finding;
  const metadata = finding.metadata;

  if (ruleId.includes("minified") || metadata.minifiedOnly === true) {
    return null;
  }

  if (category === "NATIVE_BINARY") {
    return null;
  }

  if (category === "INSTALL_SCRIPT" || ruleId === "manifest/lifecycle/install-script") {
    return RULE_WEIGHTS.A1 ?? null;
  }
  if (ruleId === "manifest/lifecycle/inline-code") {
    return RULE_WEIGHTS.A2 ?? null;
  }
  if (ruleId === "manifest/lifecycle/fetch-and-execute") {
    return RULE_WEIGHTS.A3 ?? null;
  }
  if (category === "REMOTE_CODE_FETCH") {
    return RULE_WEIGHTS.A3 ?? null;
  }
  if (category === "DOWNLOAD_BEHAVIOUR" && metadata.runsOnInstall === true) {
    return RULE_WEIGHTS.C6 ?? null;
  }

  if (category === "PROCESS_EXECUTION") {
    return RULE_WEIGHTS.B1 ?? null;
  }
  if (category === "SHELL_COMMAND") {
    return RULE_WEIGHTS.B2 ?? null;
  }

  if (category === "CREDENTIAL_RELATED_ACCESS") {
    if (ruleId.includes("env-read")) return RULE_WEIGHTS.B5 ?? null;
    if (ruleId.includes("sensitive-path")) return RULE_WEIGHTS.D2 ?? null;
    return RULE_WEIGHTS.B5 ?? null;
  }

  if (category === "ENVIRONMENT_ACCESS") {
    if (ruleId.includes("env-enumeration") || metadata.via !== undefined) {
      return RULE_WEIGHTS.B4 ?? null;
    }
    return RULE_WEIGHTS.B3 ?? null;
  }

  if (category === "NETWORK_ACCESS") {
    if (ruleId.includes("dns")) return RULE_WEIGHTS.C3 ?? null;
    return RULE_WEIGHTS.C1 ?? null;
  }

  if (category === "NETWORK_DESTINATION") {
    if (ruleId.includes("destination-collector") || metadata.collectorMarker) {
      return RULE_WEIGHTS.C5 ?? null;
    }
    if (ruleId.includes("destination-ip-literal") || metadata.ipLiteral === true) {
      return RULE_WEIGHTS.C2 ?? null;
    }
    if (metadata.interpolated === true) {
      return RULE_WEIGHTS.C4 ?? null;
    }
    return RULE_WEIGHTS.C7 ?? null;
  }

  if (category === "FILESYSTEM_READ") {
    return RULE_WEIGHTS.D1 ?? null;
  }
  if (category === "SENSITIVE_FILE_ACCESS") {
    return RULE_WEIGHTS.D2 ?? null;
  }
  if (category === "PACKAGE_MANAGER_ACCESS") {
    return RULE_WEIGHTS.D2 ?? null;
  }
  if (category === "HOME_DIRECTORY_ACCESS") {
    return RULE_WEIGHTS.D3 ?? null;
  }
  if (category === "FILESYSTEM_WRITE" || category === "EXECUTABLE_WRITE") {
    return metadata.runsOnInstall === true
      ? (RULE_WEIGHTS.D4 ?? null)
      : (RULE_WEIGHTS.D5 ?? null);
  }

  if (category === "HIGH_ENTROPY_PAYLOAD") {
    return RULE_WEIGHTS.E5 ?? null;
  }
  if (category === "ENCODED_PAYLOAD") {
    if (ruleId.includes("encoded-code")) return RULE_WEIGHTS.E2 ?? null;
    return RULE_WEIGHTS.E5 ?? null;
  }
  if (category === "DYNAMIC_CODE_EXECUTION") {
    return RULE_WEIGHTS.E2 ?? null;
  }
  if (category === "OBFUSCATION_SIGNAL") {
    if (ruleId.includes("obfuscator-fingerprint")) return RULE_WEIGHTS.E3 ?? null;
    if (ruleId.includes("bidi-or-invisible")) return RULE_WEIGHTS.E4 ?? null;
    if (ruleId.includes("dynamic-dispatch")) return RULE_WEIGHTS.I4 ?? null;
    return RULE_WEIGHTS.E3 ?? null;
  }

  if (category === "SYSTEM_INFORMATION_ACCESS") {
    return RULE_WEIGHTS.B6 ?? null;
  }

  if (category === "CRYPTOGRAPHIC_OPERATION") {
    return null;
  }

  return null;
}
