import type { EvaluationManifest } from "./types.js";

export const DEFAULT_EVALUATION_MANIFEST: EvaluationManifest = {
  version: 1,
  samples: [
    {
      id: "lodash@4.17.21",
      label: "EXPECTED_BENIGN",
      kind: "REGISTRY",
      artifact: "lodash@4.17.21",
    },
    {
      id: "express@4.21.2",
      label: "EXPECTED_BENIGN",
      kind: "REGISTRY",
      artifact: "express@4.21.2",
    },
    {
      id: "debug@4.3.4",
      label: "EXPECTED_BENIGN",
      kind: "REGISTRY",
      artifact: "debug@4.3.4",
    },
    {
      id: "JSONStream@1.3.5",
      label: "EXPECTED_BENIGN",
      kind: "REGISTRY",
      artifact: "JSONStream@1.3.5",
    },
    {
      id: "inert-env-exfil",
      label: "SYNTHETIC_SUSPICIOUS",
      kind: "FIXTURE",
      artifact: "inert-env-exfil",
    },
    {
      id: "inert-install-curl-bash",
      label: "SYNTHETIC_SUSPICIOUS",
      kind: "FIXTURE",
      artifact: "inert-install-curl-bash",
    },
    {
      id: "inert-shell-cooccurrence-negative",
      label: "EXPECTED_BENIGN",
      kind: "FIXTURE",
      artifact: "inert-shell-cooccurrence-negative",
      notes: "Negative control: unused curl string must not create a chain",
    },
    {
      id: "02-echo@0.0.7",
      label: "MALICIOUS",
      kind: "LOCAL_TGZ",
      artifact: "artifacts/02-echo-0.0.7.tgz",
      requiresMalwareRoot: true,
      notes:
        "Datadog independently labelled malicious sample. Must be provided under --malware-root; never auto-downloaded.",
    },
  ],
};
