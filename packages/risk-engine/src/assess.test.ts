import { describe, expect, it } from "vitest";
import type { BehaviourChain, Finding } from "@packagegate/shared";
import { contributionsReconcile } from "@packagegate/shared";
import { assessRisk } from "./assess.js";
import { saturateRule, B3_RULE_SATURATION_TABLE } from "./saturation.js";
import { RULE_WEIGHTS } from "./weights.js";

function baseFinding(overrides: Partial<Finding> & Pick<Finding, "id">): Finding {
  return {
    id: overrides.id,
    ruleId: overrides.ruleId ?? "js/environment/env-read",
    category: overrides.category ?? "ENVIRONMENT_ACCESS",
    title: overrides.title ?? "Environment variable read",
    description: overrides.description ?? "Reads process.env",
    severity: overrides.severity ?? "LOW",
    confidence: overrides.confidence ?? "HIGH",
    location: overrides.location ?? {
      filePath: "index.js",
      startLine: 1,
      endLine: 1,
    },
    snippet: overrides.snippet ?? "process.env.NODE_ENV",
    evidence: overrides.evidence ?? [
      {
        kind: "AST_NODE",
        description: "env read",
        location: { filePath: "index.js", startLine: 1, endLine: 1 },
      },
    ],
    metadata: overrides.metadata ?? {},
  };
}

function envReadFinding(id: string): Finding {
  return baseFinding({
    id,
    ruleId: "js/environment/env-read",
    category: "ENVIRONMENT_ACCESS",
    metadata: { variable: "NODE_ENV", targeted: false, mundane: true },
  });
}

function installScriptFinding(): Finding {
  return baseFinding({
    id: "install-script",
    ruleId: "manifest/lifecycle/install-script",
    category: "INSTALL_SCRIPT",
    title: "Install lifecycle script declared: postinstall",
    metadata: { script: "postinstall", runsOnInstall: true },
  });
}

function minifiedFinding(): Finding {
  return baseFinding({
    id: "minified",
    ruleId: "file/minified-bundle",
    category: "OBFUSCATION_SIGNAL",
    metadata: { minifiedOnly: true },
  });
}

function strongChain(id: string): BehaviourChain {
  return {
    id,
    source: "ENVIRONMENT_ACCESS",
    transformations: [],
    sink: "NETWORK_REQUEST",
    confidence: "HIGH",
    links: [
      {
        kind: "SHARED_BINDING",
        description: "token flows to fetch body",
        location: { filePath: "index.js", startLine: 10, endLine: 10 },
        via: "token",
      },
    ],
    supportingFindingIds: ["env-secret", "network-dest"],
    filePaths: ["index.js"],
    rationale: "Environment read reaches outbound network request.",
    metadata: { installTimeRooted: true, runsOnInstall: true },
  };
}

describe("saturation — B3 rule table (§4.5)", () => {
  it("matches documented per-rule saturation within tolerance", () => {
    for (const [occurrences, expected] of Object.entries(B3_RULE_SATURATION_TABLE)) {
      const count = Number(occurrences);
      const saturated = saturateRule(count, RULE_WEIGHTS.B3?.kappa ?? 4);
      expect(saturated).toBeCloseTo(expected, 1);
    }
  });
});

describe("assessRisk — §7.2 E2: 200 generic env reads", () => {
  it("scores ~3–4 and returns ALLOW / LOW_RISK", () => {
    const findings = Array.from({ length: 200 }, (_, index) =>
      envReadFinding(`env-${String(index)}`),
    );
    const result = assessRisk({ findings });

    expect(result.score).toBeGreaterThanOrEqual(2);
    expect(result.score).toBeLessThanOrEqual(4);
    expect(result.recommendation).toBe("ALLOW");
    expect(result.classification).toBe("LOW_RISK");
    expect(contributionsReconcile(result.contributions, result.rawTotal)).toBe(true);
  });
});

describe("assessRisk — §6.1 postinstall alone", () => {
  it("stays low and ALLOW", () => {
    const result = assessRisk({ findings: [installScriptFinding()] });

    expect(result.score).toBeLessThanOrEqual(3);
    expect(result.recommendation).toBe("ALLOW");
    expect(result.classification).toBe("LOW_RISK");
  });
});

describe("assessRisk — minification contributes zero", () => {
  it("does not increase score for minified-only inventory", () => {
    const baseline = assessRisk({ findings: [] });
    const withMinified = assessRisk({ findings: [minifiedFinding()] });

    expect(withMinified.score).toBe(baseline.score);
    expect(withMinified.rawTotal).toBe(baseline.rawTotal);
  });
});

describe("assessRisk — structural invariant without chains", () => {
  it("cannot reach BLOCK from breadth alone", () => {
    const findings: Finding[] = [
      installScriptFinding(),
      baseFinding({
        id: "b1",
        category: "PROCESS_EXECUTION",
        ruleId: "js/process-execution/child-process",
      }),
      baseFinding({
        id: "c1",
        category: "NETWORK_ACCESS",
        ruleId: "js/network/outbound-capability",
      }),
      baseFinding({
        id: "b5",
        category: "CREDENTIAL_RELATED_ACCESS",
        ruleId: "js/environment/env-read-credential",
        metadata: { variable: "NPM_TOKEN", targeted: true },
      }),
      baseFinding({
        id: "c5",
        category: "NETWORK_DESTINATION",
        ruleId: "js/network/destination-collector",
        metadata: { collectorMarker: "discord.com/api/webhooks" },
      }),
      baseFinding({
        id: "d2",
        category: "SENSITIVE_FILE_ACCESS",
        ruleId: "js/filesystem/sensitive-path",
      }),
    ];

    const result = assessRisk({ findings, chains: [] });

    expect(result.score).toBeLessThan(90);
    expect(result.recommendation).not.toBe("BLOCK");
  });
});

describe("assessRisk — decision thresholds (§8)", () => {
  it("BLOCK at score≥90 with ≥2 chains and max conf≥0.80", () => {
    const chains = [
      strongChain("chain-1"),
      strongChain("chain-2"),
      strongChain("chain-3"),
    ];
    const findings: Finding[] = [
      installScriptFinding(),
      baseFinding({
        id: "b4",
        ruleId: "js/environment/env-enumeration",
        category: "ENVIRONMENT_ACCESS",
        metadata: { via: "Object.keys" },
      }),
      baseFinding({
        id: "b5a",
        category: "CREDENTIAL_RELATED_ACCESS",
        ruleId: "js/environment/env-read-credential",
        metadata: { variable: "NPM_TOKEN", targeted: true },
      }),
      baseFinding({
        id: "b5b",
        category: "CREDENTIAL_RELATED_ACCESS",
        ruleId: "js/environment/env-read-credential",
        metadata: { variable: "GITHUB_TOKEN", targeted: true },
      }),
      baseFinding({
        id: "b5c",
        category: "CREDENTIAL_RELATED_ACCESS",
        ruleId: "js/environment/env-read-credential",
        metadata: { variable: "AWS_SECRET_ACCESS_KEY", targeted: true },
      }),
      baseFinding({
        id: "b5d",
        category: "CREDENTIAL_RELATED_ACCESS",
        ruleId: "js/environment/env-read-credential",
        metadata: { variable: "DOCKER_PASSWORD", targeted: true },
      }),
      baseFinding({
        id: "c5",
        category: "NETWORK_DESTINATION",
        ruleId: "js/network/destination-collector",
        metadata: { collectorMarker: "discord.com/api/webhooks" },
      }),
      baseFinding({
        id: "d2a",
        category: "SENSITIVE_FILE_ACCESS",
        ruleId: "js/filesystem/sensitive-path",
      }),
      baseFinding({
        id: "d2b",
        category: "SENSITIVE_FILE_ACCESS",
        ruleId: "js/filesystem/sensitive-path",
      }),
      baseFinding({
        id: "d2c",
        category: "SENSITIVE_FILE_ACCESS",
        ruleId: "js/filesystem/sensitive-path",
      }),
      baseFinding({
        id: "e2",
        category: "DYNAMIC_CODE_EXECUTION",
        ruleId: "js/dynamic-execution/encoded-code",
        severity: "HIGH",
      }),
      baseFinding({
        id: "f2",
        category: "ENCODED_PAYLOAD",
        ruleId: "js/encoding/base64",
      }),
      baseFinding({
        id: "h4",
        category: "FILESYSTEM_WRITE",
        ruleId: "js/filesystem/write",
        metadata: { runsOnInstall: true },
      }),
    ];

    const result = assessRisk({ findings, chains });

    expect(result.score).toBeGreaterThanOrEqual(90);
    expect(result.recommendation).toBe("BLOCK");
    expect(result.classification).toBe("HIGH_RISK_BEHAVIOUR");
  });

  it("REVIEW HIGH_RISK at score≥50", () => {
    const findings: Finding[] = [
      installScriptFinding(),
      baseFinding({
        id: "b4",
        ruleId: "js/environment/env-enumeration",
        category: "ENVIRONMENT_ACCESS",
        metadata: { via: "Object.keys" },
      }),
      baseFinding({
        id: "b5a",
        category: "CREDENTIAL_RELATED_ACCESS",
        ruleId: "js/environment/env-read-credential",
        metadata: { variable: "NPM_TOKEN", targeted: true },
      }),
      baseFinding({
        id: "b5b",
        category: "CREDENTIAL_RELATED_ACCESS",
        ruleId: "js/environment/env-read-credential",
        metadata: { variable: "GITHUB_TOKEN", targeted: true },
      }),
      baseFinding({
        id: "d2",
        category: "SENSITIVE_FILE_ACCESS",
        ruleId: "js/filesystem/sensitive-path",
      }),
      baseFinding({
        id: "c5",
        category: "NETWORK_DESTINATION",
        ruleId: "js/network/destination-collector",
        metadata: { collectorMarker: "discord.com/api/webhooks" },
      }),
    ];
    const chains = [
      {
        ...strongChain("j1"),
        metadata: { installTimeRooted: true, runsOnInstall: true },
      },
    ];

    const result = assessRisk({ findings, chains });

    expect(result.score).toBeGreaterThanOrEqual(50);
    expect(result.recommendation).toBe("REVIEW");
    expect(result.classification).toBe("HIGH_RISK_BEHAVIOUR");
  });

  it("REVIEW SUSPICIOUS at score≥25", () => {
    const findings: Finding[] = [
      installScriptFinding(),
      baseFinding({
        id: "b5",
        category: "CREDENTIAL_RELATED_ACCESS",
        ruleId: "js/environment/env-read-credential",
        metadata: { variable: "NPM_TOKEN", targeted: true },
      }),
      baseFinding({
        id: "b4",
        ruleId: "js/environment/env-enumeration",
        category: "ENVIRONMENT_ACCESS",
        metadata: { via: "Object.keys" },
      }),
      baseFinding({
        id: "c5",
        category: "NETWORK_DESTINATION",
        ruleId: "js/network/destination-collector",
        metadata: { collectorMarker: "discord.com/api/webhooks" },
      }),
    ];

    const result = assessRisk({ findings, chains: [strongChain("j1-lite")] });

    expect(result.score).toBeGreaterThanOrEqual(25);
    expect(result.recommendation).toBe("REVIEW");
    expect(result.classification).toBe("SUSPICIOUS");
  });
});

describe("assessRisk — Lane I known malware", () => {
  it("forces BLOCK / KNOWN_MALWARE regardless of score", () => {
    const result = assessRisk({
      findings: [envReadFinding("env-0")],
      knownMalware: true,
    });

    expect(result.recommendation).toBe("BLOCK");
    expect(result.classification).toBe("KNOWN_MALWARE");
    expect(result.knownMalware).toBe(true);
  });

  it("forces BLOCK via intelligence tier", () => {
    const result = assessRisk({
      findings: [],
      intelligenceTier: ["AUTHORITATIVE_MALWARE"],
    });

    expect(result.recommendation).toBe("BLOCK");
    expect(result.classification).toBe("KNOWN_MALWARE");
  });
});

describe("assessRisk — coverage floor", () => {
  it("returns REVIEW / INSUFFICIENT_EVIDENCE below 0.60", () => {
    const result = assessRisk({
      findings: [envReadFinding("env-0")],
      analysisCoverage: 0.55,
    });

    expect(result.recommendation).toBe("REVIEW");
    expect(result.classification).toBe("INSUFFICIENT_EVIDENCE");
  });
});

describe("assessRisk — contributions reconcile", () => {
  it("holds for mixed findings and chains", () => {
    const result = assessRisk({
      findings: [
        installScriptFinding(),
        envReadFinding("env-0"),
        baseFinding({
          id: "c5",
          category: "NETWORK_DESTINATION",
          ruleId: "js/network/destination-collector",
          metadata: { collectorMarker: "webhook" },
        }),
      ],
      chains: [strongChain("chain-1")],
      integrityVerified: true,
    });

    expect(contributionsReconcile(result.contributions, result.rawTotal)).toBe(true);
  });
});

describe("assessRisk — env→network chain contributes substantial X", () => {
  it("raises score materially with strong install-time J1", () => {
    const withoutChain = assessRisk({
      findings: [
        baseFinding({
          id: "b5",
          category: "CREDENTIAL_RELATED_ACCESS",
          ruleId: "js/environment/env-read-credential",
          metadata: { variable: "NPM_TOKEN", targeted: true },
        }),
      ],
    });
    const withChain = assessRisk({
      findings: [
        baseFinding({
          id: "b5",
          category: "CREDENTIAL_RELATED_ACCESS",
          ruleId: "js/environment/env-read-credential",
          metadata: { variable: "NPM_TOKEN", targeted: true },
        }),
      ],
      chains: [strongChain("j1")],
    });

    expect(withChain.score).toBeGreaterThan(withoutChain.score + 15);
    expect(withChain.rawTotal - withoutChain.rawTotal).toBeGreaterThan(15);
  });
});
