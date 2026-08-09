import { describe, expect, it } from "vitest";
import type {
  AnalysisCompleteness,
  BehaviourChain,
  Finding,
  PolicyDecision,
} from "@packagegate/shared";
import { compareInvestigations, findingIdentity } from "./index.js";
import type { DiffableInvestigation } from "./types.js";

function completeness(status: AnalysisCompleteness["status"] = "COMPLETE"): AnalysisCompleteness {
  return { status, reasons: [], coverageRatio: 1 };
}

function policy(action: PolicyDecision["finalAction"]): PolicyDecision {
  return {
    behaviouralRecommendation: action,
    analysisCompleteness: "COMPLETE",
    threatIntelligence: "NONE",
    finalAction: action,
    reasons: [{ code: "BEHAVIOURAL_ALLOW", message: "test" }],
  };
}

function finding(overrides: Partial<Finding> & Pick<Finding, "ruleId" | "category" | "title">): Finding {
  return {
    id: overrides.id ?? "f1",
    ruleId: overrides.ruleId,
    category: overrides.category,
    title: overrides.title,
    description: "test",
    severity: "LOW",
    confidence: "HIGH",
    location: overrides.location ?? { filePath: "index.js", startLine: 1, endLine: 1 },
    snippet: "",
    evidence: [{ kind: "AST_NODE", description: "test" }],
    metadata: overrides.metadata ?? {},
  };
}

function baseInv(version: string, extra: Partial<DiffableInvestigation> = {}): DiffableInvestigation {
  return {
    resolved: { name: "demo-pkg", version },
    lifecycleScripts: [],
    findings: [],
    behaviourChains: [],
    analysisCompleteness: completeness(),
    risk: { score: 3, recommendation: "ALLOW" },
    policy: policy("ALLOW"),
    ...extra,
  };
}

describe("compareInvestigations", () => {
  it("detects install-time remote execution as CRITICAL delta", () => {
    const before = baseInv("1.0.0");
    const chain: BehaviourChain = {
      id: "c1",
      source: "REMOTE_DOWNLOAD",
      transformations: [],
      sink: "PROCESS_EXECUTION",
      confidence: "HIGH",
      links: [
        {
          kind: "ARGUMENT_FLOW",
          description: "command",
          location: { filePath: "setup.js", startLine: 1, endLine: 1 },
        },
      ],
      supportingFindingIds: ["f"],
      filePaths: ["setup.js", "package.json"],
      rationale: "install remote",
      metadata: { chainType: "INSTALL_TIME_REMOTE_EXECUTION", installTimeRooted: true },
    };
    const after = baseInv("1.0.1", {
      lifecycleScripts: [
        {
          name: "preinstall",
          command: "node setup.js",
          runsOnInstall: true,
          referencedFiles: ["setup.js"],
        },
      ],
      findings: [
        finding({
          ruleId: "js/shell/remote-content-to-shell",
          category: "REMOTE_CODE_FETCH",
          title: "Remote content piped to a shell interpreter",
          location: { filePath: "setup.js", startLine: 10, endLine: 10 },
          metadata: { shellChainType: "REMOTE_CONTENT_TO_SHELL", installReachable: true },
        }),
      ],
      behaviourChains: [chain],
      risk: { score: 54, recommendation: "REVIEW" },
      policy: policy("REVIEW"),
    });

    const diff = compareInvestigations(before, after);
    expect(diff.changeSignificance).toBe("CRITICAL");
    expect(diff.lifecycleAdded).toHaveLength(1);
    expect(diff.chainsAdded).toHaveLength(1);
    expect(diff.riskDelta).toBe(51);
    expect(diff.summary).toContain("INSTALL_TIME_REMOTE_EXECUTION");
  });

  it("treats line-number-only shifts as unchanged findings", () => {
    const f1 = finding({
      id: "a",
      ruleId: "js/environment/env-read",
      category: "ENVIRONMENT_ACCESS",
      title: "Environment variable read: PATH",
      location: { filePath: "index.js", startLine: 3, endLine: 3 },
    });
    const f2 = finding({
      id: "b",
      ruleId: "js/environment/env-read",
      category: "ENVIRONMENT_ACCESS",
      title: "Environment variable read: PATH",
      location: { filePath: "index.js", startLine: 30, endLine: 30 },
    });
    expect(findingIdentity(f1)).toBe(findingIdentity(f2));

    const before = baseInv("1.0.0", { findings: [f1] });
    const after = baseInv("1.0.1", { findings: [f2] });
    const diff = compareInvestigations(before, after);
    expect(diff.findingsAdded).toHaveLength(0);
    expect(diff.findingsRemoved).toHaveLength(0);
  });

  it("reports LOW significance for comment-only style empty deltas", () => {
    const before = baseInv("1.0.0");
    const after = baseInv("1.0.1");
    const diff = compareInvestigations(before, after);
    expect(diff.changeSignificance).toBe("LOW");
    expect(diff.chainsAdded).toHaveLength(0);
    expect(diff.summary).toContain("No new high-value security behaviour");
  });
});
