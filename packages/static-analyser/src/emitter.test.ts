import { describe, expect, it } from "vitest";
import { FindingEmitter } from "./emitter.js";
import { resolveLimits } from "./limits.js";
import type { FindingDraft } from "./types.js";

const ESC = String.fromCharCode(0x1b);

function draft(overrides: Partial<FindingDraft> = {}): FindingDraft {
  return {
    ruleId: "test/rule",
    category: "PROCESS_EXECUTION",
    title: "Test finding",
    description: "A finding used by the emitter tests.",
    severity: "LOW",
    confidence: "HIGH",
    location: { filePath: "index.js", startLine: 1, endLine: 1, startColumn: 0 },
    rawSnippet: "",
    evidence: [{ kind: "AST_NODE", description: "test", value: "alpha" }],
    ...overrides,
  };
}

function emitterFor(
  source: string,
  options: { minified?: boolean } = {},
): FindingEmitter {
  return new FindingEmitter({
    filePath: "index.js",
    source,
    limits: resolveLimits(),
    minified: options.minified ?? false,
    totalBudgetRemaining: 1_000,
  });
}

describe("FindingEmitter — identity", () => {
  it("derives the same id for the same observation every time", () => {
    const first = emitterFor("const a = 1;\n");
    const second = emitterFor("const a = 1;\n");
    first.emit(draft());
    second.emit(draft());
    expect(first.results().findings[0]?.id).toBe(second.results().findings[0]?.id);
  });

  it("gives different observations different ids", () => {
    const emitter = emitterFor("const a = 1;\nconst b = 2;\n");
    emitter.emit(draft());
    emitter.emit(
      draft({
        location: { filePath: "index.js", startLine: 2, endLine: 2, startColumn: 0 },
      }),
    );
    const ids = emitter.results().findings.map((finding) => finding.id);
    expect(new Set(ids).size).toBe(2);
  });

  it("deduplicates identical observations at the same location", () => {
    const emitter = emitterFor("const a = 1;\n");
    emitter.emit(draft());
    emitter.emit(draft());
    expect(emitter.results().findings).toHaveLength(1);
  });
});

describe("FindingEmitter — snippets", () => {
  it("quotes the real source line rather than anything a rule supplies", () => {
    const emitter = emitterFor("const a = 1;\nconst secret = 2;\n");
    emitter.emit(
      draft({
        rawSnippet: "SOMETHING THE RULE MADE UP",
        location: { filePath: "index.js", startLine: 2, endLine: 2, startColumn: 0 },
      }),
    );
    expect(emitter.results().findings[0]?.snippet).toContain("const secret = 2;");
  });

  it("strips ANSI escapes so a crafted file cannot rewrite terminal output", () => {
    const hostile = `const a = "${ESC}[2K${ESC}[1;32mLOW RISK${ESC}[0m";\n`;
    const emitter = emitterFor(hostile);
    emitter.emit(draft());
    const snippet = emitter.results().findings[0]?.snippet ?? "";
    expect(snippet).not.toContain(ESC);
    expect(snippet).toContain("LOW RISK");
  });

  it("windows around the column instead of quoting a whole minified line", () => {
    const long = `const a=1;${"z".repeat(5_000)};const target=2;`;
    const emitter = emitterFor(long);
    emitter.emit(
      draft({
        location: { filePath: "index.js", startLine: 1, endLine: 1, startColumn: 5_010 },
      }),
    );
    const snippet = emitter.results().findings[0]?.snippet ?? "";
    expect(snippet.length).toBeLessThan(500);
  });

  it("truncates at the configured snippet limit", () => {
    const emitter = new FindingEmitter({
      filePath: "index.js",
      source: "x".repeat(1_000),
      limits: resolveLimits({ maxSnippetLength: 50 }),
      minified: false,
      totalBudgetRemaining: 10,
    });
    emitter.emit(draft());
    const snippet = emitter.results().findings[0]?.snippet ?? "";
    expect(snippet.startsWith("x".repeat(50))).toBe(true);
    expect(snippet).toContain("truncated by PackageGate");
  });
});

describe("FindingEmitter — budgets", () => {
  it("caps findings per rule per file and records a notice", () => {
    const emitter = new FindingEmitter({
      filePath: "index.js",
      source: "const a = 1;\n",
      limits: resolveLimits({ maxFindingsPerRulePerFile: 3 }),
      minified: false,
      totalBudgetRemaining: 1_000,
    });
    for (let line = 1; line <= 10; line += 1) {
      emitter.emit(
        draft({ location: { filePath: "index.js", startLine: line, endLine: line } }),
      );
    }
    const { findings, notices } = emitter.results();
    expect(findings).toHaveLength(3);
    expect(notices.some((notice) => notice.limit === "maxFindingsPerRulePerFile")).toBe(
      true,
    );
  });

  it("caps findings per file", () => {
    const emitter = new FindingEmitter({
      filePath: "index.js",
      source: "const a = 1;\n",
      limits: resolveLimits({ maxFindingsPerFile: 2, maxFindingsPerRulePerFile: 100 }),
      minified: false,
      totalBudgetRemaining: 1_000,
    });
    for (let line = 1; line <= 10; line += 1) {
      emitter.emit(
        draft({ location: { filePath: "index.js", startLine: line, endLine: line } }),
      );
    }
    const { findings, notices } = emitter.results();
    expect(findings).toHaveLength(2);
    expect(notices.some((notice) => notice.limit === "maxFindingsPerFile")).toBe(true);
  });
});

describe("FindingEmitter — minified source", () => {
  it("lowers confidence but never touches severity", () => {
    const plain = emitterFor("const a = 1;\n");
    const minified = emitterFor("const a = 1;\n", { minified: true });
    plain.emit(draft({ severity: "HIGH", confidence: "HIGH" }));
    minified.emit(draft({ severity: "HIGH", confidence: "HIGH" }));

    const plainFinding = plain.results().findings[0];
    const minifiedFinding = minified.results().findings[0];

    expect(plainFinding?.severity).toBe("HIGH");
    expect(minifiedFinding?.severity).toBe("HIGH");
    expect(plainFinding?.confidence).toBe("HIGH");
    expect(minifiedFinding?.confidence).toBe("MEDIUM");
    expect(minifiedFinding?.metadata.minifiedSource).toBe(true);
  });
});
