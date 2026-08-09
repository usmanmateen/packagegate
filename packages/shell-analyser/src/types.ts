import type { FindingCategory, SourceLocation } from "@packagegate/shared";

export type ShellOperationKind =
  | "REMOTE_DOWNLOAD"
  | "SHELL_INTERPRETER"
  | "FILE_WRITE"
  | "PERMISSION_CHANGE"
  | "EXECUTABLE_INVOCATION"
  | "ARCHIVE_DECODE"
  | "UNKNOWN";

export interface ShellOperation {
  readonly kind: ShellOperationKind;
  readonly tool?: string;
  readonly destinationUrl?: string;
  readonly outputPath?: string;
  readonly interpreter?: string;
  readonly tokenStart: number;
  readonly tokenEnd: number;
  readonly summary: string;
}

export interface ShellAnalyseInput {
  readonly command: string;
  readonly sourceLocation: SourceLocation;
  readonly executionSink: string;
  /** Cap on command characters analysed. */
  readonly maxCommandLength?: number;
  /** Cap on tokens considered. */
  readonly maxTokens?: number;
}

export interface ShellFindingDraft {
  readonly ruleId: string;
  readonly category: FindingCategory;
  readonly title: string;
  readonly description: string;
  readonly severity: "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  readonly confidence: "LOW" | "MEDIUM" | "HIGH";
  readonly evidenceValue: string;
  readonly metadata: Record<string, unknown>;
}

export interface ShellChainHint {
  readonly type: "REMOTE_CONTENT_TO_SHELL" | "DOWNLOAD_WRITE_EXECUTE";
  readonly confidence: "LOW" | "MEDIUM" | "HIGH";
  readonly rationale: string;
  readonly operationIndexes: number[];
}

export interface ShellAnalyseResult {
  readonly operations: ShellOperation[];
  readonly findings: ShellFindingDraft[];
  readonly chainHints: ShellChainHint[];
  readonly truncated: boolean;
}
