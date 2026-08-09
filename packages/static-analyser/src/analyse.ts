import type { Finding, ParseFailure } from "@packagegate/shared";
import { CapabilityResolver } from "./bindings.js";
import { classifyFile, isParseable, type FileClassification } from "./classify.js";
import { FindingEmitter } from "./emitter.js";
import { analyseLifecycleScripts } from "./lifecycle.js";
import { resolveLimits, type AnalysisLimits } from "./limits.js";
import { parseSource } from "./parse.js";
import { createRules, runRules } from "./rules/index.js";
import type {
  FileAnalysisReport,
  LimitNotice,
  PackageAnalysisInput,
  SourceFileInput,
  StaticAnalysisResult,
} from "./types.js";

/**
 * Orchestration.
 *
 * The invariants this file is responsible for:
 *
 *  - **Every input file is accounted for.** Analysed, skipped with a reason, or
 *    recorded as a parse failure — never silently absent. "No findings" must be
 *    distinguishable from "we did not look".
 *  - **No I/O.** Content arrives as strings from the fetcher, which has already
 *    applied extraction, traversal and size defences. There is no `fs` import
 *    anywhere in this package.
 *  - **Bounded work.** Every loop over package-controlled data has a ceiling,
 *    and reaching one is recorded.
 */

/**
 * Bumped whenever rule behaviour changes in a way that could change findings.
 * Recorded in every result so a verdict can be reproduced under the rules that
 * produced it.
 */
export const RULES_VERSION = "static-analyser/2.0.0";

/** One file's analysis, with no knowledge of the rest of the package. */
export interface FileAnalysis {
  readonly report: FileAnalysisReport;
  readonly findings: Finding[];
  readonly parseFailure?: ParseFailure;
  readonly limitNotices: LimitNotice[];
}

export interface FileAnalysisOptions {
  readonly limits?: Partial<AnalysisLimits>;
  /** True when a lifecycle script references this file. Recorded, not scored. */
  readonly installReachable?: boolean;
  /** Findings still allowed for the whole package. */
  readonly findingBudget?: number;
}

/**
 * File-level observations that need no AST: a compiled binary, or an extension
 * that disagrees with the content.
 */
function fileLevelFindings(
  file: SourceFileInput,
  classification: FileClassification,
  emitter: FindingEmitter,
): void {
  if (classification.executableFormat !== undefined) {
    emitter.emit({
      ruleId: "file/native-binary",
      category: "NATIVE_BINARY",
      title: `Compiled executable shipped in the package (${classification.executableFormat})`,
      description:
        `The file carries a ${classification.executableFormat} signature. Compiled artefacts ` +
        "are normal in native modules and in packages that vendor tools; they are recorded " +
        "because their behaviour cannot be determined by this analyser at all, which reduces " +
        "how much of the package we can claim to have examined.",
      severity: "LOW",
      confidence: "HIGH",
      location: { filePath: file.path, startLine: 1, endLine: 1 },
      rawSnippet: "",
      evidence: [
        {
          kind: "FILE_METADATA",
          description: `Leading bytes match ${classification.executableFormat}`,
          location: { filePath: file.path, startLine: 1, endLine: 1 },
          value: classification.executableFormat,
        },
      ],
      metadata: {
        format: classification.executableFormat,
        extension: classification.extension,
        sizeBytes: classification.sizeBytes,
      },
    });
  }

  // A source extension over binary content, or a `.node`/`.png` extension over
  // text, means the name is not describing the contents.
  const claimedText =
    classification.kindByExtension === "JAVASCRIPT" ||
    classification.kindByExtension === "TYPESCRIPT" ||
    classification.kindByExtension === "JSON";
  if (claimedText && classification.binaryContent) {
    emitter.emit({
      ruleId: "file/extension-mismatch",
      category: "NATIVE_BINARY",
      title: "File extension does not match its contents",
      description:
        "The extension claims text source but the content is binary. A source file that is " +
        "not source cannot be analysed, and the mismatch itself is worth a reviewer's eye.",
      severity: "MEDIUM",
      confidence: "HIGH",
      location: { filePath: file.path, startLine: 1, endLine: 1 },
      rawSnippet: "",
      evidence: [
        {
          kind: "FILE_METADATA",
          description: `Extension \`${classification.extension}\` with binary content`,
          location: { filePath: file.path, startLine: 1, endLine: 1 },
          value: classification.extension,
        },
      ],
      metadata: {
        extension: classification.extension,
        detectedKind: classification.kind,
      },
    });
  }
}

/** Analyse one file. Never throws for reasons originating in the file. */
export function analyseFile(
  file: SourceFileInput,
  options: FileAnalysisOptions = {},
): FileAnalysis {
  const limits = resolveLimits(options.limits);
  const classification = classifyFile(file);
  const emitter = new FindingEmitter({
    filePath: file.path,
    source: file.content,
    limits,
    minified: classification.minified,
    totalBudgetRemaining: options.findingBudget ?? limits.maxFindingsTotal,
  });

  fileLevelFindings(file, classification, emitter);

  const base = {
    path: file.path,
    kind: classification.kind,
    sizeBytes: classification.sizeBytes,
    minified: classification.minified,
  };

  if (!isParseable(classification.kind)) {
    const { findings, notices } = emitter.results();
    return {
      report: {
        ...base,
        analysed: false,
        skippedReason: `Not JavaScript or TypeScript source (classified as ${classification.kind})`,
        findingCount: findings.length,
        recoveredParseErrors: 0,
      },
      findings,
      limitNotices: notices,
    };
  }

  const outcome = parseSource(file.path, file.content, limits);
  if (!outcome.ok) {
    const { findings, notices } = emitter.results();
    return {
      report: {
        ...base,
        analysed: false,
        skippedReason: outcome.failure.reason,
        findingCount: findings.length,
        recoveredParseErrors: 0,
      },
      findings,
      parseFailure: outcome.failure,
      limitNotices: notices,
    };
  }

  const { ast, recoveredErrors } = outcome.parsed;
  const resolver = CapabilityResolver.collect(ast, file.path, limits);

  const traversal = runRules(ast, createRules(), {
    filePath: file.path,
    source: file.content,
    limits,
    resolver,
    emitter,
    minified: classification.minified,
    installReachable: options.installReachable ?? false,
  });

  if (traversal.outcome === "node-budget") {
    emitter.recordLimit(
      "maxNodesPerFile",
      limits.maxNodesPerFile,
      `Traversal stopped after ${String(traversal.nodesVisited)} nodes; the rest of this file was not analysed`,
    );
  } else if (traversal.outcome === "time-budget") {
    emitter.recordLimit(
      "maxFileMillis",
      limits.maxFileMillis,
      `Traversal stopped after ${String(limits.maxFileMillis)}ms; the rest of this file was not analysed`,
    );
  }

  const { findings, notices } = emitter.results();
  const analysed = traversal.outcome === "complete" && traversal.ruleErrors.length === 0;

  return {
    report: {
      ...base,
      analysed,
      ...(analysed
        ? {}
        : {
            skippedReason:
              traversal.ruleErrors.length > 0
                ? `Rule error during traversal: ${traversal.ruleErrors[0] ?? "unknown"}`
                : `Analysis budget reached (${traversal.outcome})`,
          }),
      findingCount: findings.length,
      recoveredParseErrors: recoveredErrors,
    },
    findings,
    limitNotices: notices,
  };
}

export interface PackageAnalysisOptions {
  readonly limits?: Partial<AnalysisLimits>;
}

/**
 * Analyse a whole package.
 *
 * Files referenced by install lifecycle scripts are analysed **first**. Budgets
 * are finite, and if one is going to be exhausted it must not be the code that
 * runs unattended during `npm install` that goes unexamined.
 */
export function analysePackage(
  input: PackageAnalysisInput,
  options: PackageAnalysisOptions = {},
): StaticAnalysisResult {
  const limits = resolveLimits(options.limits);

  const lifecycle = analyseLifecycleScripts(
    {
      scripts: input.scripts ?? {},
      ...(input.manifestText === undefined ? {} : { manifestText: input.manifestText }),
      ...(input.manifestPath === undefined ? {} : { manifestPath: input.manifestPath }),
    },
    limits,
  );

  const installReferenced = new Set<string>();
  for (const script of lifecycle.lifecycleScripts) {
    if (!script.runsOnInstall) continue;
    for (const reference of script.referencedFiles) installReferenced.add(reference);
  }

  const findings: Finding[] = [...lifecycle.findings];
  const parseFailures: ParseFailure[] = [];
  const files: FileAnalysisReport[] = [];
  const limitNotices: LimitNotice[] = [...lifecycle.limitNotices];

  // Install-referenced files first, then everything else in the given order.
  const ordered = [...input.files].sort((left, right) => {
    const leftPriority = installReferenced.has(left.path) ? 0 : 1;
    const rightPriority = installReferenced.has(right.path) ? 0 : 1;
    return leftPriority - rightPriority;
  });

  let analysedCount = 0;

  for (const file of ordered) {
    if (analysedCount >= limits.maxFilesAnalysed) {
      files.push({
        path: file.path,
        kind: classifyFile(file).kind,
        sizeBytes: Buffer.byteLength(file.content, "utf8"),
        analysed: false,
        skippedReason: `Package file budget of ${String(limits.maxFilesAnalysed)} reached`,
        findingCount: 0,
        recoveredParseErrors: 0,
        minified: false,
      });
      recordOnce(limitNotices, {
        filePath: "<package>",
        limit: "maxFilesAnalysed",
        limitValue: limits.maxFilesAnalysed,
        message: `Stopped analysing after ${String(limits.maxFilesAnalysed)} files; the remainder were recorded but not parsed`,
      });
      continue;
    }

    if (findings.length >= limits.maxFindingsTotal) {
      recordOnce(limitNotices, {
        filePath: "<package>",
        limit: "maxFindingsTotal",
        limitValue: limits.maxFindingsTotal,
        message: `Reached ${String(limits.maxFindingsTotal)} findings for the package; later files were analysed but their findings were not recorded`,
      });
    }

    const analysis = analyseFile(file, {
      limits: options.limits,
      installReachable: installReferenced.has(file.path),
      findingBudget: Math.max(0, limits.maxFindingsTotal - findings.length),
    });

    analysedCount += 1;
    files.push(analysis.report);
    findings.push(...analysis.findings);
    limitNotices.push(...analysis.limitNotices);
    if (analysis.parseFailure !== undefined) parseFailures.push(analysis.parseFailure);
  }

  return {
    findings,
    parseFailures,
    files,
    lifecycleScripts: lifecycle.lifecycleScripts,
    limitNotices,
    rulesVersion: RULES_VERSION,
  };
}

function recordOnce(notices: LimitNotice[], notice: LimitNotice): void {
  if (
    notices.some(
      (existing) =>
        existing.limit === notice.limit && existing.filePath === notice.filePath,
    )
  ) {
    return;
  }
  notices.push(notice);
}
