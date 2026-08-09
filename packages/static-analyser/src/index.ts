/**
 * @packagegate/static-analyser — reading published JavaScript without running it.
 *
 * The package parses attacker-authored source with a real, maintained parser
 * (`@babel/parser`), resolves capabilities through Babel's scope bindings
 * rather than by text matching, and reports observations — never verdicts.
 * Weighting those observations is the risk engine's job, and it is kept
 * deliberately far away from here.
 *
 * Two properties hold everywhere in this package and are worth stating in one
 * place:
 *
 *  - **Analysed code is never executed.** No `require`, no `import()`, no
 *    `eval`, no `vm`, no shelling out, and no command is ever constructed from
 *    package content.
 *  - **There is no I/O.** No `fs` import exists anywhere in `src/`. File
 *    content arrives as strings from the fetcher, which owns extraction and
 *    its own traversal and size defences. That is what makes this safe to run
 *    inside a network-disabled, read-only scanner process.
 *
 * What the analyser does *not* see is documented, without hedging, in
 * `docs/STATIC_ANALYSIS.md`. Absence of findings is never evidence of safety.
 */

export { analysePackage, analyseFile, RULES_VERSION } from "./analyse.js";
export type {
  FileAnalysis,
  FileAnalysisOptions,
  PackageAnalysisOptions,
} from "./analyse.js";

export { parseSource } from "./parse.js";
export type { ParsedSource, ParseOutcome } from "./parse.js";

export { CapabilityResolver, normaliseModuleSpecifier } from "./bindings.js";
export type { ModuleBinding, ResolvedTarget, ImportStyle } from "./bindings.js";

export { FindingEmitter } from "./emitter.js";
export type { EmitterOptions } from "./emitter.js";

export { analyseLifecycleScripts, referencedFilesOf } from "./lifecycle.js";
export type { LifecycleAnalysisInput, LifecycleAnalysisResult } from "./lifecycle.js";

export { classifyFile, isParseable, extensionOf } from "./classify.js";
export type { FileClassification } from "./classify.js";

export { DEFAULT_ANALYSIS_LIMITS, resolveLimits } from "./limits.js";
export type { AnalysisLimits } from "./limits.js";

export { shannonEntropy } from "./rules/encoding.js";

export { analyseOpaqueSource } from "./opaque.js";
export type { OpaqueSourceInput, OpaqueSourceResult } from "./opaque.js";

export type {
  FileAnalysisReport,
  FileKind,
  FindingDraft,
  LimitNotice,
  PackageAnalysisInput,
  SourceFileInput,
  StaticAnalysisResult,
} from "./types.js";
