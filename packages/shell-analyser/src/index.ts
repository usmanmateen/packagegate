/**
 * @packagegate/shell-analyser — static shell-command semantics.
 *
 * Parses command *strings as data*. Never executes, never spawns a shell, never
 * expands substitutions. Designed for process-execution sinks such as
 * `child_process.execSync("curl … | bash")`.
 */

export { analyseShellCommand } from "./analyse.js";
export type {
  ShellAnalyseInput,
  ShellAnalyseResult,
  ShellOperation,
  ShellOperationKind,
} from "./types.js";
export { SHELL_ANALYSER_VERSION } from "./version.js";
