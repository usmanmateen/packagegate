import { parse as babelParse, type ParserOptions, type ParseResult } from "@babel/parser";
import type * as t from "@babel/types";
import type { ParseFailure } from "@packagegate/shared";
import { sanitiseInlineValue } from "@packagegate/shared";
import type { AnalysisLimits } from "./limits.js";
import { extensionOf } from "./classify.js";

/**
 * The parser wrapper.
 *
 * Every input here is an attacker-authored file. Three properties matter more
 * than parse fidelity:
 *
 *  1. **It never throws.** A file the parser cannot handle produces a
 *     {@link ParseFailure}, which is carried all the way into the scan result.
 *     A crash would take down the scan; a silent skip would let a package hide
 *     from us by being unparseable, and would make "no findings" dishonest.
 *  2. **It never executes anything.** Babel's parser produces an AST and
 *     nothing else. No `require`, no `import()`, no `vm`, no shelling out.
 *  3. **It is bounded.** Oversized files are refused before the parser sees
 *     them, because parse cost is superlinear in pathological input and a
 *     20 MB single-line file is a trivially cheap denial-of-service payload.
 */

/** A file that parsed. `recoveredErrors` is how much Babel had to forgive. */
export interface ParsedSource {
  readonly ast: t.File;
  /** Which source type produced the better parse. */
  readonly sourceType: "module" | "script";
  /**
   * Syntax errors Babel tolerated under `errorRecovery` while still producing a
   * usable AST. Non-zero means the AST is an approximation of the file — worth
   * knowing when reasoning about coverage, and reported as such.
   */
  readonly recoveredErrors: number;
  readonly parseMillis: number;
}

export type ParseOutcome =
  | { readonly ok: true; readonly parsed: ParsedSource }
  | { readonly ok: false; readonly failure: ParseFailure };

/**
 * Plugins are chosen per extension rather than "enable everything", because
 * several Babel plugins are mutually ambiguous. `flow` and `typescript` cannot
 * coexist, and enabling `jsx` on a `.ts` file changes how `<T>(x) => x` parses.
 * Getting this wrong does not crash — it silently produces a wrong AST, which
 * is the worst failure mode available to us.
 */
function pluginsFor(extension: string): NonNullable<ParserOptions["plugins"]> {
  if (extension === ".tsx") return ["typescript", "jsx"];
  if (extension === ".ts" || extension === ".mts" || extension === ".cts") {
    return ["typescript"];
  }
  // Plain JavaScript, including `.jsx`. JSX is enabled for all of it: React
  // source ships as `.js` constantly, and a JSX-free file is unaffected.
  return ["jsx"];
}

/**
 * Permissive by design. Published packages contain CommonJS wrappers with
 * top-level `return`, ESM with top-level `await`, and re-export shims that
 * export names they never declare. Each of these is legal in the context the
 * file actually runs in, and refusing them would blind us to real code.
 */
function baseOptions(extension: string): ParserOptions {
  return {
    errorRecovery: true,
    plugins: pluginsFor(extension),
    allowReturnOutsideFunction: true,
    allowAwaitOutsideFunction: true,
    allowSuperOutsideMethod: true,
    allowUndeclaredExports: true,
    allowNewTargetOutsideFunction: true,
    // Comments are not evidence and attaching them costs memory on large files.
    attachComment: false,
    // Do not let a `// @flow`-style pragma or shebang change the parse mode.
    sourceType: "script",
  };
}

/** A Babel parse attempt that is guaranteed not to throw. */
function attempt(
  content: string,
  options: ParserOptions,
): { readonly result: ParseResult<t.File> } | { readonly error: string } {
  try {
    return { result: babelParse(content, options) };
  } catch (error: unknown) {
    // Deliberately narrow: we record the message and continue. This is not a
    // silent catch — the caller turns it into a ParseFailure that reaches the
    // scan result.
    const message = error instanceof Error ? error.message : String(error);
    return { error: message };
  }
}

function failure(filePath: string, reason: string, sizeBytes: number): ParseOutcome {
  return {
    ok: false,
    failure: { filePath, reason: sanitiseInlineValue(reason, 300), sizeBytes },
  };
}

/**
 * Parse one source file.
 *
 * ESM is tried first because it is the more constrained grammar: a file that
 * parses as a module is unambiguously a module, whereas almost every module
 * also "parses" as a script until it reaches an `import`. When the module parse
 * needs error recovery, the script parse is tried as well and whichever needed
 * less forgiveness wins — this is what correctly handles CommonJS files using
 * `with`, HTML comments, or other sloppy-mode-only constructs.
 *
 * At most two parse attempts are ever made, so a crafted file cannot turn
 * source-type detection into an amplification vector.
 */
export function parseSource(
  filePath: string,
  content: string,
  limits: AnalysisLimits,
): ParseOutcome {
  const sizeBytes = Buffer.byteLength(content, "utf8");

  if (sizeBytes > limits.maxFileBytes) {
    return failure(
      filePath,
      `File is ${String(sizeBytes)} bytes, above the ${String(limits.maxFileBytes)} byte parse limit`,
      sizeBytes,
    );
  }
  if (content.length === 0) {
    return failure(filePath, "File is empty", sizeBytes);
  }
  if (content.includes("\0")) {
    // A NUL inside "text" means the decode was lossy — this is binary content
    // wearing a source extension, not JavaScript.
    return failure(filePath, "File contains NUL bytes and is not text source", sizeBytes);
  }

  const extension = extensionOf(filePath);
  const options = baseOptions(extension);
  const startedAt = Date.now();

  const asModule = attempt(content, { ...options, sourceType: "module" });

  let chosen: ParseResult<t.File> | undefined;
  let chosenSourceType: "module" | "script" = "module";

  if ("result" in asModule && asModule.result.errors.length === 0) {
    chosen = asModule.result;
  } else {
    const asScript = attempt(content, { ...options, sourceType: "script" });
    const moduleErrors = "result" in asModule ? asModule.result.errors.length : Infinity;
    const scriptErrors = "result" in asScript ? asScript.result.errors.length : Infinity;

    if (moduleErrors === Infinity && scriptErrors === Infinity) {
      const reason = "error" in asModule ? asModule.error : "Unparseable";
      return failure(filePath, reason, sizeBytes);
    }
    if ("result" in asScript && scriptErrors < moduleErrors) {
      chosen = asScript.result;
      chosenSourceType = "script";
    } else if ("result" in asModule) {
      chosen = asModule.result;
    } else if ("result" in asScript) {
      chosen = asScript.result;
      chosenSourceType = "script";
    }
  }

  if (chosen === undefined) {
    return failure(filePath, "Unparseable", sizeBytes);
  }

  return {
    ok: true,
    parsed: {
      ast: chosen,
      sourceType: chosenSourceType,
      recoveredErrors: chosen.errors.length,
      parseMillis: Date.now() - startedAt,
    },
  };
}
