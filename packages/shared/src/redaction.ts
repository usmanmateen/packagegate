/**
 * Sanitisation helpers for text that originated inside an analysed package.
 *
 * Everything here exists because package contents are hostile input. A source
 * snippet travels from an attacker-controlled tarball into our logs, our
 * database, a terminal (via the CLI) and a browser (via the web UI). Each of
 * those is a separate injection surface:
 *
 *  - terminals interpret ANSI escapes, so a crafted file can rewrite earlier
 *    output, hide text, or spoof a "LOW RISK" verdict in CLI output
 *  - NUL bytes and control characters corrupt log lines and can truncate
 *    strings inside downstream C-backed consumers
 *  - unbounded snippets are a memory and storage exhaustion vector
 *
 * The web UI additionally renders snippets as inert text and never as HTML;
 * that is enforced at the rendering layer, not here.
 */

/** Default cap for a stored/rendered snippet. Generous enough to show context. */
export const DEFAULT_SNIPPET_MAX_LENGTH = 2_000;

/** Hard cap applied before any pattern matching, to bound worst-case work. */
const ABSOLUTE_INPUT_CAP = 64_000;

const TRUNCATION_MARKER = "\n… [truncated by PackageGate]";

// Control characters are built from char codes rather than written as literal
// escapes so that the patterns cannot be corrupted by tooling that rewrites
// escape sequences in source, and so the intent is unambiguous when reviewed.
const ESC = String.fromCharCode(0x1b);
const BEL = String.fromCharCode(0x07);

/**
 * ANSI CSI sequences (colour, cursor movement). Linear-time: a fixed ESC
 * prefix, bounded character classes with no nested quantifiers, and a single
 * terminator byte.
 */
const ANSI_CSI = new RegExp(ESC + "\\[[0-9;?]*[ -/]*[@-~]", "g");

/**
 * ANSI OSC sequences (window title, hyperlinks), terminated by BEL or ESC-\.
 * The body excludes both terminator bytes, so the quantifier cannot backtrack
 * across them, and a terminator is required — an unterminated OSC is left for
 * {@link stripControlCharacters} rather than swallowing the rest of the file.
 */
const ANSI_OSC = new RegExp(
  ESC + "\\][^" + BEL + ESC + "]*(?:" + BEL + "|" + ESC + "\\\\)",
  "g",
);

/**
 * Strip control characters other than tab and newline. Carriage returns are
 * removed rather than preserved because a lone CR lets crafted content
 * overwrite an already-rendered line in a terminal.
 */
function stripControlCharacters(input: string): string {
  let out = "";
  for (const char of input) {
    const code = char.codePointAt(0);
    if (code === undefined) continue;
    const isAllowedWhitespace = code === 0x09 || code === 0x0a;
    const isC0 = code < 0x20;
    const isDelete = code === 0x7f;
    const isC1 = code >= 0x80 && code <= 0x9f;
    if (isAllowedWhitespace) {
      out += char;
    } else if (isC0 || isDelete || isC1) {
      continue;
    } else {
      out += char;
    }
  }
  return out;
}

/**
 * Make a fragment of package source safe to store, log and render.
 *
 * This never attempts to make the code "safe to run" — nothing in PackageGate
 * runs analysed code. It only makes the text safe to *display*.
 */
export function sanitiseSnippet(
  raw: string,
  maxLength: number = DEFAULT_SNIPPET_MAX_LENGTH,
): string {
  if (raw.length === 0) return "";

  // Bound the work before doing any pattern matching.
  const capped = raw.length > ABSOLUTE_INPUT_CAP ? raw.slice(0, ABSOLUTE_INPUT_CAP) : raw;

  const withoutEscapes = capped.replace(ANSI_CSI, "").replace(ANSI_OSC, "");
  const cleaned = stripControlCharacters(withoutEscapes);

  if (cleaned.length <= maxLength) return cleaned;
  return cleaned.slice(0, maxLength) + TRUNCATION_MARKER;
}

/**
 * Sanitise a single-line value destined for a log field or terminal column —
 * a filename, a script command, a URL found in source. Newlines and tabs are
 * collapsed so a crafted value cannot forge additional log lines or columns.
 */
export function sanitiseInlineValue(raw: string, maxLength = 300): string {
  const withoutEscapes = raw
    .slice(0, ABSOLUTE_INPUT_CAP)
    .replace(ANSI_CSI, "")
    .replace(ANSI_OSC, "");
  const cleaned = stripControlCharacters(withoutEscapes)
    .replace(/[\n\t]+/g, " ")
    .trim();
  return cleaned.length <= maxLength ? cleaned : cleaned.slice(0, maxLength) + "…";
}

/**
 * True if a path taken from an archive entry or a finding is safe to treat as
 * package-relative. Rejects absolute paths, parent traversal, Windows drive
 * prefixes and embedded NUL bytes.
 *
 * This is a *validation* helper for evidence and API output. Archive extraction
 * performs its own stricter check against the resolved real path — string
 * inspection alone is not sufficient there, because symlinked parent
 * directories can make a string-clean path still escape the destination.
 */
export function isSafeRelativePath(candidate: string): boolean {
  if (candidate.length === 0 || candidate.includes("\0")) return false;
  if (candidate.startsWith("/") || candidate.startsWith("\\")) return false;
  if (/^[A-Za-z]:/.test(candidate)) return false;

  const segments = candidate.split(/[/\\]/);
  for (const segment of segments) {
    if (segment === "..") return false;
  }
  return true;
}
