import type { FileKind, SourceFileInput } from "./types.js";

/**
 * File classification.
 *
 * Extension decides the *intent*; content decides the *reality*. A file called
 * `index.js` whose first bytes are an ELF header is not JavaScript, and the
 * disagreement between the two is itself worth reporting — so both answers are
 * returned rather than one being quietly overwritten.
 */

const JAVASCRIPT_EXTENSIONS = new Set([".js", ".mjs", ".cjs", ".jsx", ".es", ".es6"]);
const TYPESCRIPT_EXTENSIONS = new Set([".ts", ".tsx", ".mts", ".cts"]);
const JSON_EXTENSIONS = new Set([".json", ".jsonc", ".json5", ".map"]);
const NATIVE_ADDON_EXTENSIONS = new Set([".node"]);
const BINARY_EXTENSIONS = new Set([
  ".so",
  ".dylib",
  ".dll",
  ".exe",
  ".bin",
  ".a",
  ".o",
  ".wasm",
  ".zip",
  ".gz",
  ".tgz",
  ".br",
  ".7z",
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".ico",
  ".woff",
  ".woff2",
  ".ttf",
  ".pdf",
]);

/**
 * Leading byte signatures for executable formats, expressed as the characters a
 * latin1/utf8 decode produces. Matching on decoded text rather than bytes is a
 * documented limitation: the analyser is given strings, not buffers, and a utf8
 * decode of binary data is lossy. The signatures below survive that decode
 * because they sit in the first four bytes and start with distinctive values.
 */
const EXECUTABLE_SIGNATURES: readonly {
  readonly prefix: string;
  readonly format: string;
}[] = [
  { prefix: "ELF", format: "ELF" },
  { prefix: "MZ", format: "PE/COFF (Windows executable)" },
  { prefix: "Ïúíþ", format: "Mach-O (little-endian 64-bit)" },
  { prefix: "Îúíþ", format: "Mach-O (little-endian 32-bit)" },
  { prefix: "þíúÏ", format: "Mach-O (big-endian 64-bit)" },
  { prefix: "þíúÎ", format: "Mach-O (big-endian 32-bit)" },
  { prefix: "\0asm", format: "WebAssembly" },
  { prefix: "!<arch>", format: "static archive" },
];

/** Number of leading characters inspected when sniffing for binary content. */
const SNIFF_LENGTH = 4_096;

export interface FileClassification {
  readonly kind: FileKind;
  /** What the extension claims, before content sniffing. */
  readonly kindByExtension: FileKind;
  /** Lowercased extension including the dot, or "" when there is none. */
  readonly extension: string;
  /** Populated when the content carries a recognised executable signature. */
  readonly executableFormat?: string;
  /** True when the content looks binary but carries no recognised signature. */
  readonly binaryContent: boolean;
  /** True when the file is text that looks machine-generated. Never a risk signal. */
  readonly minified: boolean;
  readonly sizeBytes: number;
}

export function extensionOf(filePath: string): string {
  const slash = Math.max(filePath.lastIndexOf("/"), filePath.lastIndexOf("\\"));
  const base = filePath.slice(slash + 1);
  // `.d.ts` and friends: take the last dot only, `.ts` is the meaningful part.
  const dot = base.lastIndexOf(".");
  if (dot <= 0) return "";
  return base.slice(dot).toLowerCase();
}

function kindForExtension(extension: string): FileKind {
  if (JAVASCRIPT_EXTENSIONS.has(extension)) return "JAVASCRIPT";
  if (TYPESCRIPT_EXTENSIONS.has(extension)) return "TYPESCRIPT";
  if (JSON_EXTENSIONS.has(extension)) return "JSON";
  if (NATIVE_ADDON_EXTENSIONS.has(extension)) return "NATIVE_ADDON";
  if (BINARY_EXTENSIONS.has(extension)) return "BINARY";
  return "OTHER";
}

function detectExecutableSignature(content: string): string | undefined {
  for (const signature of EXECUTABLE_SIGNATURES) {
    if (content.startsWith(signature.prefix)) return signature.format;
  }
  return undefined;
}

/**
 * Heuristic binary sniff: a high proportion of NUL bytes or replacement
 * characters in the first few kilobytes. Deliberately conservative — a false
 * "binary" verdict means a real JavaScript file goes unanalysed.
 */
function looksBinary(content: string): boolean {
  const sample = content.length > SNIFF_LENGTH ? content.slice(0, SNIFF_LENGTH) : content;
  if (sample.length === 0) return false;
  let suspicious = 0;
  for (let index = 0; index < sample.length; index += 1) {
    const code = sample.charCodeAt(index);
    // NUL, or the U+FFFD produced when a utf8 decode hits invalid bytes.
    if (code === 0 || code === 0xfffd) suspicious += 1;
  }
  return suspicious / sample.length > 0.02;
}

/**
 * Machine-generated-looking text: long average line length. Recorded for
 * context only. Minified code is completely ordinary in a published package
 * and no rule may treat it as suspicious.
 */
function looksMinified(content: string): boolean {
  if (content.length < 1_000) return false;
  let newlines = 0;
  for (let index = 0; index < content.length; index += 1) {
    if (content.charCodeAt(index) === 0x0a) newlines += 1;
  }
  const averageLineLength = content.length / (newlines + 1);
  return averageLineLength > 500;
}

export function classifyFile(file: SourceFileInput): FileClassification {
  const extension = extensionOf(file.path);
  const kindByExtension = kindForExtension(extension);
  const sizeBytes = Buffer.byteLength(file.content, "utf8");
  const executableFormat = detectExecutableSignature(file.content);
  const binaryContent = executableFormat !== undefined || looksBinary(file.content);

  let kind = kindByExtension;
  if (binaryContent) {
    kind = kindByExtension === "NATIVE_ADDON" ? "NATIVE_ADDON" : "BINARY";
  } else if (kindByExtension === "BINARY" || kindByExtension === "NATIVE_ADDON") {
    // Extension says binary but the content is text. Trust the content: a
    // `.node` file that is really a shell script is worth analysing, not skipping.
    kind = "OTHER";
  }

  return {
    kind,
    kindByExtension,
    extension,
    executableFormat,
    binaryContent,
    minified: !binaryContent && looksMinified(file.content),
    sizeBytes,
  };
}

/** True when the analyser has an AST-based path for this file. */
export function isParseable(kind: FileKind): boolean {
  return kind === "JAVASCRIPT" || kind === "TYPESCRIPT";
}
