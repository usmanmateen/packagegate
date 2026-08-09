/**
 * Safe lexical tokeniser for shell-ish command strings.
 *
 * Deliberately incomplete: quotes are respected for token boundaries, but
 * `$(...)`, backticks, globs and variable expansions are left as opaque token
 * text and never expanded or executed.
 */

export interface ShellToken {
  readonly text: string;
  readonly start: number;
  readonly end: number;
}

const OPERATORS = new Set(["|", "||", "&&", ";", "&"]);

/**
 * Split a command into tokens and operator tokens. Bounded by maxTokens.
 */
export function tokeniseCommand(
  command: string,
  maxTokens: number,
): { tokens: ShellToken[]; truncated: boolean } {
  const tokens: ShellToken[] = [];
  let i = 0;
  let truncated = false;

  while (i < command.length) {
    if (tokens.length >= maxTokens) {
      truncated = true;
      break;
    }

    const ch = command[i]!;
    if (/\s/.test(ch)) {
      i += 1;
      continue;
    }

    // Operators (multi-char first).
    if (command.startsWith("||", i) || command.startsWith("&&", i)) {
      tokens.push({ text: command.slice(i, i + 2), start: i, end: i + 2 });
      i += 2;
      continue;
    }
    if (ch === "|" || ch === ";" || ch === "&") {
      tokens.push({ text: ch, start: i, end: i + 1 });
      i += 1;
      continue;
    }

    // Quoted string.
    if (ch === '"' || ch === "'") {
      const quote = ch;
      const start = i;
      i += 1;
      while (i < command.length && command[i] !== quote) {
        if (command[i] === "\\" && quote === '"') i += 1;
        i += 1;
      }
      if (i < command.length) i += 1; // closing quote
      tokens.push({ text: command.slice(start, i), start, end: i });
      continue;
    }

    // Bare word / substitution left opaque.
    const start = i;
    while (i < command.length) {
      const c = command[i]!;
      if (/\s/.test(c)) break;
      if (c === "|" || c === ";" || c === "&") break;
      if (command.startsWith("||", i) || command.startsWith("&&", i)) break;
      i += 1;
    }
    tokens.push({ text: command.slice(start, i), start, end: i });
  }

  return { tokens, truncated };
}

export function isOperator(token: ShellToken): boolean {
  return OPERATORS.has(token.text);
}

export function stripQuotes(text: string): string {
  if (text.length < 2) return text;
  const first = text[0];
  const last = text[text.length - 1];
  if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
    return text.slice(1, -1);
  }
  return text;
}

/**
 * Split token stream into pipeline/command segments on `|`, `||`, `&&`, `;`, `&`.
 */
export function splitSegments(tokens: readonly ShellToken[]): ShellToken[][] {
  const segments: ShellToken[][] = [];
  let current: ShellToken[] = [];
  for (const token of tokens) {
    if (isOperator(token)) {
      if (current.length > 0) segments.push(current);
      current = [];
      // Preserve pipe operator as a singleton marker segment for chain detection.
      if (token.text === "|") {
        segments.push([token]);
      }
      continue;
    }
    current.push(token);
  }
  if (current.length > 0) segments.push(current);
  return segments;
}
