import type * as t from "@babel/types";
import type { SourceLocation } from "@packagegate/shared";

/** Map a Babel node to a package-relative source location. */
export function locationOf(node: t.Node, filePath: string): SourceLocation {
  const loc = node.loc;
  if (loc === null || loc === undefined) {
    return { filePath, startLine: 1, endLine: 1 };
  }
  return {
    filePath,
    startLine: loc.start.line,
    endLine: loc.end.line,
    startColumn: loc.start.column,
    endColumn: loc.end.column,
  };
}

/** True when two locations refer to the same file and overlap in line range. */
export function locationsOverlap(
  left: SourceLocation,
  right: SourceLocation,
  lineTolerance = 2,
): boolean {
  if (left.filePath !== right.filePath) return false;
  return (
    Math.abs(left.startLine - right.startLine) <= lineTolerance ||
    (left.startLine <= right.endLine && right.startLine <= left.endLine)
  );
}
