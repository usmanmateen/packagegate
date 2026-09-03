import traverse, { type Binding, type NodePath } from "@babel/traverse";
import * as t from "@babel/types";
import { createHash } from "node:crypto";
import type {
  BehaviourChain,
  ChainLink,
  ChainSink,
  ChainSource,
  ChainTransformation,
  Finding,
  SourceLocation,
} from "@packagegate/shared";
import { maxConfidenceForLinks } from "@packagegate/shared";
import {
  CapabilityResolver,
  DEFAULT_ANALYSIS_LIMITS,
  parseSource,
  type ResolvedTarget,
} from "@packagegate/static-analyser";
import { matchSinkFindings, matchSourceFindings } from "./findings.js";
import { locationOf } from "./location.js";

const NETWORK_MODULES = new Set([
  "http",
  "https",
  "http2",
  "net",
  "tls",
  "dgram",
  "dns",
  "dns/promises",
]);

const NETWORK_PACKAGES = new Set([
  "axios",
  "node-fetch",
  "got",
  "undici",
  "request",
  "superagent",
  "needle",
  "phin",
  "isomorphic-fetch",
  "cross-fetch",
  "form-data",
  "ws",
  "socket.io-client",
]);

const NETWORK_GLOBALS = new Set(["fetch", "XMLHttpRequest", "WebSocket", "EventSource"]);

const REQUEST_MEMBERS = new Set([
  "request",
  "get",
  "post",
  "put",
  "patch",
  "delete",
  "head",
  "options",
]);

const STREAM_WRITE_MEMBERS = new Set(["end", "write", "send"]);

interface TaintRecord {
  readonly source: ChainSource;
  readonly transformations: ChainTransformation[];
  readonly sourceLocation: SourceLocation;
  readonly serializeLocation?: SourceLocation;
  readonly bindingName: string;
}

interface PendingChain {
  readonly taint: TaintRecord;
  readonly sink: ChainSink;
  readonly sinkLocation: SourceLocation;
  readonly links: ChainLink[];
}

/** Analyse one file for evidenced env-to-network behaviour chains. */
export function analyseFileForChains(
  filePath: string,
  content: string,
  findings: readonly Finding[],
): BehaviourChain[] {
  const parsed = parseSource(filePath, content, DEFAULT_ANALYSIS_LIMITS);
  if (!parsed.ok) {
    return [];
  }

  const limits = DEFAULT_ANALYSIS_LIMITS;
  const resolver = CapabilityResolver.collect(parsed.parsed.ast, filePath, limits);
  // Internal vocabulary only. User-facing evidence says "source-derived"
  // rather than "tainted": this is conservative binding and argument
  // tracking, not taint analysis, and the output must not imply otherwise.
  // Source-derived, not taint analysis.
  const taintedBindings = new Map<Binding, TaintRecord>();
  const pendingChains: PendingChain[] = [];

  function isProcessEnv(path: NodePath<t.Node>): boolean {
    const target = resolver.resolve(path, limits);
    return (
      target !== undefined &&
      target.kind === "global" &&
      target.module === "process" &&
      target.member === "env"
    );
  }

  function unwrapExpression(node: t.Node): t.Node {
    let current = node;
    for (let depth = 0; depth < 8; depth += 1) {
      if (t.isAwaitExpression(current)) {
        current = current.argument;
        continue;
      }
      if (t.isTSAsExpression(current) || t.isTSNonNullExpression(current)) {
        current = current.expression;
        continue;
      }
      if (t.isParenthesizedExpression(current)) {
        current = current.expression;
        continue;
      }
      return current;
    }
    return current;
  }

  function taintFromExpression(
    path: NodePath<t.Node>,
  ): { taint: TaintRecord; links: ChainLink[] } | undefined {
    const node = unwrapExpression(path.node);

    if (t.isIdentifier(node)) {
      const binding = path.scope.getBinding(node.name);
      if (binding === undefined) return undefined;
      const record = taintedBindings.get(binding);
      if (record === undefined) return undefined;
      return {
        taint: record,
        links: [
          {
            kind: "SHARED_BINDING",
            via: node.name,
            description: `Source-derived value read from binding \`${node.name}\``,
            location: locationOf(node, filePath),
          },
        ],
      };
    }

    if (isProcessEnv(path)) {
      const loc = locationOf(node, filePath);
      return {
        taint: {
          source: "ENVIRONMENT_ACCESS",
          transformations: [],
          sourceLocation: loc,
          bindingName: "process.env",
        },
        links: [
          {
            kind: "ARGUMENT_FLOW",
            via: "process.env",
            description: "`process.env` value used in this expression",
            location: loc,
          },
        ],
      };
    }

    if (t.isMemberExpression(node) || t.isOptionalMemberExpression(node)) {
      const objectPath = path.get("object") as NodePath<t.Node>;
      if (isProcessEnv(objectPath)) {
        const loc = locationOf(node, filePath);
        return {
          taint: {
            source: "ENVIRONMENT_ACCESS",
            transformations: [],
            sourceLocation: loc,
            bindingName: "process.env",
          },
          links: [
            {
              kind: "ARGUMENT_FLOW",
              via: "process.env",
              description: "Environment variable read used in this expression",
              location: loc,
            },
          ],
        };
      }
    }

    if (t.isCallExpression(node)) {
      const calleePath = path.get("callee") as NodePath<t.Node>;
      const target = resolver.resolve(calleePath, limits);
      if (target === undefined) return undefined;

      const isJsonStringify =
        target.kind === "global" &&
        target.module === "JSON" &&
        target.member === "stringify";
      const isObjectAssign =
        target.kind === "global" &&
        target.module === "Object" &&
        target.member === "assign";

      if (isJsonStringify || isObjectAssign) {
        for (const argPath of path.get("arguments") as unknown as NodePath<t.Node>[]) {
          const inner = taintFromExpression(argPath);
          if (inner === undefined) continue;

          const transformation: ChainTransformation = isJsonStringify
            ? "JSON_SERIALIZATION"
            : "OBJECT_COLLECTION";
          const serializeLoc = locationOf(node, filePath);

          return {
            taint: {
              source: inner.taint.source,
              transformations: [...inner.taint.transformations, transformation],
              sourceLocation: inner.taint.sourceLocation,
              serializeLocation: serializeLoc,
              bindingName: inner.taint.bindingName,
            },
            links: [
              ...inner.links,
              {
                kind: "ARGUMENT_FLOW",
                via: isJsonStringify ? "JSON.stringify" : "Object.assign",
                description: isJsonStringify
                  ? "Environment value passed to `JSON.stringify`"
                  : "Environment value collected via `Object.assign`",
                location: serializeLoc,
              },
            ],
          };
        }
      }
    }

    return undefined;
  }

  function recordBindingTaint(binding: Binding, name: string, taint: TaintRecord): void {
    const existing = taintedBindings.get(binding);
    const merged: TaintRecord =
      existing === undefined
        ? { ...taint, bindingName: name }
        : {
            source: taint.source,
            transformations:
              taint.transformations.length >= existing.transformations.length
                ? taint.transformations
                : existing.transformations,
            sourceLocation: taint.sourceLocation,
            serializeLocation: taint.serializeLocation ?? existing.serializeLocation,
            bindingName: name,
          };
    taintedBindings.set(binding, merged);
  }

  function isNetworkTarget(target: ResolvedTarget): boolean {
    if (target.kind === "global" && NETWORK_GLOBALS.has(target.module)) {
      return true;
    }
    if (target.kind !== "module") {
      return false;
    }
    return NETWORK_MODULES.has(target.module) || NETWORK_PACKAGES.has(target.module);
  }

  function networkSinkKind(target: ResolvedTarget): ChainSink {
    if (target.module === "net" || target.module === "tls" || target.module === "dgram") {
      return "SOCKET_WRITE";
    }
    return "NETWORK_REQUEST";
  }

  function emitSinkChain(
    taintResult: { taint: TaintRecord; links: ChainLink[] },
    sink: ChainSink,
    sinkLocation: SourceLocation,
    sinkDescription: string,
    argumentNode: t.Node,
  ): void {
    const argumentLoc = locationOf(argumentNode, filePath);
    pendingChains.push({
      taint: taintResult.taint,
      sink,
      sinkLocation,
      links: [
        ...taintResult.links,
        {
          kind: "ARGUMENT_FLOW",
          via: taintResult.taint.bindingName,
          description: sinkDescription,
          location: argumentLoc,
        },
      ],
    });
  }

  traverse(parsed.parsed.ast, {
    VariableDeclarator(path) {
      const id = path.node.id;
      if (!t.isIdentifier(id)) return;

      const initPath = path.get("init");
      if (initPath === undefined || !initPath.isExpression()) return;

      const taintResult = taintFromExpression(initPath);
      if (taintResult === undefined) return;

      const binding = path.scope.getBinding(id.name);
      if (binding === undefined) return;

      recordBindingTaint(binding, id.name, taintResult.taint);
    },

    CallExpression(path) {
      const calleePath = path.get("callee") as NodePath<t.Node>;
      const target = resolver.resolve(calleePath, limits);

      if (target !== undefined && isNetworkTarget(target)) {
        const member = target.member?.split(".").pop();
        const isRequestLike =
          member === undefined ||
          REQUEST_MEMBERS.has(member) ||
          NETWORK_GLOBALS.has(target.module);

        if (isRequestLike || target.kind === "global") {
          for (const argPath of path.get("arguments") as unknown as NodePath<t.Node>[]) {
            const taintResult = taintFromExpression(argPath);
            if (taintResult === undefined) continue;

            emitSinkChain(
              taintResult,
              networkSinkKind(target),
              locationOf(path.node, filePath),
              `Source-derived value passed as argument to \`${describeTarget(target)}\``,
              argPath.node,
            );
          }
        }
      }

      if (
        t.isMemberExpression(path.node.callee) ||
        t.isOptionalMemberExpression(path.node.callee)
      ) {
        const property = path.node.callee.property;
        const memberName = t.isIdentifier(property)
          ? property.name
          : t.isStringLiteral(property)
            ? property.value
            : undefined;

        if (memberName === undefined || !STREAM_WRITE_MEMBERS.has(memberName)) {
          return;
        }

        const args = path.get("arguments") as unknown as NodePath<t.Node>[];
        const firstArg = args[0];
        if (firstArg === undefined) return;

        const taintResult = taintFromExpression(firstArg);
        if (taintResult === undefined) return;

        emitSinkChain(
          taintResult,
          "NETWORK_REQUEST",
          locationOf(path.node, filePath),
          `Source-derived value passed to \`.${memberName}()\` on a request stream`,
          firstArg.node,
        );
      }
    },
  });

  return pendingChains.map((pending) => buildChain(filePath, pending, findings));
}

function describeTarget(target: ResolvedTarget): string {
  if (target.member === undefined) {
    return target.module;
  }
  return `${target.module}.${target.member}`;
}

function buildChain(
  filePath: string,
  pending: PendingChain,
  findings: readonly Finding[],
): BehaviourChain {
  const { taint, sink, sinkLocation, links } = pending;

  const sourceFindings = matchSourceFindings(findings, taint.sourceLocation);
  const serializeFindings =
    taint.serializeLocation === undefined
      ? []
      : matchSourceFindings(findings, taint.serializeLocation);
  const sinkFindings = matchSinkFindings(findings, sinkLocation);

  const supportingFindingIds = [
    ...new Set(
      [...sourceFindings, ...serializeFindings, ...sinkFindings].map(
        (finding) => finding.id,
      ),
    ),
  ];

  if (supportingFindingIds.length === 0) {
    for (const finding of findings) {
      if (
        finding.category === "ENVIRONMENT_ACCESS" ||
        finding.category === "CREDENTIAL_RELATED_ACCESS" ||
        finding.category === "NETWORK_ACCESS"
      ) {
        supportingFindingIds.push(finding.id);
      }
    }
  }

  const uniqueSupporting = [...new Set(supportingFindingIds)].slice(0, 20);

  const idMaterial = [
    filePath,
    String(taint.sourceLocation.startLine),
    String(sinkLocation.startLine),
    taint.transformations.join(","),
    sink,
  ].join("\0");

  const id = createHash("sha256").update(idMaterial).digest("hex").slice(0, 32);

  const hasSerialization = taint.transformations.includes("JSON_SERIALIZATION");
  const rationale = hasSerialization
    ? "Environment data is serialized and the result is passed to a network sink in the same file, with binding or argument linkage between the steps."
    : "Environment data is assigned to a binding that is subsequently passed to a network sink in the same file.";

  return {
    id,
    source: taint.source,
    transformations: taint.transformations,
    sink,
    confidence: maxConfidenceForLinks(links),
    links,
    supportingFindingIds: uniqueSupporting.length > 0 ? uniqueSupporting : ["unknown"],
    filePaths: [filePath],
    rationale,
    metadata: {
      pattern: hasSerialization ? "J1" : "ENVIRONMENT_TO_NETWORK",
    },
  };
}
