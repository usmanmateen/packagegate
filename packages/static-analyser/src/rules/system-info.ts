import type * as t from "@babel/types";
import type { Severity } from "@packagegate/shared";
import type { ResolvedTarget } from "../bindings.js";
import {
  HOST_DESCRIPTION_MEMBERS,
  HOST_RECON_MEMBERS,
  NATIVE_LOADER_MODULES,
  OS_MODULE,
  PROCESS_RECON_MEMBERS,
} from "./catalogue.js";
import { calleePath, effectiveMember, isModule } from "./helpers.js";
import {
  bindingEvidenceText,
  confidenceFor,
  emitAt,
  locationOf,
  type Rule,
  type RuleContext,
} from "./types.js";

/**
 * System information gathering.
 *
 * Every call here is individually mundane. `os.platform()` chooses which
 * prebuilt binary to download; `os.cpus().length` sizes a worker pool;
 * telemetry and crash reporters read all of it. The observation is recorded as
 * inventory so that the *combination* — hostname, username, network interfaces,
 * all collected together and serialised — can be recognised later by the
 * behaviour engine, which is the only place that combination means anything.
 */

const RULE_PREFIX = "js/system-information";

export const systemInformationRule: Rule = {
  id: RULE_PREFIX,
  visitors: {
    CallExpression(path, ctx) {
      const target = ctx.resolver.resolve(calleePath(path), ctx.limits);
      if (target === undefined) return;
      const member = effectiveMember(target);
      if (member === undefined) return;

      if (target.kind === "module" && target.module === OS_MODULE) {
        if (HOST_RECON_MEMBERS.has(member)) {
          emit(path.node, ctx, `os.${member}`, "MEDIUM", target);
          return;
        }
        if (HOST_DESCRIPTION_MEMBERS.has(member)) {
          emit(path.node, ctx, `os.${member}`, "LOW", target);
        }
        return;
      }

      if (
        target.kind === "global" &&
        target.module === "process" &&
        PROCESS_RECON_MEMBERS.has(member)
      ) {
        emit(path.node, ctx, `process.${member}`, "LOW", target);
      }
    },

    MemberExpression(path, ctx) {
      // `process.platform` and `process.versions` are properties, not calls.
      if (path.node.computed) return;
      const target = ctx.resolver.resolve(path, ctx.limits);
      if (target === undefined) return;
      if (target.kind !== "global" || target.module !== "process") return;
      const member = target.member;
      if (member === undefined || !PROCESS_RECON_MEMBERS.has(member)) return;
      // Calls are handled above; skip the callee position to avoid duplicates.
      if (
        path.parentPath?.isCallExpression() &&
        path.parentPath.node.callee === path.node
      ) {
        return;
      }
      emit(path.node, ctx, `process.${member}`, "LOW", target);
    },
  },
};

function emit(
  node: t.Node,
  ctx: RuleContext,
  name: string,
  severity: Severity,
  target: ResolvedTarget,
): void {
  emitAt(ctx, node, {
    ruleId: `${RULE_PREFIX}/host-information`,
    category: "SYSTEM_INFORMATION_ACCESS",
    title: `Host information read: ${name}`,
    description:
      `The package reads \`${name}\`. Individually this is ordinary — platform detection, ` +
      "worker-pool sizing, telemetry and licence checks all do it. It is recorded so that a " +
      "full fingerprinting bundle can be recognised from its parts.",
    severity,
    confidence: confidenceFor(target),
    evidence: [
      {
        kind: "AST_NODE",
        description: `Read of \`${name}\``,
        location: locationOf(node, ctx.filePath),
        value: name,
      },
      { kind: "BINDING", description: bindingEvidenceText(target) },
    ],
    metadata: { source: name },
  });
}

/** Imports whose only purpose is loading a compiled native addon. */
export const nativeLoaderRule: Rule = {
  id: "js/native/loader",
  visitors: {
    CallExpression(path, ctx) {
      const target = ctx.resolver.resolve(calleePath(path), ctx.limits);
      if (target === undefined) return;
      if (!isModule(target, NATIVE_LOADER_MODULES)) return;

      emitAt(ctx, path.node, {
        ruleId: "js/native/loader",
        category: "NATIVE_BINARY",
        title: `Native addon loader used: ${target.module}`,
        description:
          `The package loads compiled native code through \`${target.module}\`. This is the ` +
          "standard mechanism for native modules across the ecosystem. It is recorded because " +
          "the loaded binary is entirely outside this analyser's reach.",
        severity: "LOW",
        confidence: confidenceFor(target),
        evidence: [
          {
            kind: "AST_NODE",
            description: `Call into \`${target.module}\``,
            location: locationOf(path.node, ctx.filePath),
            value: target.module,
          },
        ],
        metadata: { module: target.module },
      });
    },
  },
};
