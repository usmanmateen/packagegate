import * as t from "@babel/types";
import type { Evidence, Severity } from "@packagegate/shared";
import { sanitiseInlineValue } from "@packagegate/shared";
import {
  CHILD_PROCESS_MODULE,
  PROCESS_EXECUTION_MEMBERS,
  SHELL_COMMAND_MEMBERS,
} from "./catalogue.js";
import {
  argumentPaths,
  calleePath,
  effectiveMember,
  hasShellOption,
  staticStringValue,
} from "./helpers.js";
import {
  bindingEvidenceText,
  confidenceFor,
  emitAt,
  locationOf,
  type Rule,
} from "./types.js";

/**
 * Process execution.
 *
 * Severity here is deliberately low. Spawning a process is what build tools,
 * CLIs, git wrappers and test runners *are*; `docs/RISK_MODEL.md` §6 puts the
 * whole capability at 4 points out of 100 for exactly this reason. What raises
 * the observation above inventory is the *shape* of the command:
 *
 *  - a shell-interpreted command string rather than an argv array, and
 *  - a command that is built at runtime rather than written down,
 *
 * because a command we cannot read is a command the repository cannot show a
 * reviewer.
 */

const RULE_PREFIX = "js/process-execution";

/** Shell metacharacters that turn one command into several. */
const SHELL_METACHARACTERS = ["|", ";", "&&", "||", "`", "$(", ">", "<"];

function describesShell(command: string): boolean {
  return SHELL_METACHARACTERS.some((token) => command.includes(token));
}

export const processExecutionRule: Rule = {
  id: RULE_PREFIX,
  visitors: {
    CallExpression(path, ctx) {
      const target = ctx.resolver.resolve(calleePath(path), ctx.limits);
      if (target === undefined) return;
      if (target.kind !== "module" || target.module !== CHILD_PROCESS_MODULE) return;

      const member = effectiveMember(target);
      if (member === undefined || !PROCESS_EXECUTION_MEMBERS.has(member)) return;

      const confidence = confidenceFor(target);
      const args = argumentPaths(path);
      const first = args[0];
      const commandNode = first?.node;
      const literalCommand =
        commandNode === undefined ? undefined : staticStringValue(commandNode);
      const shellInterpreted = SHELL_COMMAND_MEMBERS.has(member) || hasShellOption(path);

      // A command assembled at runtime is the case that matters: the analyst
      // cannot read what will run, and neither can a code reviewer.
      const constructed =
        commandNode !== undefined &&
        literalCommand === undefined &&
        !t.isArrayExpression(commandNode);

      let severity: Severity = "LOW";
      let title = `Process execution via child_process.${member}`;
      let description =
        `The package spawns a process using \`child_process.${member}\`. ` +
        "Spawning processes is ordinary for build tooling and command-line packages; " +
        "it is recorded as a capability, not as a problem.";

      if (constructed && shellInterpreted) {
        severity = "MEDIUM";
        title = `Shell command built at runtime and executed via child_process.${member}`;
        description =
          `The command passed to \`child_process.${member}\` is not a literal, so the ` +
          "text that will be interpreted by a shell cannot be read from the source. " +
          "This is both a command-injection surface and a way to conceal the command itself.";
      } else if (constructed) {
        severity = "LOW";
        title = `Process executed with a runtime-constructed argument via child_process.${member}`;
        description =
          `The executable or arguments passed to \`child_process.${member}\` are built at ` +
          "runtime rather than written literally, so what runs cannot be read from the source.";
      }

      const evidence: Evidence[] = [
        {
          kind: "AST_NODE",
          description: `Call to \`child_process.${member}\``,
          location: locationOf(path.node, ctx.filePath),
        },
        {
          kind: "BINDING",
          description: bindingEvidenceText(target),
          ...(target.declaration === undefined ? {} : { location: target.declaration }),
        },
      ];

      if (literalCommand !== undefined) {
        evidence.push({
          kind: "STRING_LITERAL",
          description: "Command line, taken verbatim from the source",
          location: locationOf(commandNode ?? path.node, ctx.filePath),
          value: sanitiseInlineValue(literalCommand, 200),
        });
      }

      emitAt(ctx, path.node, {
        ruleId: `${RULE_PREFIX}/child-process`,
        category: "PROCESS_EXECUTION",
        title,
        description,
        severity,
        confidence,
        evidence,
        metadata: {
          module: target.module,
          member,
          shellInterpreted,
          commandIsLiteral: literalCommand !== undefined,
          aliasDepth: target.aliasDepth,
        },
      });

      // A literal command that itself contains shell control characters is a
      // separate, weaker observation: the package is driving a shell, which is
      // worth seeing next to any network or filesystem behaviour.
      if (
        shellInterpreted &&
        literalCommand !== undefined &&
        describesShell(literalCommand)
      ) {
        emitAt(ctx, path.node, {
          ruleId: `${RULE_PREFIX}/shell-command`,
          category: "SHELL_COMMAND",
          title: "Shell command line with control operators",
          description:
            "A command passed to the shell chains or redirects using shell operators. " +
            "This is common in build scripts and is recorded as context for other findings.",
          severity: "LOW",
          confidence,
          evidence: [
            {
              kind: "STRING_LITERAL",
              description: "Shell command line",
              location: locationOf(commandNode ?? path.node, ctx.filePath),
              value: sanitiseInlineValue(literalCommand, 200),
            },
          ],
          metadata: { member, module: target.module },
        });
      }
    },
  },
};
