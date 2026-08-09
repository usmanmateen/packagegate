import type * as t from "@babel/types";
import type { Confidence, Severity } from "@packagegate/shared";
import { sanitiseInlineValue } from "@packagegate/shared";
import {
  DNS_MEMBERS,
  EXFILTRATION_SHAPED_HOSTS,
  NETWORK_GLOBALS,
  NETWORK_MODULES,
  NETWORK_PACKAGES,
  NON_DESTINATION_URL_PREFIXES,
  WELL_KNOWN_RESOLVER_IPS,
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
 * Network capability and network destinations, kept as two separate rules
 * because they carry very different amounts of information.
 *
 * *Capability* is nearly worthless on its own: npm itself is a network client,
 * and so is most of the ecosystem (`docs/RISK_MODEL.md` §6.2). It is recorded
 * at LOW severity as inventory.
 *
 * *Destination* is where the information lives. A request to a host whose only
 * property is that anyone can receive data at it — a paste site, a chat
 * webhook, a request catcher, a tunnel — is a meaningfully different
 * observation from a request to a package's own CDN.
 */

const RULE_PREFIX = "js/network";

/**
 * URL extraction from an already-parsed string literal.
 *
 * Regex is the right tool for the *inside* of a literal: the AST has already
 * told us this is a string the code uses, and all that remains is to recognise
 * a URL's shape. The pattern is linear-time — a fixed scheme prefix followed by
 * a single bounded character class, with no nested quantifiers to backtrack.
 */
const URL_PATTERN = /\bhttps?:\/\/[^\s"'`<>\\)\]}]{1,2000}/gi;

/**
 * A bare IPv4 destination. Anchored to a URL authority position so that version
 * strings like `1.2.3.4` in a changelog do not match.
 */
const IPV4_HOST_PATTERN = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function hostOf(url: string): string | undefined {
  const afterScheme = url.indexOf("://");
  if (afterScheme === -1) return undefined;
  const rest = url.slice(afterScheme + 3);
  let end = rest.length;
  for (const terminator of ["/", "?", "#"]) {
    const index = rest.indexOf(terminator);
    if (index !== -1 && index < end) end = index;
  }
  const authority = rest.slice(0, end);
  const at = authority.lastIndexOf("@");
  const hostAndPort = at === -1 ? authority : authority.slice(at + 1);
  const colon = hostAndPort.lastIndexOf(":");
  const host = colon === -1 ? hostAndPort : hostAndPort.slice(0, colon);
  return host.length === 0 ? undefined : host.toLowerCase();
}

/** RFC1918, loopback, link-local and CGNAT — not an internet destination. */
function isPrivateOrLoopbackIp(host: string): boolean {
  const match = IPV4_HOST_PATTERN.exec(host);
  if (match === null) return false;
  const octets = [match[1], match[2], match[3], match[4]].map((part) =>
    Number(part ?? "0"),
  );
  const [a = 0, b = 0] = octets;
  if (octets.some((value) => value > 255)) return false;
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}

function isIpv4Host(host: string): boolean {
  const match = IPV4_HOST_PATTERN.exec(host);
  if (match === null) return false;
  return [match[1], match[2], match[3], match[4]].every(
    (part) => part !== undefined && Number(part) <= 255,
  );
}

function exfiltrationShape(url: string): string | undefined {
  const lowered = url.toLowerCase();
  for (const marker of EXFILTRATION_SHAPED_HOSTS) {
    if (lowered.includes(marker)) return marker;
  }
  return undefined;
}

function isNonDestination(url: string): boolean {
  const lowered = url.toLowerCase();
  return NON_DESTINATION_URL_PREFIXES.some((prefix) => lowered.startsWith(prefix));
}

/** The capability rule: something in this file can make an outbound request. */
export const networkCapabilityRule: Rule = {
  id: `${RULE_PREFIX}/capability`,
  visitors: {
    CallExpression(path, ctx) {
      const target = ctx.resolver.resolve(calleePath(path), ctx.limits);
      if (target === undefined) return;

      const member = effectiveMember(target);

      if (
        target.kind === "global" &&
        NETWORK_GLOBALS.has(target.module) &&
        member === undefined
      ) {
        emitCapability(
          path.node,
          ctx,
          target.module,
          "HIGH",
          `global \`${target.module}\``,
        );
        return;
      }

      if (target.kind !== "module") return;

      // DNS deserves its own observation: a hostname is a data channel that
      // survives HTTP proxying, and it is what the original dependency-confusion
      // research used to report a successful install.
      if (
        (target.module === "dns" || target.module === "dns/promises") &&
        member !== undefined &&
        DNS_MEMBERS.has(member)
      ) {
        emitAt(ctx, path.node, {
          ruleId: `${RULE_PREFIX}/dns-lookup`,
          category: "NETWORK_ACCESS",
          title: `DNS query via dns.${member}`,
          description:
            "The package performs a DNS lookup. DNS is a legitimate part of service " +
            "discovery and also an egress channel that leaves no HTTP request behind.",
          severity: "LOW",
          confidence: confidenceFor(target),
          evidence: [
            {
              kind: "AST_NODE",
              description: `Call to \`dns.${member}\``,
              location: locationOf(path.node, ctx.filePath),
            },
            {
              kind: "BINDING",
              description: bindingEvidenceText(target),
              ...(target.declaration === undefined
                ? {}
                : { location: target.declaration }),
            },
          ],
          metadata: { module: target.module, member },
        });
        return;
      }

      if (isModule(target, NETWORK_MODULES) || isModule(target, NETWORK_PACKAGES)) {
        emitCapability(
          path.node,
          ctx,
          target.module,
          confidenceFor(target),
          bindingEvidenceText(target),
        );
      }
    },
  },
};

function emitCapability(
  node: t.Node,
  ctx: RuleContext,
  moduleName: string,
  confidence: Confidence,
  binding: string,
): void {
  emitAt(ctx, node, {
    ruleId: `${RULE_PREFIX}/outbound-capability`,
    category: "NETWORK_ACCESS",
    title: `Outbound network capability via ${moduleName}`,
    description:
      `The package makes outbound requests using \`${moduleName}\`. Network access is ` +
      "ubiquitous in the ecosystem and is recorded as inventory; the destination and the " +
      "data sent are what carry information.",
    severity: "LOW",
    confidence,
    evidence: [
      {
        kind: "AST_NODE",
        description: `Network call via \`${moduleName}\``,
        location: locationOf(node, ctx.filePath),
        value: moduleName,
      },
      { kind: "BINDING", description: binding },
    ],
    metadata: { module: moduleName },
  });
}

/**
 * Destinations found in string literals.
 *
 * Every URL in a file is reported, subject to the per-rule cap in `limits.ts` —
 * bundles legitimately contain thousands, and without the cap one vendored file
 * would drown every other signal in the package.
 */
export const networkDestinationRule: Rule = {
  id: `${RULE_PREFIX}/destination`,
  visitors: {
    StringLiteral(path, ctx) {
      inspectLiteral(path.node.value, path.node, ctx);
    },
    TemplateLiteral(path, ctx) {
      // Interpolated templates are inspected quasi by quasi. A destination
      // assembled around an interpolation is reported for the part we can read,
      // and the metadata records that the rest is unknown.
      for (const quasi of path.node.quasis) {
        const text = quasi.value.cooked;
        if (text === null || text === undefined || text.length === 0) continue;
        inspectLiteral(text, quasi, ctx, path.node.expressions.length > 0);
      }
    },
  },
};

function inspectLiteral(
  value: string,
  node: t.Node,
  ctx: RuleContext,
  interpolated = false,
): void {
  if (value.length > ctx.limits.maxLiteralScanLength) return;
  if (!value.includes("://")) return;

  URL_PATTERN.lastIndex = 0;
  let match = URL_PATTERN.exec(value);
  let seen = 0;

  // Bounded: at most a handful of URLs are taken from any single literal, so a
  // pathological literal cannot produce unbounded work or unbounded findings.
  while (match !== null && seen < 8) {
    seen += 1;
    const url = match[0];
    const host = hostOf(url);
    if (host !== undefined && !isNonDestination(url) && !isPrivateOrLoopbackIp(host)) {
      emitDestination(url, host, node, ctx, interpolated);
    }
    match = URL_PATTERN.exec(value);
  }
}

function emitDestination(
  url: string,
  host: string,
  node: t.Node,
  ctx: RuleContext,
  interpolated: boolean,
): void {
  const exfilMarker = exfiltrationShape(url);
  const bareIp = isIpv4Host(host) && !WELL_KNOWN_RESOLVER_IPS.has(host);

  let severity: Severity = "INFO";
  let title = `Network destination: ${host}`;
  let description =
    `A URL naming \`${host}\` appears in the source. Recorded so that destinations can be ` +
    "compared against the package's declared repository and homepage.";
  let ruleId = `${RULE_PREFIX}/destination`;

  if (exfilMarker !== undefined) {
    severity = "HIGH";
    ruleId = `${RULE_PREFIX}/destination-collector`;
    title = `Network destination is a public collector: ${host}`;
    description =
      `The URL matches \`${exfilMarker}\`, a service that accepts data from anyone with no ` +
      "account and no attribution — paste sites, chat webhooks, request catchers and " +
      "tunnels. Chat and notification integrations use these legitimately, so this raises " +
      "the observation rather than deciding it.";
  } else if (bareIp) {
    severity = "MEDIUM";
    ruleId = `${RULE_PREFIX}/destination-ip-literal`;
    title = `Network destination is a hardcoded IP address: ${host}`;
    description =
      "The destination is an IP literal rather than a hostname, which avoids DNS and " +
      "therefore avoids domain reputation, DNS filtering and any registrable artefact. " +
      "Public DNS resolvers are excluded from this rule.";
  }

  emitAt(ctx, node, {
    ruleId,
    category: "NETWORK_DESTINATION",
    title,
    description,
    severity,
    // The URL is read verbatim from a literal. Interpolation means part of the
    // destination is unknown, which lowers certainty about the whole.
    confidence: interpolated ? "MEDIUM" : "HIGH",
    evidence: [
      {
        kind: "STRING_LITERAL",
        description: "URL literal in source",
        location: locationOf(node, ctx.filePath),
        value: sanitiseInlineValue(url, 300),
      },
    ],
    metadata: {
      host,
      url: sanitiseInlineValue(url, 300),
      interpolated,
      collectorMarker: exfilMarker ?? null,
      ipLiteral: bareIp,
    },
  });
}
