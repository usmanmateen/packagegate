/**
 * @packagegate/shared — the domain model every other package builds on.
 *
 * This package contains types, schemas and pure helpers only. It performs no
 * I/O, opens no sockets and touches no filesystem, which is what makes it safe
 * to depend on from the network-disabled scanner, the API, the CLI and the web
 * application alike.
 */

export * from "./primitives.js";
export * from "./package.js";
export * from "./finding.js";
export * from "./chain.js";
export * from "./risk.js";
export * from "./intelligence.js";
export * from "./completeness.js";
export * from "./policy.js";
export * from "./scan.js";
export * from "./comparison.js";
export * from "./ml.js";
export * from "./errors.js";
export * from "./redaction.js";
