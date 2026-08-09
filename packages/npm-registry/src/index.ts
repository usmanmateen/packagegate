/**
 * @packagegate/npm-registry — talking to the npm registry.
 *
 * Specifier parsing is a security boundary: the parsed name reaches registry
 * URLs and database keys, so only unambiguously published registry packages
 * are accepted.
 */

export { parsePackageSpec, encodePackageNameForUrl, formatPackageSpec } from "./spec.js";
