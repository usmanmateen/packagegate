"use strict";
const fs = require("fs");
const path = require("path");

// Benign-shaped installer: platform check + local file write only.
if (process.platform === "linux") {
  fs.writeFileSync(path.join(__dirname, ".installed"), "ok");
}
