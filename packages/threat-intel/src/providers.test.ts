import { describe, expect, it } from "vitest";
import {
  MemoryThreatIntelProvider,
  NoneThreatIntelProvider,
  FailingThreatIntelProvider,
} from "./providers.js";

describe("threat intel providers", () => {
  it("none provider returns NONE", () => {
    const result = new NoneThreatIntelProvider().lookup({
      packageName: "x",
      version: "1.0.0",
    });
    expect(result.status).toBe("NONE");
    expect(result.lookupFailed).toBe(false);
  });

  it("memory provider matches exact name@version as KNOWN_MALICIOUS", () => {
    const provider = new MemoryThreatIntelProvider([
      {
        packageName: "evil",
        version: "0.0.1",
        classification: "KNOWN_MALICIOUS",
        source: "test-feed",
        referenceId: "TEST-1",
      },
    ]);
    const hit = provider.lookup({ packageName: "evil", version: "0.0.1" });
    expect(hit.status).toBe("KNOWN_MALICIOUS");
    expect(hit.matches[0]?.matchedBy).toBe("NAME_VERSION");
    const miss = provider.lookup({ packageName: "evil", version: "0.0.2" });
    expect(miss.status).toBe("NONE");
  });

  it("failing provider does not throw", () => {
    const result = new FailingThreatIntelProvider().lookup({
      packageName: "x",
      version: "1",
    });
    expect(result.lookupFailed).toBe(true);
    expect(result.status).toBe("UNKNOWN");
  });

  it("does not treat KNOWN_VULNERABLE as KNOWN_MALICIOUS", () => {
    const provider = new MemoryThreatIntelProvider([
      {
        packageName: "lib",
        version: "1.0.0",
        classification: "KNOWN_VULNERABLE",
        source: "osv",
        referenceId: "CVE-1",
      },
    ]);
    expect(provider.lookup({ packageName: "lib", version: "1.0.0" }).status).toBe(
      "KNOWN_VULNERABLE",
    );
  });
});
