import { describe, expect, it } from "vitest";
import { lookupOsv, type OsvFetch } from "./osv.js";

function stub(body: unknown, init: { ok?: boolean; status?: number } = {}): OsvFetch {
  return () =>
    Promise.resolve({
      ok: init.ok ?? true,
      status: init.status ?? 200,
      text: () => Promise.resolve(typeof body === "string" ? body : JSON.stringify(body)),
    });
}

const MAL_RECORD = {
  vulns: [
    {
      id: "MAL-2026-328",
      summary: "Malicious code in demo (npm)",
      affected: [{ package: { name: "demo", ecosystem: "npm" }, versions: ["1.0.0"] }],
    },
  ],
};

describe("lookupOsv", () => {
  it("classifies a MAL- record as known malicious", async () => {
    const result = await lookupOsv("demo", "1.0.0", { fetchImpl: stub(MAL_RECORD) });
    expect(result.status).toBe("KNOWN_MALICIOUS");
    expect(result.matches[0]?.referenceId).toBe("MAL-2026-328");
    expect(result.lookupFailed).toBe(false);
  });

  it("classifies a GHSA record as a vulnerability, not malware", async () => {
    // The distinction is the point: these demand different analyst actions and
    // must never collapse into a single advisory count.
    const result = await lookupOsv("demo", "1.0.0", {
      fetchImpl: stub({
        vulns: [
          {
            id: "GHSA-xxxx-yyyy-zzzz",
            affected: [{ versions: ["1.0.0"] }],
          },
        ],
      }),
    });
    expect(result.status).toBe("KNOWN_VULNERABLE");
  });

  it("does not report a hit when the record covers a different version", async () => {
    const result = await lookupOsv("demo", "2.0.0", { fetchImpl: stub(MAL_RECORD) });
    expect(result.status).toBe("NONE");
    expect(result.matches).toHaveLength(0);
  });

  it("ignores withdrawn records", async () => {
    const result = await lookupOsv("demo", "1.0.0", {
      fetchImpl: stub({
        vulns: [
          {
            id: "MAL-2026-328",
            withdrawn: "2026-01-01T00:00:00Z",
            affected: [{ versions: ["1.0.0"] }],
          },
        ],
      }),
    });
    expect(result.status).toBe("NONE");
  });

  it("returns NONE, not a failure, when the package is clean", async () => {
    const result = await lookupOsv("demo", "1.0.0", { fetchImpl: stub({}) });
    expect(result.status).toBe("NONE");
    expect(result.lookupFailed).toBe(false);
  });

  it("reports an HTTP error as a failed lookup rather than a clean result", async () => {
    const result = await lookupOsv("demo", "1.0.0", {
      fetchImpl: stub({}, { ok: false, status: 503 }),
    });
    expect(result.lookupFailed).toBe(true);
    expect(result.status).toBe("UNKNOWN");
    expect(result.failureReason).toContain("503");
  });

  it("reports malformed JSON as a failed lookup", async () => {
    const result = await lookupOsv("demo", "1.0.0", { fetchImpl: stub("{not json") });
    expect(result.lookupFailed).toBe(true);
  });

  it("reports a transport failure as a failed lookup", async () => {
    const result = await lookupOsv("demo", "1.0.0", {
      fetchImpl: () => Promise.reject(new Error("ECONNRESET")),
    });
    expect(result.lookupFailed).toBe(true);
    expect(result.status).toBe("UNKNOWN");
  });

  it("does not treat a range-only record as a confirmed hit", async () => {
    // Range evaluation needs ecosystem-specific semver handling. Guessing would
    // either invent a hit on a clean version or silently miss a real one.
    const result = await lookupOsv("demo", "1.0.0", {
      fetchImpl: stub({
        vulns: [
          {
            id: "MAL-2026-999",
            affected: [{ ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }] }],
          },
        ],
      }),
    });
    expect(result.status).toBe("NONE");
  });
});
