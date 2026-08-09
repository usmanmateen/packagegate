import { describe, expect, it } from "vitest";
import { type ScanError } from "@packagegate/shared";
import { RegistryClient, toPackageMetadata, type FetchLike } from "./client.js";
import { VersionManifestSchema } from "./schemas.js";

interface StubResponse {
  status?: number;
  body?: string;
  headers?: Record<string, string>;
  /** When set, the transport rejects instead of responding. */
  throwError?: Error;
}

/** Records requested URLs so tests can assert on encoding without a network. */
function stubFetch(response: StubResponse): {
  fetchImpl: FetchLike;
  urls: string[];
} {
  const urls: string[] = [];
  const fetchImpl: FetchLike = (url) => {
    urls.push(url);
    if (response.throwError !== undefined) return Promise.reject(response.throwError);
    const { status = 200, body = "{}", headers = {} } = response;
    return Promise.resolve({
      ok: status >= 200 && status < 300,
      status,
      headers: { get: (name: string) => headers[name.toLowerCase()] ?? null },
      text: () => Promise.resolve(body),
    });
  };
  return { fetchImpl, urls };
}

const MINIMAL_PACKUMENT = JSON.stringify({
  name: "demo",
  "dist-tags": { latest: "1.1.0" },
  time: { "1.1.0": "2024-03-04T05:06:07.000Z" },
  versions: {
    "1.0.0": { name: "demo", version: "1.0.0", dist: { tarball: "https://r.invalid/a.tgz" } },
    "1.1.0": {
      name: "demo",
      version: "1.1.0",
      description: "a demo",
      scripts: { postinstall: "node setup.js" },
      dist: {
        tarball: "https://r.invalid/b.tgz",
        integrity: "sha512-abc",
        shasum: "deadbeef",
      },
    },
  },
});

describe("RegistryClient error mapping", () => {
  it("maps 404 to NOT_FOUND", async () => {
    const { fetchImpl } = stubFetch({ status: 404, body: '{"error":"Not found"}' });
    const client = new RegistryClient({ fetchImpl });
    await expect(client.getPackument("nope")).rejects.toMatchObject({ code: "NOT_FOUND" });
  });

  it("maps 429 to a retryable upstream error", async () => {
    const { fetchImpl } = stubFetch({ status: 429 });
    const client = new RegistryClient({ fetchImpl });
    await expect(client.getPackument("demo")).rejects.toMatchObject({
      code: "UPSTREAM_UNAVAILABLE",
      retryable: true,
    });
  });

  it("maps 503 to a retryable upstream error", async () => {
    const { fetchImpl } = stubFetch({ status: 503 });
    const client = new RegistryClient({ fetchImpl });
    await expect(client.getPackument("demo")).rejects.toMatchObject({
      code: "UPSTREAM_UNAVAILABLE",
    });
  });

  it("maps malformed JSON to an upstream error rather than crashing", async () => {
    const { fetchImpl } = stubFetch({ body: "{not json" });
    const client = new RegistryClient({ fetchImpl });
    await expect(client.getPackument("demo")).rejects.toMatchObject({
      code: "UPSTREAM_UNAVAILABLE",
    });
  });

  it("rejects a response whose declared length exceeds the cap", async () => {
    const { fetchImpl } = stubFetch({
      body: MINIMAL_PACKUMENT,
      headers: { "content-length": String(2 ** 31) },
    });
    const client = new RegistryClient({ fetchImpl });
    await expect(client.getPackument("demo")).rejects.toMatchObject({
      code: "LIMIT_EXCEEDED",
    });
  });

  it("maps a transport failure to a retryable upstream error", async () => {
    const { fetchImpl } = stubFetch({ throwError: new Error("ECONNRESET") });
    const client = new RegistryClient({ fetchImpl });
    await expect(client.getPackument("demo")).rejects.toMatchObject({
      code: "UPSTREAM_UNAVAILABLE",
    });
  });

  it("maps an abort to TIMEOUT", async () => {
    const abortError = new Error("aborted");
    abortError.name = "AbortError";
    const { fetchImpl } = stubFetch({ throwError: abortError });
    const client = new RegistryClient({ fetchImpl });
    await expect(client.getPackument("demo")).rejects.toMatchObject({ code: "TIMEOUT" });
  });

  it("never leaks the requested name unsanitised into error details", async () => {
    const ESC = String.fromCharCode(0x1b);
    const { fetchImpl } = stubFetch({ status: 404 });
    const client = new RegistryClient({ fetchImpl });
    try {
      await client.getPackument(`${ESC}[31mdemo`);
      expect.unreachable("should have thrown");
    } catch (error) {
      expect(JSON.stringify((error as ScanError).details)).not.toContain(ESC);
    }
  });
});

describe("RegistryClient request shape", () => {
  it("percent-encodes a scoped package in the URL", async () => {
    const { fetchImpl, urls } = stubFetch({ body: MINIMAL_PACKUMENT });
    const client = new RegistryClient({ fetchImpl });
    await client.getPackument("@scope/demo");
    expect(urls[0]).toBe("https://registry.npmjs.org/@scope%2Fdemo");
  });

  it("honours a custom registry URL and strips trailing slashes", async () => {
    const { fetchImpl, urls } = stubFetch({ body: MINIMAL_PACKUMENT });
    const client = new RegistryClient({ fetchImpl, registryUrl: "https://mirror.invalid/" });
    await client.getPackument("demo");
    expect(urls[0]).toBe("https://mirror.invalid/demo");
  });

  it("resolves and returns metadata in a single request", async () => {
    const { fetchImpl, urls } = stubFetch({ body: MINIMAL_PACKUMENT });
    const client = new RegistryClient({ fetchImpl });
    const { metadata, resolution } = await client.getPackageMetadata("demo");

    expect(urls).toHaveLength(1);
    expect(resolution).toEqual({ version: "1.1.0", resolvedFrom: "default-latest" });
    expect(metadata.version).toBe("1.1.0");
    expect(metadata.scripts["postinstall"]).toBe("node setup.js");
    expect(metadata.publishedAt).toBe("2024-03-04T05:06:07.000Z");
  });
});

describe("toPackageMetadata — tolerating the historical corpus", () => {
  it("accepts repository as a bare string", () => {
    const manifest = VersionManifestSchema.parse({
      name: "old",
      version: "0.1.0",
      repository: "git://github.com/example/old.git",
      dist: { tarball: "https://r.invalid/old.tgz" },
    });
    expect(toPackageMetadata(manifest).repositoryUrl).toBe("git://github.com/example/old.git");
  });

  it("accepts repository as an object", () => {
    const manifest = VersionManifestSchema.parse({
      name: "new",
      version: "1.0.0",
      repository: { type: "git", url: "git+https://github.com/example/new.git" },
      dist: { tarball: "https://r.invalid/new.tgz" },
    });
    expect(toPackageMetadata(manifest).repositoryUrl).toBe(
      "git+https://github.com/example/new.git",
    );
  });

  it("accepts license as an object", () => {
    const manifest = VersionManifestSchema.parse({
      name: "old",
      version: "0.1.0",
      license: { type: "MIT", url: "https://example.invalid/LICENSE" },
      dist: { tarball: "https://r.invalid/old.tgz" },
    });
    expect(toPackageMetadata(manifest).license).toBe("MIT");
  });

  it('parses a "name <email>" maintainer string', () => {
    const manifest = VersionManifestSchema.parse({
      name: "old",
      version: "0.1.0",
      maintainers: ["Some One <someone@example.invalid>"],
      dist: { tarball: "https://r.invalid/old.tgz" },
    });
    expect(toPackageMetadata(manifest).maintainers).toEqual([
      { name: "Some One", email: "someone@example.invalid" },
    ]);
  });

  it("drops non-string dependency values rather than rejecting the manifest", () => {
    const manifest = VersionManifestSchema.parse({
      name: "old",
      version: "0.1.0",
      dependencies: { good: "^1.0.0", broken: null },
      dist: { tarball: "https://r.invalid/old.tgz" },
    });
    expect(toPackageMetadata(manifest).dependencies).toEqual({ good: "^1.0.0" });
  });

  it("normalises deprecated:true to a message", () => {
    const manifest = VersionManifestSchema.parse({
      name: "old",
      version: "0.1.0",
      deprecated: true,
      dist: { tarball: "https://r.invalid/old.tgz" },
    });
    expect(toPackageMetadata(manifest).deprecated).toBe("This version is deprecated");
  });

  it("leaves absent fileCount and unpackedSize undefined, never zero", () => {
    // Coercing these to 0 would mark a decade of legitimate packages as empty.
    const manifest = VersionManifestSchema.parse({
      name: "old",
      version: "0.1.0",
      dist: { tarball: "https://r.invalid/old.tgz" },
    });
    const metadata = toPackageMetadata(manifest);
    expect(metadata.dist.fileCount).toBeUndefined();
    expect(metadata.dist.unpackedSize).toBeUndefined();
  });
});
