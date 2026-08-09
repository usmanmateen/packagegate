import { createHash } from "node:crypto";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { LimitExceededError, ScanError } from "@packagegate/shared";
import { downloadTarball, type HttpFetch } from "./download.js";
import { buildNpmTarball } from "./testing/tarballs.js";

/**
 * Download tests run against a local `node:http` server.
 *
 * Never the real registry: a test that depends on npmjs.com is a test that
 * fails during an outage, leaks our scan patterns to a third party, and cannot
 * express the cases that matter most here — a server that stalls, a server
 * that lies about `content-length`, a server that never stops sending.
 */

type Handler = (request: IncomingMessage, response: ServerResponse) => void;

let server: Server;
let origin: string;
let handler: Handler = (_request, response) => {
  response.writeHead(404).end();
};

beforeAll(async () => {
  server = createServer((request, response) => {
    handler(request, response);
  });
  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve();
    });
  });
  const address = server.address() as AddressInfo;
  origin = `http://127.0.0.1:${address.port}`;
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
});

afterEach(() => {
  handler = (_request, response) => {
    response.writeHead(404).end();
  };
});

function serve(bytes: Buffer, extraHeaders: Record<string, string> = {}): void {
  handler = (_request, response) => {
    response.writeHead(200, {
      "content-type": "application/octet-stream",
      "content-length": String(bytes.byteLength),
      ...extraHeaders,
    });
    response.end(bytes);
  };
}

function ssri(algorithm: "sha512" | "sha256" | "sha1", bytes: Buffer): string {
  return `${algorithm}-${createHash(algorithm).update(bytes).digest("base64")}`;
}

async function expectScanError(
  promise: Promise<unknown>,
  code: string,
): Promise<ScanError> {
  try {
    await promise;
    expect.unreachable(`expected a ${code} ScanError`);
  } catch (error) {
    expect(error).toBeInstanceOf(ScanError);
    expect((error as ScanError).code).toBe(code);
    return error as ScanError;
  }
}

describe("downloadTarball — the happy path", () => {
  it("returns the bytes, their size and our own SHA-256", async () => {
    const tarball = await buildNpmTarball({ "index.js": "1" });
    serve(tarball);

    const result = await downloadTarball({ url: `${origin}/demo-1.0.0.tgz` });

    expect(result.bytes.equals(tarball)).toBe(true);
    expect(result.compressedSizeBytes).toBe(tarball.byteLength);
    expect(result.sha256).toBe(createHash("sha256").update(tarball).digest("hex"));
  });

  it("reports integrity as not declared when the registry declared nothing", async () => {
    const tarball = await buildNpmTarball({ "index.js": "1" });
    serve(tarball);

    const result = await downloadTarball({ url: `${origin}/demo-1.0.0.tgz` });
    expect(result.integrity).toEqual({ status: "not-declared" });
  });

  it("verifies a declared sha512 integrity", async () => {
    const tarball = await buildNpmTarball({ "index.js": "1" });
    serve(tarball);

    const result = await downloadTarball({
      url: `${origin}/demo-1.0.0.tgz`,
      integrity: ssri("sha512", tarball),
    });
    expect(result.integrity).toEqual({ status: "verified", algorithm: "sha512" });
  });

  it("verifies a legacy bare-hex shasum", async () => {
    const tarball = await buildNpmTarball({ "index.js": "1" });
    serve(tarball);

    const result = await downloadTarball({
      url: `${origin}/demo-1.0.0.tgz`,
      integrity: createHash("sha1").update(tarball).digest("hex"),
    });
    expect(result.integrity).toEqual({ status: "verified", algorithm: "sha1" });
  });

  it("reports an algorithm it cannot check as unsupported rather than verified", async () => {
    const tarball = await buildNpmTarball({ "index.js": "1" });
    serve(tarball);

    const result = await downloadTarball({
      url: `${origin}/demo-1.0.0.tgz`,
      integrity: "blake3-Zm9vYmFy",
    });
    expect(result.integrity).toEqual({
      status: "unsupported",
      declaredAlgorithms: ["blake3"],
    });
  });

  it("strips userinfo and query strings from the URL it reports", async () => {
    const tarball = await buildNpmTarball({ "index.js": "1" });
    serve(tarball);

    const result = await downloadTarball({
      url: `${origin}/demo-1.0.0.tgz?token=super-secret`,
    });
    expect(result.tarballUrl).toBe(`${origin}/demo-1.0.0.tgz`);
    expect(result.tarballUrl).not.toContain("super-secret");
  });
});

describe("downloadTarball — refusals", () => {
  it("rejects a tarball whose integrity does not match the bytes", async () => {
    const tarball = await buildNpmTarball({ "index.js": "1" });
    serve(tarball);

    const error = await expectScanError(
      downloadTarball({
        url: `${origin}/demo-1.0.0.tgz`,
        integrity: ssri("sha512", Buffer.from("a different tarball entirely")),
      }),
      "INTEGRITY_MISMATCH",
    );
    expect(error.details.algorithm).toBe("sha512");
  });

  it("reports a 404 as NOT_FOUND rather than a transport failure", async () => {
    handler = (_request, response) => {
      response.writeHead(404).end();
    };
    const error = await expectScanError(
      downloadTarball({ url: `${origin}/missing.tgz` }),
      "NOT_FOUND",
    );
    expect(error.retryable).toBe(false);
  });

  it("reports a 500 as retryable", async () => {
    handler = (_request, response) => {
      response.writeHead(500).end();
    };
    const error = await expectScanError(
      downloadTarball({ url: `${origin}/broken.tgz` }),
      "UPSTREAM_UNAVAILABLE",
    );
    expect(error.retryable).toBe(true);
  });

  it("refuses a non-http URL scheme", async () => {
    await expectScanError(downloadTarball({ url: "file:///etc/passwd" }), "INVALID_SPEC");
  });

  it("refuses something that is not a URL at all", async () => {
    await expectScanError(downloadTarball({ url: "not a url" }), "INVALID_SPEC");
  });

  it("reports an unreachable host as retryable", async () => {
    const error = await expectScanError(
      downloadTarball({ url: "http://127.0.0.1:1/demo.tgz" }),
      "UPSTREAM_UNAVAILABLE",
    );
    expect(error.retryable).toBe(true);
  });
});

describe("downloadTarball — limits are enforced while the body arrives", () => {
  it("refuses a body that outgrows the budget mid-stream", async () => {
    // The declared length is a lie, so only the running count can catch this.
    handler = (_request, response) => {
      response.writeHead(200, { "content-type": "application/octet-stream" });
      for (let index = 0; index < 40; index += 1) {
        response.write(Buffer.alloc(64 * 1024, index % 256));
      }
      response.end();
    };

    const error = await expectScanError(
      downloadTarball({
        url: `${origin}/huge.tgz`,
        limits: { maxCompressedBytes: 512 * 1024 },
      }),
      "LIMIT_EXCEEDED",
    );
    expect(error).toBeInstanceOf(LimitExceededError);
    expect(error.details.limitName).toBe("compressedBytes");
  });

  it("refuses a declared content-length over the budget before reading a byte", async () => {
    let bodyBytesWritten = 0;
    handler = (_request, response) => {
      response.writeHead(200, {
        "content-type": "application/octet-stream",
        "content-length": String(100 * 1024 * 1024),
      });
      const chunk = Buffer.alloc(64 * 1024);
      bodyBytesWritten += chunk.byteLength;
      response.write(chunk);
    };

    const error = await expectScanError(
      downloadTarball({
        url: `${origin}/enormous.tgz`,
        limits: { maxCompressedBytes: 1024 * 1024 },
      }),
      "LIMIT_EXCEEDED",
    );
    expect(error.details.observed).toBe(100 * 1024 * 1024);
    expect(bodyBytesWritten).toBeGreaterThan(0);
  });

  it("gives up on a server that stalls", async () => {
    handler = (_request, response) => {
      response.writeHead(200, { "content-type": "application/octet-stream" });
      response.write(Buffer.alloc(16));
      // Deliberately never ended.
    };

    const error = await expectScanError(
      downloadTarball({ url: `${origin}/slow.tgz`, limits: { downloadTimeoutMs: 120 } }),
      "TIMEOUT",
    );
    expect(error.retryable).toBe(true);
    expect(error.details.limitMs).toBe(120);
  });

  it("honours a caller-supplied abort signal", async () => {
    handler = (_request, response) => {
      response.writeHead(200, { "content-type": "application/octet-stream" });
      response.write(Buffer.alloc(16));
    };

    const controller = new AbortController();
    const pending = downloadTarball({
      url: `${origin}/slow.tgz`,
      signal: controller.signal,
    });
    setTimeout(() => {
      controller.abort();
    }, 50);

    const error = await expectScanError(pending, "UPSTREAM_UNAVAILABLE");
    expect(error.message).toContain("cancelled");
  });

  it("rejects an empty body", async () => {
    serve(Buffer.alloc(0));
    await expectScanError(
      downloadTarball({ url: `${origin}/empty.tgz` }),
      "UPSTREAM_UNAVAILABLE",
    );
  });
});

describe("downloadTarball — the fetch seam", () => {
  it("uses an injected fetch, so nothing in a unit test needs a socket", async () => {
    const payload = Buffer.from("pretend tarball bytes");
    const seen: string[] = [];
    const stub: HttpFetch = (url, init) => {
      seen.push(url);
      expect(init.signal.aborted).toBe(false);
      return Promise.resolve({
        status: 200,
        headers: { get: () => null },
        body: (async function* () {
          // Two chunks with a turn of the event loop between them, so the
          // stub exercises the same incremental path a real socket does.
          yield payload.subarray(0, 5);
          await Promise.resolve();
          yield payload.subarray(5);
        })(),
      });
    };

    const result = await downloadTarball({
      url: "https://registry.example/x.tgz",
      fetch: stub,
    });

    expect(seen).toEqual(["https://registry.example/x.tgz"]);
    expect(result.bytes.equals(payload)).toBe(true);
    expect(result.sha256).toBe(createHash("sha256").update(payload).digest("hex"));
  });

  it("treats a body-less response as an upstream failure", async () => {
    const stub: HttpFetch = () =>
      Promise.resolve({ status: 200, headers: { get: () => null }, body: null });

    await expectScanError(
      downloadTarball({ url: "https://registry.example/x.tgz", fetch: stub }),
      "UPSTREAM_UNAVAILABLE",
    );
  });
});
