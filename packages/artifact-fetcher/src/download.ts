import { fetch as undiciFetch } from "undici";
import { LimitExceededError, ScanError } from "@packagegate/shared";
import { ArtifactDigester, parseIntegrity } from "./integrity.js";
import { resolveLimits, type ArtifactLimits } from "./limits.js";
import { verifyDigest, type IntegrityReport } from "./verify.js";

/**
 * Tarball retrieval.
 *
 * This is the only module in the package that opens a socket, and it is
 * deliberately the only one: THREAT_MODEL §5 (TB-3) requires that the
 * component with the dangerous parsers can eventually run with no network and
 * no credentials, so nothing under `extract.ts` may ever reach for an HTTP
 * client.
 *
 * The size limit is enforced *while* the body arrives. A tarball that is only
 * measured once it has been buffered has already cost us the memory it was
 * trying to take.
 */

/** Minimal structural view of a response, so tests can inject without a socket. */
export interface HttpResponseLike {
  readonly status: number;
  readonly headers: { get(name: string): string | null };
  readonly body: AsyncIterable<Uint8Array> | null;
}

export interface HttpRequestInit {
  readonly signal: AbortSignal;
  readonly headers: Record<string, string>;
  readonly redirect: "follow";
}

export type HttpFetch = (url: string, init: HttpRequestInit) => Promise<HttpResponseLike>;

export interface DownloadRequest {
  readonly url: string;
  /**
   * `dist.integrity` from the registry, or a bare `dist.shasum` for versions
   * published before SSRI existed. Absent is a legitimate state and is
   * reported as "not declared", never as a failed check.
   */
  readonly integrity?: string;
  readonly limits?: Partial<ArtifactLimits>;
  /** Injection point for tests. Production callers should leave this unset. */
  readonly fetch?: HttpFetch;
  /** Caller-supplied cancellation, composed with the download timeout. */
  readonly signal?: AbortSignal;
}

export interface DownloadedTarball {
  /** Safe form of the request URL: no userinfo, no query string. */
  readonly tarballUrl: string;
  readonly bytes: Buffer;
  readonly compressedSizeBytes: number;
  /** Our own identifier for the artifact, computed over the received bytes. */
  readonly sha256: string;
  readonly integrity: IntegrityReport;
}

const USER_AGENT = "packagegate-artifact-fetcher/0.1 (+security-research)";

/**
 * Download a tarball, enforcing the compressed-size budget mid-stream and
 * verifying the registry's integrity declaration over the bytes we received.
 *
 * @throws {ScanError} `INVALID_SPEC` for a URL we will not fetch, `NOT_FOUND`
 * for a 404, `UPSTREAM_UNAVAILABLE` for transport and server failures,
 * `LIMIT_EXCEEDED` when the body outgrows its budget, `TIMEOUT` for the
 * wall-clock budget, `INTEGRITY_MISMATCH` when the bytes disagree with the
 * registry.
 */
export async function downloadTarball(request: DownloadRequest): Promise<DownloadedTarball> {
  const limits = resolveLimits(request.limits);
  const url = safeUrl(request.url);
  const fetchImpl = request.fetch ?? defaultFetch;

  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, limits.downloadTimeoutMs);
  timer.unref();

  const onCallerAbort = (): void => {
    controller.abort();
  };
  request.signal?.addEventListener("abort", onCallerAbort, { once: true });

  try {
    const response = await callFetch(fetchImpl, request.url, controller.signal, url);
    assertAcceptableStatus(response.status, url);
    assertDeclaredLengthFits(response.headers.get("content-length"), limits);

    const declaration = parseIntegrity(request.integrity);
    const digester = new ArtifactDigester(
      declaration.kind === "expectation" ? declaration.expectation : undefined,
    );

    const bytes = await readBody(response, limits, digester);
    const integrity = verifyDigest(digester, request.integrity);

    return {
      tarballUrl: url,
      bytes,
      compressedSizeBytes: bytes.byteLength,
      sha256: digester.sha256Hex(),
      integrity,
    };
  } catch (error) {
    // Abort on every failure, including our own refusals. Bailing out on a
    // `content-length` we do not like leaves an unread body attached to a live
    // socket otherwise, and a connection an adversary can keep open is a
    // resource they control.
    controller.abort();
    throw classifyDownloadError(error, { timedOut, url, limits });
  } finally {
    clearTimeout(timer);
    request.signal?.removeEventListener("abort", onCallerAbort);
  }
}

/**
 * Read the body incrementally, hashing as we go and refusing to buffer past
 * the budget.
 *
 * The abort is the point: on overflow we stop reading rather than reading to
 * the end and then complaining. An attacker who can make us keep reading has
 * an unbounded memory sink regardless of what we report afterwards.
 */
async function readBody(
  response: HttpResponseLike,
  limits: ArtifactLimits,
  digester: ArtifactDigester,
): Promise<Buffer> {
  if (response.body === null) {
    throw new ScanError("UPSTREAM_UNAVAILABLE", "Registry returned no tarball body", {
      retryable: true,
    });
  }

  const chunks: Buffer[] = [];
  let received = 0;

  for await (const chunk of response.body) {
    received += chunk.byteLength;
    if (received > limits.maxCompressedBytes) {
      throw new LimitExceededError("compressedBytes", limits.maxCompressedBytes, received);
    }
    // Copied rather than viewed. A view over the transport's buffer is
    // correct only for as long as the transport promises not to reuse it, and
    // the failure mode if that ever changes is the worst kind available here:
    // the digest would be computed over the original bytes while the archive
    // we extract is something else.
    const buffer = Buffer.from(chunk);
    digester.update(buffer);
    chunks.push(buffer);
  }

  if (received === 0) {
    throw new ScanError("UPSTREAM_UNAVAILABLE", "Registry returned an empty tarball", {
      retryable: true,
    });
  }

  return Buffer.concat(chunks, received);
}

/**
 * Refuse the declared length before reading a byte.
 *
 * `content-length` is attacker-influenced and therefore not trusted as an
 * upper bound — {@link readBody} still counts. It is trusted as a *reason to
 * refuse*, which costs an adversary nothing to avoid and costs us nothing to
 * check.
 */
function assertDeclaredLengthFits(header: string | null, limits: ArtifactLimits): void {
  if (header === null) return;
  const declared = Number.parseInt(header, 10);
  if (!Number.isFinite(declared) || declared <= 0) return;
  if (declared > limits.maxCompressedBytes) {
    throw new LimitExceededError("compressedBytes", limits.maxCompressedBytes, declared);
  }
}

function assertAcceptableStatus(status: number, url: string): void {
  if (status >= 200 && status < 300) return;
  if (status === 404 || status === 410) {
    throw new ScanError("NOT_FOUND", "Tarball does not exist in the registry", {
      details: { status, url },
    });
  }
  throw new ScanError("UPSTREAM_UNAVAILABLE", "Registry refused to serve the tarball", {
    details: { status, url },
    retryable: status === 429 || status >= 500,
  });
}

/**
 * Normalise the URL we will fetch and the URL we are willing to talk about.
 *
 * Only `http(s)` is accepted: a `file:` or `data:` tarball URL in registry
 * metadata is a request to read our own disk, and the registry has no business
 * asking. Userinfo and query strings are dropped from the reported form so a
 * credential embedded in a URL cannot reach a log line or a database row.
 */
function safeUrl(raw: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new ScanError("INVALID_SPEC", "Tarball URL is not a valid URL");
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new ScanError("INVALID_SPEC", "Tarball URL must use http or https", {
      details: { protocol: parsed.protocol },
    });
  }
  return `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
}

async function callFetch(
  fetchImpl: HttpFetch,
  url: string,
  signal: AbortSignal,
  safeUrlForErrors: string,
): Promise<HttpResponseLike> {
  try {
    return await fetchImpl(url, {
      signal,
      headers: { accept: "application/octet-stream", "user-agent": USER_AGENT },
      redirect: "follow",
    });
  } catch (error) {
    if (isAbort(error)) throw error;
    throw new ScanError("UPSTREAM_UNAVAILABLE", "Could not reach the registry", {
      details: { url: safeUrlForErrors },
      retryable: true,
      cause: error,
    });
  }
}

/**
 * `undici` rather than the global `fetch`, so the HTTP stack this security
 * tool depends on is a pinned, auditable dependency (R-EXT-06) instead of
 * whatever the host runtime happens to ship.
 *
 * The body is adapted through an explicit reader rather than relying on the
 * stream being async-iterable, so the injected-stub contract and the real one
 * are the same shape.
 */
const defaultFetch: HttpFetch = async (url, init) => {
  const response = await undiciFetch(url, {
    signal: init.signal,
    headers: init.headers,
    redirect: init.redirect,
  });
  return {
    status: response.status,
    headers: response.headers,
    body: response.body === null ? null : toAsyncIterable(response.body),
  };
};

interface ReaderLike {
  read(): Promise<{ done: boolean; value?: Uint8Array | undefined }>;
  cancel(reason?: unknown): Promise<void>;
}

/**
 * Bridge a web `ReadableStream` to an async iterable that always releases the
 * connection.
 *
 * The `finally` is load-bearing: when the caller stops early because a limit
 * fired, cancelling the reader is what actually stops the bytes arriving.
 */
function toAsyncIterable(stream: { getReader(): ReaderLike }): AsyncIterable<Uint8Array> {
  return {
    async *[Symbol.asyncIterator](): AsyncGenerator<Uint8Array> {
      const reader = stream.getReader();
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) return;
          if (value !== undefined) yield value;
        }
      } finally {
        await reader.cancel().catch(() => undefined);
      }
    },
  };
}

function isAbort(error: unknown): boolean {
  if (error instanceof Error && error.name === "AbortError") return true;
  if (typeof error !== "object" || error === null) return false;
  return (error as { code?: unknown }).code === "ABORT_ERR";
}

function classifyDownloadError(
  error: unknown,
  context: { timedOut: boolean; url: string; limits: ArtifactLimits },
): ScanError {
  if (error instanceof ScanError) return error;

  if (isAbort(error)) {
    if (context.timedOut) {
      return new ScanError("TIMEOUT", "Tarball download exceeded its time budget", {
        details: { limitMs: context.limits.downloadTimeoutMs, url: context.url },
        retryable: true,
      });
    }
    return new ScanError("UPSTREAM_UNAVAILABLE", "Tarball download was cancelled", {
      details: { url: context.url },
      retryable: true,
    });
  }

  return new ScanError("UPSTREAM_UNAVAILABLE", "Tarball download failed", {
    details: { url: context.url },
    retryable: true,
    cause: error,
  });
}
