# External API Contracts — Verified

**Verification date:** 2026-08-09
**Method:** every endpoint below was called live with `curl` from this machine, and every
behavioural claim is backed either by a captured response or by a quotation from current
primary documentation. Where documentation and observed behaviour disagree, the observed
behaviour is recorded as authoritative and the disagreement is called out.

**Status legend used throughout:**

- **VERIFIED** — observed in a live response captured on 2026-08-09.
- **DOC** — stated by current primary documentation, not independently exercised.
- **UNVERIFIED** — could not be confirmed; stated as an open question, never guessed.

> Anything marked UNVERIFIED must not be encoded into a type or a schema constraint
> without being checked first.

---

## Table of contents

1. [npm registry HTTP API](#1-npm-registry-http-api)
2. [npm provenance and attestations](#2-npm-provenance-and-attestations)
3. [GitHub Security Advisories REST API](#3-github-security-advisories-rest-api)
4. [OSV.dev and ossf/malicious-packages](#4-osvdev-and-ossfmalicious-packages)
5. [Current stable versions](#5-current-stable-versions)
6. [Cross-cutting: what we must not assume](#6-cross-cutting-what-we-must-not-assume)

---

## 1. npm registry HTTP API

Primary docs:

- <https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md>
- <https://docs.npmjs.com/policies/crawlers>
- <https://api-docs.npmjs.com/> (npm's own API doc site; thin, and does **not** document
  registry read endpoints in detail — see [1.7](#17-rate-limiting-and-polite-client-behaviour))

### 1.1 Packument endpoint

```
GET https://registry.npmjs.org/<package>
```

**VERIFIED.** Returns the full packument. Response headers observed:

```
HTTP/2 200
content-type: application/json
cache-control: public, max-age=300
etag: "61d587418ff21c8341943fdb641ec691"
last-modified: Wed, 29 Apr 2026 11:19:03 GMT
vary: accept-encoding, accept
```

`vary: accept-encoding, accept` matters: the `Accept` header participates in cache keying,
so the abbreviated and full documents are cached separately and correctly.

### 1.2 Abbreviated metadata and exactly what it omits

```
GET https://registry.npmjs.org/<package>
Accept: application/vnd.npm.install-v1+json
```

**VERIFIED.** Responds with `content-type: application/vnd.npm.install-v1+json`.

Size effect on `tar-stream` (a small package): **137,875 bytes full → 58,482 bytes
abbreviated**, a 58% reduction. With `Accept-Encoding: gzip` the full packument drops to
29,185 bytes on the wire, so compression is worth more than abbreviation alone; use both.

The spec describes abbreviated metadata as: *"This form of the package metadata exists to
provide a smaller payload designed to support installation. It contains an allow list of
fields from the full metadata set."*
([package-metadata.md](https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md))

**Document level — VERIFIED by diffing the two live responses for `tar-stream`:**

| | Fields |
|---|---|
| Abbreviated has | `name`, `modified`, `dist-tags`, `versions` |
| Abbreviated **omits** | `_id`, `_rev`, `author`, `bugs`, `description`, `homepage`, `license`, `maintainers`, `readme`, `readmeFilename`, `repository`, `time`, `users` |

**The two omissions that hurt us most are `time` and `maintainers`.** Package age,
publish cadence, version-burst detection and maintainer-set-change detection all need the
full packument. `modified` (abbreviated) gives only the single most recent mutation
timestamp, not per-version times.

**Version level.** The spec's allow list is:

> `name`, `version`, `deprecated`, `dependencies`, `acceptDependencies`,
> `optionalDependencies`, `devDependencies`, `bundleDependencies`, `peerDependencies`,
> `peerDependenciesMeta`, `bin`, `directories`, `dist`, `engines`, `_hasShrinkwrap`,
> `hasInstallScript`, `funding`, `cpu`, `os`

and: *"The name, version, and dist fields will always be present. The others will be
absent if they are irrelevant for this package version."*

**VERIFIED against live responses** — `esbuild@0.28.2` abbreviated returned exactly
`['bin','dist','engines','hasInstallScript','name','optionalDependencies','version']`,
including:

```json
{ "hasInstallScript": true, "bin": { "esbuild": "bin/esbuild" }, "engines": { "node": ">=18" } }
```

and `request@2.88.2` abbreviated carried `deprecated` with the same string as the full
document.

Fields present in full but **omitted** from abbreviated version objects (VERIFIED on
`tar-stream@3.1.7`): `_id`, `_nodeVersion`, `_npmUser`, `_npmVersion`,
`_npmOperationalInternal`, `author`, `browser`, `bugs`, `description`, `gitHead`,
`homepage`, `license`, `main`, `maintainers`, `repository`, **`scripts`**.

> **Load-bearing for us:** abbreviated metadata gives us `hasInstallScript` (a boolean)
> but **not** `scripts` (the actual command strings). Detecting *that* a package has an
> install hook is cheap; reading *what the hook runs* requires the full packument or the
> tarball's own `package.json`. Note also that `hasInstallScript` is registry-computed
> metadata, not something we verified against tarball contents — treat the tarball as the
> source of truth and this flag as a cheap pre-filter.

### 1.3 Scoped package URL encoding

**VERIFIED.** On `registry.npmjs.org`, all of these return `200` for both the packument
and the version-manifest endpoints:

| Form | Packument | Version manifest |
|---|---|---|
| `/@babel/parser` (raw slash) | 200 | 200 |
| `/@babel%2fparser` (lowercase `%2f`) | 200 | 200 |
| `/@babel%2Fparser` (uppercase `%2F`) | 200 | — |
| `/%40babel%2fparser` (also encoding `@`) | 200 | 200 |
| `/%40babel/parser` | 200 | — |

So the public registry is permissive. **We should still standardise on `@scope%2fname`
(lowercase `%2f`, `@` left literal)**, for three reasons:

1. It is the form **npm itself emits** — VERIFIED in the registry's own response body, in
   `dist.attestations.url` for a scoped package:
   `https://registry.npmjs.org/-/npm/v1/attestations/@sigstore%2fsign@5.0.0`
2. A raw `/` makes the path structurally ambiguous and is vulnerable to path
   normalisation by intermediate proxies and by URL libraries that collapse `..`
   segments. Percent-encoding removes the ambiguity.
3. Third-party registries and proxies (Verdaccio, Artifactory, GitHub Packages) are
   **not** guaranteed to be as permissive. **UNVERIFIED** — we did not test any registry
   other than `registry.npmjs.org`. If we ever support a configurable registry base URL,
   this needs retesting there.

Build URLs by percent-encoding the package name and appending path segments; never
string-concatenate a user-supplied spec into a URL.

### 1.4 Single-version manifest endpoint

```
GET https://registry.npmjs.org/<package>/<version-or-dist-tag>
```

**VERIFIED.** `/@babel/parser/7.28.4` returns a single version object. `/@babel/parser/latest`
also returns `200` — dist-tags are accepted in the version position.

Top-level keys observed on `@babel/parser@7.28.4`:

```
_hasShrinkwrap, _id, _npmOperationalInternal, _npmUser, author, bin, bugs, dependencies,
description, devDependencies, directories, dist, engines, homepage, keywords, license,
main, maintainers, name, publishConfig, repository, type, types, version
```

It **does not** contain `time` or `dist-tags` — those live only on the packument.

> **VERIFIED gotcha, and a real trap:** sending
> `Accept: application/vnd.npm.install-v1+json` to a **single-version manifest** URL
> returns **HTTP 406** with an empty body. The abbreviated Accept header is valid on the
> packument endpoint **only**. A client that sets that header globally on its HTTP agent
> will get a 406 the moment it fetches a single version. Set the header per-request.

### 1.5 The `dist` object — which fields actually appear

Union of fields observed across live responses:

| Field | Presence | Notes |
|---|---|---|
| `tarball` | **Always** (VERIFIED, 100% of ~1,000 version objects sampled) | Absolute URL |
| `shasum` | **Always** (VERIFIED, 100%) | SHA-1 hex. Legacy; weak — do not treat as a security control |
| `integrity` | **Always on `registry.npmjs.org` today** (VERIFIED, 100%) | SRI string, `sha512-<base64>` |
| `signatures` | **Always** (VERIFIED, 100%) | Registry ECDSA signature, `[{ sig, keyid }]` |
| `fileCount` | **Frequently absent** (VERIFIED) | Missing on older publishes |
| `unpackedSize` | **Frequently absent** (VERIFIED) | Co-occurs with `fileCount` |
| `attestations` | **Usually absent** (VERIFIED) | Present only for provenance publishes — see [§2](#2-npm-provenance-and-attestations) |
| `npm-signature` | **Rare, legacy** (VERIFIED) | Old detached PGP signature; seen on 13 of 117 lodash versions. Deprecated — ignore |

Example of a modern, complete `dist` (`@babel/parser@7.28.4`, trimmed):

```json
{
  "shasum": "da25d4643532890932cc03f7705fe19637e03fa8",
  "tarball": "https://registry.npmjs.org/@babel/parser/-/parser-7.28.4.tgz",
  "fileCount": 8,
  "integrity": "sha512-yZbBqeM6TkpP9du/I2pUZnJsRMGGvOuIrhjzC1AwHwW+6he4mni6Bp/m8ijn0iOuZuPI2BfkCoSRunpyjnrQKg==",
  "signatures": [
    { "sig": "MEQCIBf92raA6ZDSO9k20cx/Rw9thF6TFOBnKhFbAXFOk3s3AiBU+BpakQLxPLGd/AGzqDX8sl9R00IHKGs6zyCppLxTOA==",
      "keyid": "SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U" }
  ],
  "unpackedSize": 1980416
}
```

#### 1.5.1 CORRECTION: `integrity` is **not** absent on old versions

The brief instructed me to confirm that `integrity` is absent on older published versions
using a 2014-era lodash version. **That is not what the registry returns today, and the
assumption should be removed from our design.**

`lodash@0.1.0`, published **2012-04-23**, full packument:

```json
{
  "shasum": "392617f69a947e40cec7848d85fcc3dd29d74bc5",
  "tarball": "https://registry.npmjs.org/lodash/-/lodash-0.1.0.tgz",
  "integrity": "sha512-ufIfwX7g5obXKaJhzbnAJBNf5Idxqty+AHaNadWFxtNKjGmF/ZO8ptSEjQRQRymBPZtLa0NV9sbrsH87Ae2R1A==",
  "signatures": [ { "sig": "MEQCIBB7pdqPfBFUsZQhVr3woDJ7/bbRWV3tlXQZNp3ivosbAiBMhwfq9fqaJvFFX1/scqPbIywUUZCQkfJaISqaJbZX2Q==",
                    "keyid": "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA" } ]
}
```

I downloaded the actual 2012 tarball and hashed it:

```
tarball bytes:              263470
computed sha512 integrity:  sha512-ufIfwX7g5obXKaJhzbnAJBNf5Idxqty+AHaNadWFxtNKjGmF/ZO8ptSEjQRQRymBPZtLa0NV9sbrsH87Ae2R1A==
registry   integrity:       sha512-ufIfwX7g5obXKaJhzbnAJBNf5Idxqty+AHaNadWFxtNKjGmF/ZO8ptSEjQRQRymBPZtLa0NV9sbrsH87Ae2R1A==   MATCH
computed sha1 shasum:       392617f69a947e40cec7848d85fcc3dd29d74bc5
registry   shasum:          392617f69a947e40cec7848d85fcc3dd29d74bc5                                                          MATCH
```

The sha512 is genuine and verifies against the real bytes — npm has backfilled `integrity`
across the historical corpus. Identical result across the same three endpoint shapes
(full packument, abbreviated packument, single-version manifest).

Survey across ten legacy packages, oldest publish 2010-12-19 (VERIFIED):

| package | versions | missing `integrity` | missing `shasum` | missing `fileCount` | missing `signatures` |
|---|---:|---:|---:|---:|---:|
| express | 288 | 0 | 0 | **258** | 0 |
| request | 126 | 0 | 0 | **120** | 0 |
| underscore | 55 | 0 | 0 | **33** | 0 |
| async | 93 | 0 | 0 | **77** | 0 |
| coffee-script | 45 | 0 | 0 | **45** | 0 |
| jquery | 64 | 0 | 0 | **48** | 0 |
| bluebird | 223 | 0 | 0 | **215** | 0 |
| q | 76 | 0 | 0 | **76** | 0 |
| optimist | 39 | 0 | 0 | **39** | 0 |
| colors | 26 | 0 | 0 | **14** | 0 |

**Conclusion for schema design.** `fileCount` and `unpackedSize` are the genuinely
optional `dist` fields, not `integrity`.

- Type `integrity`, `shasum`, `tarball`, `signatures` as **required** for parsing
  convenience if you like — **but still validate at runtime and handle absence**, because
  (a) this is a registry-side backfill that is policy, not contract, and no npm
  documentation I could find *promises* `integrity` on historical versions
  (**UNVERIFIED** — I could not locate a primary doc guaranteeing it), and (b) a mirror,
  proxy or private registry may not have backfilled. Model it as
  "present in practice on registry.npmjs.org, must be tolerated as absent".
- **Never** make `fileCount` or `unpackedSize` required. Any "package size" or
  "file count" signal must degrade to *unknown* rather than to *zero*. A rule that reads
  `unpackedSize ?? 0` will silently score every pre-2016 package as empty.

#### 1.5.2 Registry signature keys

**VERIFIED.** `GET https://registry.npmjs.org/-/npm/v1/keys` returns:

```json
{ "keys": [
  { "expires": "2025-01-29T00:00:00.000Z",
    "keyid": "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA",
    "keytype": "ecdsa-sha2-nistp256", "scheme": "ecdsa-sha2-nistp256", "key": "MFkwEwYH...gg==" },
  { "expires": null,
    "keyid": "SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U",
    "keytype": "ecdsa-sha2-nistp256", "scheme": "ecdsa-sha2-nistp256", "key": "MFkwEwYH...2g==" } ]}
```

Note the key rotation: the first key **has expired** (2025-01-29) yet is the `keyid` on
`lodash@0.1.0` and `tar-stream@3.1.7`; current publishes such as `@babel/parser@8.0.4` and
`sigstore@5.0.0` use the non-expiring second key. If we ever verify `dist.signatures`, an
expired key is still the correct key for signatures created before its expiry — do not
treat "signed with an expired key" as a failure. **UNVERIFIED:** I did not perform an
actual ECDSA verification of a `dist.signatures` entry; only the key material was fetched.

### 1.6 `dist-tags`, `time`, `deprecated`, `maintainers`

**`dist-tags`** — VERIFIED. Object of tag → version, on the packument only. `latest` is
present on every package checked, but it is **conventional, not guaranteed** — treat a
missing `latest` as a resolution failure rather than crashing. Tag sets can be large and
messy: `drizzle-orm` currently publishes **56** dist-tags including dozens of
`1.0.0-beta.*` branch tags. Do not assume a small enum of tag names, and do not assume
tag names are safe identifiers — they contain `/` and `.` (e.g. `drizzle-seed/bug-fixes`,
`kit/node-sqlite`, `beta.16`).

**`time`** — VERIFIED. Packument only. Object of key → ISO 8601 timestamp, with special
keys `created` and `modified` alongside per-version entries.

> **VERIFIED schema trap:** `time` and `versions` are **not** the same key set.
> Unpublished versions keep their `time` entry after their manifest is gone. Observed:
> **express has 30** keys in `time` with no corresponding entry in `versions`
> (e.g. `1.0.0beta`, `1.0.0rc`), and **tar-stream has 2** (`1.0.1`, `1.1.0`).
> Never `Object.keys(time)` and index into `versions`, and never assume
> `time[version]` exists for a version you found in `versions`. Iterate `versions` and
> look up `time` defensively. A `time.unpublished` key can also appear on
> fully-unpublished packages — **UNVERIFIED**, I did not capture a live example.

**`deprecated`** — VERIFIED. A **per-version** string (not a boolean, not top-level).
Present in **both** full and abbreviated metadata. `request@2.88.2` returns identically in
both: `"request has been deprecated, see https://github.com/request/request/issues/3142"`.
Absent entirely when the version is not deprecated — so `deprecated` is
`string | undefined`, and its mere presence means deprecated. An empty-string value is
possible in principle; **UNVERIFIED** whether the registry permits it, so prefer
`typeof deprecated === 'string'` over truthiness.

**`maintainers`** — VERIFIED. Array of `{ name, email }`. Present at the packument top
level and on each **full** version object; **absent from abbreviated**. Example from
`tar-stream`:

```json
[ { "name": "mafintosh", "email": "mathiasbuus@gmail.com" },
  { "name": "maxogden",  "email": "max@maxogden.com" } ]
```

The per-version `maintainers` is a snapshot at publish time while the top-level one is
current, which is exactly what makes maintainer-change detection possible — but it is
also PII (email addresses). Per our data-handling rules, store what we need for the
signal and do not surface raw maintainer emails through the API.

Related: full version objects carry `_npmUser` (`{ name, email }`) — the actual publishing
account, distinct from the maintainer list. This is the more precise signal for
"who published this version", and it is **absent from abbreviated metadata**.

### 1.7 Rate limiting and polite client behaviour

**VERIFIED:** `registry.npmjs.org` returns **no** rate-limit headers at all — no
`x-ratelimit-*`, no `retry-after` on a normal 200. We cannot introspect our budget. There
is no published numeric rate limit for registry reads; `docs.npmjs.com/policies/rate-limits`
returns **404** (checked 2026-08-09).

The binding published guidance is the **crawler policy**
(<https://docs.npmjs.com/policies/crawlers>):

> *"they keep their request velocity to 1 request per second or less"*
>
> *"we reserve the right to rate-limit or ban your IP, user-agent or both"*
>
> *"if you want a full copy of our metadata it is always going to be faster to access the
> data via replication, which takes only an hour or two to provide full data and will
> thereafter automatically stay in sync"*

Client requirements that follow:

1. **Set a descriptive, stable `User-Agent`** identifying PackageGate with a contact URL.
   npm bans by user-agent, so an honest one is both polite and a liability shield; a
   forged or generic one is the thing that gets a shared IP banned.
2. **Default to ≤ 1 request/second** sustained per host, with a token-bucket limiter and
   jittered exponential backoff. Treat `429` and `5xx` as retryable, `4xx` otherwise as
   terminal. Honour `retry-after` if it ever appears.
3. **Use conditional requests.** VERIFIED: the registry supports `ETag` and returns
   **HTTP 304 with 0 bytes** for `If-None-Match`. Also supports `Last-Modified`. Persist
   the etag next to the cached packument.
4. **Use `Accept-Encoding: gzip`.** VERIFIED: 137,875 → 29,185 bytes on `tar-stream`.
5. **Respect `cache-control: max-age=300`.** Do not re-fetch a packument more than once
   per 5 minutes.
6. If we ever need bulk/corpus-wide metadata, use **replication**, not crawling — npm says
   so explicitly. **UNVERIFIED:** I did not exercise the replication endpoint
   (`replicate.npmjs.com`); its current availability and terms need separate checking
   before we design anything around it.

---

## 2. npm provenance and attestations

Primary docs:

- <https://docs.npmjs.com/generating-provenance-statements>
- Sigstore bundle format: <https://github.com/sigstore/protobuf-specs>
- SLSA provenance v1: <https://slsa.dev/provenance/v1>

### 2.1 Discovering that provenance exists

**VERIFIED.** The authoritative, cheap signal is `dist.attestations` in the packument /
version manifest. It appears **only** when the version was published with provenance:

```json
"attestations": {
  "url": "https://registry.npmjs.org/-/npm/v1/attestations/sigstore@5.0.0",
  "provenance": { "predicateType": "https://slsa.dev/provenance/v1" }
}
```

Live survey (VERIFIED, `latest` of each):

| package | version | `dist.attestations` |
|---|---|---|
| `sigstore` | 5.0.0 | present |
| `@sigstore/sign` | 5.0.0 | present (URL uses `@sigstore%2fsign@5.0.0`) |
| `tuf-js` | 6.0.0 | present |
| `vitest` | 4.1.10 | present |
| `zod` | 4.4.3 | present |
| **`npm`** | **12.0.2** | **absent** |

The npm CLI itself does not publish with provenance — a useful reminder that absence of
provenance says nothing about trustworthiness.

### 2.2 The attestations endpoint

```
GET https://registry.npmjs.org/-/npm/v1/attestations/<package>@<version>
```

**VERIFIED.** Scoped packages work with both `@sigstore%2fsign@5.0.0` and a raw slash, but
**npm's own emitted URL uses `%2f`** — prefer it. Response is 14,701 bytes for
`sigstore@5.0.0`, top-level shape:

```json
{ "attestations": [ /* … */ ] }
```

There is **no** top-level `package` key (VERIFIED — the only top-level key is
`attestations`). Two entries are returned:

```
[0] predicateType: https://github.com/npm/attestation/tree/main/specs/publish/v0.1
    bundle.mediaType: application/vnd.dev.sigstore.bundle+json;version=0.2
    bundle.verificationMaterial keys: publicKey, timestampVerificationData, tlogEntries
    bundle.dsseEnvelope: { payload, payloadType: application/vnd.in-toto+json, signatures }
    (also: signedAccessSignatureUrl)

[1] predicateType: https://slsa.dev/provenance/v1
    bundle.mediaType: application/vnd.dev.sigstore.bundle.v0.3+json
    bundle.verificationMaterial keys: certificate, timestampVerificationData, tlogEntries
    bundle.dsseEnvelope: { payload, payloadType: application/vnd.in-toto+json, signatures }
```

Note the two entries differ structurally: the **publish** attestation is verified against
an npm-held `publicKey`, the **provenance** attestation against a Fulcio `certificate`
(keyless). They also use different Sigstore bundle media type versions (0.2 vs v0.3).
Any parser must handle both `publicKey` and `certificate` variants.

Decoded DSSE payload of the **SLSA provenance** attestation (base64 → in-toto statement,
trimmed):

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [ { "name": "pkg:npm/sigstore@5.0.0",
                 "digest": { "sha512": "849a897e81bf7b8a…5559597fbd5f80e" } } ],
  "predicate": {
    "buildDefinition": {
      "buildType": "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1",
      "externalParameters": { "workflow": {
        "ref": "refs/heads/main",
        "repository": "https://github.com/sigstore/sigstore-js",
        "path": ".github/workflows/release.yml" } },
      "internalParameters": { "github": { "event_name": "push",
        "repository_id": "495574555", "repository_owner_id": "71096353" } },
      "resolvedDependencies": [ { "uri": "git+https://github.com/sigstore/sigstore-js@refs/heads/main",
        "digest": { "gitCommit": "7d2900eca1c22b3f87c13987c8d4b7c9a29b733a" } } ]
    },
    "runDetails": {
      "builder": { "id": "https://github.com/actions/runner/github-hosted" },
      "metadata": { "invocationId": "https://github.com/sigstore/sigstore-js/actions/runs/26781866618/attempts/1" }
    }
  }
}
```

Decoded **publish** attestation predicate (much thinner):

```json
{ "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [ { "name": "pkg:npm/sigstore@5.0.0", "digest": { "sha512": "849a897e…" } } ],
  "predicate": { "name": "sigstore", "version": "5.0.0", "registry": "https://registry.npmjs.org" } }
```

Note the statement `_type` differs between the two (`v0.1` vs `v1`).

### 2.3 The subject digest binds to the tarball we download — VERIFIED

The attestation subject digest is a **hex** sha512; `dist.integrity` is a **base64** sha512.
They are the same bytes:

```
dist.integrity   sha512-hJqJfoG/e4qFQaauQL00c6J6FrHLBGKtkFvW3JbTSIEFOhLrSjdSM/gWd/yUOfYo/gsERehTXGC1VZWX+9X4Dg==
as hex           849a897e81bf7b8a8541a6ae40bd3473a27a16b1cb0462ad905bd6dc96d34881053a12eb4a375233f81677fc9439f628fe0b0445e8535c60b5559597fbd5f80e
attestation      849a897e81bf7b8a8541a6ae40bd3473a27a16b1cb0462ad905bd6dc96d34881053a12eb4a375233f81677fc9439f628fe0b0445e8535c60b5559597fbd5f80e
MATCH
```

This is the useful property: we can cryptographically tie *the artifact we actually
scanned* to *the build that claims to have produced it*, by converting our computed
sha512 to hex and comparing to `subject[].digest.sha512`. Do that comparison ourselves;
do not take the registry's word that the attestation belongs to the tarball.

### 2.4 What provenance attests to — and what it does NOT prove

npm's own words (<https://docs.npmjs.com/generating-provenance-statements>):

> *"it does not guarantee the package has no malicious code. Instead, npm provenance
> provides a verifiable link to the package's source code and build instructions, which
> developers can then audit and determine whether to trust it or not."*

**Provenance DOES establish (given signature verification succeeds):**

- The tarball with this exact sha512 was produced by a specific workflow file, at a
  specific git ref and commit, in a specific repository, on a specific CI run.
- The signing happened at a time witnessed by a public transparency log (Rekor), so the
  claim cannot be silently backdated or repudiated.
- Separately, the **publish attestation** shows the registry accepted this publish from an
  authorised account.

**Provenance DOES NOT establish:**

- That the code is not malicious. The build was honest; the *source* may be hostile.
- That the source repository was not compromised. A stolen maintainer credential or a
  malicious PR merged to `main` produces perfectly valid provenance — this is exactly what
  happened in the September 2025 `chalk`/`debug` compromise.
- That the workflow itself is trustworthy. `.github/workflows/release.yml` at that ref
  could have been modified in the same attacker commit.
- That dependencies are safe. `resolvedDependencies` records the source checkout, not the
  transitive npm dependency set.
- That the repository named actually owns the package. It shows the repo that ran the
  build; a look-alike repo can publish its own package with valid provenance. Any
  "repository matches" claim requires checking `externalParameters.workflow.repository`
  against something we independently trust — and npm only requires the `repository` field
  to match, which is publisher-controlled metadata.
- Anything at all until we **verify the signature**. An unverified bundle is just JSON the
  registry handed us. **UNVERIFIED:** we have not yet implemented or exercised Sigstore
  bundle verification (Fulcio cert chain, Rekor inclusion proof, certificate identity
  extensions). Until we do, we can only report *"a provenance attestation is published"*,
  never *"provenance verified"*.

### 2.5 Representing provenance honestly

**VERIFIED and important:** the attestations endpoint returns **`404` with body
`{"error":"Not found"}`** for *both*:

- a real package/version that simply has no provenance (`npm@12.0.2`), and
- a package that does not exist at all (`this-pkg-does-not-exist-pg@1.0.0`).

A 404 is therefore **ambiguous** and must never by itself be rendered as
"no provenance found".

Recommended state model — three distinct states, never collapsed to a boolean:

| State | How we determine it | How we may phrase it |
|---|---|---|
| `PROVENANCE_VERIFIED` | `dist.attestations` present, bundle fetched, signature chain verified, and subject digest matches our computed tarball sha512 | "Provenance verified: built by `<repo>` at `<commit>` via `<workflow>`" |
| `PROVENANCE_PRESENT_UNVERIFIED` | `dist.attestations` present, bundle fetched, but verification not performed or inconclusive | "Provenance attestation published but not verified by PackageGate" |
| `PROVENANCE_ABSENT` | Version resolved successfully **and** `dist.attestations` is absent | "No provenance attestation published for this version" |
| `PROVENANCE_UNKNOWN` | Registry lookup failed, endpoint errored, or a 404 we cannot disambiguate | "Could not determine provenance status" |

Rules:

- Drive the decision from **`dist.attestations` in the packument**, which unambiguously
  distinguishes "package exists, no provenance" from "package not found". Use the
  attestations endpoint to *retrieve* the bundle, not to *decide* whether provenance exists.
- Never render absence of provenance as a risk finding on its own. The overwhelming
  majority of legitimate npm packages have no provenance — including the `npm` CLI.
  At most it is a weak positive signal when present, never a negative signal when absent.
- Never render presence of provenance as "safe". See §2.4.

---

## 3. GitHub Security Advisories REST API

Primary docs:

- <https://docs.github.com/en/rest/security-advisories/global-advisories>
- <https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api>

### 3.1 Endpoint

```
GET https://api.github.com/advisories?ecosystem=npm
Accept: application/vnd.github+json
X-GitHub-Api-Version: 2022-11-28
```

**VERIFIED** working unauthenticated. `ecosystem` enum includes `npm` (DOC; `npm`
VERIFIED live).

### 3.2 THE CRITICAL FINDING: `type` defaults to `reviewed`, which EXCLUDES malware

Docs (<https://docs.github.com/en/rest/security-advisories/global-advisories>):

> **`type`** — *"If specified, only advisories of this type will be returned."*
> Allowed values: **`reviewed`**, **`malware`**, **`unreviewed`**. **Default: `reviewed`.**

**VERIFIED empirically.** `GET /advisories?ecosystem=npm&per_page=100` with **no** `type`
parameter returned 100 advisories, of which:

```
type value counts: {'reviewed': 100}
malware present in default results? False
```

> **This is the single most important fact in this document for our data model.**
> If we call `/advisories?ecosystem=npm` without `type`, we get **zero malware advisories**
> and will silently believe no npm package is ever malware. Malware requires an explicit
> `&type=malware`. The three types are disjoint result sets, and there is no
> "give me everything" value — we must issue **separate queries per type** and persist
> them into **separate tables**, which is exactly the KNOWN_MALWARE / KNOWN_VULNERABILITY
> separation the platform requires. The API's own partitioning matches our intended
> schema boundary; we should mirror it rather than merge and re-split.

### 3.3 Captured malware advisory (real, unmodified except for trimming)

`GET /advisories?ecosystem=npm&type=malware&per_page=3` → first result:

```json
{
  "ghsa_id": "GHSA-4fvg-gp6j-v2qm",
  "cve_id": null,
  "url": "https://api.github.com/advisories/GHSA-4fvg-gp6j-v2qm",
  "html_url": "https://github.com/advisories/GHSA-4fvg-gp6j-v2qm",
  "summary": "Malware in statist-browser-typed-client-eventea.projects.pwakasko",
  "description": "Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. …",
  "type": "malware",
  "severity": "critical",
  "repository_advisory_url": null,
  "source_code_location": "",
  "identifiers": [ { "value": "GHSA-4fvg-gp6j-v2qm", "type": "GHSA" } ],
  "references": [ "https://github.com/advisories/GHSA-4fvg-gp6j-v2qm" ],
  "published_at": "2026-08-08T17:27:55Z",
  "updated_at": "2026-08-08T17:28:01Z",
  "github_reviewed_at": "2026-08-08T17:27:55Z",
  "nvd_published_at": null,
  "withdrawn_at": null,
  "vulnerabilities": [
    { "package": { "ecosystem": "npm", "name": "statist-browser-typed-client-eventea.projects.pwakasko" },
      "vulnerable_version_range": ">= 0",
      "first_patched_version": null,
      "vulnerable_functions": [] }
  ],
  "cvss_severities": { "cvss_v3": { "vector_string": null, "score": 0.0 },
                       "cvss_v4": { "vector_string": null, "score": 0.0 } },
  "cwes": [ { "cwe_id": "CWE-506", "name": "Embedded Malicious Code" } ],
  "credits": [],
  "cvss": { "vector_string": null, "score": null }
}
```

A second, higher-value malware example — the September 2025 `chalk` compromise, retrieved
via `GET /advisories/GHSA-2v46-p5h4-248w` (VERIFIED):

```json
{ "ghsa_id": "GHSA-2v46-p5h4-248w", "type": "malware", "severity": "critical", "cve_id": null,
  "summary": "Malware in chalk",
  "vulnerabilities": [ { "package": { "ecosystem": "npm", "name": "chalk" },
                         "vulnerable_version_range": "= 5.6.1",
                         "first_patched_version": null, "vulnerable_functions": [] } ],
  "withdrawn_at": null }
```

`?ecosystem=npm&type=malware&affects=chalk` returns exactly this one advisory — **VERIFIED**,
so `type` and `affects` compose, which is what we need for per-package malware lookup.

**Structural signature of a malware advisory (VERIFIED across both examples):**

| Field | Malware | Reviewed vulnerability |
|---|---|---|
| `type` | `"malware"` | `"reviewed"` |
| `cve_id` | `null` | usually a CVE (e.g. `"CVE-2026-71851"`) |
| `severity` | always `"critical"` | varies (`low`…`critical`) |
| `first_patched_version` | `null` | version string, e.g. `"4.0.0"` |
| `vulnerable_version_range` | `">= 0"` (purpose-built malware) or exact `"= 5.6.1"` (compromised release) | real range, e.g. `"< 4.0.0"` |
| `cwes` | `CWE-506 Embedded Malicious Code` | topic-specific CWEs |
| `cvss` / `cvss_severities` | null / `0.0` | populated vector + score |
| `epss` | **field absent entirely** | present, `{ percentage, percentile }` |
| `source_code_location` | `""` | repo URL |
| `description` | fixed boilerplate ("…should be considered fully compromised…") | bespoke prose |

> Do **not** discriminate on `severity`, `cwes` or `summary` text. `type` is the only
> field that is definitionally authoritative; everything else in that table is
> corroboration. In particular CWE-506 also appears on non-malware advisories (see §4.4).

For contrast, a captured **reviewed** advisory (trimmed):

```json
{ "ghsa_id": "GHSA-rg76-677x-56q9", "cve_id": "CVE-2026-71851", "type": "reviewed", "severity": "critical",
  "summary": "crypto-js: Insufficient Entropy in Cryptographic Secret Generation via Vulnerable CryptoJS Dependency Chain",
  "source_code_location": "https://github.com/brix/crypto-js",
  "identifiers": [ { "value": "GHSA-rg76-677x-56q9", "type": "GHSA" },
                   { "value": "CVE-2026-71851", "type": "CVE" } ],
  "cvss_severities": { "cvss_v3": { "vector_string": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H", "score": 9.0 },
                       "cvss_v4": { "vector_string": null, "score": 0.0 } },
  "epss": { "percentage": 0.00317, "percentile": 0.24074 },
  "cwes": [ { "cwe_id": "CWE-331", "name": "Insufficient Entropy" }, … ],
  "vulnerabilities": [ { "package": { "ecosystem": "npm", "name": "crypto-js" },
                         "vulnerable_version_range": "< 4.0.0",
                         "first_patched_version": "4.0.0", "vulnerable_functions": [] } ] }
```

### 3.4 Response shape notes that affect our schema

- **`first_patched_version` is a plain string** on this REST endpoint (`"4.0.0"`), or
  `null`. It is **not** an object. Note that GitHub's **GraphQL** `SecurityAdvisory` API
  and some older examples model it as `{ identifier: "..." }` — if anyone ports code from
  GraphQL, this will break. VERIFIED as a string on `/advisories`.
- **`vulnerabilities` is an array and routinely covers multiple packages.** VERIFIED:
  `?affects=lodash` returned advisories spanning `['lodash','lodash-es','lodash-amd']` and
  `['lodash','lodash.unset','lodash-es']`. Advisory→package is **many-to-many**; a join
  table is required. Do not model `advisory.package` as a scalar.
- `cvss_severities.cvss_v4.score` is `0.0` rather than `null` when unset — **0.0 does not
  mean "no risk"**, it means "not scored". Store the vector string's nullness as the
  presence test, not the score.
- `epss` is **absent as a key** on malware advisories but present on reviewed ones —
  optional field, not nullable field.
- `withdrawn_at` is nullable and must be honoured; a withdrawn advisory is a retraction
  (false positive) and must not raise a finding.
- `identifiers[]` carries `{ value, type }` with types `GHSA` and `CVE`; `cve_id` is a
  convenience duplicate.
- **Pagination is cursor-based**, not page-numbered. VERIFIED `link` header:
  `<https://api.github.com/advisories?…&after=Y3Vyc29yOnYyOpK0MjAyNi0wOC0wOFQxNzoyNzo1NVrOAAYgyg%3D%3D>; rel="next"`
  Parse the `link` header; do not synthesise `page=N`. There is **no total-count field**,
  so we cannot show "N of M" without walking every page.
- `per_page` max is 100 (DOC).

### 3.5 Auth and rate limits

**VERIFIED:** the endpoint works **unauthenticated**, despite the docs page presenting an
`Authorization: Bearer` header as part of the standard request. Observed headers on an
unauthenticated call:

```
x-ratelimit-limit: 60
x-ratelimit-remaining: 49
x-ratelimit-used: 11
x-ratelimit-resource: core
x-ratelimit-reset: 1786242255
```

Documented primary limits
(<https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api>):

| Credential | Limit |
|---|---|
| Unauthenticated | **60 requests/hour** (per IP) |
| Personal access token | **5,000 requests/hour** |
| GitHub App installation | 5,000/hour (up to 12,500 by size; 15,000 Enterprise Cloud) |
| `GITHUB_TOKEN` in Actions | 1,000/hour per repository (15,000 Enterprise Cloud) |

60/hour unauthenticated is **not viable** for anything but local development — a single
scan can burn several calls. Require a token in any deployed configuration, read it from
the environment, and never log it. Note the limit is per-IP when unauthenticated, so in
containerised CI all our jobs share one bucket.

Backoff, per docs: honour `retry-after` if present; else if `x-ratelimit-remaining` is `0`
wait until `x-ratelimit-reset`; else *"wait for at least one minute before retrying."*

The docs also specify `X-GitHub-Api-Version`. The version string is a dated value — the
docs page currently shows `2026-03-10`, while `2022-11-28` is what I sent and it worked
(VERIFIED). Pin an explicit version rather than omitting the header, and treat the version
bump as a deliberate change.

---

## 4. OSV.dev and ossf/malicious-packages

Primary docs:

- <https://google.github.io/osv.dev/post-v1-query/>
- <https://ossf.github.io/osv-schema/>
- <https://github.com/ossf/malicious-packages>

### 4.1 Query endpoint

```
POST https://api.osv.dev/v1/query
Content-Type: application/json

{ "version": "4.17.20", "package": { "name": "lodash", "ecosystem": "npm" } }
```

**VERIFIED** — returned 5 vulnerabilities. Response is `{ "vulns": [ … ] }` plus an
optional `next_page_token`.

Captured entry (trimmed):

```json
{
  "id": "GHSA-29mw-wpgm-hmr9",
  "aliases": [ "CVE-2020-28500" ],
  "summary": "Regular Expression Denial of Service (ReDoS) in lodash",
  "schema_version": "1.7.3",
  "severity": [ { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" } ],
  "affected": [ {
    "package": { "name": "lodash", "ecosystem": "npm", "purl": "pkg:npm/lodash" },
    "ranges": [ { "type": "SEMVER", "events": [ { "introduced": "4.0.0" }, { "fixed": "4.17.21" } ] } ],
    "database_specific": { "source": "https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/…json" }
  } ],
  "database_specific": { "cwe_ids": [ "CWE-1333", "CWE-400" ], "github_reviewed": true, "severity": "MODERATE" }
}
```

**VERIFIED:** `ecosystem` is **case-sensitive and must be exactly `npm`**.
`"NPM"` and `"Npm"` both return `{"code":3,"message":"invalid ecosystem"}`.

Docs constraints (DOC): `version` and `commit` are mutually exclusive; supplying a version
both in `version` and in a versioned `purl` is a 400; pagination kicks in above 1,000
vulns or a 20-second query.

### 4.2 Querybatch — and its important shape difference

```
POST https://api.osv.dev/v1/querybatch
{ "queries": [ { "package": { "name": "chalk", "ecosystem": "npm" }, "version": "5.6.1" }, … ] }
```

**VERIFIED.** Returns `{ "results": [ { "vulns": [...] }, … ] }`, positionally aligned with
the input `queries` array.

> **VERIFIED gotcha:** querybatch returns **stub objects only** — `{ "id", "modified" }` —
> not full records:
>
> ```json
> { "id": "GHSA-9x64-5r7x-2q53", "modified": "2021-10-01T13:30:04Z" }
> ```
>
> To get details you must follow up with `GET https://api.osv.dev/v1/vulns/{id}` per id.
> Plan for the two-phase fetch: batch to discover, then fan out (deduplicated, cached by
> `id` + `modified`) to hydrate. `modified` is the natural cache-invalidation key.

### 4.3 Yes — OSV carries `MAL-` records for npm, and they dominate

**VERIFIED** via querybatch against known incidents:

| query | MAL ids | other ids |
|---|---|---|
| `flatmap-stream@0.1.1` | `MAL-2025-20690` | `GHSA-9x64-5r7x-2q53`, `GHSA-mh6f-8j2x-4483` |
| `@ctrl/tinycolor@4.1.1` | `MAL-2025-47141` | — |
| `chalk@5.6.1` | `MAL-2025-46969` | — |
| `event-stream@3.3.6` | — | `GHSA-mh6f-8j2x-4483` |
| `eslint-scope@3.7.2` | — | `GHSA-hxxf-q3w9-4xgw` |
| `ua-parser-js@0.7.29` | — | `GHSA-pjwm-rvh2-c87w` |

Note `flatmap-stream` carries **both** a MAL record and GHSA records — a single package
version can be simultaneously malware and vulnerable. Our schema must permit that;
KNOWN_MALWARE and KNOWN_VULNERABILITY are separate tables, not a single enum column.

**Corpus scale — VERIFIED** by downloading the official bulk export
`https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip` (209 MB, 2026-08-09):

```
total records in npm/all.zip: 226,453
ID prefixes: { 'MAL': 219,308, 'GHSA': 7,143, 'EEF': 1, 'GSD': 1 }
```

**96.8% of OSV's npm corpus is malware records.** This should shape our storage and
indexing decisions far more than the vulnerability side.

Also VERIFIED: `https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt` lists
`npm`, and per-ecosystem `all.zip` bulk exports exist — a far better ingestion path than
per-package API calls for the malware corpus.

### 4.4 How MAL records are identified, and their structure

Captured full record, `GET https://api.osv.dev/v1/vulns/MAL-2025-46969` (the chalk
compromise, trimmed):

```json
{
  "schema_version": "1.7.3",
  "id": "MAL-2025-46969",
  "summary": "Malicious code in chalk (npm)",
  "details": "The package was compromised and malicious code added.\n\n---\n_-= Per source details… =-_\n\n## Source: ghsa-malware (985b6546…)\nAny computer that has this package installed or running should be considered fully compromised. …",
  "aliases": [ "GHSA-2v46-p5h4-248w" ],
  "published": "2025-09-08T17:11:19Z",
  "modified": "2025-09-12T01:13:34Z",
  "affected": [ {
    "package": { "name": "chalk", "ecosystem": "npm", "purl": "pkg:npm/chalk" },
    "versions": [ "5.6.1" ],
    "database_specific": { "cwes": [ { "cweId": "CWE-506", "name": "Embedded Malicious Code", … } ] }
  } ],
  "references": [
    { "type": "ARTICLE", "url": "https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised" },
    { "type": "ADVISORY", "url": "https://github.com/advisories/GHSA-2v46-p5h4-248w" } ],
  "credits": [ { "name": "Amazon Inspector", "contact": [ "…" ], "type": "FINDER" } ],
  "database_specific": {
    "malicious-packages-origins": [
      { "source": "ghsa-malware", "id": "GHSA-2v46-p5h4-248w",
        "sha256": "985b6546ed08c8482326a4819faec318c27c1f6d7518acdf384d5f5a8c1453aa",
        "versions": [ "5.6.1" ],
        "modified_time": "2025-09-08T18:23:16Z", "import_time": "2025-09-09T00:35:48.404674353Z" }
      /* … repeated per re-import … */
    ]
  }
}
```

**Discriminator — VERIFIED on a random sample of 800 MAL records from the bulk export:**

- **`id` starts with `MAL-`** — 100% reliable. IDs are `MAL-<year>-<n>`.
- **`summary` is `"Malicious code in <pkg> (npm)"`** — 800/800.
- **MAL records never carry a top-level `severity` array** — 0/800. GHSA records usually do
  (525/600 sampled). Absence of `severity` is a useful corroborating signal.

> **Do not use CWE-506 as the discriminator.** VERIFIED: 41 of 600 sampled **GHSA**
> (vulnerability) records in the npm corpus also contain CWE-506. Use the `MAL-` id prefix.

**Version semantics differ from what the chalk example suggests.** Sample of 500 MAL
records (VERIFIED):

- **465** affected entries use `ranges` (typically `introduced: "0"` — the *entire package*
  is malicious, which is the purpose-built-malware case).
- **51** use an explicit `versions` list (the *compromised legitimate release* case, like
  chalk 5.6.1).

Our matcher must handle **both** `ranges` and `versions`, and must not assume malware
records pin exact versions.

**Provenance of the records themselves** — `database_specific.malicious-packages-origins[].source`,
sampled (VERIFIED):

```
amazon-inspector 350, ghsa-malware 67, reversing-labs 29, ossf-package-analysis 13,
google-open-source-security 5
```

**Only 61 of 500 MAL records had any `aliases` at all** (60 GHSA, 6 SNYK). So the OSV/OpenSSF
malware corpus is **far broader than GitHub's `type=malware` advisories** — roughly 88% of
MAL records have no GHSA counterpart. Querying GitHub alone would miss the large majority
of known-malicious npm packages. **We need both sources.**

### 4.5 The `github.com/ossf/malicious-packages` dataset

- **Format:** OSV schema. README: *"a collection of reports of malicious packages
  identified in Open Source package repositories, consumable via the
  [Open Source Vulnerability (OSV)](https://osv.dev) format."*
- **Licence:** **Apache-2.0** (VERIFIED — fetched `LICENSE`, it is the Apache License
  Version 2.0). Attribution required; commercially usable.
- **Contents — labels/reports only, NOT artifacts.** The repository contains OSV JSON
  reports about malicious packages. It does **not** distribute malicious code. Layout
  (VERIFIED via the GitHub contents API): top level has `osv/`, `cmd/`, `config/`,
  `docs/`, `internal/`, `site/`; and `osv/` contains exactly
  `malicious/`, `unmergable/`, `withdrawn/`.
- **`withdrawn/`** holds false positives — README: *"Move the entire report into the
  `./osv/withdrawn/` directory."* We must exclude withdrawn records on ingest.
- **Scope caveat that materially affects honest reporting.** The README's Scope section
  explicitly says of borderline content:

  > *"typosquatting, or spam packages that are empty or trivial, while not malicious, are
  > allowed to be present in the dataset"*

  and the corpus bears this out — a sampled record describes the **tea.xyz token-reward
  spam campaign**, packages whose "malice" is auto-publishing derivative packages to farm
  reputation points. So **"appears in the MAL corpus" ≠ "will compromise your machine"**.
  With 219,308 npm MAL records, a large fraction is registry spam. We must surface the
  `database_specific.malicious-packages-origins[].source` and the `details` text so an
  investigator can judge severity themselves, and we must not render every MAL hit as a
  critical compromise.
- The README's out-of-scope list explicitly excludes *"vulnerability reports"* — confirming
  the dataset is definitionally malware-only, which aligns with our KNOWN_MALWARE table.
- **UNVERIFIED:** I did not confirm a documented bulk-download mechanism *in the README*
  (it mentions S3/GCS only in passing regarding deployment). The working bulk path I did
  verify is OSV's own export bucket, `osv-vulnerabilities.storage.googleapis.com/npm/all.zip`,
  which is the practical ingestion route.

---

## 5. Current stable versions

All resolved on **2026-08-09** by `curl https://registry.npmjs.org/<pkg>` and reading
`dist-tags.latest` (VERIFIED). `engines.node` and module type read from each resolved
version manifest. Local toolchain for reference: **Node v24.19.0**.

| package | `dist-tags.latest` | published | `engines.node` | module type | provenance |
|---|---|---|---|---|---|
| `fastify` | **5.11.3** | 2026-08-08 | — | commonjs | no |
| `drizzle-orm` | **0.45.2** | 2026-03-27 | — | module | yes |
| `drizzle-kit` | **0.31.10** | 2026-03-17 | — | cjs | yes |
| `zod` | **4.4.3** | 2026-05-04 | — | dual (module + require) | yes |
| `@babel/parser` | **8.0.4** | 2026-07-09 | `^22.18.0 \|\| >=24.11.0` | **ESM-only** | yes |
| `@babel/traverse` | **8.0.4** | 2026-07-09 | `^22.18.0 \|\| >=24.11.0` | **ESM-only** | yes |
| `@babel/types` | **8.0.4** | 2026-07-09 | `^22.18.0 \|\| >=24.11.0` | **ESM-only** | yes |
| `tar-stream` | **3.2.0** | 2026-04-29 | — | cjs | no |
| `next` | **16.3.0** | 2026-08-03 | `>=20.9.0` | cjs | yes |
| `react` | **19.2.8** | 2026-07-21 | `>=0.10.0` | cjs | yes |
| `vitest` | **4.1.10** | 2026-07-06 | `^20.0.0 \|\| ^22.0.0 \|\| >=24.0.0` | dual | yes |
| `@playwright/test` | **1.62.1** | 2026-07-30 | `>=20` | cjs | yes |
| `turbo` | **2.10.9** | 2026-08-07 | — | cjs | yes |
| `pino` | **10.3.1** | 2026-02-09 | — | commonjs | yes |
| `commander` | **15.0.0** | 2026-05-29 | `>=22.12.0` | **ESM-only** | no |
| `undici` | **8.10.0** | 2026-08-03 | `>=22.19.0` | cjs | yes |

None of these `latest` versions is deprecated (VERIFIED).

### 5.1 Node 24 concerns and breaking changes

**`@babel/parser` / `@babel/traverse` / `@babel/types` 8.0.4 — highest impact.**

- `engines.node` is `^22.18.0 || >=24.11.0`. **This range excludes Node 23.x and
  Node 24.0 through 24.10.** Our Node v24.19.0 satisfies it, but a CI image pinned to,
  say, `node:24.9` would fail `engines` checks. Confirmed by the Babel 8 migration guide:
  *"All Babel 8 packages require Node.js `^22.18.0 || >=24.11.0`."*
  (<https://babeljs.io/docs/v8-migration>)
- **Babel 8 is ESM-only.** VERIFIED from the published manifest: `"type": "module"` and the
  `exports` map has **no `require` condition**. The migration guide states
  *"Babel is now shipped as native ECMAScript modules."* Any CommonJS module in our
  static-analysis package will **not** be able to `require('@babel/parser')`.
  This is a hard constraint on the parser package's module format — it must be ESM, or
  must use dynamic `import()`.
- Other Babel 8 changes affecting a parser consumer (DOC): parser plugins
  `importAssertions`, `deprecatedImportAssert`, `importReflection` and `decimal` are
  **removed**; the `estree` plugin's `classFeatures` option is removed (now default);
  sequence expressions in JSX attributes and raw `{ } < >` in JSX text are now rejected.
  Rules that pass removed plugin names will throw.
- This mainly lands on the Static Analysis Engineer — flagging it here because it is a
  cross-cutting toolchain constraint discovered during version resolution.

**`commander` 15.0.0 — ESM-only.** VERIFIED: `"type": "module"`, and `exports` is
`{ ".": { "types": "./typings/index.d.ts", "default": "./index.js" } }` with **no
`require` condition**. Requires Node `>=22.12.0`. If any CLI entrypoint is CommonJS, this
is a breaking change; either go ESM or pin commander 14.x.

**`undici` 8.10.0** requires Node `>=22.19.0` — fine on Node 24. Major 8; **UNVERIFIED**
what its breaking changes are, I did not review its changelog. Also worth noting Node 24
has a capable built-in `fetch` (undici under the hood), so undici may be an unnecessary
dependency unless we need connection-pool control, interceptors or mock agents for tests.

**`drizzle-orm` / `drizzle-kit` — version-selection decision required.** `latest` is
`0.45.2` / `0.31.10`, but both publish a `rc` tag at **`1.0.0-rc.4`**, alongside ~56
other prerelease dist-tags. Drizzle 1.0 is in release-candidate. Shipping on `0.45.2`
means a known-imminent major migration; shipping on an RC means depending on a
prerelease. This is a call for the lead — flagging, not deciding. **UNVERIFIED:** I did
not assess the 0.x→1.0 migration surface.

**`zod` 4.4.3** — Zod 4 major line, dual CJS/ESM (`exports` has a `require` condition), no
`engines` constraint. Zod 4 has meaningful API differences from Zod 3; since we plan to
use Zod for runtime validation at every external boundary, write against v4 from the start
rather than porting v3 idioms. **UNVERIFIED:** specific v3→v4 breaking changes not reviewed.

**`vitest` 4.1.10** — major 4; a `5.0.0-beta.7` exists on the `beta` tag. Node range
`^20.0.0 || ^22.0.0 || >=24.0.0` accommodates Node 24 fully.

**`next` 16.3.0** (`>=20.9.0`) and **`react` 19.2.8** — both current majors, no Node 24
issue. `react`'s `engines` of `>=0.10.0` is vestigial and should be ignored.

**`fastify` 5.11.3**, **`pino` 10.3.1**, **`turbo` 2.10.9**, **`tar-stream` 3.2.0**,
**`@playwright/test` 1.62.1** — no `engines` constraint that conflicts with Node 24; no
concerns found.

> **Note on `tar-stream` 3.2.0:** no provenance, and it is the library we would point at
> hostile archives. Its lack of attestation is not a red flag (most packages lack one),
> but all the streaming limits in our charter — decompressed size, per-file size, file
> count, wall-clock — must be enforced by **our** wrapper during iteration. Do not assume
> the library bounds anything.

---

## 6. Cross-cutting: what we must not assume

Consolidated list of assumptions that this research **disproved** or that remain unproven.

### Disproved by live capture

1. **"`integrity` is missing on old packages."** False on `registry.npmjs.org` today —
   present on 100% of versions back to 2010, and cryptographically genuine. The genuinely
   absent `dist` fields are **`fileCount`** and **`unpackedSize`** (missing on ~90% of
   pre-2016 versions). §1.5.1
2. **"Set the abbreviated `Accept` header on the HTTP client and forget it."** Sending it
   to a single-version manifest URL returns **HTTP 406**. Packument-only. §1.4
3. **"`/advisories?ecosystem=npm` returns all npm advisories."** It returns **only
   `reviewed` vulnerabilities**; `type` defaults to `reviewed` and malware is invisible
   without `&type=malware`. §3.2
4. **"OSV querybatch returns full records."** It returns `{id, modified}` stubs; details
   require a second call per id. §4.2
5. **"A 404 from the attestations endpoint means no provenance."** The same 404 is returned
   for a nonexistent package. Decide from `dist.attestations`, not from the 404. §2.5
6. **"`time` keys and `versions` keys correspond."** Unpublished versions persist in `time`
   with no manifest — 30 such keys on `express`. §1.6
7. **"CWE-506 identifies malware."** 41 of 600 sampled OSV **GHSA vulnerability** records
   also carry CWE-506. Use `type == "malware"` (GitHub) or the `MAL-` id prefix (OSV). §4.4
8. **"OSV malware records pin exact versions."** Only ~10% do; ~90% use `ranges` covering
   the whole package. §4.4
9. **"GitHub's malware advisories cover the known-malware space."** ~88% of OSV `MAL-`
   records have no GHSA alias; OSV's npm corpus is 219,308 MAL records against roughly
   7,143 GHSA. Both sources are required. §4.3, §4.4
10. **"`first_patched_version` is an object."** On this REST endpoint it is a **string** or
    `null` (the GraphQL API is the one that uses `{identifier}`). §3.4
11. **"An advisory concerns one package."** `vulnerabilities[]` regularly spans several
    (`lodash`, `lodash-es`, `lodash-amd`). Many-to-many. §3.4

### Must not assume (design rules)

- **Do not treat absence of provenance as a negative signal.** Most legitimate packages —
  including the `npm` CLI — publish without it.
- **Do not report "provenance verified" until we actually verify the Sigstore bundle.**
  Until then the honest phrasing is "provenance attestation published". §2.4
- **Do not treat "present in the MAL corpus" as "will compromise your machine".** The
  OpenSSF dataset deliberately admits trivial/spam packages, and the npm corpus is heavily
  padded by the tea.xyz token-farming campaign. Surface the source and details. §4.5
- **Do not merge malware and vulnerability records.** Both upstreams partition them
  natively (`type`, `MAL-` prefix); mirror the partition in our schema. A single
  package version can be **both**. §4.3
- **Do not default numeric absent fields to zero.** `unpackedSize ?? 0` and
  `fileCount ?? 0` silently mark historical packages as empty; `cvss_v4.score == 0.0`
  means "not scored", not "no risk". §1.5, §3.4
- **Do not synthesise `page=N` for GitHub advisories.** Cursor pagination via the `link`
  header, and no total count is available. §3.4
- **Do not run unauthenticated against GitHub in any deployed configuration** — 60 req/hour
  per IP, shared across all containers behind one NAT. §3.5
- **Do not exceed ~1 request/second to the npm registry**, and send an honest, identifying
  `User-Agent`: npm bans by IP *and* user-agent. There are no rate-limit headers to warn us
  first. §1.7
- **Do not string-concatenate package names into URLs.** Percent-encode; standardise on
  `@scope%2fname`. §1.3
- **Validate every external response at the boundary.** Registry, GitHub and OSV responses
  are untrusted input. Field presence surveyed here is *observed behaviour on one date*,
  not a contract.

### Explicitly unverified — check before relying on

- Whether any npm documentation **guarantees** `integrity` on historical versions (I found
  none; the backfill appears to be policy, not contract). §1.5.1
- Behaviour of scoped-package URL forms on **non-npmjs registries** (Verdaccio,
  Artifactory, GitHub Packages). Only `registry.npmjs.org` was tested. §1.3
- **Actual ECDSA verification** of `dist.signatures`, and full **Sigstore bundle
  verification** (Fulcio chain, Rekor inclusion proof, certificate identity extensions).
  Key material was fetched; no verification was performed. §1.5.2, §2.4
- The `time.unpublished` key shape on a fully-unpublished package — no live example
  captured. §1.6
- npm **replication** endpoint availability and terms, if we ever want the bulk corpus. §1.7
- Breaking-change surfaces for **undici 8**, **zod 3→4**, and **drizzle 0.x→1.0**. §5.1
- Whether the registry ever emits an **empty-string** `deprecated` value. §1.6
