# Security Policy

## Reporting a vulnerability in PackageGate

Please report security issues privately using GitHub's **Report a vulnerability**
button under the repository's Security tab, rather than opening a public issue.

Include the affected component, a reproduction, and what an attacker gains. If
you have a crafted artifact that demonstrates the issue, describe how to build it
rather than attaching a live malicious sample.

## Threat model in one paragraph

PackageGate processes **attacker-controlled input by design**. Every tarball it
downloads is assumed hostile. The security boundary that matters is between an
analysed package and the host running PackageGate. The full model is in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## What counts as a vulnerability here

These are the failures we consider serious, roughly in priority order:

**Escape from the analysis pipeline.** Anything that lets a crafted package
achieve code execution, write outside the extraction root, follow or create a
symlink, read host files, or reach the network from the scanning stage.

**Defeating a resource budget.** Extraction enforces compressed size,
decompressed size, per-file size, file count, path length, compression ratio and
wall-clock limits, all *during* streaming. A package that exhausts memory, disk
or CPU despite those budgets is a bug.

**Evidence forgery.** Output travels into logs, a terminal and a browser. A
package that injects ANSI escapes to repaint CLI output, forges log lines, or
achieves script execution in a rendered report is a vulnerability, not a
cosmetic issue.

**Leaking host paths or secrets.** No host filesystem path, credential or
environment value may appear in a finding, an error, a log field or an API
response.

**Silent failure.** A scan that errors but reports as clean is among the worst
outcomes this tool can produce, because it reports a hostile package as
uninteresting. Unparseable files must surface as `ParseFailure`, and failed
lookups must be distinguishable from empty results.

## What is not a vulnerability

**A missed detection.** PackageGate performs static analysis and cannot see
runtime-gated behaviour, computed member access, or `require` targets built from
strings. Absence of findings is explicitly not a safety claim — see
[`docs/LIMITATIONS.md`](docs/LIMITATIONS.md). Missed detections are very welcome
as **issues**, but they are not security reports.

**A false positive.** Also welcome as an issue, and genuinely valuable to us —
false positives are the central product risk — but not a vulnerability.

**Scoring disagreements.** Weights are judgement calls, documented with their
rationale in [`docs/RISK_MODEL.md`](docs/RISK_MODEL.md). Argue with them in an
issue.

## Handling malicious samples

If you contribute test material:

- **Never commit live malware.** Fixtures must be inert: no real credential
  paths read, no real network destinations, no working payload. They exist to
  exercise the parser and nothing else.
- Real samples are never auto-downloaded by this project. Evaluation requires an
  explicit `--malware-root` you populated deliberately.
- Even then, samples are only statically inspected. **PackageGate does not
  execute analysed code, and no contribution that introduces dynamic execution of
  unknown packages will be accepted** into the scanner.

## Supported versions

PackageGate is pre-1.0. Security fixes land on `main`; there are no backported
release branches yet.
