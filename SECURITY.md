# Security disclosure policy

`korrel-cli` is a public OSS probe tool that audits remote MCP
servers against the OAuth 2.1 authorization requirements of the
Model Context Protocol specification. It runs unauthenticated
probes against arbitrary URLs the operator supplies, captures HTTP
responses to disk, and emits findings against a documented
methodology.

The tool is designed to be safe to point at any spec-compliant MCP
server; the probes mirror what a conformant client would do during
discovery and registration. If you find a way to make `korrel-cli`
behave outside that envelope, this file describes how to disclose
it.

## What counts as a security issue

Five categories.

**1. Probe behavior outside spec envelope.** A probe sends a
request the documented methodology doesn't authorize, or sends a
request shape no spec-compliant client would generate. Examples:
a probe that POSTs to an endpoint outside RFC 7591 / RFC 9728 /
RFC 8414's discovery surface; a probe that sends payloads the
methodology doesn't describe; a probe that ignores `Retry-After`
and re-hits a target after a 429.

**2. Evidence handling weakness.** Evidence files written under
`outputs/` (or the legacy `audits/` path) contain raw HTTP
responses including headers, cookies, and bodies. The tool does
not redact at write time; redaction happens before audit
publication in the separate
[`mcp-audits`](https://github.com/korrel-dev/mcp-audits) repository.
A weakness in this category would be: the tool persists an
evidence file outside the configured output directory, the tool
includes secrets in stdout the operator did not consent to, the
tool writes evidence files with permissions that expose them
beyond the operator's process.

**3. Probe-payload exfiltration vector.** A probe accepts an
operator-supplied URL and crafts requests including identifiers
the operator did not explicitly provide. If the tool ever sends
operator-side credentials, environment variables, or
cross-target identifiers in a probe payload, that is an
exfiltration vector.

**4. Dependency vulnerability.** A direct or transitive dependency
of `korrel-cli` is published with a known CVE that affects the
probe pipeline's threat surface. We track Node 22+ runtime,
`commander`, `zod`, `tsx`, and a small list of HTTP / crypto
helpers; the dependency tree is bounded by design.

**5. Methodology violation in probe code.** A probe's emitted
observation cites an RFC clause the spec does not contain. The
audit accuracy pattern in
[`METHODOLOGY.md`](https://github.com/korrel-dev/mcp-audits/blob/main/METHODOLOGY.md)
catches most of these in audit prose review, but the probe code
itself is the source. Live probe-citation follow-ups, plus a
"Closed not-a-bug" section recording reviews where the original
filing was in error, are tracked in
[`docs/ROADMAP.md`](./docs/ROADMAP.md#follow-ups-tracked-against-shipped-probes).

## What is not a security issue

- A probe returns `info` / `warn` / `issue` for a finding you
  disagree with on the merits. Open a public issue. The severity
  vocabulary is documented in `docs/SEVERITY.md`; framing
  disagreements are technical, not security.
- A probe times out against a slow target. Open a public issue
  with the target URL and rough latency.
- The tool does not yet probe a category you care about
  (token introspection, RP-initiated logout, etc.). Open a
  public issue or send a PR; the methodology version log
  documents which probes are V1.0.
- A request for the tool to support a new flag or output format.
  Public issue.

## How to disclose

Email `security@korrel.dev` with:

- The category from the list above.
- The probe (1-6 per `METHODOLOGY.md`) and the source file path
  (`src/probes/<name>.ts`).
- Reproduction steps including the target URL the operator
  supplied and the observed behavior.
- Whether you have published this finding anywhere.

PGP available on request.

## What happens next

Acknowledgment within 72 hours. Substantive response within 7
days.

For categories 2 and 3 (evidence handling, exfiltration), the
timeline is 24 hours: probes that leak operator-side state are
disabled in the next patch release with a security advisory, and
the affected probe is gated behind a `--allow-leaky` flag (off
by default) until the fix lands. Past audits that captured
evidence with the leaky probe are flagged in `mcp-audits` for
re-review.

For categories 1 and 5 (probe behavior, methodology violation),
the fix is a probe-code change plus a test plus a methodology
amendment if the change shifts what the probe asserts. The
[`mcp-audits` METHODOLOGY.md](https://github.com/korrel-dev/mcp-audits/blob/main/METHODOLOGY.md)
version log records the amendment with a discloser credit if
the discloser wishes.

For category 4 (dependency CVE), the fix is a dependency bump
plus a release. Audit reports are not affected unless the CVE
demonstrably affected probe behavior at the time of the audit;
in that case the audit is amended with a footnote.

## Scope

This policy covers code in the
[`korrel-dev/korrel-cli`](https://github.com/korrel-dev/korrel-cli)
repository.

The audit reports the tool generates are published in the separate
[`korrel-dev/mcp-audits`](https://github.com/korrel-dev/mcp-audits)
repository; that repository's
[`SECURITY.md`](https://github.com/korrel-dev/mcp-audits/blob/main/SECURITY.md)
covers the audit content and evidence files.

## Out of scope

- Issues in MCP servers that `korrel-cli` audits. Disclose to the
  affected vendor directly.
- Issues in the [Model Context Protocol](https://github.com/modelcontextprotocol)
  specification. Disclose to the spec maintainers.
- Issues in [korrel.dev](https://korrel.dev) (the company website)
  or the Korrel managed cloud. Email `security@korrel.dev` with
  the product name in the subject line.

## Hall of fame

Disclosers who report valid issues and want public credit will be
listed here. Anonymous disclosure is fine.

(No reports yet.)
