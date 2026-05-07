# korrel-cli

Audits remote Model Context Protocol (MCP) servers for OAuth 2.1 and
spec compliance. Produces a Markdown report with findings and raw
HTTP evidence for every request.

`korrel audit https://mcp.example.com/` runs six probes against the
authorization surface and writes:

```
audits/mcp.example.com/
├── report.md
└── evidence/
    ├── 01-discovery.http
    ├── 02-prm.http
    ├── 03-as-metadata.http
    ├── 04-registration.http
    ├── 05-pkce.http
    └── 06-tokens.http
```

Findings render with five severity levels:
[`info`, `warn`, `issue`, `critical`, `skipped`](./docs/SEVERITY.md).
A target with only `info` findings is clean on the probed surface;
`issue` findings drive coordinated disclosure to the target operator.

## Why this exists

`korrel-cli` produces the evidence for a public audit series at
[`korrel-dev/mcp-audits`](https://github.com/korrel-dev/mcp-audits).
Each audit follows the same pattern: run the probes, draft findings
against the methodology, disclose privately to the target operator,
publish the report after a coordinated disclosure window.

Audits published so far:

- [GitHub Copilot MCP](https://github.com/korrel-dev/mcp-audits/tree/main/audits/github)
  (2026-04-27)
- [Linear MCP](https://github.com/korrel-dev/mcp-audits/tree/main/audits/linear)
  (2026-05-04)
- Supabase MCP (2026-05-11)

The methodology that drives the probes is versioned at
[`mcp-audits/METHODOLOGY.md`](https://github.com/korrel-dev/mcp-audits/blob/main/METHODOLOGY.md).
Methodology v1.0 closed on 2026-04-29; v2.0 expands into tool
authorization, prompt-injection signatures, agent-vs-user identity,
session lifecycle, consent, and audit integrity.

## Probes

| # | ID | Methodology § | RFCs | Status |
|---|---|---|---|---|
| 1 | `01-discovery` | §1 Discovery | RFC 9728, RFC 6750 §3.1, RFC 7235 | Implemented |
| 2 | `02-prm` | §2 PRM half | RFC 9728 | Implemented |
| 3 | `03-as-metadata` | §2 AS half | RFC 8414 | Implemented |
| 4 | `04-registration` | §3 Client registration | RFC 7591, MCP CIMD (spec 2025-11-25) | Implemented |
| 5 | `05-pkce` | §4 PKCE enforcement | RFC 7636 | Implemented |
| 6 | `06-tokens` | §5-6 Token hygiene + ancillary | RFC 8707, RFC 6750, RFC 6749 §10.12 | Implemented |

Per-probe scope and follow-ups in [`docs/ROADMAP.md`](./docs/ROADMAP.md).
Architectural decisions in [`docs/DESIGN.md`](./docs/DESIGN.md).

## Install

Not yet published to npm. Clone and run against source:

```
git clone https://github.com/korrel-dev/korrel-cli
cd korrel-cli
npm install
npm run dev -- audit https://mcp.example.com/
```

Requires Node 22 or later.

## Usage

```
npm run dev -- audit <url>
```

Output lands at `audits/<host>/`. The tool does not redact evidence
files at write time. Evidence captures may contain live OAuth
credentials returned by the target during DCR; see the disclosure
section before sharing or committing the captures.

## What the report says

A finding has a severity, a short title, an RFC citation, and an
evidence reference. Example:

> **Probe 4: Client registration**
> **Result:** issue
> **Finding:** DCR accepted HTTP redirect URI for confidential client
> **Citation:** OAuth 2.1 §1.5 (HTTPS scheme on redirect URIs for
> confidential clients), RFC 7591 §5 (metadata scrutiny)
> **Evidence:** `evidence/04-registration.http`

The audit series uses these reports verbatim, with target-specific
context and a disclosure timeline added in
[`mcp-audits/audits/<vendor>/`](https://github.com/korrel-dev/mcp-audits/tree/main/audits).

## Disclosure

If you find an issue in `korrel-cli` itself, see
[`SECURITY.md`](./SECURITY.md). The audit reports the tool generates
follow the disclosure policy of
[`korrel-dev/mcp-audits`](https://github.com/korrel-dev/mcp-audits/blob/main/SECURITY.md).

If you operate an MCP server that has been audited or might be
audited, the audit series welcomes pre-publication review of
findings. Email `founder@korrel.dev`.

If you operate an MCP server and want to run the probes yourself
before someone else does, that is the intended use case. The
methodology is open, the probes are open, the evidence format is
open. A clean run against your staging server is the cheapest
audit you will ever buy.

## Severity, briefly

Per [`docs/SEVERITY.md`](./docs/SEVERITY.md):

- `info` — probe ran, target did the correct thing.
- `warn` — SHOULD-level deviation, worth operator attention.
- `issue` — MUST-level spec violation, drives disclosure.
- `critical` — orchestrator-level fault (no probe emits this today).
- `skipped` — required upstream input missing.

Each report includes a severity footer linking to the full vocabulary.

## What this is not

`korrel-cli` is a probe tool, not a compliance attestation. A clean
run does not certify SOC 2, HIPAA, PCI, or EU AI Act compliance; it
records that the OAuth surface passes the documented probes against
the methodology version run. Compliance attestation is what the
broader Korrel platform produces from audit logs and runtime
controls.

`korrel-cli` is also not a fuzzer or security scanner. It does not
send malformed payloads beyond what the methodology probes specify.
It does not test for application-level vulnerabilities (injection,
deserialization, business logic). It tests OAuth conformance.

## Status

Early development. Methodology v1.0 closed 2026-04-29. Probe
implementations validated against three real MCP servers
(GitHub Copilot, Linear, Supabase) plus internal test fixtures.
Per-probe issue tracking in [GitHub issues](https://github.com/korrel-dev/korrel-cli/issues).

## License

MIT. See [`LICENSE`](./LICENSE).

The audit reports the tool produces are licensed separately under
[CC BY 4.0](https://github.com/korrel-dev/mcp-audits/blob/main/LICENSE-CONTENT)
in the
[`mcp-audits`](https://github.com/korrel-dev/mcp-audits) repository.

## Related

- [`korrel-dev/mcp-audits`](https://github.com/korrel-dev/mcp-audits) —
  audit reports and methodology.
- [Korrel](https://korrel.dev) — the broader platform: MCP-native
  auth and observability for SaaS publishers shipping remote MCP
  servers.
