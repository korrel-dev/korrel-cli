# ROADMAP.md

Probe-by-probe status for `korrel-cli`. Updated on every probe
landing. Maps each probe to the
[audit methodology](https://github.com/korrel-dev/mcp-audits/blob/main/METHODOLOGY.md)
step it implements.

## Probes

| # | ID | Methodology § | RFCs | Status |
|---|---|---|---|---|
| 1 | `01-discovery` | §1 Discovery probe | RFC 9728, RFC 6750 §3.1, RFC 7235 | Implemented |
| 2 | `02-prm` | §2 AS metadata (PRM half) | RFC 9728 §3 | Implemented |
| 3 | `03-as-metadata` | §2 AS metadata (AS half) | RFC 8414 | Implemented |
| 4 | `04-registration` | §3 Client registration | RFC 7591, MCP CIMD (spec 2025-11-25) | Implemented |
| 5 | `05-pkce` | §4 PKCE enforcement | RFC 7636 | Pending |
| 6 | `06-tokens` | §5 Token hygiene | RFC 8707, RFC 6750 | Pending |
| 7 | `07-ancillary` | §6 Ancillary controls | transport, CSRF, security headers | Pending |

Methodology §2 splits into two probes (`02-prm` and
`03-as-metadata`) because each emits its own evidence file and the
failure modes are distinct: a server can ship RFC 9728 PRM and
still fail RFC 8414 AS metadata, or vice versa. Probes 4-7 may
split similarly when they land.

## Legend

- **Implemented** — ships in main, validated against at least one
  real MCP server.
- **Scaffolded** — structure and primary-path checks ship, but
  depth items (e.g. non-compliant alternate forms, multiple
  authorization_servers, corner-case spec text) are follow-ups.
- **Pending** — not yet written.

## Follow-ups tracked against shipped probes

- `03-as-metadata`: RFC 8414 §3.1 non-compliance detection
  (fetch the naive `issuer/.well-known/...` form for contrast and
  flag servers serving at both or only the wrong one).
- `03-as-metadata`: multi-AS support. Current implementation
  fetches only the first entry in `authorization_servers` and
  notes the others.
- `02-prm`: explicit check that the PRM document is served with
  `Content-Type: application/json` (RFC 9728 §3).
- `04-registration`: bodyExcerpt may leak client_id on
  invalid-response paths. Tracked as #11.
