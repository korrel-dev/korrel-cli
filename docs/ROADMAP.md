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
| 5 | `05-pkce` | §4 PKCE enforcement | RFC 7636 | Implemented |
| 6 | `06-tokens` | §5-6 Token hygiene + ancillary | RFC 8707, RFC 6750, RFC 6749 §10.12 | Implemented |

Methodology v1.0 closed 2026-04-29 with six probes covering the
authorization surface end-to-end. Probe count reflects the
methodology's surface decomposition; future methodology versions
may add or split probes.

Methodology §2 splits into two probes (`02-prm` and
`03-as-metadata`) because each emits its own evidence file and the
failure modes are distinct: a server can ship RFC 9728 PRM and
still fail RFC 8414 AS metadata, or vice versa.

Methodology §5 (token hygiene) and §6 (ancillary controls) collapse
into a single probe (`06-tokens`) at v1.0 because the observable
surface is shared (token endpoint metadata, audience claim semantics,
state echo, HTTPS scheme). Future methodology versions may split
when ancillary controls grow beyond what one probe can cover.

## Future probes

Methodology v2.0 (planned) expands into:

- Tool authorization scope checking (per-tool ACL granularity).
- Prompt-injection signature detection at the protocol layer.
- Agent-vs-user identity binding (CIMD lineage, agent attestation).
- Session lifecycle and concurrent-session policies.
- Consent screen behavior on dynamic scope grants.
- Audit log integrity verification at the AS level.

No timeline for v2.0; it lands when at least three of these surfaces
have enough adoption in published MCP servers to warrant a
deterministic probe.

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
- `02-prm`: cites RFC 9728 §3 for fields defined in §2, and treats
  three OPTIONAL fields as RECOMMENDED. Filed during audit-03
  polish, 2026-05-06. Non-blocking but tracked.
- `04-registration`: bodyExcerpt may leak client_id on
  invalid-response paths. Tracked as #11.

Probe-citation correction follow-ups land alongside the next
methodology amendment in
[`mcp-audits/METHODOLOGY.md`](https://github.com/korrel-dev/mcp-audits/blob/main/METHODOLOGY.md);
the audit accuracy pattern locked 2026-05-02 catches future
miscites at draft-review time before they ship.

## Closed not-a-bug

- `04-registration` (host-mismatch §5 SHOULD framing). Filed
  2026-05-06 during audit-03 polish on the basis that probe-04's
  POST 3 cited "RFC 7591 §5 SHOULD" but no such SHOULD existed.
  Closed 2026-05-07 after a careful read of RFC 7591 §5 paragraph
  by paragraph: §5 Para 6 contains a direct SHOULD covering the
  exact check the probe performs. The probe citation is correct.
  Audit-02 and audit-03 prose has been amended to match (see
  `mcp-audits` commits 0401d933 and cccf901e). Lesson: when
  reviewing an RFC section, read every paragraph; "logo /
  redirect_uris" sits in §5 Para 5, "client_uri / redirect_uris"
  sits in §5 Para 6, and the May 6 review only saw the first.
