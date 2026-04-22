# NOTES.md

Running log of cross-server observations from `korrel audit` runs.
Audit post material; not user-facing.

## 2026-04-22 — probes 1-3 against four public MCP endpoints

Targets:

- `https://api.githubcopilot.com/mcp`
- `https://mcp.linear.app/mcp`
- `https://mcp.notion.com/mcp`
- `https://mcp.atlassian.com/v1/sse`

### Per-server

**GitHub Copilot MCP** — all three probes structurally pass.
`WWW-Authenticate` uses `error="invalid_request"` on an
unauthenticated request, which RFC 6750 §3.1 reserves for
malformed requests (missing parameters, duplicate tokens). The
spec-correct value is `invalid_token`. GitHub is the only one of
the four that gets this wrong. PRM is the only one of the four
that populates `scopes_supported`. Disclosure sent to
`security@github.com` on 2026-04-20; publish scheduled for
2026-04-27.

Per-server findings for Linear, Notion, and Atlassian held in
`PRIVATE-NOTES.md` until coordinated disclosure is complete.

### Patterns across the four

- Three of four (Linear, Notion, Atlassian) self-host the AS
  alongside the resource (same origin). GitHub is the outlier,
  delegating to `github.com/login/oauth`.
- All three servers whose AS metadata resolved used the RFC 8414
  §3.1 path-insertion form. No fallback to the naive
  `issuer/.well-known/...` form was needed, which matches the
  hand-captured GitHub evidence (`04-naive-metadata-404.txt` in
  `mcp-audits`).
- `resource_documentation` and `resource_signing_alg_values_supported`
  are absent from every PRM we saw. The RFC 9728 "recommended"
  fields are, in practice, not adopted.
- `bearer_methods_supported` is present on GitHub and Linear,
  absent from Notion (inferred from observations, confirm from
  evidence if it matters).

### Tool observations

- Report initially linked to evidence files for skipped probes;
  fixed this session (commit touching `report.ts`).
- Probe 3 only handles the first entry in `authorization_servers`.
  None of the four servers advertised more than one, so this was
  not exercised. Multi-AS handling is a follow-up.
- Probe 3 does not yet check the RFC 8414 §3.1 non-compliant
  ("naive") form for contrast. Follow-up.
