# TODO.md

Follow-ups tracked outside of HANDOFF.md. Each item has a target
window; do not pull forward into tonight's session.

## Pending

- Add `--name` flag so CLI output can be written under curated
  directory names (e.g. `github/` instead of `api.githubcopilot.com/`).
  Host-based names stay as default for scratch runs; `--name`
  required when output targets `mcp-audits/audits/`. Implement
  Thursday or Saturday, not tonight.

- Probe 2 should fall back to the RFC 9728 §3 well-known URL
  (`<origin>/.well-known/oauth-protected-resource` and the
  per-resource `<origin>/.well-known/oauth-protected-resource<path>`
  form) when `WWW-Authenticate` lacks a `resource_metadata`
  parameter, instead of silent-skipping. Current behavior produces
  incomplete findings when a server omits the header hint but does
  serve a PRM document (or vice versa, which is the real
  compliance signal). Surfaced by the Atlassian audit on
  2026-04-22. Fix Thursday 2026-04-23.
