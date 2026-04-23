# Severity vocabulary

korrel-cli emits findings at five severity levels. This document defines each. The severity of a finding determines how it renders in generated `report.md` files and how it should be interpreted by audit readers and target operators.

## info

The probe ran. The target did the correct thing, or made a legitimate design choice that the probe observed successfully. Informational observation, no action needed by the target operator.

Examples:

- "PRM document served at the advertised URL and validates"
- "AS metadata advertises PKCE S256"
- "CIMD advertised in AS metadata"
- "DCR not advertised" (target deliberately omitted DCR in favor of CIMD or pre-registration; probe observed successfully)

A target with only `info` findings is clean on the probed surface.

## warn

The probe ran. The target has a SHOULD-level spec deviation, a minor gap, or a non-breaking oddity worth flagging. The target is not violating a hard spec requirement but is doing something the spec discourages, or has a gap that merits operator attention.

Examples:

- "DCR accepted host-mismatched redirect URI (RFC 7591 §5 SHOULD)"
- "DCR registration response uses HTTP 200 instead of 201 (RFC 7591 §3.2.1 MUST, but non-exploitable in practice)"
- "AS metadata missing RECOMMENDED fields"

A `warn` finding in an audit gets a paragraph explaining why it's worth flagging. Target operators should evaluate whether to fix.

## issue

The probe ran. The target has a MUST-level spec violation or a concrete gap with real threat-model implications. The target is violating a hard spec requirement, or has a missing control that opens an attack path.

Examples:

- "DCR accepted HTTP redirect URI for confidential client (RFC 7591 §5 MUST)"
- "Registration endpoint not TLS-protected (RFC 7591 §3 MUST)"
- "AS metadata failed schema validation"

An `issue` finding in an audit drives the disclosure email. Target operators should fix these, coordinated disclosure norms apply.

## critical

Reserved for the orchestrator. No probe emits `critical` today.

Intended for cross-probe catastrophic findings: probe harness itself crashed, evidence collection failed mid-audit, target returned responses that broke multiple probes simultaneously. The slot exists so `report.ts` and the `Severity` type do not need a schema change when the orchestrator grows cross-probe state-validation logic.

## skipped

The probe could not execute because a required input from an upstream probe is missing, or a precondition is unmet. The probe was a no-op: no evidence of compliance, no evidence of violation.

Examples:

- "DCR/CIMD probe skipped: AS metadata not available" (probe 3 did not populate the required input)
- "AS metadata fetch skipped: probe 2 did not discover any authorization_servers"

`skipped` is an explicit signal to audit readers that this surface of the target was not tested. A target with many `skipped` findings has limited audit coverage on the skipped paths.

## Key distinctions

**`info` versus `skipped`:** `info` means "I checked and the target is fine." `skipped` means "I couldn't check." Both imply no problem, but they communicate very different things. A target with ten `info` findings and zero skips is thoroughly audited. A target with five `info` findings and five skips has half its surface unaudited.

**`warn` versus `issue`:** SHOULD-level vs MUST-level in RFC terms. Observable gap vs concrete violation. `warn` findings get a paragraph of context, `issue` findings get a section with inline evidence and RFC citation.

**`issue` versus `critical`:** Per-probe observation vs cross-probe orchestrator-level fault. A probe finding a MUST violation in the AS it was testing is `issue`. The probe harness producing a result that can't be trusted is `critical`.

## In generated reports

Generated `report.md` files render severity literally: `**Result:** info`, `**Result:** warn`, `**Result:** issue`, `**Result:** skipped`. Reports include a footer linking to this document.
