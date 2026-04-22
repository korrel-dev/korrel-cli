# DESIGN.md

Version 0. Pins the abstractions behind `korrel-cli` so future probes
land without re-litigating shape.

## What is a probe?

A probe is one function that tests one property of an MCP server's
authorization surface. It maps to one step of the methodology at
[`mcp-audits/METHODOLOGY.md`](https://github.com/korrel-dev/mcp-audits/blob/main/METHODOLOGY.md).
Probe 1 is discovery. Probe 2 is protected resource metadata. Probe
3 is authorization server metadata. One step, one probe, one file
under `src/probes/`. A probe issues HTTP requests, records the
exchanges as evidence, emits findings, and optionally hands
structured state back to the orchestrator for downstream probes
to consume. It does not log, write files, or mutate its input.

## How do probes compose?

They don't compose, they sequence. The orchestrator runs probes
in a fixed order and threads an `AuditContext` through them. Each
probe reads the fields it needs and writes back via
`contextUpdates`. Probe 1 populates the protected resource
metadata URL. Probe 2 fetches that URL and populates the
authorization server list. Probe 3 fetches AS metadata and
populates endpoint URLs for probe 4. This is a straight pipeline,
not a DAG, and no probe imports another probe. If a later probe
needs something earlier, the earlier probe exposes it on the
context.

## Contract between orchestrator and probe

A probe has the signature `(ctx: AuditContext) => Promise<ProbeResult>`.
`ProbeResult` carries zero or more `Finding` entries, zero or more
`NamedEvidence` exchanges, and an optional `Partial<AuditContext>`
to merge back in. The orchestrator does the side effects: it writes
each `NamedEvidence` to `evidence/<name>.http`, merges
`contextUpdates` into the running context, collects findings, and
renders the final report. Probes do not touch the filesystem and
do not read the network beyond what the contract implies.

Metadata fields on `AuditContext` start as `unknown` and get
retyped as `z.infer<typeof schema>` once the probe that validates
them lands. Downstream probes read the typed value directly. No
re-validation, no second parse. The zod schema is the boundary; past
it, the data is trusted.

## Probes fail gracefully

The orchestrator wraps every probe call in `try`/`catch`. An
uncaught exception becomes a `Finding` with `severity: 'issue'`
and the error message as an observation, and the audit moves on
to the next probe. A single broken server response does not
terminate the run. This is the contract: no probe can halt the
audit, and an auditor always gets whatever evidence the earlier
probes captured before the failure.

## Why `.http` files for evidence

The `.http` format is the same one JetBrains HTTP Client and the
VS Code REST Client extension consume, so an auditor replays a
recorded exchange in their editor without conversion. It is also
close to the wire format RFC 7230 describes: request line,
headers, blank line, body, then the response in the same shape.
A reviewer reads the bytes, not a renderer's interpretation. Plain
text also greps cleanly and diffs cleanly, which matters when the
same server is re-audited months later.

## Why zod for validation

RFC 9728 and RFC 8414 describe narrow JSON schemas with required
fields, recommended fields, and type constraints (URIs, arrays of
URIs, enumerated strings). We need both runtime validation of the
server's response and a static type for the parsed document to
flow through the rest of the pipeline. zod gives both from one
definition via `z.infer<>`. The alternative is a hand-rolled
validator plus a parallel TypeScript interface, which drift apart
the first time the schema changes. One source of truth beats
two.

## Out of scope for v0

No retry logic, no caching, no parallelism across probes, no
custom HTTP client. Probes use the platform `fetch`. When a probe
needs something richer (e.g. probe 4 may hit multiple endpoints
in one logical step), the `NamedEvidence[]` array in `ProbeResult`
absorbs it without restructuring the contract.
