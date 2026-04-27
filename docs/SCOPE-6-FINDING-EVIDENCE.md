# Scope: Finding.evidence field (#6)

## Problem

`src/report.ts` links findings to evidence files via bidirectional
prefix-match:

```ts
const relatedEvidence = [...evidenceNames]
  .filter(name =>
    name === finding.id
    || name.startsWith(`${finding.id}-`)  // probe 4 case
    || finding.id.startsWith(`${name}-`)  // probe 1 case
  )
  .sort();
```

This works for single-finding probes. It over-attaches for probe 4:
six findings sharing id `04-dcr` and three evidence files starting
`04-dcr-` produce a Cartesian product. Every finding lists every
evidence file. The "CIMD advertised" finding ends up linked to the
HTTP-redirect evidence file.

Per #6 Option B: replace the heuristic with explicit per-finding
evidence references.

## Files touched

Three:

1. `src/types.ts` — add `evidence?: string[]` to `Finding`.
2. `src/report.ts` — replace prefix-match with explicit reference.
3. `src/probes/discovery.ts`, `src/probes/prm.ts`,
   `src/probes/as-metadata.ts`, `src/probes/dcr.ts` — backfill
   `evidence` field on findings that should link to evidence files.

All four files ship in one commit. Partial migration (type +
report.ts but not probe backfills) produces an *under-linking*
regression where every report has zero evidence links.

## Type change

```ts
// src/types.ts
export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  passed: boolean;
  observations: string[];
  evidence?: string[]; // names of evidence files this finding relates to
}
```

Optional. Findings about passive metadata reads, missing-field
detections, or skipped probes omit the field.

## report.ts change

Replace the existing prefix-match block (lines around `relatedEvidence`):

```ts
const relatedEvidence = (finding.evidence ?? [])
  .filter(name => evidenceNames.has(name))
  .sort();
```

The `evidenceNames.has(name)` filter prevents linking to evidence
files that were not actually written (probe failed before evidence
capture, probe author typo).

## Probe backfills

Policy: a finding gets `evidence: [name]` only if the finding
describes a property of an HTTP transaction captured in
`evidence/<name>.http`. Findings derived from already-fetched data
(AS metadata fields), findings about advertisement absence, and
skipped findings get no `evidence` field.

### Probe 1 — `src/probes/discovery.ts`

All three findings describe properties of the same 401 response.

| Finding id | evidence |
|---|---|
| `01-discovery-auth-challenge` | `['01-discovery']` |
| `01-discovery-prm-advertisement` | `['01-discovery']` |
| `01-discovery-error-code-absent` | `['01-discovery']` |

### Probe 2 — `src/probes/prm.ts`

| Finding id | evidence |
|---|---|
| `02-prm` (passing — PRM document fetched and validated) | `['02-prm']` |
| `02-prm` (any skipped or pre-fetch failure variants) | none |

### Probe 3 — `src/probes/as-metadata.ts`

All three primary findings describe properties of the same AS
metadata document.

| Finding id | evidence |
|---|---|
| `03-as-metadata` | `['03-as-metadata']` |
| `03-as-metadata-issuer-validation` | `['03-as-metadata']` |
| `03-as-metadata-pkce-methods` | `['03-as-metadata']` |
| Any `skipped` companion findings (zero-AS early-return etc.) | none |

### Probe 4 — `src/probes/dcr.ts`

| Finding title | evidence |
|---|---|
| CIMD advertised / CIMD not advertised | none |
| DCR not advertised | none |
| DCR endpoint not TLS-protected | none |
| DCR advertised | none |
| DCR valid registration accepted | `['04-dcr-register-valid']` |
| DCR registration response uses HTTP 200 instead of 201 | `['04-dcr-register-valid']` |
| DCR registration returned 200 but response lacks valid client_id | `['04-dcr-register-valid']` |
| DCR valid registration not accepted | `['04-dcr-register-valid']` |
| DCR accepted/rejected HTTP redirect URI for confidential client | `['04-dcr-register-http-redirect']` |
| DCR accepted/rejected host-mismatched redirect URI | `['04-dcr-register-host-mismatch']` |

## Verification

1. `npm run typecheck` passes.
2. `npm run dev -- audit https://api.githubcopilot.com/mcp` and
   inspect generated `report.md`. Expected:
   - Each `01-discovery-*` finding lists exactly one evidence link:
     `evidence/01-discovery.http`.
   - `02-prm` finding lists exactly `evidence/02-prm.http`.
   - Each `03-as-metadata*` finding lists exactly
     `evidence/03-as-metadata.http`.
   - `04-dcr` findings (CIMD not advertised, DCR not advertised on
     GitHub) list no evidence link.
3. Stretch — multi-evidence-file probe 4 case is not exercised by
   the GitHub target (DCR not advertised). Linear's MCP server
   advertises DCR; verifying the probe 4 split there can either
   happen now (no disclosure risk — Linear is already disclosed,
   audit publishes May 4) or defer to the audit 02 fresh-data run
   on Sun May 3.

## Commit message

```
report: replace prefix-match with explicit Finding.evidence (#6)
```

## Disclosure-hygiene

Issue #6 references probe 4 generically (CIMD, DCR, RFC 7591). No
vendor names appear in the issue body, this scope doc, the type
change, or the report.ts change. Probe backfill mappings reference
probe-internal evidence file names only. Safe to push pre-disclosure
of any audited vendor.

## Retroactive close

Per project pattern, leave #6 open until Linear audit publishes
on Mon May 4. The Linear audit is the public artifact that
demonstrates the multi-finding-with-evidence case produces
correctly-scoped evidence links in production output.

## Related

- #2 — the prefix-match fix that got us here
- #3 — sibling cluster of pre-probe-4 conventions
- #11 — recently closed via commit d578949 (probe 4 disclosure
  hygiene)
