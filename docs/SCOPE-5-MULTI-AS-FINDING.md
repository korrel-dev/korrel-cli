# Scope: probe 3 multi-AS as separate finding (#5)

## Problem

When AS metadata's `authorization_servers` array contains more than
one entry, probe 3 currently records the gap as an inline observation
on the existing `03-as-metadata` finding:

```ts
if (servers.length > 1) {
  observations.push(`authorization_servers lists ${servers.length} entries; ...`);
}
```

The audit drafter has no explicit finding to cite. Multi-AS targets
are silently under-audited. No current audit target triggers this
path (GitHub, Linear, Atlassian, Supabase are all single-AS), but
the code path is real and the gap compounds as the audit cohort grows.

## Severity choice

The issue body suggests `severity: 'finding'`, which is not in the
vocabulary (`info | warn | issue | critical | skipped` per
`src/types.ts`).

A multi-AS scope gap fits none of the existing severities cleanly:
- Not `info` (compliant) — the target is fine, but the audit is
  incomplete.
- Not `warn` (spec deviation) — the target has not deviated.
- Not `issue` (MUST violation) — same.
- Not `skipped` (probe could not run) — the probe DID run, just on
  a subset of the listed authorization servers.

**Closest existing precedent:** probe 4's "DCR not advertised" finding,
which is `severity: 'info'`, `passed: false`. The `passed: false`
carries the "known gap" semantics without inventing a new severity.

This scope adopts the same shape:
- `severity: 'info'`
- `passed: false`

The audit drafter can cite the finding by id and describe the gap
in their own words.

## Files touched

One:

- `src/probes/as-metadata.ts` — emit a separate finding when
  `servers.length > 1`. Keep the inline observation OR remove it
  (recommend remove — duplicate signal).

No type changes. No report.ts changes. No backfill across other
probes.

## Finding shape

```ts
{
  id: '03-as-metadata-multi-as',
  title: 'Multi-AS configuration not fully audited',
  severity: 'info',
  passed: false,
  observations: [
    `AS metadata lists ${servers.length} authorization_servers entries. ` +
    `Probe 3 v0 audits only the first (${servers[0]}). ` +
    `Remaining: ${servers.slice(1).join(', ')}. ` +
    `Multi-AS coverage is planned for a future probe revision.`
  ],
  evidence: ['03-as-metadata']
}
```

The `evidence` field uses the policy from `SCOPE-6-FINDING-EVIDENCE.md`:
the finding describes a property of the AS metadata document, which
is captured in `evidence/03-as-metadata.http`.

## Emission rule

Emit only when `servers.length > 1`. Do not emit on single-AS targets.
The finding does not appear in clean reports.

Place the emission alongside the existing primary `03-as-metadata`
finding (not inside the issuer-validation or PKCE-methods sub-finding
blocks). Order within the findings array does not matter for report
output.

## Inline observation handling

The existing inline observation in the primary `03-as-metadata`
finding (`observations.push(\`authorization_servers lists ${servers.length}...\`)`)
becomes redundant after this change. Remove it so the multi-AS
condition is reported in exactly one place.

## Verification

1. `npm run typecheck` passes.
2. `npm run dev -- audit https://api.githubcopilot.com/mcp` — single-AS
   target. Expected: no `03-as-metadata-multi-as` finding in output.
   Expected: existing primary `03-as-metadata` finding does not
   contain the inline multi-AS observation.
3. Stretch — multi-AS verification requires a target that actually
   advertises multiple ASes. None of the audited cohort does. Defer
   to whichever indie SaaS audit (week 5+) first surfaces this case,
   or build a fixture later if the case never naturally appears.

## Commit message

```
probe-3: emit multi-AS scope gap as separate finding (#5)
```

## Disclosure-hygiene

Issue #5 references probe 3 generically and discusses RFC 8414
concepts (`authorization_servers` array). No vendor names appear in
the issue body, this scope doc, or the proposed code change. Safe
to push pre-disclosure of any audited vendor.

## Retroactive close

#5 closes immediately after merge. No audit currently exercises the
multi-AS code path, so there is no published artifact pending. If a
future audit surfaces the multi-AS condition, the finding will appear
in that audit's output as designed; no retroactive demonstration
required.

## Related

- #6 — `Finding.evidence` field used by this scope (shipped via
  commit 2954b92).
- #2 — earlier evidence-linking work this scope builds on.
