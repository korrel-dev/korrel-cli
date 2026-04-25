# ISSUE-21 Scope: AS metadata probe zero-AS early-return omits A4 and A5 as skipped findings

## Background

`asMetadataProbe` emits three findings on the post-fetch path: the outer `03-as-metadata`,
assertion A4 (`03-as-metadata-pkce-methods`, added by issue #19), and assertion A5
(`03-as-metadata-issuer-validation`, added by issue #20). The early-return at lines 44-54
of `src/probes/as-metadata.ts`, triggered when `ctx.authorizationServers` is absent or
empty, returns only the outer finding. A4 and A5 are silently absent on that path. An audit
consumer or downstream test that expects a fixed finding-id set per probe cannot rely on
`asMetadataProbe` always returning three findings, which breaks the invariant established
across all other multi-assertion probes.

The fix is narrow: on the zero-AS path, emit A4 and A5 as `skipped` with a skip-reason
that names the actual cause (no authorization_servers discovered upstream) rather than
reusing the existing body-not-parseable skip text.

The OQ-2 sweep confirmed that no other probe has the same asymmetry. Findings for each
probe are documented in the Sweep section below.

## In scope

- Add A4 (`03-as-metadata-pkce-methods`) as a `skipped` finding on the zero-AS early-return
  path in `asMetadataProbe`.
- Add A5 (`03-as-metadata-issuer-validation`) as a `skipped` finding on the zero-AS
  early-return path in `asMetadataProbe`.
- Use a distinct skip-reason string for the zero-AS case on both A4 and A5. The existing
  `'Skipped: AS metadata body not available or not parseable.'` text is preserved exactly for
  the not-parseable path and is not reused for the zero-AS case.
- The zero-AS skip-reason text for both A4 and A5 is:
  `'Skipped: probe 2 did not discover any authorization_servers.'`
- `asMetadataProbe` returns exactly three findings on every execution path after this fix:
  `[outerFinding, a5Finding, a4Finding]`.

## Out of scope

- Changes to `src/types.ts`, `src/report.ts`, or `docs/SEVERITY.md`.
- Changes to `mcp-audits/` or any audit archive.
- Adding new assertions to any probe. This fix makes existing emissions consistent; it does
  not add new assertions.
- Changes to the outer `03-as-metadata` finding on the zero-AS path. Its text, severity, and
  `passed` value are correct today and are not modified.
- Changes to comparison or validation logic inside any probe.
- Refactoring the helper extraction pattern (e.g., moving `buildPkceMethodsFinding` or
  `buildIssuerValidationFinding` to a shared module).
- Multi-AS coverage (probe 3 v0 limitation, noted in issue #20 scope).
- Changes to probe 2, probe 1, or probe 4. The sweep below documents why none of them require
  changes.
- Changes to the not-parseable skip text (`'Skipped: AS metadata body not available or not
  parseable.'`) used in `buildPkceMethodsFinding` and `buildIssuerValidationFinding` on the
  post-fetch unparseable path. That text remains correct for its context.

## OQ-2 Sweep: early-return asymmetry analysis across all four probes

### Probe 1: `src/probes/discovery.ts`

**Conclusion: no fix needed.**

`discoveryProbe` has no early return. It always makes the HTTP request and always proceeds
to construct A1, A2, and A3. A2 and A3 are skipped when A1 fails, but that skip is emitted
as a `skipped` finding (not silently omitted). The probe always returns exactly three findings.
This is the correct pattern; no asymmetry bug exists.

### Probe 2: `src/probes/prm.ts`

**Conclusion: no fix needed.**

`prmProbe` has no zero-precondition early return. Whether `ctx.protectedResourceMetadataUrl`
is set or not, the probe always proceeds: the direct-URL path calls `fetchAndValidate`, the
no-URL path calls `runFallback`. Both paths emit at least one finding with id `02-prm`. The
fallback-success path emits two findings (the validation finding and the well-known fallback
info finding), but both share the same id `02-prm`. There is no split into distinct assertion
ids (`02-prm-something`) that would create an asymmetric-emission bug. Probe 2 is a
single-outer-finding probe with a variable observation count depending on path. The variable
emission count is design, not asymmetry.

### Probe 3: `src/probes/as-metadata.ts`

**Conclusion: fix required. This is the subject of issue #21.**

The zero-AS early-return at lines 44-54 emits one finding (`03-as-metadata`). The post-fetch
path emits three findings (`03-as-metadata`, `03-as-metadata-issuer-validation`,
`03-as-metadata-pkce-methods`). A4 and A5 are silently absent on the zero-AS path. Both
must be emitted as `skipped` with the skip-reason specified in the In scope section.

### Probe 4: `src/probes/dcr.ts`

**Conclusion: no fix needed.**

The `!as` early-return at lines 56-69 emits one finding (`04-dcr`, titled 'DCR/CIMD probe
skipped: AS metadata not available'). The post-fetch path emits a variable number of findings,
but all share the same id `04-dcr`. Probe 4 has no split into distinct assertion ids
(`04-dcr-something`) that would be expected on both the skip and the non-skip paths. The
single-finding early return is appropriate for probe 4's current structure. This is not the
same bug class.

## Normative assertions being tested

| Level | Clause | Probe observation |
|-------|--------|-------------------|
| N/A (structural) | Audit tool invariant: probes emit a fixed, predictable set of finding ids on every path | `asMetadataProbe` returns the same three finding ids regardless of whether zero-AS or post-fetch path executes |

This fix is structural, not a new spec assertion. No additional RFC or MCP spec clause is
tested by emitting `skipped` findings; the skipped findings are an absence-of-coverage signal
per `docs/SEVERITY.md` ("I couldn't check"), not a spec evaluation.

## Control flow

```
asMetadataProbe(ctx):

  servers = ctx.authorizationServers

  --- Zero-AS early return ---

  If NOT servers OR servers.length === 0:
    outerFinding = {
      id:           '03-as-metadata',
      title:        'Authorization Server metadata (RFC 8414)',
      severity:     'skipped',
      passed:       false,
      observations: ['Probe 2 did not discover any authorization_servers; AS metadata fetch skipped.']
    }
    // NEW: A5 skipped finding
    a5Finding = {
      id:           '03-as-metadata-issuer-validation',
      title:        'AS metadata issuer validation (RFC 8414 §3.3)',
      severity:     'skipped',
      passed:       false,
      observations: ['Skipped: probe 2 did not discover any authorization_servers.']
    }
    // NEW: A4 skipped finding
    a4Finding = {
      id:           '03-as-metadata-pkce-methods',
      title:        'PKCE code_challenge_methods_supported advertisement (RFC 7636 §4.2)',
      severity:     'skipped',
      passed:       false,
      observations: ['Skipped: probe 2 did not discover any authorization_servers.']
    }
    return { findings: [outerFinding, a5Finding, a4Finding], evidence: [] }

  --- Post-fetch path (lines 57 onward) ---
  // Unchanged. buildIssuerValidationFinding and buildPkceMethodsFinding are called with
  // metadataParsed as before; their not-parseable skip text is unchanged.
```

Note: the finding order `[outerFinding, a5Finding, a4Finding]` matches the existing
post-fetch return order established in issue #20 (`findings: [finding, a5Finding, a4Finding]`
at line 183 of the current code).

## Finding shapes

### `03-as-metadata-issuer-validation` (A5) -- zero-AS path only

**Skipped (severity: `skipped`)**
- title: `"AS metadata issuer validation (RFC 8414 §3.3)"`
- observations: `["Skipped: probe 2 did not discover any authorization_servers."]`

The pass and issue shapes for A5 are unchanged from issue #20. This fix adds only the
zero-AS skipped shape.

### `03-as-metadata-pkce-methods` (A4) -- zero-AS path only

**Skipped (severity: `skipped`)**
- title: `"PKCE code_challenge_methods_supported advertisement (RFC 7636 §4.2)"`
- observations: `["Skipped: probe 2 did not discover any authorization_servers."]`

The pass, warn, issue, and info-absent shapes for A4 are unchanged from issue #19. This fix
adds only the zero-AS skipped shape.

### Distinction between zero-AS skip text and not-parseable skip text

| Context | Observation text |
|---------|-----------------|
| Zero-AS path (this fix) | `'Skipped: probe 2 did not discover any authorization_servers.'` |
| Post-fetch: HTTP non-200 or schema failure | `'Skipped: AS metadata body not available or not parseable.'` |

These are distinct. The zero-AS text names the upstream cause (no authorization_servers).
The not-parseable text names the fetch/parse failure. They must not be conflated.

## Evidence files

`evidence/03-as-metadata.http` -- this file is written only on the post-fetch path. The
zero-AS early-return continues to return `evidence: []`. No evidence file is created on the
zero-AS path. No new evidence files are introduced by this fix.

## Verification

### Target 1: Linear (`https://mcp.linear.app/mcp`)

Linear's probe 2 succeeds and populates `authorizationServers`. Probe 3 takes the post-fetch
path. Expected behavior after fix: unchanged from the current post-implementation state of
issues #19 and #20. All three findings are emitted with their existing severities. The fix
has no observable effect on Linear.

### Target 2: Supabase (`https://mcp.supabase.com/mcp`)

Same as Linear. Probe 2 succeeds. Post-fetch path. No observable effect from this fix.

### Target 3: Atlassian (`https://mcp.atlassian.com/v1/sse`)

Atlassian has no `authorization_servers` discovered by probe 2. Probe 3 takes the zero-AS
early-return path. Expected behavior after fix:

- `03-as-metadata`: `skipped` (unchanged).
- `03-as-metadata-issuer-validation`: `skipped` (NEW; previously absent).
- `03-as-metadata-pkce-methods`: `skipped` (NEW; previously absent).

The user accepts that the zero-AS path is not exercised by Linear or Supabase smoke runs and
that Atlassian is the reference target for confirming this fix. The smoke runs on Linear and
Supabase confirm no regression on the post-fetch path.

## Acceptance criteria

- [ ] `asMetadataProbe` returns exactly three findings on every execution path: `03-as-metadata`,
      `03-as-metadata-issuer-validation`, `03-as-metadata-pkce-methods`. No path returns fewer
      or more than three.
- [ ] On the zero-AS path (`!servers || servers.length === 0`): `03-as-metadata` has
      `severity: 'skipped'` and `passed: false` (unchanged).
- [ ] On the zero-AS path: `03-as-metadata-issuer-validation` has `severity: 'skipped'` and
      `passed: false`.
- [ ] On the zero-AS path: `03-as-metadata-pkce-methods` has `severity: 'skipped'` and
      `passed: false`.
- [ ] On the zero-AS path: the observation text for both A4 and A5 is exactly
      `'Skipped: probe 2 did not discover any authorization_servers.'`.
- [ ] On the zero-AS path: the observation text does NOT contain the string
      `'not available or not parseable'`.
- [ ] On the not-parseable post-fetch path (`metadataParsed === false`): A4 and A5 observation
      text remains `'Skipped: AS metadata body not available or not parseable.'` (unchanged).
- [ ] On the zero-AS path: `evidence` array is `[]` (unchanged).
- [ ] Finding order on the zero-AS path is `[outerFinding, a5Finding, a4Finding]`, matching
      the post-fetch return order.
- [ ] No `contextUpdates` are returned on the zero-AS path (unchanged).
- [ ] The post-fetch path behavior is unchanged: `buildIssuerValidationFinding` and
      `buildPkceMethodsFinding` are called with the same arguments as before, emitting the same
      finding shapes as established by issues #19 and #20.
- [ ] Linear post-implementation smoke run: all three probe 3 findings emit non-`skipped`
      severities (same as pre-fix). No regression.
- [ ] Supabase post-implementation smoke run: same as Linear.
- [ ] Atlassian post-implementation run (if accessible): `03-as-metadata-issuer-validation`
      and `03-as-metadata-pkce-methods` both appear as `skipped` findings.
- [ ] `npm run typecheck` passes with zero errors after the change.

## Open questions

None blocking. All three open questions from the issue brief are resolved:

1. **OQ-1 (Emit A4 and A5 as skipped on zero-AS path):** Yes, both are emitted. Skip-reason
   text: `'Skipped: probe 2 did not discover any authorization_servers.'` This is distinct
   from the not-parseable text and matches the tone of the existing outer finding observation
   at line 50 of the current code.

2. **OQ-2 (Sweep other early-return paths):** Completed above. Probe 1 has no early return.
   Probe 2 has no early return and no split assertion ids. Probe 4 has an early return but no
   split assertion ids; the single-finding skip is appropriate. Only probe 3 requires a fix.

3. **OQ-3 (Skip-reason text per probe per assertion):** Only probe 3 requires new skip text.
   The zero-AS skip text is `'Skipped: probe 2 did not discover any authorization_servers.'`
   for both A4 and A5. The not-parseable text for both helpers is unchanged. No other probe
   requires new skip text.
