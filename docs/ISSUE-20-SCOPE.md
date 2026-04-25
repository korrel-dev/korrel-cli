# ISSUE-20 Scope: AS metadata probe -- issuer mismatch must flip passed and suppress contextUpdates (RFC 8414 §3.3)

## OQ resolutions (pre-amble)

### OQ-1: Severity

**Decision: `issue`.**

RFC 8414 §3.3 contains a MUST pair: the returned `issuer` value MUST be identical to the issuer identifier used to construct the well-known URL, and if they are not identical the data MUST NOT be used. Per `docs/SEVERITY.md`, `issue` applies to "a MUST-level spec violation or a concrete gap with real threat-model implications." This is both. Severity is `issue`.

### OQ-2: Failure-path structure

**Decision: option (c) hybrid -- flip `passed` in the outer finding AND add a new dedicated assertion `03-as-metadata-issuer-validation` at `issue` severity.**

Rationale for rejecting (a): The outer `03-as-metadata` finding has a severity ladder of `passed ? 'info' : 'warn'`. `docs/SEVERITY.md` defines `warn` as SHOULD-level deviations. An issuer mismatch is MUST-level. Leaving the outer at `warn` after flipping `passed` would misrepresent severity to an audit reader who reads only the outer finding. Changing the outer severity ladder to include `issue` would make the outer finding carry mixed responsibilities (was the metadata reachable/parseable? did the issuer match?) in a way that is hard to interpret in a report.

Rationale for rejecting (b): The outer `passed` flag gates whether `contextUpdates` is published. RFC 8414 §3.3 MUST NOT requires that on mismatch, downstream endpoints MUST NOT be used. Suppressing `contextUpdates` requires `passed = false` in the outer control flow path. A standalone new assertion that does not touch the outer finding cannot satisfy this requirement without additional control-flow changes.

Rationale for (c): Flip `passed = false` in the outer finding when issuer mismatch is detected. The outer finding stays at `warn` (its maximum non-passing severity per the current ladder) and becomes a delegation note: it records that metadata was reachable and parseable but that the issuer check failed, with a pointer to `03-as-metadata-issuer-validation`. The new dedicated finding at `issue` severity carries the MUST-level violation. `contextUpdates` is suppressed (not populated) when `passed = false`. This follows the exact structural pattern of issues #18 and #19: a separate finding carries a distinct assertion, the outer probe finding is unchanged in shape but updated in behavior.

Report readability: an audit reader sees `03-as-metadata: warn` (metadata fetch partially failed) and `03-as-metadata-issuer-validation: issue` (MUST violation). The `issue` finding drives disclosure. This is clearer than a single `issue`-severity outer finding that conflates fetch success with issuer validation.

### OQ-3: Sweep of other observation paths

**Pre-resolved by user: sweep any other observation paths that exhibit the same bug class -- observation appended for a spec deviation but `passed` not flipped.**

Analysis of each candidate:

**Candidate 1 (line 118-120): issuer mismatch.** This is the primary subject of issue #20. Qualifies. Addressed by this scope.

**Candidate 2 (line 131-132): `grant_types_supported` does not include `authorization_code`.** RFC 8414 §2 defines `grant_types_supported` as OPTIONAL and states that when absent the default value is `["authorization_code", "implicit"]`. No RFC 8414, RFC 6749, or OAuth 2.1 draft-15 clause requires an AS to advertise `authorization_code` when the field is present. The observation flags a potentially unusual configuration but cites no MUST. Does not qualify for the sweep: there is no spec deviation that should flip `passed`.

**Candidate 3 (lines 134-136): OAuth 2.1-deprecated grants (`password`, `implicit`).** OAuth 2.1 draft-15 removes these grant types from the core spec. However, OAuth 2.1 draft-15 does not contain a server-directed MUST NOT against advertising deprecated grants in AS metadata. The deprecation means OAuth 2.1 implementations should not use these flows, not that AS metadata advertising them is itself a MUST violation. This is at most a SHOULD-level concern. Does not qualify: no MUST violated by the advertisement itself, and the current observation is informational without flipping `passed`. No change needed.

**Net sweep result:** Only the issuer mismatch (candidate 1) qualifies. The other two candidates do not exhibit a genuine MUST-level deviation that should flip `passed`.

---

## Background

The `03-as-metadata` probe fetches Authorization Server metadata per RFC 8414. When the parsed `issuer` field does not match the issuer identifier used to construct the well-known URL, the probe appends an observation but leaves `passed = true`. RFC 8414 §3.3 requires the values to be identical (MUST) and states that if they are not, the data MUST NOT be used. With `passed = true`, the probe also publishes `contextUpdates` containing `authorizationEndpoint`, `tokenEndpoint`, and potentially `registrationEndpoint` from an unverified AS. Downstream probes (PKCE enforcement, token hygiene, DCR/CIMD) would then operate against endpoints that RFC 8414 §3.3 prohibits using.

## In scope

- Flip `passed = false` in the outer `03-as-metadata` finding when `as.issuer !== issuer`.
- Suppress `contextUpdates`: do not populate or return `contextUpdates` when issuer mismatch is detected.
- Add one new finding, id `03-as-metadata-issuer-validation`, emitted by `asMetadataProbe`.
- The new finding evaluates issuer equality per RFC 8414 §3.3 and emits `issue` on mismatch, `info` on match.
- The new finding is `skipped` when the AS metadata body was not successfully fetched and parsed (HTTP status non-200, or `validateAsMetadata` returned `ok: false`).
- The outer `03-as-metadata` finding, when issuer mismatch occurs, gains one delegation observation pointing to `03-as-metadata-issuer-validation`. The existing mismatch observation text at line 119 is retained as additional context.
- The outer `03-as-metadata` finding severity ladder remains `passed ? 'info' : 'warn'`. The ladder does not change.
- The `metadataParsed` flag and `buildPkceMethodsFinding` (A4) are unchanged. A4 remains `skipped` when `metadataParsed` is false. A4 is still emitted when `metadataParsed` is true, including on issuer mismatch (the PKCE advertisement is an independent assertion about what the AS claims; it is recorded even if the AS is unverified, and audit readers can interpret it in context of the `issue` finding).
- No changes to the comparison logic at line 118. JS `!==` on strings satisfies RFC 8414 §4 Unicode code-point equality. No normalization.

## Out of scope

- Comparison-logic changes. RFC 8414 §4 code-point equality is already satisfied by JS `!==`.
- Changes to `src/types.ts`, `src/report.ts`, or `docs/SEVERITY.md`.
- Changes to any probe other than `as-metadata.ts`.
- Changes to `mcp-audits/` or any audit archive file.
- Multi-AS coverage (probe v0 limitation, line 56-58 in `as-metadata.ts`).
- Changing what grant-type observations the probe appends (lines 128-138). These are informational and do not require a `passed` flip per the sweep analysis above.
- Changing A4 (`03-as-metadata-pkce-methods`) behavior. A4 was settled by issue #19 and is not affected.
- Tightening schema validation behavior (lines 109-111). `passed` is already `false` in that branch.
- Adding a trailing-slash normalisation advisory. The spec does not permit normalisation; strict equality is correct. No change needed.

## Normative assertions being tested

| Level | Clause | Probe observation |
|-------|--------|-------------------|
| MUST | RFC 8414 §3.3: "The `issuer` value returned MUST be identical to the authorization server's issuer identifier value into which the well-known URI string was inserted to create the URL used to retrieve the metadata." | `03-as-metadata-issuer-validation`: `as.issuer === issuer` |
| MUST NOT | RFC 8414 §3.3: "If these values are not identical, the data contained in the response MUST NOT be used." | `contextUpdates` suppressed on mismatch; downstream probes do not receive unverified endpoints |
| Code-point equality | RFC 8414 §4: issuer comparison is Unicode code-point equality, no normalization | JS `!==` on strings satisfies this; no change needed |

## Control flow

```
Steps 1-N (fetch, evidence capture, validateAsMetadata) unchanged.

--- Outer finding and issuer check ---

If response.status !== 200:
  outerPassed = false
  // existing branch, unchanged

Else if validateAsMetadata returned ok: false:
  outerPassed = false
  // existing branch, unchanged

Else:
  as = validation.data
  observations.push("issuer: {as.issuer}")
  observations.push("authorization_endpoint: {as.authorization_endpoint}")
  observations.push("token_endpoint: {as.token_endpoint}")

  issuerMismatch = (as.issuer !== issuer)

  If issuerMismatch:
    observations.push(
      'issuer "{as.issuer}" does not match the advertised AS URL "{issuer}" (RFC 8414 §3.3).'
    )
    observations.push(
      'AS metadata data MUST NOT be used per RFC 8414 §3.3; contextUpdates suppressed. See 03-as-metadata-issuer-validation finding.'
    )
    outerPassed = false
    metadataParsed = true   // body was parsed; A4 still evaluates PKCE advertisement
    // Do NOT populate contextUpdates

  Else:
    // existing logic: populate contextUpdates, outerPassed = true, metadataParsed = true
    contextUpdates = { authorizationServerMetadata, authorizationEndpoint, tokenEndpoint }
    if as.registration_endpoint: contextUpdates.registrationEndpoint = ...
    outerPassed = true
    metadataParsed = true

--- pkce / grant observations ---
// unchanged from current code

--- Outer finding construction ---

outerFinding = {
  id:           '03-as-metadata',
  title:        'Authorization Server metadata (RFC 8414)',
  severity:     outerPassed ? 'info' : 'warn',
  passed:       outerPassed,
  observations
}

--- Assertion 5: issuer validation ---

If NOT metadataParsed:
  a5Finding = {
    id:           '03-as-metadata-issuer-validation',
    title:        'AS metadata issuer validation (RFC 8414 §3.3)',
    severity:     'skipped',
    passed:       false,
    observations: ['Skipped: AS metadata body not available or not parseable.']
  }

Else if issuerMismatch:
  a5Finding = {
    id:           '03-as-metadata-issuer-validation',
    title:        'AS metadata issuer validation (RFC 8414 §3.3)',
    severity:     'issue',
    passed:       false,
    observations: [
      'Returned issuer: "{as.issuer}"',
      'Expected issuer (from well-known URL construction): "{issuer}"',
      'RFC 8414 §3.3 MUST: the issuer value in the metadata response MUST be identical to the issuer identifier value used to construct the well-known URI.',
      'RFC 8414 §3.3 MUST NOT: the data contained in this response MUST NOT be used. contextUpdates suppressed; downstream probes will not receive authorization_endpoint, token_endpoint, or registration_endpoint from this response.'
    ]
  }

Else:
  a5Finding = {
    id:           '03-as-metadata-issuer-validation',
    title:        'AS metadata issuer validation (RFC 8414 §3.3)',
    severity:     'info',
    passed:       true,
    observations: [
      'Returned issuer "{as.issuer}" matches the expected issuer identifier. RFC 8414 §3.3 MUST satisfied.'
    ]
  }

--- Build ProbeResult ---

findings: [outerFinding, a5Finding, a4Finding]
evidence: unchanged (single entry, name '03-as-metadata')
contextUpdates: present only when outerPassed is true (i.e., no issuer mismatch and schema valid)
```

Note on `a5Finding` ordering: `a5Finding` is emitted after `outerFinding` and before `a4Finding`. The order matches the logical dependency: outer establishes fetch/parse success, a5 validates issuer, a4 evaluates PKCE methods. Probe-engineer may reorder within the array if an established convention differs; the finding ids and severities are what matter.

Note on A4 when issuer mismatch: `metadataParsed` is `true` after a mismatch (the body was validly parsed; only the issuer field failed). A4 therefore emits a substantive finding (info, warn, or issue based on PKCE methods). This records what the AS advertised, even though the data is not trusted. Audit readers can see both the `issue` from A5 and the PKCE advertisement state. If this behavior is undesirable, the probe-engineer should surface it to the main thread before implementation; it is a judgment call not pre-decided here.

## Finding shapes

### `03-as-metadata-issuer-validation` (A5)

**Pass (severity: `info`)**
- title: `"AS metadata issuer validation (RFC 8414 §3.3)"`
- observations:
  1. `"Returned issuer \"{as.issuer}\" matches the expected issuer identifier. RFC 8414 §3.3 MUST satisfied."`

**Fail (severity: `issue`)**
- title: `"AS metadata issuer validation (RFC 8414 §3.3)"`
- observations:
  1. `"Returned issuer: \"{as.issuer}\""`
  2. `"Expected issuer (from well-known URL construction): \"{issuer}\""`
  3. `"RFC 8414 §3.3 MUST: the issuer value in the metadata response MUST be identical to the issuer identifier value used to construct the well-known URI."`
  4. `"RFC 8414 §3.3 MUST NOT: the data contained in this response MUST NOT be used. contextUpdates suppressed; downstream probes will not receive authorization_endpoint, token_endpoint, or registration_endpoint from this response."`

**Skipped (severity: `skipped`)**
- title: `"AS metadata issuer validation (RFC 8414 §3.3)"`
- observations:
  1. `"Skipped: AS metadata body not available or not parseable."`

### Change to `03-as-metadata` finding when issuer mismatch

Two observations are added to the outer finding's `observations` array (after the existing issuer-value line) when `as.issuer !== issuer`:

1. `"issuer \"{as.issuer}\" does not match the advertised AS URL \"{issuer}\" (RFC 8414 §3.3)."` (this text already exists at line 119; retain it)
2. `"AS metadata data MUST NOT be used per RFC 8414 §3.3; contextUpdates suppressed. See 03-as-metadata-issuer-validation finding."`

The outer finding `passed` flips to `false`. Severity becomes `'warn'` (the non-passing value in `passed ? 'info' : 'warn'`). The severity ladder code itself does not change.

## Evidence files

`evidence/03-as-metadata.http` -- unchanged. Single file per run. A5 attaches to this file via the prefix-match rule: `03-as-metadata` is a prefix of `03-as-metadata-issuer-validation`.

No new evidence files are created.

## Verification

### Target 1: Linear (`https://mcp.linear.app/mcp`)

Linear's AS metadata currently passes probe 03 (`passed: true`). The issuer value in the response should match `https://mcp.linear.app`. Expected behavior after fix:

- `03-as-metadata`: `info` / passed. Behavior unchanged.
- `03-as-metadata-issuer-validation`: `info` / passed. Observation: issuer matches, RFC 8414 §3.3 satisfied.
- `03-as-metadata-pkce-methods`: unchanged from current behavior (A4 not affected).
- `contextUpdates`: unchanged, still published.

If Linear's issuer does NOT match after the fix, that is a real spec deviation. Raise it as a separate issue; do not suppress it.

### Target 2: Supabase (`https://mcp.supabase.com/mcp`)

Supabase's issuer is `https://api.supabase.com`. The well-known URL is constructed from the issuer discovered in PRM (probe 2). The two must match. Expected behavior after fix:

- `03-as-metadata`: `info` / passed (if issuer matches) or `warn` / failed (if mismatch detected).
- `03-as-metadata-issuer-validation`: `info` / passed (match) or `issue` / failed (mismatch).
- `contextUpdates`: published only on match.

Confirm the actual issuer value in the fetched metadata matches the expected issuer. If it does not, raise separately; do not assume it is a pre-existing acceptable state.

### Target 3: Atlassian (`https://mcp.atlassian.com/v1/sse`)

Atlassian has no `authorization_servers` discovered by probe 2. Probe 03 currently emits `skipped`. After fix:

- `03-as-metadata`: `skipped` (unchanged).
- `03-as-metadata-issuer-validation`: `skipped`.
- `03-as-metadata-pkce-methods`: `skipped`.

No change in behavior for Atlassian.

## Acceptance criteria

- [ ] When `as.issuer !== issuer` and the body is successfully parsed: `03-as-metadata` finding has `passed: false` and `severity: 'warn'`.
- [ ] When `as.issuer !== issuer` and the body is successfully parsed: `contextUpdates` is not present in the `ProbeResult` (or is `undefined`).
- [ ] When `as.issuer !== issuer` and the body is successfully parsed: `03-as-metadata-issuer-validation` has `severity: 'issue'` and `passed: false`.
- [ ] When `as.issuer === issuer` and the body is successfully parsed: `03-as-metadata` finding behavior is unchanged from pre-fix (passes, severity `info`).
- [ ] When `as.issuer === issuer` and the body is successfully parsed: `03-as-metadata-issuer-validation` has `severity: 'info'` and `passed: true`.
- [ ] When `as.issuer === issuer` and the body is successfully parsed: `contextUpdates` is populated with `authorizationEndpoint`, `tokenEndpoint`, and optionally `registrationEndpoint` (unchanged from pre-fix).
- [ ] When the AS metadata body is not parseable (non-200 or schema failure): `03-as-metadata-issuer-validation` has `severity: 'skipped'` and `passed: false`.
- [ ] `asMetadataProbe` returns exactly three findings on every run: `03-as-metadata`, `03-as-metadata-issuer-validation`, `03-as-metadata-pkce-methods`.
- [ ] `03-as-metadata-issuer-validation` severity is in `{'info', 'issue', 'skipped'}` for all runs. No other value is ever assigned.
- [ ] The outer `03-as-metadata` finding severity ladder code `passed ? 'info' : 'warn'` is unchanged.
- [ ] `03-as-metadata-issuer-validation` issue observation text contains the string `"RFC 8414 §3.3"` and the word `"MUST"`.
- [ ] `03-as-metadata-issuer-validation` issue observation text contains the string `"contextUpdates suppressed"`.
- [ ] `03-as-metadata-issuer-validation` issue observation includes both the returned issuer value and the expected issuer value as separate observation lines.
- [ ] The comparison uses JS `!==` on string values. No normalization (trailing slash, case folding, percent-encoding normalization) is applied.
- [ ] A4 (`03-as-metadata-pkce-methods`) behavior is unchanged from issue #19 implementation: it still evaluates PKCE methods when `metadataParsed` is true, including when issuer mismatch is detected.
- [ ] Grant-type observations (lines 128-138 in current code) are unchanged.
- [ ] Evidence array contains exactly one entry with name `'03-as-metadata'` per run.
- [ ] `npm run typecheck` passes with zero errors after the change.
- [ ] Linear post-implementation run: `03-as-metadata` and `03-as-metadata-issuer-validation` both pass with `info`/`passed: true`. `contextUpdates` is populated.
- [ ] Supabase post-implementation run: confirm issuer match or raise separately if mismatch detected.

## Open questions

None blocking. All three open questions from the issue brief are resolved above:

1. **OQ-1 (Severity):** `issue`. RFC 8414 §3.3 MUST + MUST NOT pair. `docs/SEVERITY.md` confirms MUST-level maps to `issue`. Resolved.
2. **OQ-2 (Structure):** Option (c) hybrid. Outer `passed` flips to `false` suppressing `contextUpdates`. New dedicated assertion `03-as-metadata-issuer-validation` carries the `issue`-severity finding. Outer severity ladder unchanged. Rationale documented in OQ-2 resolution block above.
3. **OQ-3 (Sweep):** Only issuer mismatch (candidate 1) qualifies. `authorization_code` absence (candidate 2) has no MUST basis. Deprecated grants (candidate 3) are SHOULD-level at most and do not require a `passed` flip. Sweep yields no additional fixes.
