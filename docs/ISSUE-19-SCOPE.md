# Issue #19 Scope: AS metadata probe -- flag PKCE plain advertisement

## OQ resolutions (pre-amble)

### OQ-1: Severity

**Decision: three-outcome model with the following severity assignments.**

- `plain` present, `S256` also present: `warn`.
- `plain` present, `S256` absent (plain-only): `issue`.
- `code_challenge_methods_supported` absent: `info`.

Rationale for `warn` (plain + S256): No RFC 7636, RFC 8414, or OAuth 2.1 draft-15 clause
constitutes a server-directed MUST NOT against advertising `plain`. However, `docs/SEVERITY.md`
defines `warn` as "a SHOULD-level spec deviation, a minor gap, or a non-breaking oddity worth
flagging." RFC 7636 §4.2's rationale for the client MUST is precisely that S256 is MTI on the
server side and `plain` is not recommended where S256 is available. Advertising `plain`
alongside S256 weakens the protection surface for clients that do not correctly implement the
RFC 7636 §4.2 client-side MUST. That is a non-breaking oddity with a non-zero threat-model
implication, which fits `warn` by `docs/SEVERITY.md`'s definition. The finding observation
will state the spec basis honestly.

Rationale for `issue` (plain-only): A plain-only server forecloses the S256 MTI baseline.
RFC 7636 §4.2 states that S256 is "Mandatory To Implement (MTI) on the server." Even though
the sentence is framed in client-directed language, the MTI designation cannot be satisfied
for any client if the server does not advertise S256 at all. This is a concrete gap with
real threat-model implication. Per `docs/SEVERITY.md`, `issue` applies to "a MUST-level spec
violation or a concrete gap with real threat-model implications." Plain-only meets the second
criterion: it eliminates the MTI baseline for all connecting clients. Severity is `issue`.

Rationale for `info` (field absent): RFC 8414 §2 states that `code_challenge_methods_supported`
is OPTIONAL and that if omitted the authorization server does not support PKCE. Absence is a
factual observation, not a deviation; probe 05 (PKCE enforcement) is the right place to test
whether PKCE is actually required. Here it is an informational note. Severity is `info`.

The existing inline observation in the single probe-03 finding ("code_challenge_methods_supported
not advertised; PKCE support is unknown") is moved into the new A4 finding so it lives in
a dedicated assertion. No existing passing condition changes.

### OQ-2: Extend probe 03 vs new assertion

**Decision: add A4 as a new finding within `asMetadataProbe`, following the exact pattern
established by issue #8 (A1/A2 split in discovery.ts) and issue #18 (A3 addition in discovery.ts).**

The existing probe 03 already conflates multiple spec assertions inside one `Finding`. The
`plain` advertisement check is an independently evaluable assertion about a specific field
within the AS metadata body. It does not affect the pass/fail logic of the existing
`03-as-metadata` finding. A new finding id `03-as-metadata-pkce-methods` expresses it
cleanly and follows the established naming convention (`{probe-id}-{assertion-slug}`).

A4 is emitted only when the AS metadata fetch succeeded and the body parsed. It is `skipped`
when the outer probe could not parse a valid AS metadata body.

The existing `03-as-metadata` finding is preserved unchanged in its pass/fail logic.

### OQ-3: Finding text wording

**Decision: observation text describes only what was observed and what the spec says. No
prescriptive "the server should remove plain" language.**

Pass text cites RFC 7636 §4.2 MTI status satisfied. Warn text cites RFC 7636 §4.2 and OAuth
2.1 draft-15 §4.1.1 as the basis for the concern, states no explicit server-side MUST NOT
exists, and describes the configuration as weakening the protection surface. Issue (plain-only)
text cites RFC 7636 §4.2 MTI and states that S256 cannot be used by clients when the server
does not advertise it. Exact text in Finding shapes section below.

---

## Background

The `03-as-metadata` probe fetches and validates Authorization Server metadata per RFC 8414.
It currently checks whether `code_challenge_methods_supported` includes S256 but does not
emit a distinct finding when `plain` appears in that array. Advertising `plain` alongside S256
is not a MUST-level violation under RFC 7636, RFC 8414, or OAuth 2.1 draft-15, but it weakens
the PKCE protection surface for clients that do not faithfully implement the RFC 7636 §4.2
client-side MUST. A plain-only advertisement is the genuinely problematic case: it prevents
clients from using the S256 MTI baseline at all. Issue #19 adds a dedicated assertion (A4)
covering both sub-cases with distinct severities.

## In scope

- Add one new finding, id `03-as-metadata-pkce-methods`, to `asMetadataProbe`.
- A4 evaluates `code_challenge_methods_supported` and emits one of four outcomes: pass
  (S256 present, plain absent), warn (S256 present, plain also present), issue (plain present,
  S256 absent), info (field absent entirely).
- Remove the existing inline observations about `code_challenge_methods_supported` from the
  `03-as-metadata` finding and replace them with a delegation note ("see `03-as-metadata-pkce-methods`").
- A4 is skipped when the AS metadata fetch did not return a parseable body (i.e., the outer
  probe's `validateAsMetadata` returned `ok: false`).
- The existing `03-as-metadata` finding pass/fail logic is unchanged.
- The existing `contextUpdates` population logic is unchanged.
- Evidence file naming is unchanged.

## Out of scope

- Changes to probe 05 (PKCE enforcement) or any other probe.
- Changes to `src/types.ts`, `src/report.ts`, or `docs/SEVERITY.md`.
- Changes to `mcp-audits/` or any audit output file.
- Checking whether the server actually enforces PKCE at the authorization endpoint (that is
  probe 05's responsibility).
- Checking `code_challenge_methods_supported` values other than `plain` and `S256` (unknown
  values are a separate concern, not addressed here).
- Checking whether `plain` is documented in a server's security policy or terms of service.
- Emitting a finding when `code_challenge_methods_supported` is present but empty. That edge
  case is outside the issue brief and deferred.
- Reporting on whether `plain` is used in live authorization requests. Static metadata
  observation only.

## Normative assertions being tested

| Level | Clause | Probe observation |
|-------|--------|-------------------|
| MTI (server) | RFC 7636 §4.2: "S256 is Mandatory To Implement (MTI) on the server" (expressed as client-MUST rationale) | A4: `S256` present in `code_challenge_methods_supported` |
| Client-MUST rationale | RFC 7636 §4.2: "If the client is capable of using 'S256', it MUST use 'S256'" | A4: advertised method set does not include `plain` alongside S256 |
| No server-directed MUST NOT | RFC 7636, RFC 8414 §2, OAuth 2.1 draft-15 §4.1.1: no clause prohibits advertising `plain` | A4 warn observation states explicitly that no server-side MUST NOT exists |
| OAuth 2.1 discovery path | OAuth 2.1 draft-15 §4.1.1: "or via Authorization Server Metadata [RFC8414]" -- advertising `plain` is the intended AS-metadata discovery path for constrained clients | A4 warn observation notes this context |
| OPTIONAL field | RFC 8414 §2: `code_challenge_methods_supported` is OPTIONAL; omission means PKCE not supported | A4 info outcome when field is absent |

Note on `issue` severity for plain-only: RFC 7636 §4.2 makes S256 MTI on the server. A
plain-only advertisement means S256 is unavailable for all connecting clients, foreclosing
the MTI baseline. This is treated as a concrete threat-model gap per `docs/SEVERITY.md`
issue definition ("concrete gap with real threat-model implications"), even though no single
sentence says "server MUST NOT advertise only plain."

## Control flow

```
Steps 1-N of asMetadataProbe (fetch, evidence capture, validateAsMetadata, outer 03-as-metadata
finding, contextUpdates) are unchanged. A4 is appended.

--- Assertion 4: PKCE methods advertisement ---

After outer finding construction:

If validateAsMetadata returned ok: false OR response.status !== 200:
  a4Finding = {
    id:           '03-as-metadata-pkce-methods',
    title:        'PKCE code_challenge_methods_supported advertisement (RFC 7636 §4.2)',
    severity:     'skipped',
    passed:       false,
    observations: ['Skipped: AS metadata body not available or not parseable.']
  }

Else:
  pkce = as.code_challenge_methods_supported  // string[] | undefined

  If pkce is undefined:
    a4Finding = {
      id:           '03-as-metadata-pkce-methods',
      title:        'PKCE code_challenge_methods_supported advertisement (RFC 7636 §4.2)',
      severity:     'info',
      passed:       false,
      observations: [
        'code_challenge_methods_supported not present in AS metadata.',
        'RFC 8414 §2: if omitted, the authorization server does not support PKCE.'
      ]
    }

  Else if pkce includes 'S256' AND NOT pkce includes 'plain':
    a4Finding = {
      id:           '03-as-metadata-pkce-methods',
      title:        'PKCE code_challenge_methods_supported advertisement (RFC 7636 §4.2)',
      severity:     'info',
      passed:       true,
      observations: [
        'code_challenge_methods_supported: [{pkce.join(", ")}]',
        'S256 advertised; plain not advertised. RFC 7636 §4.2 MTI baseline satisfied.'
      ]
    }

  Else if pkce includes 'S256' AND pkce includes 'plain':
    a4Finding = {
      id:           '03-as-metadata-pkce-methods',
      title:        'PKCE code_challenge_methods_supported advertisement (RFC 7636 §4.2)',
      severity:     'warn',
      passed:       false,
      observations: [
        'code_challenge_methods_supported: [{pkce.join(", ")}]',
        'plain is advertised alongside S256. No server-directed MUST NOT exists in RFC 7636,
         RFC 8414 §2, or OAuth 2.1 draft-15 §4.1.1. However, RFC 7636 §4.2 makes S256 the
         MTI method and states clients capable of S256 MUST use it; advertising plain weakens
         the protection surface for clients that do not enforce this. OAuth 2.1 draft-15 §4.1.1
         notes advertising plain in metadata is the intended mechanism for constrained clients
         to discover fallback availability.'
      ]
    }

  Else:   // pkce present but does not include 'S256' (may include 'plain' or other values)
    a4Finding = {
      id:           '03-as-metadata-pkce-methods',
      title:        'PKCE code_challenge_methods_supported advertisement (RFC 7636 §4.2)',
      severity:     'issue',
      passed:       false,
      observations: [
        'code_challenge_methods_supported: [{pkce.join(", ")}]',
        'S256 is not advertised. RFC 7636 §4.2 designates S256 as Mandatory To Implement (MTI)
         on the server. Without S256 in the advertised methods, clients cannot use the MTI
         baseline regardless of their own capability.'
      ]
    }

Return findings: [...existing findings, a4Finding]
Evidence and contextUpdates: unchanged.
```

Note on the else-branch: a server advertising neither S256 nor plain (unknown methods only)
also falls into the `issue` branch. This is correct: the MTI concern applies equally.

Existing inline observations in the `03-as-metadata` finding that mention
`code_challenge_methods_supported` are removed. The outer finding gains one observation when
`pkce` is defined: `'PKCE methods: see 03-as-metadata-pkce-methods finding.'` This keeps
the outer finding readable without duplicating logic.

## Finding shapes

### `03-as-metadata-pkce-methods` (A4)

**Pass (severity: `info`, S256 present, plain absent)**
- title: `"PKCE code_challenge_methods_supported advertisement (RFC 7636 §4.2)"`
- observations:
  1. `"code_challenge_methods_supported: [S256]"` (or full array if more values present)
  2. `"S256 advertised; plain not advertised. RFC 7636 §4.2 MTI baseline satisfied."`

**Warn (severity: `warn`, S256 present, plain also present)**
- title: `"PKCE code_challenge_methods_supported advertisement (RFC 7636 §4.2)"`
- observations:
  1. `"code_challenge_methods_supported: [S256, plain]"` (or full array)
  2. `"plain is advertised alongside S256. No server-directed MUST NOT exists in RFC 7636, RFC 8414 §2, or OAuth 2.1 draft-15 §4.1.1. However, RFC 7636 §4.2 makes S256 the MTI method and states clients capable of S256 MUST use it; advertising plain weakens the protection surface for clients that do not enforce this. OAuth 2.1 draft-15 §4.1.1 notes advertising plain in metadata is the intended mechanism for constrained clients to discover fallback availability."`

**Issue (severity: `issue`, S256 absent)**
- title: `"PKCE code_challenge_methods_supported advertisement (RFC 7636 §4.2)"`
- observations:
  1. `"code_challenge_methods_supported: [{methods}]"` (or `"[]"` if empty)
  2. `"S256 is not advertised. RFC 7636 §4.2 designates S256 as Mandatory To Implement (MTI) on the server. Without S256 in the advertised methods, clients cannot use the MTI baseline regardless of their own capability."`

**Info -- field absent (severity: `info`, `code_challenge_methods_supported` not in response)**
- title: `"PKCE code_challenge_methods_supported advertisement (RFC 7636 §4.2)"`
- observations:
  1. `"code_challenge_methods_supported not present in AS metadata."`
  2. `"RFC 8414 §2: if omitted, the authorization server does not support PKCE."`

**Skipped (severity: `skipped`)**
- title: `"PKCE code_challenge_methods_supported advertisement (RFC 7636 §4.2)"`
- observations: `["Skipped: AS metadata body not available or not parseable."]`

### Change to `03-as-metadata` finding observations

The two observation lines below are removed from the `03-as-metadata` finding body:

- `"code_challenge_methods_supported not advertised; PKCE support is unknown (RFC 7636)."`
- `"code_challenge_methods_supported=[{pkce}] does not include S256 (RFC 7636 §4.2)."`

Replacement line added when `pkce` is defined (i.e., the field is present in the parsed body):

- `"PKCE methods advertised: [{pkce.join(", ")}]. See 03-as-metadata-pkce-methods finding."`

When `pkce` is undefined, no replacement line is added to `03-as-metadata`; the A4 finding
carries the absent-field observation.

## Evidence files

`evidence/03-as-metadata.http` -- unchanged. Single file per run. A4 attaches to this file
via the same prefix-match rule used for all multi-finding probes: `03-as-metadata` is a prefix
of `03-as-metadata-pkce-methods`.

No new evidence files are created.

## Verification

### Target 1: Linear (`https://mcp.linear.app/mcp`)

Expected behavior depends on Linear's AS metadata. Based on the reference verification targets
in project memory, Linear is a live target. If Linear's AS metadata does not advertise
`code_challenge_methods_supported`, A4 should emit `info` (field absent). If it advertises
S256 only, A4 should emit `info` (pass). If it advertises S256 and plain, A4 should emit
`warn`. Confirm by running `korrel-cli` against Linear after implementation.

Expected minimum:
- `03-as-metadata`: behavior unchanged from current passing state.
- `03-as-metadata-pkce-methods`: one of `info`/`warn`/`issue` depending on actual field value.
  Not `skipped` (Linear's AS metadata fetch currently succeeds).

### Target 2: GitHub MCP (`https://api.githubcopilot.com/mcp`)

Same pattern as Linear. Run post-implementation to confirm actual `code_challenge_methods_supported`
value. If probe 03 currently succeeds (AS metadata reachable), A4 will not be `skipped`.

### Target 3: Atlassian MCP (`https://mcp.atlassian.com/v1/sse`)

Existing evidence shows probe 03 is `skipped` for Atlassian (no `authorization_servers`
upstream). A4 will therefore also be `skipped`. No change in behavior for Atlassian.

Expected:
- `03-as-metadata`: `skipped` (unchanged).
- `03-as-metadata-pkce-methods`: `skipped`.

## Acceptance criteria

- [ ] `asMetadataProbe` returns the existing findings plus exactly one additional finding with
      id `03-as-metadata-pkce-methods` on every run where AS metadata is successfully fetched.
- [ ] A4 severity is in `{'info', 'warn', 'issue', 'skipped'}` for all reachable targets. No
      other value is ever assigned.
- [ ] A4 severity is `'skipped'` if and only if the AS metadata body was not successfully
      fetched and parsed (status !== 200 or `validateAsMetadata` returned `ok: false`).
- [ ] A4 severity is `'info'` with `passed: false` when `code_challenge_methods_supported`
      is absent from the parsed metadata.
- [ ] A4 severity is `'info'` with `passed: true` when `code_challenge_methods_supported`
      includes `S256` and does not include `plain`.
- [ ] A4 severity is `'warn'` with `passed: false` when `code_challenge_methods_supported`
      includes both `S256` and `plain`.
- [ ] A4 severity is `'issue'` with `passed: false` when `code_challenge_methods_supported`
      is present but does not include `S256` (regardless of whether `plain` is present).
- [ ] A4 warn observation text does not contain the phrase "should remove", "should not advertise",
      or any other prescriptive instruction to the server operator.
- [ ] A4 warn observation text contains the string "RFC 7636 §4.2" and "OAuth 2.1 draft-15 §4.1.1".
- [ ] A4 issue observation text contains the string "RFC 7636 §4.2" and "Mandatory To Implement".
- [ ] A4 info (pass) observation text contains the string "RFC 7636 §4.2".
- [ ] A4 info (absent) observation text contains the string "RFC 8414 §2".
- [ ] The two removed inline observations (about `code_challenge_methods_supported` in the
      `03-as-metadata` finding body) do not appear in any output after the fix.
- [ ] The `03-as-metadata` finding pass/fail and severity logic is unchanged: it still passes
      when issuer matches and required fields are valid, fails otherwise.
- [ ] `contextUpdates` population logic is unchanged.
- [ ] Evidence array still contains exactly one entry with name `'03-as-metadata'` per run.
- [ ] `npm run typecheck` passes with zero errors after the change.
- [ ] Linear post-implementation run: `03-as-metadata-pkce-methods` emits `info` or `warn`
      (not `skipped`, not `issue`) -- confirm actual field value, update this criterion.
- [ ] Atlassian post-implementation run: `03-as-metadata-pkce-methods` is `skipped`.

## Open questions

None blocking. All three open questions from the issue brief are resolved above:

1. **OQ-1 (Severity):** Three-outcome model. Plain + S256 is `warn` (no explicit server-side
   MUST NOT but weakens protection surface per RFC 7636 §4.2 rationale and SEVERITY.md
   definition of warn). Plain-only is `issue` (forecloses MTI baseline, concrete threat-model
   gap). Field absent is `info`. Resolved above with full rationale.
2. **OQ-2 (Extend probe 03 vs new assertion):** New assertion A4 with id
   `03-as-metadata-pkce-methods`, following the exact pattern of issue #8 (A1/A2) and
   issue #18 (A3). The existing `03-as-metadata` finding is preserved.
3. **OQ-3 (Finding text wording):** Observation text is fully specified in Finding shapes.
   No prescriptive server-config language. RFC 7636 §4.2 and OAuth 2.1 draft-15 §4.1.1
   cited explicitly. The warn text states "no server-directed MUST NOT exists" to accurately
   represent the spec.
