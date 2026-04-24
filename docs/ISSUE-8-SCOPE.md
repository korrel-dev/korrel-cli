# Issue #8 Scope: Probe 1 compound pass condition split

## Background

`src/probes/discovery.ts` currently evaluates `response.status === 401 && prmUrl !== null`
as a single boolean and emits one `Finding` with id `01-discovery`. This conflates two
independent spec assertions: RFC 6750 §3 (401 with Bearer challenge) and RFC 9728 §5.1
(`resource_metadata` parameter in that challenge). Targets that satisfy the first assertion
but not the second, such as Atlassian's MCP endpoint, appear as a single undifferentiated
failure. The fix splits the compound check into two `Finding` objects with independent
severity logic, matching the two-assertion structure of the methodology.

## In scope

- Replace the single `Finding` (id `01-discovery`) with two findings: `01-discovery-auth-challenge`
  and `01-discovery-prm-advertisement`.
- Implement A1 pass condition: `response.status === 401 && challenge !== null && challenge.scheme.toLowerCase() === 'bearer'`.
- Implement A2 pass condition: A1 passed AND `prmUrl !== null`.
- Implement A2 skip condition: A1 failed.
- Apply the severity mapping defined in the pre-settled brief (see Normative assertions table).
- Preserve all existing observations, distributed between the two findings as specified.
- Preserve `contextUpdates.protectedResourceMetadataUrl` behaviour: set when `prmUrl !== null`,
  regardless of severity outcomes.
- Keep `discoveryProbe` function signature unchanged.
- Keep evidence output as a single `01-discovery.http` file per run.
- Recommend a one-line amendment to `mcp-audits/METHODOLOGY.md` step 1 noting that the two
  assertions are evaluated independently. The amendment is advisory: methodology alignment
  is the main thread's call.

## Out of scope

- Probe 2, 3, 4, 5, or 6 changes of any kind.
- `Severity` type changes (`'info' | 'warn' | 'issue' | 'critical' | 'skipped'` is the
  complete set as shipped in issue #3, and is correct for this work).
- `Finding` interface schema changes.
- `AuditContext` or `ProbeResult` type changes.
- Evidence file restructure or multi-file evidence output.
- `contextUpdates.protectedResourceMetadataUrl` behaviour changes.
- New assertions beyond the A1/A2 split. No additional spec checks are added.
- Fixing the report.ts prefix-match over-attachment issue (tracked as issue #6).
- Changes to probe 1 parsing logic (`parseWwwAuthenticate`, `consumeParam`).
- Improvements to any sibling probe discovered during review.

## Normative assertions being tested

| Level | Clause | Probe observation |
|-------|--------|-------------------|
| MUST  | RFC 6750 §3: "the resource server MUST include the HTTP 'WWW-Authenticate' response header field" when "the protected resource request does not include authentication credentials" | A1: 401 status received AND WWW-Authenticate header present AND scheme is Bearer |
| SHOULD | RFC 9728 §5.1: `resource_metadata` parameter in the Bearer challenge | A2: `resource_metadata` parameter present and non-empty in the Bearer challenge |

Note on A2 normative level: RFC 9728 §5.1 defines `resource_metadata` as a parameter
servers may include in the challenge. The MCP spec (2025-06-18 revision) references RFC 9728
as the discovery mechanism. Absence of `resource_metadata` is not a MUST violation against
RFC 9728 alone (a client may fall back to path-derived PRM URLs per RFC 9728 §3.1), but it
is a gap against the MCP spec's assumption of machine-discoverable auth. Severity is `warn`,
not `issue`. If the main thread interprets the MCP spec as elevating this to MUST, the
severity would change to `issue`; that reinterpretation is out of scope here.

## OQ-A resolution: 401 without WWW-Authenticate

RFC 6750 §3 states: "the resource server **MUST** include the HTTP 'WWW-Authenticate'
response header field" when the request lacks valid credentials. This is unambiguous.

Decision: a 401 response with no `WWW-Authenticate` header is an `issue` severity finding
for A1. The cited clause is RFC 6750 §3, first normative sentence. No hedging.

## Control flow

```
1. Send unauthenticated POST to ctx.target (existing request construction, unchanged).
2. Read response status, headers, body (unchanged).
3. Build evidence record (unchanged).
4. Parse WWW-Authenticate header -> challenge (existing parseWwwAuthenticate, unchanged).
5. Extract prmUrl from challenge.params.get('resource_metadata') (unchanged).

--- Assertion 1: auth challenge ---

6. a1Passed = (response.status === 401)
              AND (challenge !== null)
              AND (challenge.scheme.toLowerCase() === 'bearer')

7. Build a1Observations:
   - Always: "HTTP {status} {statusText}"
   - If wwwAuth present:    "WWW-Authenticate: {wwwAuth}"
   - If wwwAuth absent:     "No WWW-Authenticate header returned."
   - If challenge present but scheme !== 'bearer':
       "WWW-Authenticate scheme is '{scheme}'; expected Bearer (RFC 6750 §3)."
   - If errorParam present and not in VALID_BEARER_ERRORS:
       "WWW-Authenticate error='{errorParam}' is not a valid RFC 6750 §3.1 value
        (invalid_request | invalid_token | insufficient_scope)."
   - If errorParam present, valid, but !== 'invalid_token':
       "WWW-Authenticate error='{errorParam}' deviates from RFC 6750 §3.1;
        invalid_token is the correct value for an unauthenticated request."

8. a1Finding = {
     id: '01-discovery-auth-challenge',
     title: 'Bearer authentication challenge on unauthenticated request (RFC 6750)',
     severity: a1Passed ? 'info' : 'issue',
     passed: a1Passed,
     observations: a1Observations
   }

--- Assertion 2: PRM advertisement ---

9. If NOT a1Passed:
     a2Finding = {
       id: '01-discovery-prm-advertisement',
       title: 'PRM advertisement in WWW-Authenticate (RFC 9728 §5.1)',
       severity: 'skipped',
       passed: false,
       observations: ['Skipped: A1 (auth challenge) did not pass.']
     }
   Else if prmUrl !== null:
     a2Finding = {
       id: '01-discovery-prm-advertisement',
       title: 'PRM advertisement in WWW-Authenticate (RFC 9728 §5.1)',
       severity: 'info',
       passed: true,
       observations: ['resource_metadata URL: {prmUrl}']
     }
   Else:
     a2Finding = {
       id: '01-discovery-prm-advertisement',
       title: 'PRM advertisement in WWW-Authenticate (RFC 9728 §5.1)',
       severity: 'warn',
       passed: false,
       observations: ['WWW-Authenticate present but no resource_metadata parameter
                       (RFC 9728 §5.1).']
     }

10. Build ProbeResult:
    findings: [a1Finding, a2Finding]
    evidence: [{ name: '01-discovery', evidence }]
    contextUpdates: prmUrl !== null ? { protectedResourceMetadataUrl: prmUrl } : undefined
```

## Finding shapes

### `01-discovery-auth-challenge` (A1)

**Pass (severity: `info`)**
- title: `"Bearer authentication challenge on unauthenticated request (RFC 6750)"`
- detail: observations include HTTP status line, full WWW-Authenticate header value, and
  any error parameter notes.

**Fail (severity: `issue`)**
- title: `"Bearer authentication challenge on unauthenticated request (RFC 6750)"`
- detail: observations identify which sub-condition failed. Examples:
  - `"HTTP 200 OK"` (no 401 at all)
  - `"No WWW-Authenticate header returned."` (401 but header absent)
  - `"WWW-Authenticate scheme is 'Basic'; expected Bearer (RFC 6750 §3)."` (wrong scheme)

### `01-discovery-prm-advertisement` (A2)

**Pass (severity: `info`)**
- title: `"PRM advertisement in WWW-Authenticate (RFC 9728 §5.1)"`
- detail: `"resource_metadata URL: {prmUrl}"`

**Fail (severity: `warn`)**
- title: `"PRM advertisement in WWW-Authenticate (RFC 9728 §5.1)"`
- detail: `"WWW-Authenticate present but no resource_metadata parameter (RFC 9728 §5.1)."`

**Skipped (severity: `skipped`)**
- title: `"PRM advertisement in WWW-Authenticate (RFC 9728 §5.1)"`
- detail: `"Skipped: A1 (auth challenge) did not pass."`

## Evidence files

One file per run: `evidence/01-discovery.http`

Both findings attach to this file because `report.ts` uses a bidirectional prefix match
between evidence stems and finding ids: a finding links to an evidence file if the evidence
stem is a prefix of the finding id (with `-` separator), or the finding id is a prefix of
the evidence stem (with `-` separator), or the two are equal. Both directions matter here:

- Finding id `01-discovery-auth-challenge` links to evidence `01-discovery.http` because
  the evidence stem is a prefix of the finding id. Same for `01-discovery-prm-advertisement`.
  This is the split-probe case introduced by this work.
- Finding id `01-discovery` links to evidence `01-discovery-auth-challenge.http` and
  `01-discovery-prm-advertisement.http` because the finding id is a prefix of each evidence
  stem. This is the fail-soft synthesis case, where a thrown probe produces a synthetic
  finding keyed on the probe's stem rather than a specific assertion id.

The over-attachment behaviour is acknowledged (issue #6) and unchanged by this work.

## Verification

### Verification gap: no Atlassian or Linear evidence on disk

No Atlassian or Linear evidence files exist in `mcp-audits/` or `/tmp/` at time of scoping.
The predictions below are derived from the pre-settled brief and public MCP implementation
knowledge, not from observed HTTP captures. Before marking Atlassian acceptance criteria
green, the implementer must run `korrel-cli` against the Atlassian MCP endpoint and confirm
the actual 401 response shape. If Atlassian does not return 401 at all, or returns 401
without Bearer, the prediction for A1 changes.

### Target 1: GitHub Copilot MCP (`api.githubcopilot.com/mcp`)

Evidence on disk at `mcp-audits/_archive/api.githubcopilot.com/evidence/01-discovery.http`
confirms:
- `HTTP 401 Unauthorized`
- `WWW-Authenticate: Bearer error="invalid_request", ..., resource_metadata="https://api.githubcopilot.com/.well-known/oauth-protected-resource/mcp"`

Expected output after split:
- A1: `info` / passed. Observations: status 401, full WWW-Authenticate value, note that
  `error="invalid_request"` deviates from RFC 6750 §3.1 (`invalid_token` is correct for
  unauthenticated requests).
- A2: `info` / passed. Observation: resource_metadata URL present.

### Target 2: Linear MCP (predicted, no evidence on disk)

Prediction: full spec compliance, 401 + Bearer + `resource_metadata`.
Expected output:
- A1: `info` / passed.
- A2: `info` / passed.

Must be confirmed by running `korrel-cli` against the Linear endpoint before closing
acceptance criteria.

### Target 3: Atlassian MCP (predicted, no evidence on disk)

Prediction: 401 + Bearer challenge present, `resource_metadata` absent.
Expected output:
- A1: `info` / passed.
- A2: `warn` / failed. Observation: `"WWW-Authenticate present but no resource_metadata parameter (RFC 9728 §5.1)."`
- `contextUpdates.protectedResourceMetadataUrl`: not set (prmUrl is null).

Must be confirmed by running `korrel-cli` against the Atlassian endpoint before closing
acceptance criteria.

## Acceptance criteria

- [ ] `discoveryProbe` function signature is unchanged: `(ctx: AuditContext) => Promise<ProbeResult>`.
- [ ] Every reachable-target run returns exactly two findings.
- [ ] Finding ids are `01-discovery-auth-challenge` and `01-discovery-prm-advertisement`, no others.
- [ ] A1 severity is in `{'info', 'issue'}` for all reachable targets. No other value is ever assigned.
- [ ] A2 severity is in `{'info', 'warn', 'skipped'}` for all reachable targets. No other value is ever assigned.
- [ ] A2 severity is `'skipped'` if and only if A1 passed is `false`.
- [ ] `contextUpdates.protectedResourceMetadataUrl` is set when `prmUrl !== null`, regardless of A1 or A2 severity.
- [ ] `contextUpdates` is absent (not set to `{}`) when `prmUrl === null`.
- [ ] Evidence array contains exactly one entry with name `'01-discovery'` per run.
- [ ] `npm run typecheck` passes with zero errors.
- [ ] GitHub report: two findings under probe 1, both `info`, A1 includes the `invalid_request` deviation note.
- [ ] Linear report: two findings under probe 1, both `info`. (Requires live run to confirm.)
- [ ] Atlassian report: A1 is `info`, A2 is `warn`. (Requires live run; prediction must be confirmed against actual response before closing.)
- [ ] Old finding id `01-discovery` does not appear in any output.

## Open questions

### OQ-A: RESOLVED

"401 without WWW-Authenticate" is `issue` severity for A1.

Cited clause: RFC 6750 §3, exact text: "the resource server MUST include the HTTP
'WWW-Authenticate' response header field" when "the protected resource request does not
include authentication credentials or does not contain an access token that enables access
to the protected resource."

`MUST` is unambiguous. No further decision needed.

### OQ-B: `error` parameter observation placement (needs main-thread decision)

The current probe collects observations about the RFC 6750 §3.1 `error` parameter
(valid values: `invalid_request`, `invalid_token`, `insufficient_scope`; expected value for
unauthenticated requests: `invalid_token`). After the split these observations logically
belong in A1 because the `error` parameter is part of the Bearer challenge shape, not the
`resource_metadata` advertisement. The GitHub evidence shows `error="invalid_request"`,
which the probe currently notes as a deviation.

Recommendation: keep the `error` parameter observations in A1. They describe challenge
correctness, not PRM discovery.

No third finding should be added. This is an observation within A1, not a separate
assertion. Main thread must confirm this placement is acceptable. If main thread disagrees,
options are:
1. Keep in A1 (recommended).
2. Drop the `error` parameter observation entirely.
3. Escalate to a named finding in a future issue (out of scope here).

### OQ-C: Atlassian and Linear evidence not on disk (implementation blocker, not design blocker)

Verification targets for Atlassian and Linear are predictions, not confirmed observations.
Acceptance criteria for those targets cannot be marked green until `korrel-cli` has been
run against live endpoints and the actual HTTP responses have been captured. The
implementer should capture new evidence files and compare against the predictions in this
scope doc before closing the issue. If any prediction is wrong, the implementer must flag
it to the main thread rather than silently adjusting severity mapping.

## Methodology amendment (advisory)

The current `mcp-audits/METHODOLOGY.md` step 1 text describes both assertions together
without distinguishing them as independently evaluated. Recommended one-line addition at
the end of the first paragraph of step 1:

> The 401+Bearer assertion and the `resource_metadata` advertisement assertion are
> evaluated independently; a target may pass the first and fail the second.

This is a documentation alignment, not a behaviour change. Main thread decides whether to
apply it.
