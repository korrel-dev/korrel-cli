# Issue #18 Scope: Discovery probe error code on unauthenticated 401 conflicts with RFC 6750 §3.1

## OQ-2 resolution (extend A1 vs new A3)

**Decision: add A3 as a new finding, `01-discovery-error-code-absent`.**

Rationale: A1 already has a settled pass/fail condition (`status === 401 AND challenge present AND scheme === Bearer`). Grafting a new SHOULD-level warn onto A1 would require A1 to carry both `issue` and `warn` outcomes on the same finding id, which breaks the invariant established by issue #8 ("A1 severity is in `{'info', 'issue'}` for all reachable targets"). A3 is a distinct, independently evaluable assertion about a different property of the same challenge. The existing pattern shows A2 was separated from A1 for exactly this reason. A3 follows the same logic. A3 is skipped when A1 fails, because the error-code rule only applies once a valid Bearer challenge is confirmed.

The existing `VALID_BEARER_ERRORS` constant and `EXPECTED_UNAUTH_ERROR` constant in `discovery.ts` are both wrong and are removed as part of this fix. No replacement constants are needed: the correct behavior is to warn whenever `error` is present, regardless of its value.

---

## Background

RFC 6750 §3.1 states that when a request lacks any authentication information, the resource server SHOULD NOT include an `error` parameter, an `error_description` parameter, or an `error_uri` parameter in the Bearer challenge. The three enumerated error code values (`invalid_request`, `invalid_token`, `insufficient_scope`) all presuppose a token was present but was somehow defective. None of them apply to the no-credentials case.

The discovery probe currently contains two incorrect behaviors stemming from this misreading. First, it treats `invalid_token` as the expected error code for a no-credentials 401 and silently passes when it is present (Linear). Second, it treats `invalid_request` as a deviation from `invalid_token` and suggests the latter as the correct value (Supabase). Both behaviors are wrong. The correct behavior is to warn whenever any `error` parameter appears on a no-credentials 401.

RFC 9728 §5.1 is not affected by this change. The `resource_metadata` parameter is a discovery mechanism, not an error report, and its presence or absence is governed by A2 independently.

## In scope

- Remove `VALID_BEARER_ERRORS` and `EXPECTED_UNAUTH_ERROR` constants from `discovery.ts`.
- Remove the two observation branches in A1 that check `errorParam` against those constants and emit deviation notes.
- Add assertion A3 (`01-discovery-error-code-absent`) as a new finding emitted by `discoveryProbe`.
- A3 evaluates whether the Bearer challenge contains any of the three RFC 6750 §3.1 error parameters: `error`, `error_description`, `error_uri`.
- A3 passes when none of those three parameters are present in the challenge.
- A3 warns when any of those three parameters are present.
- A3 is skipped when A1 fails (no valid Bearer challenge to evaluate).
- A3 finding id is `01-discovery-error-code-absent`.
- No changes to A1 pass condition, A1 severity range, A2 logic, evidence file naming, `parseWwwAuthenticate`, `consumeParam`, or any sibling probe.

## Out of scope

- Changing A1 severity range (`{'info', 'issue'}` is unchanged).
- Changing A2 logic or severity range.
- Adding a fourth assertion about `error_description` or `error_uri` as separate findings. All three parameters are checked within A3 as a group.
- Fixing the report.ts prefix-match over-attachment issue (tracked as issue #6).
- Re-running audits for Linear or Supabase. Re-runs are post-implementation work.
- Changes to `mcp-audits/METHODOLOGY.md`. Advisory note only, main thread decides.
- Changes to any probe other than `discovery.ts`.
- Changes to `src/types.ts`, `src/report.ts`, or `docs/SEVERITY.md`.
- Tightening the RFC 6750 §3.1 `realm` parameter: `realm` is explicitly permitted on a no-credentials challenge and is not checked here.
- Tightening the RFC 6750 §3.1 `scope` parameter: `scope` is also permitted on a no-credentials challenge and is not checked here.

## Normative assertions being tested

| Level     | Clause                  | Probe observation                                                                                                                       |
|-----------|-------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| SHOULD NOT | RFC 6750 §3.1: "If the request lacks any authentication information, the resource server SHOULD NOT include an error code or other error information" | A3: `error`, `error_description`, and `error_uri` are all absent from the Bearer challenge |
| SHOULD NOT | RFC 6750 §3.1: "other error information" covers `error_description` and `error_uri` as well as `error` | A3 checks all three parameters as a unit; presence of any one triggers the warn |

Note on severity: the cited clauses are SHOULD NOT, not MUST NOT. Per `docs/SEVERITY.md`, SHOULD-level deviations map to `warn`. A3 never emits `issue`.

Note on A1 error-code observations: the existing A1 observations that note `error` parameter deviations are removed entirely. They were based on the incorrect premise that `invalid_token` is the expected value. Removing them is a correctness fix, not a behavior regression.

## Control flow

```
Steps 1-9 (request, evidence capture, parseWwwAuthenticate, A1, A2) are unchanged.

--- Assertion 3: error code absent on no-credentials challenge ---

10. If NOT a1Passed:
      a3Finding = {
        id:           '01-discovery-error-code-absent',
        title:        'No error code in unauthenticated Bearer challenge (RFC 6750 §3.1)',
        severity:     'skipped',
        passed:       false,
        observations: ['Skipped: A1 (auth challenge) did not pass.']
      }

11. Else:
      errorPresent     = challenge.params.has('error')
      errorDescPresent = challenge.params.has('error_description')
      errorUriPresent  = challenge.params.has('error_uri')
      anyErrorParam    = errorPresent OR errorDescPresent OR errorUriPresent

      a3Observations = []
      a3Observations.push("WWW-Authenticate: {wwwAuth}")

      If anyErrorParam:
        For each of ['error', 'error_description', 'error_uri'] that is present:
          a3Observations.push(
            "WWW-Authenticate includes '{param}' parameter; RFC 6750 §3.1 states the
             resource server SHOULD NOT include error information on a request that
             lacks authentication credentials."
          )
        a3Finding = {
          id:           '01-discovery-error-code-absent',
          title:        'No error code in unauthenticated Bearer challenge (RFC 6750 §3.1)',
          severity:     'warn',
          passed:       false,
          observations: a3Observations
        }
      Else:
        a3Observations.push(
          "No error, error_description, or error_uri parameter present (RFC 6750 §3.1 SHOULD NOT satisfied)."
        )
        a3Finding = {
          id:           '01-discovery-error-code-absent',
          title:        'No error code in unauthenticated Bearer challenge (RFC 6750 §3.1)',
          severity:     'info',
          passed:       true,
          observations: a3Observations
        }

12. Build ProbeResult:
      findings: [a1Finding, a2Finding, a3Finding]
      evidence and contextUpdates: unchanged from current implementation
```

## Finding shapes

### `01-discovery-error-code-absent` (A3)

**Pass (severity: `info`)**
- title: `"No error code in unauthenticated Bearer challenge (RFC 6750 §3.1)"`
- observations include the full `WWW-Authenticate` header value, then:
  `"No error, error_description, or error_uri parameter present (RFC 6750 §3.1 SHOULD NOT satisfied)."`

**Fail (severity: `warn`)**
- title: `"No error code in unauthenticated Bearer challenge (RFC 6750 §3.1)"`
- observations include the full `WWW-Authenticate` header value, then one line per offending parameter:
  `"WWW-Authenticate includes 'error' parameter; RFC 6750 §3.1 states the resource server SHOULD NOT include error information on a request that lacks authentication credentials."`
  (repeat for `error_description` and/or `error_uri` if also present)

**Skipped (severity: `skipped`)**
- title: `"No error code in unauthenticated Bearer challenge (RFC 6750 §3.1)"`
- observations: `["Skipped: A1 (auth challenge) did not pass."]`

### A1 change: observations cleanup

The two observation branches removed from A1 are:

- The branch that checked `!VALID_BEARER_ERRORS.has(errorParam)` and reported the value as not a valid RFC 6750 §3.1 value.
- The branch that checked `errorParam !== EXPECTED_UNAUTH_ERROR` and reported `invalid_token` as the correct value.

No replacement text is added to A1. A1 observations after this fix cover: HTTP status line, `WWW-Authenticate` header value (or its absence), and scheme deviations only.

## Evidence files

`evidence/01-discovery.http` — unchanged. Single file per run. A3 attaches to this file via the same prefix-match rule as A1 and A2 (`01-discovery` is a prefix of `01-discovery-error-code-absent`).

No new evidence files are created.

## Verification

### Target 1: Linear (`https://mcp.linear.app/mcp`)

Existing evidence `audits/linear/evidence/01-discovery.http` shows `error="invalid_token"` in the `WWW-Authenticate` header.

Expected output after fix:
- A1: `info` / passed. Observations: status 401, full WWW-Authenticate value. No mention of `invalid_token` as correct or incorrect.
- A2: `info` / passed. `resource_metadata` URL present.
- A3: `warn` / failed. Observation names `error` parameter and cites RFC 6750 §3.1 SHOULD NOT.

Before fix (current behavior): A1 passes silently with no warning about the `error` parameter. After fix: A3 surfaces the deviation.

### Target 2: Supabase (`https://mcp.supabase.com/mcp` or equivalent, re-run post-implementation)

Scratch evidence from today shows `error="invalid_request"` in the `WWW-Authenticate` header.

Expected output after fix:
- A1: `info` / passed. Observations: status 401, full WWW-Authenticate value. No suggestion that `invalid_token` would be correct.
- A2: pass or warn depending on whether `resource_metadata` is present (confirm from re-run).
- A3: `warn` / failed. Observation names `error` parameter and cites RFC 6750 §3.1 SHOULD NOT.

Before fix (current behavior): A1 produces an incorrect observation suggesting `invalid_token` as the correct value. After fix: A3 surfaces the correct deviation without naming any error code as correct.

### Target 3: GitHub Copilot MCP (`https://api.githubcopilot.com/mcp`)

Archived evidence shows `error="invalid_request"` in the `WWW-Authenticate` header.

Expected output after fix:
- A1: `info` / passed. Observations: status 401, full WWW-Authenticate value. No `invalid_token` suggestion.
- A2: `info` / passed. `resource_metadata` URL present.
- A3: `warn` / failed. Observation names `error` parameter, cites RFC 6750 §3.1 SHOULD NOT.

## Acceptance criteria

- [ ] `VALID_BEARER_ERRORS` constant does not exist anywhere in `src/discovery.ts` after the fix.
- [ ] `EXPECTED_UNAUTH_ERROR` constant does not exist anywhere in `src/discovery.ts` after the fix.
- [ ] A1 observations block contains no branch that references `invalid_token` as a correct or preferred value.
- [ ] A1 observations block contains no branch that checks `errorParam` against any set of valid values.
- [ ] `discoveryProbe` returns exactly three findings on every reachable-target run.
- [ ] Finding ids are `01-discovery-auth-challenge`, `01-discovery-prm-advertisement`, and `01-discovery-error-code-absent`, no others.
- [ ] A3 severity is in `{'info', 'warn', 'skipped'}` for all reachable targets. No other value is ever assigned.
- [ ] A3 severity is `'skipped'` if and only if A1 `passed` is `false`.
- [ ] A3 severity is `'warn'` when any of `error`, `error_description`, or `error_uri` is present in the Bearer challenge.
- [ ] A3 severity is `'info'` when none of those three parameters are present.
- [ ] A3 warn observation text does not contain the string `invalid_token`, `invalid_request`, or `insufficient_scope`.
- [ ] A3 pass observation text does not contain the string `invalid_token`, `invalid_request`, or `insufficient_scope`.
- [ ] Linear report: A3 is `warn` with observation citing `error` parameter and RFC 6750 §3.1.
- [ ] Supabase report (post re-run): A3 is `warn`; A1 contains no mention of `invalid_token` as correct.
- [ ] GitHub report: A3 is `warn`; A1 contains no mention of `invalid_token` as correct.
- [ ] `npm run typecheck` passes with zero errors.
- [ ] Evidence array still contains exactly one entry with name `'01-discovery'` per run.
- [ ] `contextUpdates.protectedResourceMetadataUrl` behavior is unchanged.

## Open questions

None blocking. All three open questions from the issue brief are resolved above:

1. **Severity:** `warn`. SHOULD NOT per RFC 6750 §3.1. `docs/SEVERITY.md` defines `warn` as "SHOULD-level spec deviation." Confirmed.
2. **A1 extension vs new A3:** New A3. Rationale documented in the OQ-2 resolution block at the top of this document.
3. **Finding text wording:** Exact text specified in Finding shapes section. No error code value is named as correct or preferred in either the pass or fail observation.

## Methodology amendment (advisory)

`mcp-audits/METHODOLOGY.md` step 1 does not currently mention the error-code constraint for unauthenticated challenges. Recommended addition at the end of the step 1 description:

> The Bearer challenge on a no-credentials request SHOULD carry no `error`, `error_description`, or `error_uri` parameter (RFC 6750 §3.1). The probe evaluates this as a third independent assertion.

This is advisory. Main thread decides whether to apply it before the Audit 02 Linear publish (May 4).
