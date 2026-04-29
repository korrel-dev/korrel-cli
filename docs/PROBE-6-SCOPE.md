# PROBE-6 Scope: token-hygiene metadata signals

## Background

Probe 6 covers the token-hygiene surface of methodology step 5. Full token hygiene
testing (audience-claim binding per RFC 8707, token expiry, storage practices) requires
a real access token, which a headless CLI cannot obtain: no browser, no user-consent
flow. Probe 6 therefore restricts itself to signals derivable from already-fetched AS
metadata (RFC 8414 §2) and PRM (RFC 9728 §3): four assertions (B1-B4) about field
presence and advertised values. The live-token work is explicitly deferred to a future
browser-harness probe, mirroring the verifier-mismatch deferral in probe 5.

Probe ID: `06-token-hygiene`.

Probe 6 makes no network requests. All inputs come from `AuditContext` fields populated
by probes 2 and 3.

## In scope

- Read `AuditContext.authorizationServerMetadata` (set by probe 3). If absent, emit
  `skipped` findings for B1, B2, and B3 and return.
- Read `AuditContext.protectedResourceMetadata` (set by probe 2). If absent, emit a
  `skipped` finding for B4. B1-B3 are still evaluable if AS metadata is present.
- B1: check whether `jwks_uri` is present in AS metadata. Emit `info` either way.
- B2: check whether `revocation_endpoint` is present in AS metadata (RFC 7009). Emit
  `info` if present, `warn` if absent.
- B3: check whether `introspection_endpoint` is present in AS metadata (RFC 7662).
  Emit `info` either way.
- B4: check the values in PRM `bearer_methods_supported` against the set
  `{query, form}` (RFC 6750 §2.3 / §5.3). Emit `warn` if `query` is present, `info`
  (passed=false) if only `form` is present, `info` (passed=false) if the field is
  absent, `info` (passed=true) if the field is present and contains only `header` or
  other non-URL methods.
- Deferral finding: always emit one `skipped` finding documenting that live-token tests
  (aud-claim, expiry, storage) could not run in the headless v0 probe harness.
- No network requests. No evidence files.

## Out of scope

- Aud-claim (`aud`) inspection: requires a real JWT access token. Deferred.
- Token expiry inspection: requires a real access token with `exp` claim. Deferred.
- Token-storage guidance review in SDK documentation: manual review, not automatable
  by this probe. Deferred.
- Cross-resource token confusion testing: requires multiple live tokens. Deferred.
- Introspection-endpoint liveness check: probe 6 checks advertisement only. Whether
  the endpoint actually processes tokens requires a real access token.
- Revocation-endpoint liveness check: same constraint as introspection.
- Token Binding (RFC 8471) or DPoP (RFC 9449): out of scope for methodology v1.0.
- Checking any AS metadata field not enumerated in B1-B3 above.
- Checking any PRM field other than `bearer_methods_supported`.
- Fetching the JWKS document at `jwks_uri`: presence of the field is the signal;
  document validity belongs in a future cryptographic-validation probe.

## Normative assertions being tested

| Level    | Clause           | Probe observation                                                                                     |
|----------|------------------|-------------------------------------------------------------------------------------------------------|
| OPTIONAL | RFC 8414 §2      | `jwks_uri` field present in AS metadata. Signals JWT-format tokens; enables offline validation.       |
| OPTIONAL | RFC 8414 §2      | `revocation_endpoint` field present in AS metadata. Defense-in-depth per RFC 7009.                    |
| OPTIONAL | RFC 8414 §2      | `introspection_endpoint` field present in AS metadata. Enables opaque-token validation per RFC 7662.  |
| SHOULD   | RFC 6750 §5.3    | Bearer tokens SHOULD NOT be sent in URI query strings. `bearer_methods_supported: query` signals risk.|
| MAY      | RFC 6750 §2.4    | `bearer_methods_supported` field is OPTIONAL in PRM (RFC 9728 §3). Absence means all methods allowed. |

Notes on RFC 6750 §5.3: the RFC advises that query-string bearer tokens "SHOULD NOT be
used" because they end up in access logs, browser history, and Referer headers. The
classification of `query` as `warn` rather than `issue` reflects that this is a SHOULD
NOT, not a MUST NOT. The MCP specification (2025-11-25) does not independently add a
MUST NOT for query-string tokens.

## Control flow

```
function probe6(ctx):

  findings = []

  // --- B1, B2, B3 guard ---
  if ctx.authorizationServerMetadata is absent:
    emit finding(id="06-token-hygiene-jwks-uri",
                 severity=skipped, passed=false,
                 title="JWKS URI advertisement (RFC 8414 §2)",
                 obs="AS metadata not available; probe 3 did not populate authorizationServerMetadata.")
    emit finding(id="06-token-hygiene-revocation-endpoint",
                 severity=skipped, passed=false,
                 title="Revocation endpoint advertisement (RFC 7009)",
                 obs="AS metadata not available.")
    emit finding(id="06-token-hygiene-introspection-endpoint",
                 severity=skipped, passed=false,
                 title="Introspection endpoint advertisement (RFC 7662)",
                 obs="AS metadata not available.")
    // fall through to B4 guard and deferral finding

  else:
    as = ctx.authorizationServerMetadata

    // --- B1: jwks_uri ---
    if as["jwks_uri"] is present:
      emit finding(id="06-token-hygiene-jwks-uri",
                   severity=info, passed=true,
                   title="JWKS URI advertised",
                   obs=["jwks_uri: {url}", "AS advertises JWT token format; offline validation is possible."])
    else:
      emit finding(id="06-token-hygiene-jwks-uri",
                   severity=info, passed=false,
                   title="JWKS URI not advertised",
                   obs=["jwks_uri absent from AS metadata.",
                        "Tokens may be opaque; offline JWT validation not available. Opaque-token design is legitimate."])

    // --- B2: revocation_endpoint ---
    if as["revocation_endpoint"] is present:
      emit finding(id="06-token-hygiene-revocation-endpoint",
                   severity=info, passed=true,
                   title="Revocation endpoint advertised (RFC 7009)",
                   obs=["revocation_endpoint: {url}", "Token revocation is available."])
    else:
      emit finding(id="06-token-hygiene-revocation-endpoint",
                   severity=warn, passed=false,
                   title="Revocation endpoint not advertised (RFC 7009)",
                   obs=["revocation_endpoint absent from AS metadata.",
                        "RFC 7009 revocation not available. Issued tokens cannot be invalidated before expiry.",
                        "This gap requires a live token to confirm in practice; metadata signal only."])

    // --- B3: introspection_endpoint ---
    if as["introspection_endpoint"] is present:
      emit finding(id="06-token-hygiene-introspection-endpoint",
                   severity=info, passed=true,
                   title="Introspection endpoint advertised (RFC 7662)",
                   obs=["introspection_endpoint: {url}",
                        "Resource servers can validate opaque tokens without storing them."])
    else:
      emit finding(id="06-token-hygiene-introspection-endpoint",
                   severity=info, passed=false,
                   title="Introspection endpoint not advertised (RFC 7662)",
                   obs=["introspection_endpoint absent from AS metadata.",
                        "Opaque-token validation by Resource Servers requires out-of-band means."])

  // --- B4 guard ---
  if ctx.protectedResourceMetadata is absent:
    emit finding(id="06-token-hygiene-bearer-methods",
                 severity=skipped, passed=false,
                 title="Bearer methods advertisement (RFC 6750 §2.3)",
                 obs="PRM not available; probe 2 did not populate protectedResourceMetadata.")
  else:
    prm = ctx.protectedResourceMetadata
    methods = prm["bearer_methods_supported"]  // may be undefined

    if methods is absent:
      emit finding(id="06-token-hygiene-bearer-methods",
                   severity=info, passed=false,
                   title="bearer_methods_supported not advertised",
                   obs=["bearer_methods_supported absent from PRM.",
                        "RFC 6750 default allows all three bearer methods (header, query, form).",
                        "No explicit restriction; URL-borne token risk cannot be ruled out from metadata alone."])
    else if methods contains "query":
      emit finding(id="06-token-hygiene-bearer-methods",
                   severity=warn, passed=false,
                   title="bearer_methods_supported includes query",
                   obs=["bearer_methods_supported: [{methods joined}]",
                        "query method accepted. Bearer tokens in URI query strings appear in access logs and Referer headers.",
                        "RFC 6750 §5.3 advises against URL query string bearer tokens."])
    else if methods contains "form" (and not "query"):
      emit finding(id="06-token-hygiene-bearer-methods",
                   severity=info, passed=false,
                   title="bearer_methods_supported includes form but not query",
                   obs=["bearer_methods_supported: [{methods joined}]",
                        "form method accepted. Lower risk than query; not logged in access logs by default."])
    else:
      // methods present, no "query", no "form"
      emit finding(id="06-token-hygiene-bearer-methods",
                   severity=info, passed=true,
                   title="bearer_methods_supported restricts to header only",
                   obs=["bearer_methods_supported: [{methods joined}]",
                        "URL-borne bearer token methods not advertised. RFC 6750 §5.3 recommendation satisfied."])

  // --- Deferral finding (always emitted) ---
  emit finding(id="06-token-hygiene-live-token-deferred",
               severity=skipped, passed=false,
               title="Live-token hygiene tests deferred to future probe",
               obs=["Live-token tests (aud-claim binding, token expiry, storage practices) require obtaining an access token, which requires user consent. Headless probe cannot complete these tests in v0. Tracked for future browser-harness probe."])

  return { findings, evidence=[] }
```

## Finding shapes

| ID                                         | Severity  | passed | Title                                                          | Detail template                                                                                                                                                                |
|--------------------------------------------|-----------|--------|----------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `06-token-hygiene-jwks-uri`                | `skipped` | false  | JWKS URI advertisement (RFC 8414 §2)                          | AS metadata not available; probe 3 did not populate authorizationServerMetadata.                                                                                               |
| `06-token-hygiene-jwks-uri`                | `info`    | true   | JWKS URI advertised                                            | jwks_uri: {url}. AS advertises JWT token format; offline validation is possible.                                                                                               |
| `06-token-hygiene-jwks-uri`                | `info`    | false  | JWKS URI not advertised                                        | jwks_uri absent from AS metadata. Tokens may be opaque; offline JWT validation not available. Opaque-token design is legitimate.                                               |
| `06-token-hygiene-revocation-endpoint`     | `skipped` | false  | Revocation endpoint advertisement (RFC 7009)                  | AS metadata not available.                                                                                                                                                     |
| `06-token-hygiene-revocation-endpoint`     | `info`    | true   | Revocation endpoint advertised (RFC 7009)                     | revocation_endpoint: {url}. Token revocation is available.                                                                                                                     |
| `06-token-hygiene-revocation-endpoint`     | `warn`    | false  | Revocation endpoint not advertised (RFC 7009)                 | revocation_endpoint absent from AS metadata. RFC 7009 revocation not available. Issued tokens cannot be invalidated before expiry. Metadata signal only.                       |
| `06-token-hygiene-introspection-endpoint`  | `skipped` | false  | Introspection endpoint advertisement (RFC 7662)               | AS metadata not available.                                                                                                                                                     |
| `06-token-hygiene-introspection-endpoint`  | `info`    | true   | Introspection endpoint advertised (RFC 7662)                  | introspection_endpoint: {url}. Resource servers can validate opaque tokens without storing them.                                                                               |
| `06-token-hygiene-introspection-endpoint`  | `info`    | false  | Introspection endpoint not advertised (RFC 7662)              | introspection_endpoint absent from AS metadata. Opaque-token validation by Resource Servers requires out-of-band means.                                                        |
| `06-token-hygiene-bearer-methods`          | `skipped` | false  | Bearer methods advertisement (RFC 6750 §2.3)                  | PRM not available; probe 2 did not populate protectedResourceMetadata.                                                                                                         |
| `06-token-hygiene-bearer-methods`          | `info`    | false  | bearer_methods_supported not advertised                        | bearer_methods_supported absent from PRM. RFC 6750 default allows all three bearer methods (header, query, form). URL-borne token risk cannot be ruled out from metadata alone.|
| `06-token-hygiene-bearer-methods`          | `warn`    | false  | bearer_methods_supported includes query                        | bearer_methods_supported: [{methods}]. query method accepted. Bearer tokens in URI query strings appear in access logs and Referer headers. RFC 6750 §5.3.                     |
| `06-token-hygiene-bearer-methods`          | `info`    | false  | bearer_methods_supported includes form but not query           | bearer_methods_supported: [{methods}]. form method accepted. Lower risk than query; not logged in access logs by default.                                                      |
| `06-token-hygiene-bearer-methods`          | `info`    | true   | bearer_methods_supported restricts to header only              | bearer_methods_supported: [{methods}]. URL-borne bearer token methods not advertised. RFC 6750 §5.3 recommendation satisfied.                                                  |
| `06-token-hygiene-live-token-deferred`     | `skipped` | false  | Live-token hygiene tests deferred to future probe             | Live-token tests (aud-claim binding, token expiry, storage practices) require obtaining an access token, which requires user consent. Headless probe cannot complete these tests in v0. Tracked for future browser-harness probe. |

Severity vocabulary used: `info`, `warn`, `skipped`. `issue` and `critical` are not emitted
by probe 6. All levels match the `Severity` union in `src/types.ts`. See `docs/SEVERITY.md`
for canonical definitions.

## Evidence files

None. Probe 6 reads only from `AuditContext` fields already populated by probes 2 and 3. No
network requests are made. No evidence files are written.

Per the policy in `docs/SCOPE-6-FINDING-EVIDENCE.md`: a finding gets `evidence: [name]` only
when it describes a property of an HTTP transaction captured in an evidence file. All five
findings in probe 6 are derived from already-fetched documents; none warrants an `evidence`
field. All five findings omit `evidence`.

## AuditContext consumption

Probe 6 reads two fields:

| Field                          | Type              | Set by | Used for     |
|--------------------------------|-------------------|--------|--------------|
| `ctx.authorizationServerMetadata` | `AsMetadata \| undefined` | Probe 3 (`as-metadata.ts`) | B1, B2, B3 |
| `ctx.protectedResourceMetadata`   | `Prm \| undefined`        | Probe 2 (`prm.ts`)          | B4         |

Both fields are already declared in `src/types.ts` (lines 37-38). `AsMetadata` is typed via
`AsMetadataSchema.passthrough()` (in `src/probes/as-metadata.ts`) and therefore carries
`jwks_uri`, `revocation_endpoint`, and `introspection_endpoint` as `unknown` values on the
passthrough record. `Prm` is typed via `PrmSchema.passthrough()` (in `src/probes/prm.ts`)
and carries `bearer_methods_supported` as `string[] | undefined` on the named field.

`AsMetadata` is set by probe 3 only when issuer validation passes (RFC 8414 §3.3). When the
issuer check fails, `contextUpdates` is suppressed in probe 3, so `ctx.authorizationServerMetadata`
is undefined when probe 6 runs. This is correct: the B1-B3 skip case covers it.

**No `contextUpdates` extension is needed.** Probe 6 returns `{ findings, evidence: [] }` with
no `contextUpdates` key. No new `AuditContext` fields are required. Probe 6 is the final probe
in methodology v1.0 and has no downstream dependents.

Accessing optional passthrough fields (`jwks_uri`, `revocation_endpoint`, `introspection_endpoint`)
requires indexing `AsMetadata` with bracket notation. Because `AsMetadataSchema` uses
`.passthrough()`, the inferred type for unknown-key access is `unknown`. Implementation must
narrow to `string` with a typeof guard before interpolating into observations. This is the
existing pattern in `as-metadata.ts` for passthrough fields.

## Skip-case matrix

| Condition                                        | B1 (`jwks-uri`) | B2 (`revocation`) | B3 (`introspection`) | B4 (`bearer-methods`) |
|--------------------------------------------------|-----------------|-------------------|----------------------|-----------------------|
| AS metadata absent (probe 3 did not run / failed) | `skipped`       | `skipped`         | `skipped`            | depends on PRM        |
| PRM absent (probe 2 did not run / failed)         | evaluable       | evaluable         | evaluable            | `skipped`             |
| Both absent                                       | `skipped`       | `skipped`         | `skipped`            | `skipped`             |
| Both present                                      | evaluable       | evaluable         | evaluable            | evaluable             |

The deferral finding (`06-token-hygiene-live-token-deferred`) is always emitted regardless of
skip state.

## Test plan for probe-engineer

Each branch below specifies the `AuditContext` fixture to construct and the expected finding
output. Use these as the basis for unit tests; no live network calls are needed.

### Fixture A: AS metadata and PRM both absent

```
ctx = { target: new URL("https://example.com") }
// authorizationServerMetadata: undefined
// protectedResourceMetadata: undefined
```

Expected findings:
- `06-token-hygiene-jwks-uri` severity=skipped passed=false
- `06-token-hygiene-revocation-endpoint` severity=skipped passed=false
- `06-token-hygiene-introspection-endpoint` severity=skipped passed=false
- `06-token-hygiene-bearer-methods` severity=skipped passed=false
- `06-token-hygiene-live-token-deferred` severity=skipped passed=false

### Fixture B: AS metadata has all three fields; PRM has `bearer_methods_supported: ["header"]`

```
ctx.authorizationServerMetadata = {
  issuer: "https://as.example.com",
  authorization_endpoint: "https://as.example.com/authorize",
  token_endpoint: "https://as.example.com/token",
  response_types_supported: ["code"],
  jwks_uri: "https://as.example.com/.well-known/jwks.json",
  revocation_endpoint: "https://as.example.com/revoke",
  introspection_endpoint: "https://as.example.com/introspect"
}
ctx.protectedResourceMetadata = {
  resource: "https://example.com",
  authorization_servers: ["https://as.example.com"],
  bearer_methods_supported: ["header"]
}
```

Expected findings:
- `06-token-hygiene-jwks-uri` severity=info passed=true title="JWKS URI advertised"
- `06-token-hygiene-revocation-endpoint` severity=info passed=true title="Revocation endpoint advertised (RFC 7009)"
- `06-token-hygiene-introspection-endpoint` severity=info passed=true title="Introspection endpoint advertised (RFC 7662)"
- `06-token-hygiene-bearer-methods` severity=info passed=true title="bearer_methods_supported restricts to header only"
- `06-token-hygiene-live-token-deferred` severity=skipped passed=false

### Fixture C: AS metadata has none of the three fields; PRM has `bearer_methods_supported: ["query", "header"]`

```
ctx.authorizationServerMetadata = {
  issuer: "https://as.example.com",
  authorization_endpoint: "https://as.example.com/authorize",
  token_endpoint: "https://as.example.com/token",
  response_types_supported: ["code"]
  // no jwks_uri, no revocation_endpoint, no introspection_endpoint
}
ctx.protectedResourceMetadata = {
  resource: "https://example.com",
  authorization_servers: ["https://as.example.com"],
  bearer_methods_supported: ["query", "header"]
}
```

Expected findings:
- `06-token-hygiene-jwks-uri` severity=info passed=false title="JWKS URI not advertised"
- `06-token-hygiene-revocation-endpoint` severity=warn passed=false title="Revocation endpoint not advertised (RFC 7009)"
- `06-token-hygiene-introspection-endpoint` severity=info passed=false title="Introspection endpoint not advertised (RFC 7662)"
- `06-token-hygiene-bearer-methods` severity=warn passed=false title="bearer_methods_supported includes query"
- `06-token-hygiene-live-token-deferred` severity=skipped passed=false

### Fixture D: AS metadata absent; PRM has `bearer_methods_supported: ["form", "header"]`

```
ctx = { target: new URL("https://example.com") }
ctx.protectedResourceMetadata = {
  resource: "https://example.com",
  authorization_servers: ["https://as.example.com"],
  bearer_methods_supported: ["form", "header"]
}
```

Expected findings:
- `06-token-hygiene-jwks-uri` severity=skipped passed=false
- `06-token-hygiene-revocation-endpoint` severity=skipped passed=false
- `06-token-hygiene-introspection-endpoint` severity=skipped passed=false
- `06-token-hygiene-bearer-methods` severity=info passed=false title="bearer_methods_supported includes form but not query"
- `06-token-hygiene-live-token-deferred` severity=skipped passed=false

### Fixture E: PRM present but `bearer_methods_supported` field absent

```
ctx.authorizationServerMetadata = { ... minimal valid ... }
ctx.protectedResourceMetadata = {
  resource: "https://example.com",
  authorization_servers: ["https://as.example.com"]
  // bearer_methods_supported: undefined
}
```

Expected findings for B4:
- `06-token-hygiene-bearer-methods` severity=info passed=false title="bearer_methods_supported not advertised"

### Live target verification

After implementation, run against a live target to confirm no runtime errors and that the
findings match the shapes above. No vendor names in this scope doc; probe-engineer should
select from the known audit targets available in the development environment.

Expected invariants on any live target:
- Exactly five findings emitted (four B-assertions plus the deferral finding).
- Zero evidence files written.
- `contextUpdates` absent from the returned `ProbeResult`.
- `tsc --noEmit` passes before and after probe file is added.

## Acceptance criteria

- [ ] `korrel-cli/docs/PROBE-6-SCOPE.md` exists at this path
- [ ] `src/types.ts` `AuditContext.authorizationServerMetadata` field exists, type `AsMetadata | undefined` (confirmed: line 39)
- [ ] `src/types.ts` `AuditContext.protectedResourceMetadata` field exists, type `Prm | undefined` (confirmed: line 37)
- [ ] No new fields added to `AuditContext` (no `contextUpdates` extension)
- [ ] Probe file exports a function matching `Probe` type: `(ctx: AuditContext) => Promise<ProbeResult>`
- [ ] Probe ID in all emitted finding IDs is `06-token-hygiene` or `06-token-hygiene-{suffix}`
- [ ] Probe returns exactly five findings on any input (four B-assertions + one deferral)
- [ ] Probe returns zero evidence entries in all code paths
- [ ] Probe returns no `contextUpdates` key in the result
- [ ] All five finding IDs match the names in the Finding Shapes table exactly
- [ ] Passthrough-field access (`jwks_uri`, `revocation_endpoint`, `introspection_endpoint`) is
      narrowed with a `typeof x === 'string'` guard before use; no `as` cast, no `@ts-ignore`
- [ ] No `any` types and no `@ts-ignore` comments in the probe file
- [ ] `tsc --noEmit` passes with strict config and `noUncheckedIndexedAccess` after probe file is added
- [ ] Unit test fixtures A-E all produce the expected findings
- [ ] Live-target run produces exactly five findings and zero evidence files
- [ ] Probe registered in the orchestrator probe list after probe 5 (`pkce-enforcement.ts`)

## Open questions

None blocking scope. The following is noted for implementation and does not require a
main-thread decision:

1. The `AsMetadata` type is `z.infer<typeof AsMetadataSchema>` where the schema uses
   `.passthrough()`. TypeScript types passthrough extra keys as `{ [key: string]: unknown }` on
   the base record plus the named fields. Probe-engineer should verify at implementation time
   that bracket-indexing `as["jwks_uri"]` compiles without `noUncheckedIndexedAccess` error.
   If the inferred type does not permit bracket access, the probe should cast to
   `Record<string, unknown>` at the boundary, which is safe given the passthrough contract.

---

## METHODOLOGY.md amendment

See `docs/METHODOLOGY-V1-AMENDMENT.md` for the proposed edits to
`../mcp-audits/METHODOLOGY.md`. Five edits: intro line, §4 (PKCE
deferral note), §5 (token hygiene rewrite), §6 (trim query-string
bullet, add probe-coverage note), References (add RFC 7662).
Probe-engineer does not write to the sibling repo; user copies
edits over after sign-off.
