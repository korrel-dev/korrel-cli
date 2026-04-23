# PROBE-4 Scope: DCR endpoint validation and CIMD advertisement

## Background

Probe 4 covers methodology step 3 (client registration surface). It tests three concerns
against the Authorization Server metadata already loaded by probe 3: whether a Dynamic Client
Registration endpoint (RFC 7591) is present and well-formed; whether redirect URI validation
is strict when DCR is active; and whether the AS advertises Client ID Metadata Document support
per draft-ietf-oauth-client-id-metadata-document-01. The MCP spec (2025-11-25 §2.3) treats
CIMD as the preferred client identification method and DCR as a backwards-compatibility fallback,
so probe 4 checks both paths. Probes 5 and 6 depend on `AuditContext.registeredClient` populated
here when DCR succeeds.

## In scope

- Read `AuditContext.authorizationServerMetadata` (set by probe 3). If absent, emit one
  skip finding and return immediately.
- Passive: inspect AS metadata for `registration_endpoint`. Emit an info finding on presence
  or absence. No network request needed for this check.
- Passive: inspect AS metadata for `client_id_metadata_document_supported`. Emit an info
  finding whether it is present-and-true or absent/false. No network request needed.
- Active (only when `registration_endpoint` is present): POST exactly three registration
  requests and record each as a separate evidence file.
  1. Valid baseline: single HTTPS redirect URI, `grant_types=["authorization_code"]`,
     `response_types=["code"]`, `token_endpoint_auth_method=none`.
  2. HTTP redirect URI with `token_endpoint_auth_method=client_secret_basic` (confidential
     client). Per RFC 7591 §5 MUST, the AS must reject this.
  3. Host mismatch: `redirect_uri` host differs from `client_uri` host. Per RFC 7591 §5
     SHOULD, the AS should reject this.
- Populate `AuditContext.registeredClient` via `contextUpdates` when test 1 succeeds (HTTP
  201 with `client_id` present in body, or HTTP 200 with `client_id` present in body per the
  resolved 200-handling rule below). Future probes 5 and 6 will consume this field.
- Write one evidence file per active POST (three files when DCR is present).

## Out of scope

- Full CIMD flow test: exercising a CIMD client identifier end-to-end requires hosting a
  `client_id` URL with a metadata document. Infrastructure not available. Flag-only check
  for this probe.
- Software statement validation (RFC 7591 §2.3): no initial access tokens are available for
  target servers; out of scope for all v1 probes.
- Client registration management (RFC 7592): read/update/delete of registered clients is a
  separate protocol extension. Not tested here.
- Token endpoint auth method verification: the probe sends `token_endpoint_auth_method` in
  registration payloads as stimulus only. Whether the AS enforces that method at the token
  endpoint is tested in probe 5 (PKCE enforcement) and probe 6 (token hygiene).
- PKCE enforcement testing: that is probe 5.
- Deletion of stale client records created by test 1: the valid baseline POST creates one
  record per target. This is accepted and disclosed in the Footprint section below.
- Testing multiple `authorization_servers` entries: probe 4 operates on whichever AS probe 3
  resolved (first entry). Multi-AS coverage is a roadmap item.
- Cleanup of test 2 and test 3 client records if those POSTs unexpectedly return 201: the
  probe records the anomaly as a finding but does not attempt deletion.

## Normative assertions being tested

| Level    | Clause                   | Probe observation                                                                      |
|----------|--------------------------|----------------------------------------------------------------------------------------|
| MUST     | RFC 7591 §3              | Registration endpoint accepts HTTP POST with `Content-Type: application/json`          |
| MUST     | RFC 7591 §3              | Registration endpoint is TLS-protected (HTTPS URL in AS metadata)                     |
| MUST     | RFC 7591 §3.2.1          | Successful registration returns HTTP 201 with `Content-Type: application/json`         |
| MUST     | RFC 7591 §3.2.2          | Error response returns HTTP 400 with JSON body containing `error` field                |
| MUST     | RFC 7591 §5              | AS must require clients to register redirect URIs for redirect-based grants            |
| MUST     | RFC 7591 §5              | HTTP redirect URIs must be rejected for confidential clients                           |
| SHOULD   | RFC 7591 §5              | AS should check host/scheme match between `client_uri` and `redirect_uris`             |
| OPTIONAL | CIMD draft §5            | `client_id_metadata_document_supported` is an optional boolean in AS metadata. CIMD field name verified against draft-ietf-oauth-client-id-metadata-document-01 §5 on 2026-04-23. |

Note: the METHODOLOGY.md step 3 description aligns with these assertions. No methodology
delta is present; probe 4 implements step 3 as written.

## Control flow

```
function probe4(ctx):

  // Guard: require upstream AS metadata
  if ctx.authorizationServerMetadata is absent:
    emit finding(severity=skipped, title="DCR/CIMD probe skipped: AS metadata not available",
                 detail="Probe 3 did not populate authorizationServerMetadata; probe 4 cannot run.")
    return { findings, evidence=[] }

  as = ctx.authorizationServerMetadata

  // --- Concern (c): CIMD flag check (passive) ---
  cimdSupported = as["client_id_metadata_document_supported"]
  if cimdSupported is true:
    emit finding(severity=info, title="CIMD advertised",
                 detail="AS metadata sets client_id_metadata_document_supported=true.")
  else:
    emit finding(severity=info, title="CIMD not advertised",
                 detail="client_id_metadata_document_supported absent or false in AS metadata.")

  // --- Concern (a): DCR endpoint discovery (passive) ---
  registrationEndpoint = as["registration_endpoint"]
  if registrationEndpoint is absent:
    emit finding(severity=info, title="DCR not advertised",
                 detail="AS metadata does not include registration_endpoint.")
    return { findings, evidence }

  // Verify TLS on registration endpoint URL
  if registrationEndpoint does not start with "https://":
    emit finding(severity=issue, title="DCR endpoint not TLS-protected",
                 detail="registration_endpoint={url} uses non-HTTPS scheme (RFC 7591 §3 MUST).")

  emit finding(severity=info, title="DCR advertised",
               detail="AS metadata registration_endpoint={url}.")

  // --- Concern (b): active redirect URI validation (three POSTs maximum) ---

  // POST 1: valid baseline
  payload1 = {
    client_name: "korrel-cli audit probe",
    client_uri: "https://korrel.dev",
    redirect_uris: ["https://korrel.dev/callback"],
    grant_types: ["authorization_code"],
    response_types: ["code"],
    token_endpoint_auth_method: "none"
  }
  response1 = POST registrationEndpoint, body=payload1, Content-Type=application/json
  write evidence file 04-dcr-register-valid.http

  // Check status first, then body validity, then emit and optionally populate context.
  if response1.status == 201:
    if response1.body.client_id present:
      emit finding(severity=info, title="DCR valid registration accepted",
                   detail="POST returned 201 with client_id={id}.")
      set contextUpdates.registeredClient = response1.body
    else:
      emit finding(severity=info, title="DCR valid registration not accepted",
                   detail="POST returned HTTP {status}; body: {body_excerpt}.")
  else if response1.status == 200:
    if response1.body.client_id present:
      emit finding(severity=warn, title="DCR registration response uses HTTP 200 instead of 201",
                   detail="POST returned 200 with client_id={id}. RFC 7591 §3.2.1 MUST requires HTTP 201 for successful registration.")
      set contextUpdates.registeredClient = response1.body
    else:
      emit finding(severity=issue, title="DCR registration returned 200 but response lacks valid client_id",
                   detail="POST returned 200 but body does not contain a valid client_id. RFC 7591 §3.2.1 MUST requires HTTP 201 and a client_id in the response body.")
      // Do NOT populate contextUpdates.registeredClient
  else:
    emit finding(severity=info, title="DCR valid registration not accepted",
                 detail="POST returned HTTP {status}; body: {body_excerpt}.")

  // POST 2: HTTP redirect URI for confidential client (MUST violation probe)
  // redirect_uri uses HTTP scheme; host matches client_uri to isolate scheme as the sole variable.
  payload2 = {
    client_name: "korrel-cli audit probe",
    client_uri: "https://korrel.dev",
    redirect_uris: ["http://korrel.dev/callback"],
    grant_types: ["authorization_code"],
    response_types: ["code"],
    token_endpoint_auth_method: "client_secret_basic"
  }
  response2 = POST registrationEndpoint, body=payload2, Content-Type=application/json
  write evidence file 04-dcr-register-http-redirect.http

  if response2.status == 201:
    emit finding(severity=issue, title="DCR accepted HTTP redirect URI for confidential client",
                 detail="POST returned 201; HTTP redirect URIs must be rejected for confidential clients (RFC 7591 §5 MUST).")
  else:
    emit finding(severity=info, title="DCR rejected HTTP redirect URI for confidential client",
                 detail="POST returned HTTP {status} as expected (RFC 7591 §5).")

  // POST 3: host mismatch between client_uri and redirect_uri (SHOULD violation probe)
  payload3 = {
    client_name: "korrel-cli audit probe",
    client_uri: "https://korrel.dev",
    redirect_uris: ["https://other-host.example.com/callback"],
    grant_types: ["authorization_code"],
    response_types: ["code"],
    token_endpoint_auth_method: "none"
  }
  response3 = POST registrationEndpoint, body=payload3, Content-Type=application/json
  write evidence file 04-dcr-register-host-mismatch.http

  if response3.status == 201:
    emit finding(severity=warn, title="DCR accepted host-mismatched redirect URI",
                 detail="POST returned 201; redirect_uri host differs from client_uri host. AS SHOULD reject this (RFC 7591 §5 SHOULD).")
  else:
    emit finding(severity=info, title="DCR rejected host-mismatched redirect URI",
                 detail="POST returned HTTP {status}. Host mismatch check is enforced.")

  return { findings, evidence, contextUpdates }
```

## Finding shapes

| Severity  | Title                                                                  | Detail template                                                                                                                                                                      |
|-----------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `skipped` | DCR/CIMD probe skipped: AS metadata not available                     | Probe 3 did not populate authorizationServerMetadata; probe 4 cannot run.                                                                                                            |
| `info`    | CIMD advertised                                                       | AS metadata sets client_id_metadata_document_supported=true.                                                                                                                         |
| `info`    | CIMD not advertised                                                   | client_id_metadata_document_supported absent or false in AS metadata.                                                                                                                |
| `info`    | DCR not advertised                                                    | AS metadata does not include registration_endpoint.                                                                                                                                  |
| `info`    | DCR advertised                                                        | AS metadata registration_endpoint={url}.                                                                                                                                             |
| `issue`   | DCR endpoint not TLS-protected                                        | registration_endpoint={url} uses non-HTTPS scheme (RFC 7591 §3 MUST).                                                                                                               |
| `info`    | DCR valid registration accepted                                       | POST returned 201 with client_id={id}.                                                                                                                                               |
| `warn`    | DCR registration response uses HTTP 200 instead of 201               | POST returned 200 with client_id={id}. RFC 7591 §3.2.1 MUST requires HTTP 201 for successful registration. Context populated; downstream probes may proceed.                         |
| `issue`   | DCR registration returned 200 but response lacks valid client_id      | POST returned 200 but body does not contain a valid client_id. RFC 7591 §3.2.1 MUST requires HTTP 201 and a client_id in the response body. Context not populated.                   |
| `info`    | DCR valid registration not accepted                                   | POST returned HTTP {status}; body: {body_excerpt}.                                                                                                                                   |
| `issue`   | DCR accepted HTTP redirect URI for confidential client                | POST returned 201; HTTP redirect URIs must be rejected for confidential clients (RFC 7591 §5 MUST).                                                                                  |
| `info`    | DCR rejected HTTP redirect URI for confidential client                | POST returned HTTP {status} as expected (RFC 7591 §5).                                                                                                                               |
| `warn`    | DCR accepted host-mismatched redirect URI                             | POST returned 201; redirect_uri host differs from client_uri host. AS SHOULD reject this (RFC 7591 §5 SHOULD).                                                                       |
| `info`    | DCR rejected host-mismatched redirect URI                             | POST returned HTTP {status}. Host mismatch check is enforced.                                                                                                                        |

Severity vocabulary used: `info`, `warn`, `issue`, `skipped`. These match `Severity` in
`src/types.ts`. The `critical` level is reserved for the orchestrator; probe 4 does not emit it.
See `docs/SEVERITY.md` for canonical definitions.

## Evidence files

| File name                          | Written when                              | Contents                                                    |
|------------------------------------|-------------------------------------------|-------------------------------------------------------------|
| `04-dcr-register-valid.http`       | When `registration_endpoint` is present   | POST request + response for valid baseline registration     |
| `04-dcr-register-http-redirect.http` | When `registration_endpoint` is present | POST request + response for HTTP-scheme redirect URI        |
| `04-dcr-register-host-mismatch.http` | When `registration_endpoint` is present | POST request + response for host-mismatched redirect URI    |

No CIMD evidence file is written. The CIMD flag check reads `client_id_metadata_document_supported`
from `AuditContext.authorizationServerMetadata`, which was captured by probe 3's evidence file
`03-as-metadata.http`. Writing a duplicate is unnecessary.

## Footprint

Probe 4 is the former first probe in korrel-cli to write state to a remote server. The footprint is
bounded and intentional:

- POST 1 (valid baseline) creates one stale OAuth client record on the target AS. This record
  is identified by `client_name="korrel-cli audit probe"` and `client_uri="https://korrel.dev"`,
  allowing operators to locate and delete it. Probe 4 does not delete it; RFC 7592 client
  management is out of scope and not universally supported.
- Posts 2 and 3 are expected to be rejected by a conformant AS and therefore create no records.
  If either unexpectedly returns 201, the probe records the finding but does not attempt
  deletion. The operator is responsible for cleanup of any such records.
- Three POSTs maximum per target where DCR is enabled. No network requests otherwise.
- Disclosure emails for DCR-enabled targets will reference this footprint explicitly.

## Verification

### Target 1: Linear (`https://mcp.linear.app/mcp`)

Probe 3 is expected to have populated AS metadata that includes both `registration_endpoint`
and `client_id_metadata_document_supported=true`. Expected probe 4 output:

- Finding: "CIMD advertised" (info)
- Finding: "DCR advertised" with `registration_endpoint` URL (info)
- Finding: one of "DCR valid registration accepted" (info, 201), "DCR registration response
  uses HTTP 200 instead of 201" (warn, 200 + valid body), "DCR registration returned 200
  but response lacks valid client_id" (issue, 200 + no body), or "DCR valid registration not
  accepted" (info, other status) depending on the server's behavior
- Evidence: `04-dcr-register-valid.http`, `04-dcr-register-http-redirect.http`,
  `04-dcr-register-host-mismatch.http` written
- Finding: "DCR rejected HTTP redirect URI for confidential client" (info) or
  "DCR accepted HTTP redirect URI for confidential client" (issue) depending on enforcement
- Finding: "DCR rejected host-mismatched redirect URI" (info) or
  "DCR accepted host-mismatched redirect URI" (warn) depending on enforcement
- `contextUpdates.registeredClient` populated if POST 1 returned 201 with valid body, or
  200 with valid body

### Target 2: GitHub (`https://api.githubcopilot.com/mcp`)

Evidence at `mcp-audits/audits/github/evidence/03-as-metadata.json` shows the GitHub AS
metadata (`https://github.com/login/oauth`) contains no `registration_endpoint` field and no
`client_id_metadata_document_supported` field. Expected probe 4 output:

- Finding: "CIMD not advertised" (info)
- Finding: "DCR not advertised" (info)
- No evidence files written
- No active POST requests made
- `contextUpdates` empty or absent

### Target 3: Atlassian (`https://mcp.atlassian.com/v1/sse`)

Probe 2 (PRM) failed on this target and probe 3 (AS metadata) did not run. Therefore
`AuditContext.authorizationServerMetadata` is absent when probe 4 runs. Expected probe 4 output:

- Finding: "DCR/CIMD probe skipped: AS metadata not available" (skipped)
- No evidence files written
- No network requests made

## Acceptance criteria

- [ ] `korrel-cli/docs/PROBE-4-SCOPE.md` exists at this path
- [ ] `src/types.ts` `AuditContext.authorizationServerMetadata` field exists (confirmed: yes, type `AsMetadata | undefined`)
- [ ] `src/types.ts` `AuditContext.registeredClient` field exists (confirmed: yes, type `unknown | undefined`)
- [ ] `src/types.ts` `Severity` union includes `'warn'` (confirmed: used for host-mismatch finding and 200-status finding)
- [ ] Probe file (when written) exports a function matching `Probe` type: `(ctx: AuditContext) => Promise<ProbeResult>`
- [ ] Probe returns early with a single info finding when `ctx.authorizationServerMetadata` is absent
- [ ] Probe writes zero evidence files when `ctx.authorizationServerMetadata` is absent
- [ ] Probe writes zero evidence files when `registration_endpoint` is absent from AS metadata
- [ ] Probe writes 0 to 3 evidence files: zero when AS metadata absent or DCR absent, three when DCR present.
- [ ] Probe makes exactly three POST requests when `registration_endpoint` is present, no more
- [ ] `contextUpdates.registeredClient` is set when POST 1 returns HTTP 201 with a parseable `client_id`, or HTTP 200 with a parseable `client_id`; it is not set when POST 1 returns HTTP 200 without a valid `client_id`, or any other non-201 status
- [ ] All three evidence file names match the names in the Evidence Files table exactly (no magic strings elsewhere in the codebase)
- [ ] `tsc --noEmit` passes with strict config and `noUncheckedIndexedAccess` after probe file is added
- [ ] No `any` types and no `@ts-ignore` comments in the probe file
- [ ] Probe verified against Linear target: all three evidence files produced, findings match expected shapes above
- [ ] Probe verified against GitHub target: no evidence files written, two info findings emitted
- [ ] Probe verified against Atlassian target: no evidence files, one skipped finding emitted

## Open questions

None blocking scope. The following is noted for implementation time and does not require a
main-thread decision before work proceeds:

1. Linear's DCR endpoint behavior under public (no initial access token) registration is
   unknown from current evidence. The probe will record whichever HTTP status is returned.
   No pre-judgment on pass/fail is made in this scope doc.
