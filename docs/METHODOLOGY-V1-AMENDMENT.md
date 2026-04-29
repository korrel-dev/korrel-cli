# METHODOLOGY.md v1.0 amendment for probe 6

This file holds the proposed edits to `../mcp-audits/METHODOLOGY.md`,
ready for the user to copy over after sign-off. Probe-engineer does
not write to the sibling repo.

The amendment lands alongside probe 6 implementation. It rebalances
the methodology so that the published §4-§6 sections describe what
korrel-cli v1.0 actually probes, rather than the original aspirational
coverage. Probes 5 and 6 each carry one explicit architectural
deferral; the closing line acknowledges both.

The amendment is structured as five edits against the current file
(read at line ranges noted in each edit header). Apply them in order.

---

## Edit 1: introductory paragraph (line 2)

**Replace:**

```
*Version 1.0, April 2026. OAuth 2.1 + MCP spec compliance scope. See [Roadmap](#roadmap) for planned extensions.*
```

**With:**

```
*Version 1.0, April 2026. OAuth 2.1 + MCP spec compliance scope. 6 probes implemented; probes 5 and 6 each carry one documented architectural deferral. See [Roadmap](#roadmap) for planned extensions.*
```

---

## Edit 2: §4 PKCE enforcement (lines 83-98)

PKCE stays at §4. Soften the verifier-mismatch sentence in the body
to a forward reference, and append an architectural-deferral note.

**Replace:**

```
## 4. PKCE enforcement

PKCE advertised in metadata is not the same as PKCE enforced on
the token endpoint. Initiate an authorization code flow without
sending `code_challenge`, and separately with `code_challenge_method=plain`.
Both should be rejected. Additionally, attempt token exchange with
a mismatched `code_verifier`; the token endpoint must reject.

**What this tests:** Whether PKCE is actually required, not
merely supported. A server that advertises `S256` but accepts
requests without a challenge provides no protection against
authorization code interception.

**Common failures:** PKCE advertised but not enforced; `plain`
accepted when only `S256` is advertised; verifier mismatch not
rejected.
```

**With:**

```
## 4. PKCE enforcement

PKCE advertised in metadata is not the same as PKCE enforced at
the authorization endpoint. Initiate an authorization code flow
without sending `code_challenge`, and separately with
`code_challenge_method=plain`. Both should be rejected. Token-endpoint
verifier-mismatch enforcement is a separate test; see the
architectural note below.

**What this tests:** Whether PKCE is actually required, not
merely supported. A server that advertises `S256` but accepts
requests without a challenge provides no protection against
authorization code interception.

**Common failures:** PKCE advertised but not enforced; `plain`
accepted when only `S256` is advertised.

**Architectural note:** Verifier-mismatch enforcement at the
token endpoint is deferred. Obtaining an authorization code
requires user consent, which a headless CLI cannot provide.
Tracked for a future browser-harness probe.
```

---

## Edit 3: §5 Token hygiene (lines 100-114)

Replace body with metadata-signals prose. Section title stays
"Token hygiene". Live-token deferral is explicit in the body.

**Replace:**

```
## 5. Token hygiene

Examine issued tokens for: audience binding per RFC 8707 (where
JWT tokens are used, the `aud` claim must match the MCP resource;
where opaque tokens are used, binding should be enforced
server-side), reasonable expiry (bearer tokens should be short-lived,
typically under one hour), and storage practices advertised in
SDK documentation.

**What this tests:** Whether tokens are scoped to the correct
resource and whether a leaked token has a bounded blast radius.

**Common failures:** JWT tokens without `aud` claim (token
confusion across resources); excessive token lifetime; SDK
guidance that stores tokens in insecure locations.
```

**With:**

```
## 5. Token hygiene

Full token hygiene testing requires a real access token:
audience-claim binding (RFC 8707 `aud`), token expiry, and
storage-practice review are all contingent on completing an
OAuth flow. A headless CLI cannot obtain a token without browser
interaction. v1.0 therefore restricts itself to metadata-derivable
signals.

Three signals come from AS metadata (RFC 8414 §2):

- `jwks_uri` presence: indicates JWT-format tokens; enables
  offline validation. Absence indicates opaque tokens or an
  undocumented token format. Neither is a violation; this is
  an informational observation.
- `revocation_endpoint` presence (RFC 7009): enables clients
  and resource servers to invalidate issued tokens before
  expiry. Absence is a defense-in-depth gap: leaked tokens
  remain valid until they expire.
- `introspection_endpoint` presence (RFC 7662): enables
  Resource Servers to validate opaque tokens. Informational;
  no SHOULD or MUST applies to advertisement.

One signal comes from Protected Resource Metadata (RFC 9728 §3):

- `bearer_methods_supported` values (RFC 6750 §2.3): if `query`
  is advertised, bearer tokens may appear in URIs, which end up
  in access logs and Referer headers (RFC 6750 §5.3 advises
  against this).

**What this tests:** Whether the AS and Resource Server advertise
the controls that bound the blast radius of a leaked token.

**Common failures:** No `revocation_endpoint` in AS metadata;
`bearer_methods_supported` includes `query`; `jwks_uri` absent
with no other token-format signal.

**Architectural note:** aud-claim inspection, token expiry
verification, and storage-practice review require a real access
token and are deferred. Tracked for a future browser-harness
probe. v1.0 closes with 6 probes implemented; probes 5 and 6
each carry one documented architectural deferral.
```

---

## Edit 4: §6 Ancillary controls (lines 116-130)

Trim only the URL-borne-token bullet (now covered by §5
`bearer_methods_supported`). Keep state/CSRF, HSTS, and security
headers. Add a probe-coverage note.

**Replace:**

```
## 6. Ancillary controls

Verify: the authorization endpoint requires `state` and checks
it on callback (CSRF defense); transport is HTTPS-only with HSTS;
tokens are never accepted in query strings or URL fragments;
security headers are present (`Strict-Transport-Security`,
`X-Content-Type-Options: nosniff`, appropriate `Content-Security-Policy`).

**What this tests:** Defense-in-depth at the transport and browser
layers. None of these are unique to MCP, but all are common
rollout gaps.

**Common failures:** Tokens accepted in query strings
(`bearer_methods_supported` including `query`); missing HSTS;
no state parameter enforcement.
```

**With:**

```
## 6. Ancillary controls

Verify: the authorization endpoint requires `state` and echoes
it on callback (CSRF defense, RFC 6749 §10.12); transport is
HTTPS-only with HSTS; security headers are present
(`Strict-Transport-Security`, `X-Content-Type-Options: nosniff`,
appropriate `Content-Security-Policy`).

**What this tests:** Defense-in-depth at the transport and browser
layers. None of these are unique to MCP, but all are common
rollout gaps.

**Common failures:** Missing or unechoed `state` parameter;
missing HSTS; absent or weak browser security headers.

**Probe coverage in v1.0:** State/CSRF is partially probed by
probe 5's state-echo assertion on 3xx-to-redirect_uri responses
(RFC 6749 §10.12). HSTS and browser security headers are not
currently probed by korrel-cli v1.0.
```

---

## Edit 5: References section (lines 183-193)

Add RFC 7662 immediately after RFC 7009 (already listed).

**Insert after the existing line `- RFC 7009: Token Revocation`:**

```
- RFC 7662: Token Introspection
```

---

## Verification checklist after applying

- [ ] Intro line shows "6 probes implemented; probes 5 and 6 each carry one documented architectural deferral."
- [ ] §4 title is still "PKCE enforcement"; body no longer asserts a verifier-mismatch test as something the methodology runs
- [ ] §4 carries the architectural-deferral note for verifier-mismatch
- [ ] §5 title is still "Token hygiene" (no subtitle)
- [ ] §5 body lists jwks_uri / revocation_endpoint / introspection_endpoint / bearer_methods_supported
- [ ] §5 carries the architectural-deferral note for live-token hygiene and the v1.0 closing line
- [ ] §6 title is still "Ancillary controls"
- [ ] §6 body keeps state/CSRF, HSTS, security headers; query-string bullet removed
- [ ] §6 carries the probe-coverage note
- [ ] References section lists RFC 7662 after RFC 7009
- [ ] No other sections changed
