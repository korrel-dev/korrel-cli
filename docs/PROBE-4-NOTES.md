# PROBE-4-NOTES.md

Reading worksheet for probe 4 (DCR + CIMD). Answer each question
in your own words, not copy-paste from the spec. If a question
doesn't have a clear answer in the source, say so rather than
guessing.

Target file location if committing: `korrel-cli/docs/PROBE-4-NOTES.md`.
Keep local in scratch if you'd rather not commit work-in-progress
thinking.

Total reading time: ~30 minutes. Don't over-research. Plain-English
understanding first, edge cases later.

---

## Source 1: MCP specification, 2025-11-25 authorization section

URL: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization

Read time: ~15 min

### 1.1 Dynamic Client Registration (DCR)

Does the MCP spec **require**, **recommend**, or **permit** DCR? Quote the exact word (MUST / SHOULD / MAY) from the spec.

> MAY

If the AS doesn't support DCR, what does the spec say the client should do? Is there a defined fallback?

> Since DCR is a fallback, the recommended step after that is to "Prompt the user to enter the client information if no other option is available"

### 1.2 Client ID Metadata Documents (CIMD)

Does the spec prefer CIMD over DCR? Quote the language that establishes preference.

> CIMD, DCR is a fallback. "Client ID Metadata Documents: When client and server have no prior relationship (most common). Pre-registration: When client and server have an existing relationship. Dynamic Client Registration: For backwards compatibility or specific requirements"

What problem does CIMD solve that DCR doesn't? (Think: who hosts the client metadata? What trust model differs?)

> It enables clients to use HTTPS URLs as client identifiers.

### 1.3 PKCE

Is PKCE required for MCP clients? Which code challenge methods are allowed? Is `plain` permitted?

> PKCE MUST be implemented according to OAuth 2.1 Section 7.5.2.

Who is responsible for enforcing PKCE: the client, the authorization server, or both?

> Client

### 1.4 Resource Indicators (RFC 8707)

Where and when does the spec require `resource` parameters on authorization and token requests?

> Resource parameters are to specify the target resource for which the token is being requested.

How does the spec describe audience binding? Is it MUST, SHOULD, or MAY?

> MUST

### 1.5 Session semantics

Does the spec define anything about session lifecycle, token refresh, re-authentication, or revocation flows? If yes, summarize in one sentence. If no, say so.

> The spec reccomends rotating refresh tokens, to reduce the impact of leaked tokens. Good practice.

---

## Source 2: RFC 7591 (Dynamic Client Registration)

URL: https://datatracker.ietf.org/doc/html/rfc7591

Read time: ~10 min. Skim §2 (metadata) and §3 (registration endpoint). Skip everything else.

### 2.1 The registration request

A client POSTs to the `registration_endpoint`. What Content-Type does the body use?

> "application/json"

What's the minimum set of fields a client must send? (Hint: look for any required fields in §2.)

> 6

What are 3-4 common optional fields a client might send?

> client_name, scope, contacts, software_id

### 2.2 The registration response

What status code does a successful registration return?

> A client identifier

What fields does the AS return in the body? Which are required in the response?

> authorization_code, implicit, password, client_credentials, refresh_token, urn:ietf:params:oauth:grant-type:jwt-bearer, urn:ietf:params:oauth:grant-type:saml2-bearer

Specifically: does the response always include `client_secret`? When might it not?

> It doesnt always, only when the client uses HTTP

### 2.3 Error cases

What does a failed registration look like? Status code + body shape.

>  When an OAuth 2.0 error condition occurs, such as the client presenting an invalid initial access token, the authorization server returns an error response appropriate to the OAuth 2.0 token type.
 Two members are defined for inclusion in the JSON object:

   error
      REQUIRED.  Single ASCII error code string.

   error_description
      OPTIONAL.  Human-readable ASCII text description of the error used
      for debugging.

   Other members MAY also be included and, if they are not understood,
   they MUST be ignored.

   This specification defines the following error codes:

   invalid_redirect_uri
      The value of one or more redirection URIs is invalid.

   invalid_client_metadata
      The value of one of the client metadata fields is invalid and the
      server has rejected this request.  Note that an authorization
      server MAY choose to substitute a valid value for any requested
      parameter of a client's metadata.

   invalid_software_statement
      The software statement presented is invalid.

   unapproved_software_statement
      The software statement presented is not approved for use by this
      authorization server.

Name one specific error code defined in the RFC.

> invalid_client_metadata

---

## Source 3: CIMD draft

Find the latest draft. Likely URL: https://datatracker.ietf.org/doc/draft-parecki-oauth-client-id-metadata-document/

If the Parecki draft doesn't resolve, search for "Client ID Metadata Document OAuth draft" and find the current version. Note the draft version number you read.

Draft version read: ______

Read time: ~5 min. Abstract + §1-2 only.

### 3.1 Client ID structure

How is a CIMD Client ID formatted? Is it an opaque string (like DCR) or a URL?

> URL

What's at that URL when the AS fetches it?

> A document containing the necessary client Metadata

### 3.2 The metadata document

What fields are in a CIMD metadata document? How does this compare to RFC 7591's client metadata?

> Application name, icon and redirect URIs.

### 3.3 Trust model

DCR: AS generates the `client_id` and trusts what the client registered. CIMD: ?

Fill in. What's the trust model shift?

> The client must establish and provide a unique identifier.

---

## Synthesis: what probe 4 should check

After reading the above, list specific testable assertions probe 4 should check. Format: one line each, imperative.

Example format (don't copy these, write your own from what you learned):
- AS metadata advertises `registration_endpoint`
- POST to registration endpoint with minimal body returns 201 and a `client_id`
- Registered client can be used for an authorization request

Your list:  

- Whether DCR returns the right fields.
- Sessions, find structural gaps
- Complete a registration and see what code it returns.
- ...

---

## Open questions

Things you read that you don't understand, or that seem ambiguous.
Don't feel obligated to resolve them yourself. Flag them here and
we'll discuss Thursday before coding.

- Difference betweena field and status code
- (question 2)
- ...

---

## Reading log

Filled in after finishing, not during.

- Start time: 11pm
- End time: 11:45pm
- Hardest source to parse: The second one
- Most surprising finding: The DCR just trusts what the client put in.
