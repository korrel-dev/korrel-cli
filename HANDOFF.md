# HANDOFF.md

Session handoff prompt for Claude Code. Wed 22 Apr 2026 evening software block.

## How to use

Start Claude Code from the repo root, then say: **"Read `HANDOFF.md` and follow it. Start with step 1."**

---

## Context

Korrel is an MCP-native auth and observability platform. `korrel-cli` is the first software deliverable: a CLI that automates the 6-step audit methodology documented at [`korrel-dev/mcp-audits/METHODOLOGY.md`](https://github.com/korrel-dev/mcp-audits/blob/main/METHODOLOGY.md). The CLI dogfoods Korrel's public weekly audit series and becomes the seed of the broader product.

**Read before proposing anything:**

- `README.md`, `package.json`, `tsconfig.json`
- Everything in `src/`
- `../mcp-audits/METHODOLOGY.md` (clone the sibling repo if it isn't already present)

## Current state

Commit `be187c2` on `main`. Scaffold plus probe 1 (discovery, RFC 9728) works end-to-end. Validated against `https://api.githubcopilot.com/mcp`; output matches the hand-captured evidence in `../mcp-audits/audits/github/evidence/`.

GitHub's server returns `error="invalid_request"` on unauthenticated requests, which is a spec nit (RFC 6750 §3.1 says `invalid_token` is the correct value for an unauthenticated request). Probe 1 currently misses this.

## Design decisions already agreed

These came out of a short design exchange before this handoff. Do not re-propose.

**`AuditContext` shape:** a plain struct threaded through probes, populated as discovery happens. Fields: `target: URL`, plus optional fields populated by later probes (`protectedResourceMetadataUrl`, `protectedResourceMetadata`, `authorizationServers`, `authorizationServerMetadata`, `registrationEndpoint`, `tokenEndpoint`, `authorizationEndpoint`, `registeredClient`).

**Metadata fields in `AuditContext`** (`protectedResourceMetadata`, `authorizationServerMetadata`) start as `unknown` but get properly typed as `z.infer<typeof schema>` once probe 2 and probe 3 define their zod schemas. Mark with `// TODO: type after probe N defines schema` until then. Downstream probes read these fields as the inferred types; no re-validation.

**`ProbeResult` shape:**

```typescript
interface ProbeResult {
  findings: Finding[];           // zero or more, ordered
  evidence: NamedEvidence[];     // zero or more HTTP exchanges
  contextUpdates?: Partial<AuditContext>;
}
interface NamedEvidence {
  name: string;                  // filename stem, e.g. "01-discovery"
  evidence: Evidence;
}
type Probe = (ctx: AuditContext) => Promise<ProbeResult>;
```

The orchestrator writes each evidence item to `evidence/<name>.http` and merges `contextUpdates` into the context for downstream probes.

**Probes stay 1:1 with methodology steps.** Probe 2 is PRM fetch (one evidence file), probe 3 is AS metadata (one evidence file). Don't merge them into one probe using the `NamedEvidence[]` array. The array exists for probes that genuinely need multiple exchanges (e.g. probe 4 may hit both `/register` for DCR and the CIMD fallback).

**Probes fail gracefully.** A probe that throws is caught by the orchestrator, recorded as a `severity: 'issue'` finding with the error message as an observation, and remaining probes still run. No probe can halt the audit.

## Tonight's scope, in order

### Step 1. Write `docs/DESIGN.md`

Before any code. Short prose doc pinning the abstractions. Answer these five questions in flowing paragraphs, not bullet lists:

1. What is a probe?
2. How do probes compose?
3. What's the contract between orchestrator and probe?
4. Why `.http` files for evidence?
5. Why zod for validation?

Also document the "probes fail gracefully" rule.

No em-dashes. Concise. Commit as `docs: pin probe/orchestrator design (v0)`.

### Step 2. Refactor scaffold to match the design

Introduce `AuditContext` as a typed object threaded through probes. Change probes to return `ProbeResult`. Orchestrator wraps each probe call in try/catch; uncaught throws become `severity: 'issue'` findings.

Keep probe 1 as `01-discovery` but ensure the ID is emitted consistently in report and evidence filename.

### Step 3. Sharpen probe 1

Add RFC 6750 §3.1 spec-correctness check on the `error` parameter of `WWW-Authenticate`. Valid values: `invalid_request`, `invalid_token`, `insufficient_scope`. For an unauthenticated request, `invalid_token` is the correct response. Flag deviations as observations but don't fail the probe on them; structural presence (401 plus PRM link) is still the pass criterion.

Replace the fragile regex with a proper `WWW-Authenticate` parser that handles quoted values, comma-separated params, and missing quotes. Test it against the GitHub response already captured in evidence.

### Step 4. Add probe 2: PRM fetch and validation

Fetches the `resource_metadata` URL discovered by probe 1. Captures as `evidence/02-prm.http`. Parses body as JSON. Validates with zod per RFC 9728 §3:

- **Required:** `resource` (string, URI), `authorization_servers` (array of URI strings)
- **Recommended:** `scopes_supported`, `bearer_methods_supported`, `resource_documentation`, `resource_signing_alg_values_supported`
- Check `resource` matches the audited URL's origin and path prefix (RFC 9728 §3.3)
- Check at least one `authorization_servers` entry is present

Export `contextUpdates` with the parsed PRM and the AS URLs for probe 3 to consume.

### Step 5. Scaffold probe 3: AS metadata

Fetch `/.well-known/oauth-authorization-server` from each discovered AS URL per RFC 8414. Validate with zod:

- **Required:** `issuer`, `authorization_endpoint`, `token_endpoint`, `response_types_supported`
- **PKCE:** `code_challenge_methods_supported` must include `S256`
- **Grant types:** `grant_types_supported` should include `authorization_code`; flag if `password` or `implicit` are advertised

Evidence: `evidence/03-as-metadata.http`. Deeper checks (e.g. RFC 8414 §3.1 path-insertion form) can land next session.

### Step 6. Run against multiple real servers before committing

Targets:

- `https://api.githubcopilot.com/mcp` (known-good baseline, diff vs manual audit)
- Linear's MCP endpoint (Audit 02 target for next week)
- Any public Postgres MCP deployment you can find, or spin one up locally
- One or two more from the MCP directory if accessible

Diverse inputs reveal fragility. Note anything surprising in a running `NOTES.md` or GitHub issue; audit post material.

### Step 7. Commit in clean chunks

One commit per logical step: design doc, refactor, probe 1 sharpening, probe 2, probe 3 scaffold, orchestrator resilience. Declarative short messages. RFCs cited inline where they load-bear. No AI tells. No em-dashes.

### Step 8. Add `docs/ROADMAP.md` before quitting

Table of the 6 probes with status: implemented, scaffolded, pending. Updated on every probe landing. README "Status" section links to this doc.

## Constraints

- TypeScript, Node 22+, ESM, strict tsconfig with `noUncheckedIndexedAccess`
- No new deps beyond `commander` and `zod`
- `.http` evidence format matches `src/evidence.ts`
- No tests tonight (vitest lands when probe 3 is fully complete)
- No CI workflow
- No npm publish
- No README rewrite beyond the Status section update

## Writing and code style

Commit messages, comments, docs: declarative, no em-dashes, no emoji, no AI tells.

**Banned phrases:** "dive into", "unpack", "crucial", "pivotal", "genuinely", "worth noting", "in today's rapidly evolving", "let's explore", "buckle up", "delve", "navigate the landscape", "in the realm of", "myriad", "tapestry", "moreover", "furthermore", "in essence", "at the end of the day", "it's important to note", "that being said", "when it comes to".

Reference RFCs inline as `(RFC 8414 §3.1)`. Voice models: Latacora, Filippo Valsorda, rachelbythebay.

**Code:** keep functions small. Avoid premature abstraction; don't extract a `BaseProbe` class until three probes exist and the shared shape is obvious. Comments explain why, not what.

## Working ground rules

- Execution partner, not strategy re-litigator. Don't re-propose design choices once decided.
- Push back on scope creep. If a step spawns a "while we're here, let's also..." impulse, resist and note it as a follow-up in `TODO.md` or a GitHub issue.
- Run `npx tsx src/cli.ts audit <url>` yourself after each change. Don't ask for verification; you can see the output.
- If you hit a design question not covered here, stop and ask before burning tokens on a guess.
- Concise responses. No ceremonial preamble.

## Stop conditions

Stop when **any** of these trigger:

- Probes 1-3 are shipping and validated against 3+ real MCP servers.
- You'd need to refactor the evidence format, report structure, or `AuditContext` shape to proceed further. Those decisions need probes 4-6 context.
- You're guessing at methodology rather than following it.

## Start

Read the repo, confirm the design decisions above are reflected in your plan, then begin step 1. Do not re-propose `AuditContext` or `ProbeResult` shapes; those are settled.
