# Contributing to korrel-cli

This document is for non-security contributions. Security issues
go to [`SECURITY.md`](./SECURITY.md).

`korrel-cli` is a probe tool that audits remote MCP servers for
OAuth 2.1 conformance against a documented methodology. Most
contributions either improve a probe's accuracy against the
methodology, file a bug report against probe behavior, or scaffold
a new probe for a future methodology version.

## What contributions are welcome

**Bug reports.** A probe behaves incorrectly against a real MCP
server, emits the wrong severity, cites an RFC clause that does
not say what the citation implies, or misses an observable
finding that the methodology says it should catch. Open a public
issue with the target URL, the probe ID (`01-discovery` through
`06-tokens`), the observed output, and the expected output. If
the bug touches RFC citation accuracy, include the RFC section
text alongside the cite.

**RFC citation corrections.** A probe cites an RFC section that
does not contain the clause the citation implies. Two such issues
are tracked in
[#24](https://github.com/korrel-dev/korrel-cli/issues/24) and
[#25](https://github.com/korrel-dev/korrel-cli/issues/25); both
were filed during audit-03 polish on 2026-05-06 against probe-04
host-mismatch §5 framing and probe-02 RFC 9728 §3-vs-§2. These
are the reference cases for what a probe-citation correction
looks like.

**Probe accuracy improvements.** A probe's primary path is
correct but it misses a non-compliant alternate form, an edge
case the spec text covers, or a depth check the probe scaffold
deferred. Open a public issue tagged with the probe ID and the
RFC section the improvement covers.

**Methodology v2.0 probe scaffolds.** The
[methodology](https://github.com/korrel-dev/mcp-audits/blob/main/METHODOLOGY.md)
v2.0 expansion covers tool authorization scope checking,
prompt-injection signature detection, agent-vs-user identity
binding, session lifecycle, consent screen behavior, and audit
log integrity at the AS level. A scaffold PR for any of these
surfaces is welcome if it lands as a new probe directory under
`src/probes/` with a corresponding scope doc under
[`docs/`](./docs/) and is marked `Pending` in
[`docs/ROADMAP.md`](./docs/ROADMAP.md). Scaffolds do not need
to ship full implementation; they need the structure plus tests
plus the methodology citation surface.

**Evidence format improvements.** The `.http` evidence format is
intentionally minimal and human-readable. Improvements that
preserve human readability while adding structure (e.g. a
canonical YAML or JSON sidecar with parsed headers) are welcome.

## What is not in scope

- Changes that would shift what a probe asserts without a
  corresponding amendment in
  [`mcp-audits/METHODOLOGY.md`](https://github.com/korrel-dev/mcp-audits/blob/main/METHODOLOGY.md).
  The methodology is the source of truth; probe behavior follows.
  If you think a probe should assert something different, the
  first PR is to the methodology repo, not this one.
- Probes that send payloads outside what a spec-compliant client
  would generate. `korrel-cli` is not a fuzzer.
- Probes that send identifying payloads beyond what the operator
  supplies. Probes are stateless against an operator-supplied
  URL; they do not exfiltrate operator-side state.
- Changes that drop evidence file emission. Every probe
  observation must produce an evidence file the operator can
  inspect.
- Pull requests that bundle behavior changes with formatting
  changes. Split them.

## The audit accuracy pattern

Every probe-emitted observation that cites an RFC clause must
survive a careful read of the cited section. The pattern locked
on 2026-05-02 after audit-03 polish caught two false MUST citations
that nearly shipped: a `warn`-emitting probe is one thing, a
`warn`-emitting probe that says the target violates a SHOULD that
does not exist in the cited section is something else.

For contributors, this means: a PR that adds a new RFC citation
to probe output also includes the RFC section text in the PR
description. The reviewer reads the section text against the
citation. If the citation does not survive the read, the PR
either changes the citation or changes the assertion.

The same pattern applies to corrections. A PR that corrects an
existing RFC citation in probe code includes both the old citation
text and the section text from the cited RFC, plus a one-paragraph
explanation of why the old citation was wrong. Issue #24 and #25
follow this format.

## Severity vocabulary discipline

`korrel-cli` emits findings at five severity levels documented in
[`docs/SEVERITY.md`](./docs/SEVERITY.md): `info`, `warn`, `issue`,
`critical`, `skipped`.

Bug reports against probe behavior should label which severity
level the probe is currently emitting and which the contributor
believes is correct. PRs that touch probe code articulate the
severity of the assertion the new check produces.

`info` is for "the probe ran and the target did the right thing."
`warn` is for SHOULD-level deviations. `issue` is for MUST-level
violations. `critical` is reserved for orchestrator-level faults
(no probe emits this today). `skipped` means the probe could not
run because a required upstream input was missing.

The severity is not aesthetic; it determines how an audit report
treats the finding and whether it drives a disclosure email to
the target operator.

## Methodology versioning

Probe behavior changes that shift what a probe asserts require a
corresponding amendment in
[`mcp-audits/METHODOLOGY.md`](https://github.com/korrel-dev/mcp-audits/blob/main/METHODOLOGY.md).
Methodology v1.0 closed on 2026-04-29 with the six probes that
ship today; v2.0 is not yet published.

If a probe assertion change does not have a methodology amendment
backing it, the PR is on hold until the amendment lands. This
keeps probe behavior aligned with the published methodology that
audit reports cite.

Methodology version log lives in
[`mcp-audits/METHODOLOGY.md`](https://github.com/korrel-dev/mcp-audits/blob/main/METHODOLOGY.md);
the version applicable to each probe ships in the probe's
`emit()` output.

## Code conventions

- TypeScript with strict mode plus `noUncheckedIndexedAccess`. No
  `any`, no `as` casts that defeat the type checker, no
  `// @ts-ignore`. If the type system fights you, the type model
  is wrong.
- Node 22+ ESM. No CommonJS, no transpilation that produces
  CommonJS output.
- Vitest for tests. Each probe has a fixture-driven test that
  exercises the primary path plus at least one non-compliant
  fixture per emitted assertion.
- Zod for input validation at the probe boundary. Probes consume
  validated inputs from the orchestrator; they do not parse
  upstream output ad hoc.
- Probe output is structured. `report.md` rendering is a
  formatting layer over a typed `ProbeResult` value; probes do
  not write Markdown directly.

## Pull request convention

PR descriptions include:

1. The issue number this PR closes (file an issue first if one
   does not exist).
2. The probe ID(s) touched.
3. RFC section text for any new or changed citations.
4. Severity of any new or changed assertions.
5. Whether the change requires a methodology amendment in
   `mcp-audits` (and a link if one has been filed).
6. The fixtures added or changed under `tests/fixtures/`.

Reviews happen in the open. The author engages on technical
points; "I'll fix it" without addressing the substantive feedback
is not a review response.

## Local development

```
git clone https://github.com/korrel-dev/korrel-cli
cd korrel-cli
npm install
npm test
npm run dev -- audit https://mcp.example.com/
```

Requires Node 22 or later. Tests run against fixtures in
`tests/fixtures/`; no network access required for the test suite.

## License

Contributions are licensed under MIT, the same as the project.
By submitting a PR you confirm you have the right to contribute
the code under that license.

## Recognition

Contributors who file valid bug reports, correct RFC citations,
or scaffold v2.0 probes are credited in the relevant audit
amendments and in
[`docs/ROADMAP.md`](./docs/ROADMAP.md) follow-ups list. Anonymous
contribution is fine; ask in the initial issue or PR.

## Where to start

Three good first contributions:

- Read [`METHODOLOGY.md`](https://github.com/korrel-dev/mcp-audits/blob/main/METHODOLOGY.md)
  end-to-end, then run the probes against a target you operate.
  File issues against any probe-output discrepancies.
- Pick one of the open follow-ups in
  [`docs/ROADMAP.md`](./docs/ROADMAP.md) and propose a scope.
- Read one published audit in
  [`mcp-audits/audits/`](https://github.com/korrel-dev/mcp-audits/tree/main/audits),
  then read the cited RFC sections, then file an issue if the
  audit's RFC framing is wrong.

The third is the highest-value contribution to the project and
the audit series both. The audit accuracy pattern works because
contributors apply it; outside readers who do are credited.
