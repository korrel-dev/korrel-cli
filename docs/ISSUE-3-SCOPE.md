# ISSUE-3 Scope: Severity type rename and severity footer

## Background

`src/types.ts` currently defines `Severity = 'info' | 'finding' | 'issue' | 'critical'`.
The label `'finding'` is semantically overloaded: every probe result is a finding, so the
severity level name is redundant and misleading. Issue #3 renames it to `'warn'`, adds
`'skipped'` for probes that could not run due to missing upstream input, and propagates
the change through all probe files, the PROBE-4-SCOPE doc, and the report renderer.
A new `docs/SEVERITY.md` canonicalizes the definitions so report consumers can interpret
labels without reading source code.

## In scope

- Rename `'finding'` to `'warn'` in the `Severity` union in `src/types.ts`.
- Add `'skipped'` to the `Severity` union in `src/types.ts`.
- Rename every `'finding'` severity literal in `src/probes/discovery.ts` to `'warn'`.
- Rename every `'finding'` severity literal in `src/probes/prm.ts` to `'warn'`.
- In `src/probes/as-metadata.ts`: rename the main-finding `'finding'` branch to `'warn'`;
  rename the "no authorization_servers" early-exit finding from `'finding'` to `'skipped'`.
- In `src/probes/dcr.ts`: rename the "200 instead of 201" `'finding'` to `'warn'`; rename
  the "accepted host-mismatched redirect URI" `'finding'` to `'warn'`; rename the
  "DCR/CIMD probe skipped" `'info'` to `'skipped'`.
- Create `docs/SEVERITY.md` with verbatim content from HANDOFF.md.
- src/report.ts: append severity footer to renderMarkdown output; update summary line to exclude 'skipped' findings from the pass/total count and append '(N skipped)' suffix when any skipped findings are present.
- Update `docs/PROBE-4-SCOPE.md`: replace all `finding` severity references in the Finding
  Shapes table, the Control Flow pseudocode, and the vocabulary note with `warn`; replace the
  "DCR/CIMD probe skipped" row from `info` to `skipped`.

## Out of scope

- `README.md` updates: separate future pass, not touched here.
- `mcp-audits/METHODOLOGY.md` changes: that document uses pass/gap/fail vocabulary tied to
  the published methodology; it does not reference the `Severity` type directly.
- Audit post draft files: local only, not touched.
- Probe 5 and probe 6 preparation: future probes, not affected by this rename.
- Any code changes outside severity handling: no refactors, no new probe logic.
- `'critical'` semantics: the level exists and its definition is documented in SEVERITY.md,
  but no probe emits it today and no code changes are required for it.
- `passed` field semantics audit: the `passed: boolean` field on `Finding` is not changed.
  See Open Questions for the `'skipped'` / `passed` interaction.

## Normative assertions being tested

This issue is a code-quality and vocabulary change, not a new audit probe. There are no RFC
clauses being newly tested. The table below records the spec-level rationale for the two
categorization decisions that are non-obvious.

| Level  | Clause            | Decision                                                                                      |
|--------|-------------------|-----------------------------------------------------------------------------------------------|
| MUST   | RFC 7591 §3.2.1   | "200 instead of 201" stays `warn`, not `issue`: the AS returned a functional response; the   |
|        |                   | violation is a status-code deviation only. Non-exploitable in practice.                       |
| SHOULD | RFC 7591 §5       | "Accepted host-mismatched redirect URI" is `warn`: RFC 7591 §5 uses SHOULD, not MUST.        |

## Control flow

This issue has no runtime control-flow changes. The probe logic is unchanged; only severity
literal values change. `renderMarkdown` in `report.ts` gains one new section appended after
the existing findings loop:

```
function renderMarkdown(input):
  // ... existing findings rendering unchanged ...

  lines.push("---")
  lines.push("")
  lines.push("Severity levels: [info / warn / issue / critical / skipped]" +
             "(https://github.com/korrel-dev/korrel-cli/blob/main/docs/SEVERITY.md)")

  return lines.join("\n")
```

The exact Markdown text and link format are provided in HANDOFF.md and must be used verbatim.

## Finding shapes

No new finding shapes are introduced. The table below records the before/after for every
site that changes severity. All other existing finding shapes are unchanged.

| Probe file         | Finding title                                                 | Old severity | New severity |
|--------------------|---------------------------------------------------------------|--------------|--------------|
| discovery.ts       | Discovery probe (RFC 9728) [passed=false branch]              | `finding`    | `warn`       |
| prm.ts             | Protected Resource Metadata (RFC 9728) [passed=false, direct] | `finding`    | `warn`       |
| prm.ts             | Protected Resource Metadata (RFC 9728) [passed=false, fallback success] | `finding` | `warn` |
| as-metadata.ts     | Authorization Server metadata (RFC 8414) [passed=false branch]| `finding`    | `warn`       |
| as-metadata.ts     | Authorization Server metadata (RFC 8414) [no AS servers case] | `finding`    | `skipped`    |
| dcr.ts             | DCR/CIMD probe skipped: AS metadata not available             | `info`       | `skipped`    |
| dcr.ts             | DCR registration response uses HTTP 200 instead of 201       | `finding`    | `warn`       |
| dcr.ts             | DCR accepted host-mismatched redirect URI                     | `finding`    | `warn`       |

### Post-rename Severity union

```
type Severity = 'info' | 'warn' | 'issue' | 'critical' | 'skipped'
```

### Semantic definitions (canonical)

- `info`: probe ran, target did the correct thing.
- `warn`: SHOULD-level spec deviation or minor gap worth flagging.
- `issue`: MUST-level spec violation or concrete threat-model gap.
- `critical`: reserved for orchestrator; no probe emits it today.
- `skipped`: probe could not run due to missing upstream input.

`'info'` and `'skipped'` are not interchangeable. `'info'` means "I looked and the target
made a choice; the choice was correct or legitimate." `'skipped'` means "I could not look
at all because an upstream probe did not give me what I needed." probe-engineer must not
collapse them.

Note on passed field: Findings with severity 'skipped' have passed: false. Summary renderer excludes skipped findings from both the 'passed' count and the 'total' count, appending '(N skipped)' when any are present. This reflects that a skipped probe produced no observation and should not be counted as a target failure.

## Evidence files

No new evidence files are created by this issue. No existing evidence file names change.
The severity footer added to `report.md` is a report artifact, not an evidence file.

## Verification

### Target 1: Linear (`https://mcp.linear.app/mcp`)

Linear has DCR active and probe 3 succeeds. Expected changes in generated `report.md`:

- Previously `finding`-severity findings for "200 instead of 201" and/or "accepted
  host-mismatched redirect URI" now render as `warn`.
- No `finding` label appears anywhere in the report.
- Severity footer appears at the end of the report, linking to SEVERITY.md.

### Target 2: GitHub (`https://api.githubcopilot.com/mcp`)

GitHub has no DCR and all probes run cleanly. Expected changes in generated `report.md`:

- All findings show `info` severity (no severity labels change for this target).
- No `finding` label appears anywhere in the report.
- Severity footer appears at the end of the report.

### Target 3: Atlassian (`https://mcp.atlassian.com/v1/sse`)

Probe 3 fails on Atlassian because AS metadata is unavailable. Expected changes in
generated `report.md`:

- The probe 3 "no authorization_servers" finding now shows `skipped` instead of `finding`.
- The probe 4 "DCR/CIMD probe skipped" finding now shows `skipped` instead of `info`.
- Severity footer appears at the end of the report.

## Acceptance criteria

- [ ] `npm run typecheck` passes with new Severity type (`'info' | 'warn' | 'issue' | 'critical' | 'skipped'`).
- [ ] No `'finding'` literal remains anywhere in `src/` after the rename (grep confirms zero hits).
- [ ] Every probe file compiles clean with `tsc --noEmit`; no orphaned `'finding'` literals.
- [ ] `docs/SEVERITY.md` created with exact content from HANDOFF.md.
- [ ] `docs/PROBE-4-SCOPE.md` updated: Finding Shapes table, Control Flow pseudocode, and
      vocabulary note all use `warn` and `skipped` instead of `finding` and the old `info`
      skip case respectively.
- [ ] `src/report.ts` `renderMarkdown` emits a severity footer as the last content block.
- [ ] Generated `report.md` for Linear shows one or more `warn` findings where `finding` appeared before.
- [ ] Generated `report.md` for GitHub shows only `info` findings and the new footer.
- [ ] Generated `report.md` for Atlassian shows `skipped` for the probe 3 skip case and the
      probe 4 skip case; no `finding` or bare `info` for those two rows.
- [ ] Footer link in all generated reports resolves to
      `https://github.com/korrel-dev/korrel-cli/blob/main/docs/SEVERITY.md`.
- [ ] Generated report.md summary line for Atlassian (where probes 3 and 4 skip due to upstream failure) reads '1 of 1 probes passed (2 skipped)' or equivalent, not '1 of 3 probes passed'.

## Open questions

None blocking. All prior open questions resolved by main thread 2026-04-23.
