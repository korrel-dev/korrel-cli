import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { Finding } from './types.js';

export interface ReportInput {
  target: string;
  findings: Finding[];
  // Stems of evidence files actually written (e.g. "01-discovery").
  // Skipped or thrown probes produce findings with no evidence; the
  // report should not link to files that do not exist.
  evidenceNames: Set<string>;
}

export async function writeReport(
  dir: string,
  input: ReportInput
): Promise<void> {
  const content = renderMarkdown(input);
  await writeFile(join(dir, 'report.md'), content, 'utf-8');
}

function renderMarkdown({ target, findings, evidenceNames }: ReportInput): string {
  const host = new URL(target).host;
  // Findings with severity 'skipped' represent probes that could not run
  // due to missing upstream input. Exclude them from both pass and total
  // counts so summary reflects only probes that actually executed.
  const skipped = findings.filter(f => f.severity === 'skipped').length;
  const scoreable = findings.filter(f => f.severity !== 'skipped');
  const passed = scoreable.filter(f => f.passed).length;
  const total = scoreable.length;
  const skippedSuffix = skipped > 0 ? ` (${skipped} skipped)` : '';

  const lines: string[] = [];
  lines.push(`# Audit: ${host}`);
  lines.push('');
  lines.push(`- **Target:** ${target}`);
  lines.push(`- **Generated:** ${new Date().toISOString()}`);
  lines.push(`- **Tool:** korrel-cli v0.0.0`);
  lines.push('');
  lines.push('## Summary');
  lines.push('');
  lines.push(`${passed} of ${total} probes passed${skippedSuffix}.`);
  lines.push('');
  lines.push('## Findings');
  lines.push('');

  for (const finding of findings) {
    lines.push(`### ${finding.id}: ${finding.title}`);
    lines.push('');
    lines.push(`**Result:** ${finding.passed ? 'passed' : finding.severity}`);
    lines.push('');
    for (const obs of finding.observations) {
      lines.push(`- ${obs}`);
    }
    lines.push('');
    const relatedEvidence = (finding.evidence ?? [])
      .filter(name => evidenceNames.has(name))
      .sort();

    if (relatedEvidence.length > 0) {
      for (const name of relatedEvidence) {
        lines.push(`- Evidence: \`evidence/${name}.http\``);
      }
      lines.push('');
    }
  }

  lines.push('---');
  lines.push('');
  lines.push('Severity vocabulary: info (compliant), warn (spec deviation), issue (MUST violation), skipped (probe could not run). See [SEVERITY.md](https://github.com/korrel-dev/korrel-cli/blob/main/docs/SEVERITY.md) for full definitions.');
  lines.push('');

  return lines.join('\n');
}
