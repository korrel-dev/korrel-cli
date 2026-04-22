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
  const passed = findings.filter(f => f.passed).length;

  const lines: string[] = [];
  lines.push(`# Audit: ${host}`);
  lines.push('');
  lines.push(`- **Target:** ${target}`);
  lines.push(`- **Generated:** ${new Date().toISOString()}`);
  lines.push(`- **Tool:** korrel-cli v0.0.0`);
  lines.push('');
  lines.push('## Summary');
  lines.push('');
  lines.push(`${passed} of ${findings.length} probes passed.`);
  lines.push('');
  lines.push('## Findings');
  lines.push('');

  for (const finding of findings) {
    lines.push(`### ${finding.id}: ${finding.title}`);
    lines.push('');
    lines.push(`**Result:** ${finding.passed ? 'passed' : 'finding'}`);
    lines.push('');
    for (const obs of finding.observations) {
      lines.push(`- ${obs}`);
    }
    lines.push('');
    if (evidenceNames.has(finding.id)) {
      lines.push(`Evidence: \`evidence/${finding.id}.http\``);
      lines.push('');
    }
  }

  return lines.join('\n');
}
