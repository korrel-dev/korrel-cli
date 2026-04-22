import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { discoveryProbe } from './probes/discovery.js';
import { writeEvidence } from './evidence.js';
import { writeReport } from './report.js';
import type { Finding } from './types.js';

export async function runAudit(target: string, outputRoot: string): Promise<void> {
  const url = new URL(target);
  const host = url.host;
  const outputDir = join(outputRoot, host);
  const evidenceDir = join(outputDir, 'evidence');

  await mkdir(evidenceDir, { recursive: true });

  console.log(`[korrel] auditing ${url.toString()}`);
  console.log(`[korrel] output: ${outputDir}`);

  const findings: Finding[] = [];

  // Probe 1: discovery (RFC 9728).
  const discovery = await discoveryProbe(url);
  await writeEvidence(evidenceDir, '01-discovery', discovery.evidence);
  findings.push(discovery.finding);

  // Probes 2-6 land next.

  await writeReport(outputDir, { target: url.toString(), findings });

  console.log(`[korrel] done. report: ${join(outputDir, 'report.md')}`);
}
