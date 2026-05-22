import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { DISCOVERY_PROBE_STEM, discoveryProbe } from './probes/discovery.js';
import { PRM_PROBE_STEM, prmProbe } from './probes/prm.js';
import { AS_METADATA_PROBE_STEM, asMetadataProbe } from './probes/as-metadata.js';
import { DCR_PROBE_STEM, dcrProbe } from './probes/dcr.js';
import { PKCE_PROBE_STEM, pkceEnforcementProbe } from './probes/pkce-enforcement.js';
import { TOKEN_HYGIENE_PROBE_STEM, tokenHygieneProbe } from './probes/token-hygiene.js';
import { writeEvidence } from './evidence.js';
import { writeReport } from './report.js';
import type { AuditContext, Finding, Probe } from './types.js';

interface ProbeEntry {
  stem: string;
  run: Probe;
}

const probes: ProbeEntry[] = [
  { stem: DISCOVERY_PROBE_STEM, run: discoveryProbe },
  { stem: PRM_PROBE_STEM, run: prmProbe },
  { stem: AS_METADATA_PROBE_STEM, run: asMetadataProbe },
  { stem: DCR_PROBE_STEM, run: dcrProbe },
  { stem: PKCE_PROBE_STEM, run: pkceEnforcementProbe },
  { stem: TOKEN_HYGIENE_PROBE_STEM, run: tokenHygieneProbe }
];

export async function runAudit(target: string, outputRoot: string): Promise<void> {
  const url = new URL(target);
  const host = url.host;
  const outputDir = join(outputRoot, host);
  const evidenceDir = join(outputDir, 'evidence');

  await mkdir(evidenceDir, { recursive: true });

  console.log(`[korrel] auditing ${url.toString()}`);
  console.log(`[korrel] output: ${outputDir}`);

  let ctx: AuditContext = { target: url };
  const findings: Finding[] = [];
  const evidenceNames = new Set<string>();

  for (const probe of probes) {
    try {
      const result = await probe.run(ctx);
      findings.push(...result.findings);
      for (const item of result.evidence) {
        await writeEvidence(evidenceDir, item.name, item.evidence);
        evidenceNames.add(item.name);
      }
      if (result.contextUpdates) {
        ctx = { ...ctx, ...result.contextUpdates };
      }
    } catch (err) {
      // Fail-soft: a probe that throws becomes an 'issue' finding and
      // the audit continues. No probe can halt the run.
      const message = err instanceof Error ? err.message : String(err);
      findings.push({
        stem: probe.stem,
        title: `${probe.stem} threw`,
        severity: 'issue',
        passed: false,
        observations: [message]
      });
    }
  }

  await writeReport(outputDir, { target: url.toString(), findings, evidenceNames });

  console.log(`[korrel] done. report: ${join(outputDir, 'report.md')}`);
}
