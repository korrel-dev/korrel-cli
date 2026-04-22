import { z } from 'zod';
import type { AuditContext, Evidence, Finding, ProbeResult } from '../types.js';

export const PRM_PROBE_ID = '02-prm';

/**
 * Protected Resource Metadata, per RFC 9728 §3.
 *
 * Required: resource, authorization_servers.
 * Recommended: scopes_supported, bearer_methods_supported,
 * resource_documentation, resource_signing_alg_values_supported.
 *
 * Passthrough: RFC 9728 §3 permits extension fields; the schema
 * must not reject unknown keys.
 */
export const PrmSchema = z.object({
  resource: z.string().url(),
  authorization_servers: z.array(z.string().url()).min(1),
  scopes_supported: z.array(z.string()).optional(),
  bearer_methods_supported: z.array(z.string()).optional(),
  resource_documentation: z.string().url().optional(),
  resource_signing_alg_values_supported: z.array(z.string()).optional()
}).passthrough();

export type Prm = z.infer<typeof PrmSchema>;

const RECOMMENDED_FIELDS = [
  'scopes_supported',
  'bearer_methods_supported',
  'resource_documentation',
  'resource_signing_alg_values_supported'
] as const;

/**
 * Probe 2: Protected Resource Metadata fetch and validation (RFC 9728).
 *
 * Consumes `ctx.protectedResourceMetadataUrl` discovered by probe 1,
 * fetches it, validates the body against the RFC 9728 §3 schema, and
 * publishes the parsed document plus the authorization_servers array
 * on the context for probe 3.
 */
export async function prmProbe(ctx: AuditContext): Promise<ProbeResult> {
  const prmUrl = ctx.protectedResourceMetadataUrl;
  if (!prmUrl) {
    const finding: Finding = {
      id: PRM_PROBE_ID,
      title: 'Protected Resource Metadata (RFC 9728)',
      severity: 'finding',
      passed: false,
      observations: ['Probe 1 did not discover a resource_metadata URL; PRM fetch skipped.']
    };
    return { findings: [finding], evidence: [] };
  }

  const requestHeaders: Record<string, string> = {
    'Accept': 'application/json',
    'User-Agent': 'korrel-cli/0.0.0'
  };

  const response = await fetch(prmUrl, {
    method: 'GET',
    headers: requestHeaders,
    redirect: 'manual'
  });

  const responseBody = await response.text();
  const responseHeaders: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    responseHeaders[key] = value;
  });

  const evidence: Evidence = {
    request: {
      method: 'GET',
      url: prmUrl,
      headers: requestHeaders
    },
    response: {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
      body: responseBody
    }
  };

  const observations: string[] = [];
  observations.push(`HTTP ${response.status} ${response.statusText}`);

  let passed = false;
  let contextUpdates: Partial<AuditContext> | undefined;

  if (response.status !== 200) {
    observations.push('PRM endpoint did not return 200; cannot validate.');
  } else {
    let json: unknown;
    try {
      json = JSON.parse(responseBody);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      observations.push(`PRM body is not valid JSON: ${message}`);
    }

    if (json !== undefined) {
      const parseResult = PrmSchema.safeParse(json);
      if (!parseResult.success) {
        for (const issue of parseResult.error.issues) {
          const path = issue.path.length > 0 ? issue.path.join('.') : '(root)';
          observations.push(`PRM schema: ${path}: ${issue.message} (RFC 9728 §3)`);
        }
      } else {
        const prm = parseResult.data;
        observations.push(`resource: ${prm.resource}`);
        observations.push(`authorization_servers: ${prm.authorization_servers.join(', ')}`);

        const resourceUrl = safeUrl(prm.resource);
        const originMatch = resourceUrl !== null && resourceUrl.origin === ctx.target.origin;
        const pathMatch = resourceUrl !== null && ctx.target.pathname.startsWith(resourceUrl.pathname);

        if (!originMatch) {
          observations.push(`PRM resource origin ${resourceUrl?.origin ?? '(unparseable)'} does not match audited ${ctx.target.origin} (RFC 9728 §3.3).`);
        }
        if (originMatch && !pathMatch) {
          observations.push(`PRM resource path "${resourceUrl?.pathname}" is not a prefix of audited path "${ctx.target.pathname}" (RFC 9728 §3.3).`);
        }

        for (const field of RECOMMENDED_FIELDS) {
          if (prm[field] === undefined) {
            observations.push(`RFC 9728 §3 recommends "${field}"; not present.`);
          }
        }

        passed = originMatch && pathMatch;
        contextUpdates = {
          protectedResourceMetadata: prm,
          authorizationServers: prm.authorization_servers
        };
      }
    }
  }

  const finding: Finding = {
    id: PRM_PROBE_ID,
    title: 'Protected Resource Metadata (RFC 9728)',
    severity: passed ? 'info' : 'finding',
    passed,
    observations
  };

  const result: ProbeResult = {
    findings: [finding],
    evidence: [{ name: PRM_PROBE_ID, evidence }]
  };
  if (contextUpdates) {
    result.contextUpdates = contextUpdates;
  }
  return result;
}

function safeUrl(raw: string): URL | null {
  try {
    return new URL(raw);
  } catch {
    return null;
  }
}
