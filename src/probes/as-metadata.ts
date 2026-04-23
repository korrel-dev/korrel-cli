import { z } from 'zod';
import type { AuditContext, Evidence, Finding, ProbeResult } from '../types.js';

export const AS_METADATA_PROBE_ID = '03-as-metadata';

/**
 * Authorization Server metadata, per RFC 8414 §2.
 *
 * Required fields tested here:
 *   issuer, authorization_endpoint, token_endpoint, response_types_supported.
 *
 * Other fields (code_challenge_methods_supported, grant_types_supported,
 * registration_endpoint, etc.) are optional per RFC 8414 but drive
 * downstream probes and OAuth 2.1 compliance checks.
 */
export const AsMetadataSchema = z.object({
  issuer: z.string().url(),
  authorization_endpoint: z.string().url(),
  token_endpoint: z.string().url(),
  response_types_supported: z.array(z.string()).min(1),
  code_challenge_methods_supported: z.array(z.string()).optional(),
  grant_types_supported: z.array(z.string()).optional(),
  registration_endpoint: z.string().url().optional(),
  scopes_supported: z.array(z.string()).optional(),
  token_endpoint_auth_methods_supported: z.array(z.string()).optional()
}).passthrough();

export type AsMetadata = z.infer<typeof AsMetadataSchema>;

const DEPRECATED_GRANTS = new Set(['password', 'implicit']);

/**
 * Probe 3: Authorization Server metadata fetch and validation (RFC 8414).
 *
 * Resolves the well-known URL per RFC 8414 §3.1 path-insertion form,
 * fetches, validates, and publishes endpoints on the context. Version 0
 * handles only the first entry in `authorization_servers`; multiple-AS
 * coverage and the naive §3.1-violating form are follow-ups.
 */
export async function asMetadataProbe(ctx: AuditContext): Promise<ProbeResult> {
  const servers = ctx.authorizationServers;
  if (!servers || servers.length === 0) {
    const finding: Finding = {
      id: AS_METADATA_PROBE_ID,
      title: 'Authorization Server metadata (RFC 8414)',
      severity: 'skipped',
      passed: false,
      observations: ['Probe 2 did not discover any authorization_servers; AS metadata fetch skipped.']
    };
    return { findings: [finding], evidence: [] };
  }

  const observations: string[] = [];
  if (servers.length > 1) {
    observations.push(`authorization_servers lists ${servers.length} entries; probe 3 v0 only fetches the first. Remaining: ${servers.slice(1).join(', ')}.`);
  }

  const issuer = servers[0]!;
  const wellKnownUrl = asMetadataUrl(issuer);
  observations.push(`Fetching AS metadata at ${wellKnownUrl} (RFC 8414 §3.1 path-insertion form).`);

  const requestHeaders: Record<string, string> = {
    'Accept': 'application/json',
    'User-Agent': 'korrel-cli/0.0.0'
  };

  const response = await fetch(wellKnownUrl, {
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
      url: wellKnownUrl,
      headers: requestHeaders
    },
    response: {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
      body: responseBody
    }
  };

  observations.push(`HTTP ${response.status} ${response.statusText}`);

  let passed = false;
  let contextUpdates: Partial<AuditContext> | undefined;

  if (response.status !== 200) {
    observations.push('AS metadata endpoint did not return 200; cannot validate.');
  } else {
    const validation = validateAsMetadata(responseBody);
    if (!validation.ok) {
      observations.push(...validation.observations);
    } else {
      const as = validation.data;
      observations.push(`issuer: ${as.issuer}`);
      observations.push(`authorization_endpoint: ${as.authorization_endpoint}`);
      observations.push(`token_endpoint: ${as.token_endpoint}`);

      if (as.issuer !== issuer) {
        observations.push(`issuer "${as.issuer}" does not match the advertised AS URL "${issuer}" (RFC 8414 §3.3).`);
      }

      const pkce = as.code_challenge_methods_supported;
      if (!pkce) {
        observations.push('code_challenge_methods_supported not advertised; PKCE support is unknown (RFC 7636).');
      } else if (!pkce.includes('S256')) {
        observations.push(`code_challenge_methods_supported=[${pkce.join(', ')}] does not include S256 (RFC 7636 §4.2).`);
      }

      const grants = as.grant_types_supported;
      if (!grants) {
        observations.push('grant_types_supported not advertised; defaults to ["authorization_code", "implicit"] per RFC 8414 §2.');
      } else {
        if (!grants.includes('authorization_code')) {
          observations.push(`grant_types_supported=[${grants.join(', ')}] does not include authorization_code.`);
        }
        const deprecated = grants.filter(g => DEPRECATED_GRANTS.has(g));
        if (deprecated.length > 0) {
          observations.push(`grant_types_supported advertises OAuth 2.1-deprecated grants: ${deprecated.join(', ')}.`);
        }
      }

      contextUpdates = {
        authorizationServerMetadata: as,
        authorizationEndpoint: as.authorization_endpoint,
        tokenEndpoint: as.token_endpoint
      };
      if (as.registration_endpoint) {
        contextUpdates.registrationEndpoint = as.registration_endpoint;
      }

      passed = true;
    }
  }

  const finding: Finding = {
    id: AS_METADATA_PROBE_ID,
    title: 'Authorization Server metadata (RFC 8414)',
    severity: passed ? 'info' : 'warn',
    passed,
    observations
  };

  const result: ProbeResult = {
    findings: [finding],
    evidence: [{ name: AS_METADATA_PROBE_ID, evidence }]
  };
  if (contextUpdates) {
    result.contextUpdates = contextUpdates;
  }
  return result;
}

type AsMetadataValidation =
  | { ok: true; data: AsMetadata }
  | { ok: false; observations: string[] };

/**
 * Parse and schema-validate an AS metadata response body. Collapses the
 * JSON.parse and zod.safeParse failure paths into a single discriminated
 * return so callers do not need an intermediate `unknown` binding or a
 * defined-ness guard. Mirrors the helper shape used in `prm.ts`.
 */
function validateAsMetadata(body: string): AsMetadataValidation {
  let json: unknown;
  try {
    json = JSON.parse(body);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, observations: [`AS metadata body is not valid JSON: ${message}`] };
  }

  const parseResult = AsMetadataSchema.safeParse(json);
  if (!parseResult.success) {
    const observations: string[] = [];
    for (const issue of parseResult.error.issues) {
      const path = issue.path.length > 0 ? issue.path.join('.') : '(root)';
      observations.push(`AS metadata schema: ${path}: ${issue.message} (RFC 8414 §2)`);
    }
    return { ok: false, observations };
  }

  return { ok: true, data: parseResult.data };
}

/**
 * Build the RFC 8414 §3.1 path-insertion well-known URL for an issuer.
 * Example: `https://example.com/tenant1` →
 * `https://example.com/.well-known/oauth-authorization-server/tenant1`.
 */
export function asMetadataUrl(issuer: string): string {
  const url = new URL(issuer);
  const path = url.pathname === '/' ? '' : url.pathname.replace(/\/$/, '');
  return `${url.origin}/.well-known/oauth-authorization-server${path}`;
}
