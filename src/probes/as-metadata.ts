import { z } from 'zod';
import type { AuditContext, Evidence, Finding, ProbeResult } from '../types.js';

export const AS_METADATA_PROBE_ID = '03-as-metadata';
export const AS_METADATA_PKCE_METHODS_FINDING_ID = '03-as-metadata-pkce-methods';
const A4_TITLE = 'PKCE code_challenge_methods_supported advertisement (RFC 7636 §4.2)';

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
  // Tracks whether the outer probe successfully parsed an AS metadata body.
  // A4 (PKCE methods) is `skipped` when this is false. When true, `pkce`
  // carries the advertised code_challenge_methods_supported array (or
  // undefined when the field is absent from the parsed body).
  let metadataParsed = false;
  let pkce: string[] | undefined;

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

      pkce = as.code_challenge_methods_supported;
      if (pkce) {
        observations.push(`PKCE methods advertised: [${pkce.join(', ')}]. See 03-as-metadata-pkce-methods finding.`);
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
      metadataParsed = true;
    }
  }

  const finding: Finding = {
    id: AS_METADATA_PROBE_ID,
    title: 'Authorization Server metadata (RFC 8414)',
    severity: passed ? 'info' : 'warn',
    passed,
    observations
  };

  const a4Finding = buildPkceMethodsFinding(metadataParsed, pkce);

  const result: ProbeResult = {
    findings: [finding, a4Finding],
    evidence: [{ name: AS_METADATA_PROBE_ID, evidence }]
  };
  if (contextUpdates) {
    result.contextUpdates = contextUpdates;
  }
  return result;
}

/**
 * Assertion 4 (issue #19): evaluate `code_challenge_methods_supported`
 * advertisement per RFC 7636 §4.2 and OAuth 2.1 draft-15 §4.1.1.
 *
 * Five outcomes:
 *   - skipped: AS metadata body not available or not parseable.
 *   - info (passed: false): field absent entirely.
 *   - info (passed: true): S256 present, plain absent.
 *   - warn (passed: false): S256 present, plain also present.
 *   - issue (passed: false): field present, S256 absent.
 */
function buildPkceMethodsFinding(metadataParsed: boolean, pkce: string[] | undefined): Finding {
  if (!metadataParsed) {
    return {
      id: AS_METADATA_PKCE_METHODS_FINDING_ID,
      title: A4_TITLE,
      severity: 'skipped',
      passed: false,
      observations: ['Skipped: AS metadata body not available or not parseable.']
    };
  }

  if (pkce === undefined) {
    return {
      id: AS_METADATA_PKCE_METHODS_FINDING_ID,
      title: A4_TITLE,
      severity: 'info',
      passed: false,
      observations: [
        'code_challenge_methods_supported not present in AS metadata.',
        'RFC 8414 §2: if omitted, the authorization server does not support PKCE.'
      ]
    };
  }

  const methodsLine = `code_challenge_methods_supported: [${pkce.join(', ')}]`;
  const hasS256 = pkce.includes('S256');
  const hasPlain = pkce.includes('plain');

  if (hasS256 && !hasPlain) {
    return {
      id: AS_METADATA_PKCE_METHODS_FINDING_ID,
      title: A4_TITLE,
      severity: 'info',
      passed: true,
      observations: [
        methodsLine,
        'S256 advertised; plain not advertised. RFC 7636 §4.2 MTI baseline satisfied.'
      ]
    };
  }

  if (hasS256 && hasPlain) {
    return {
      id: AS_METADATA_PKCE_METHODS_FINDING_ID,
      title: A4_TITLE,
      severity: 'warn',
      passed: false,
      observations: [
        methodsLine,
        'plain advertised alongside S256.',
        'No server-directed MUST NOT exists in RFC 7636, RFC 8414 §2, or OAuth 2.1 draft-15 §4.1.1.',
        'RFC 7636 §4.2 designates S256 as MTI on the server and requires clients capable of S256 to use it.',
        'OAuth 2.1 draft-15 §4.1.1 permits plain in AS metadata as a fallback discovery path for clients that cannot support S256.'
      ]
    };
  }

  // pkce present but does not include 'S256' (may include 'plain' or other values).
  return {
    id: AS_METADATA_PKCE_METHODS_FINDING_ID,
    title: A4_TITLE,
    severity: 'issue',
    passed: false,
    observations: [
      methodsLine,
      'S256 is not advertised. RFC 7636 §4.2 designates S256 as Mandatory To Implement (MTI) on the server. Without S256 in the advertised methods, clients cannot use the MTI baseline regardless of their own capability.'
    ]
  };
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
