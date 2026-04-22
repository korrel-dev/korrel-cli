import type { AuditContext, Evidence, Finding, ProbeResult } from '../types.js';

export const DISCOVERY_PROBE_ID = '01-discovery';

const MCP_INITIALIZE_BODY = {
  jsonrpc: '2.0' as const,
  id: 1,
  method: 'initialize',
  params: {
    protocolVersion: '2025-11-25',
    capabilities: {},
    clientInfo: {
      name: 'korrel-cli',
      version: '0.0.0'
    }
  }
};

// RFC 6750 §3.1 enumerates the only valid `error` values for Bearer
// challenges. For an unauthenticated request the spec-correct value
// is `invalid_token`; `invalid_request` is reserved for malformed
// requests (e.g. duplicate token parameters).
const VALID_BEARER_ERRORS = new Set(['invalid_request', 'invalid_token', 'insufficient_scope']);
const EXPECTED_UNAUTH_ERROR = 'invalid_token';

/**
 * Probe 1: Discovery.
 *
 * Sends an unauthenticated MCP initialize request and expects:
 *   - HTTP 401 Unauthorized
 *   - WWW-Authenticate: Bearer ... resource_metadata="<PRM URL>"
 *
 * Per RFC 9728 (OAuth 2.0 Protected Resource Metadata), RFC 6750
 * (Bearer Token Usage), and the MCP auth spec (2025-06-18 onwards).
 */
export async function discoveryProbe(ctx: AuditContext): Promise<ProbeResult> {
  const requestHeaders: Record<string, string> = {
    'Content-Type': 'application/json',
    'Accept': 'application/json, text/event-stream',
    'User-Agent': 'korrel-cli/0.0.0'
  };
  const body = JSON.stringify(MCP_INITIALIZE_BODY);

  const response = await fetch(ctx.target, {
    method: 'POST',
    headers: requestHeaders,
    body,
    redirect: 'manual'
  });

  const responseBody = await response.text();
  const responseHeaders: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    responseHeaders[key] = value;
  });

  const evidence: Evidence = {
    request: {
      method: 'POST',
      url: ctx.target.toString(),
      headers: requestHeaders,
      body
    },
    response: {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
      body: responseBody
    }
  };

  const wwwAuth = response.headers.get('www-authenticate');
  const challenge = wwwAuth ? parseWwwAuthenticate(wwwAuth) : null;
  const prmUrl = challenge?.params.get('resource_metadata') ?? null;
  const errorParam = challenge?.params.get('error') ?? null;

  const observations: string[] = [];
  observations.push(`HTTP ${response.status} ${response.statusText}`);
  if (wwwAuth) {
    observations.push(`WWW-Authenticate: ${wwwAuth}`);
  } else {
    observations.push('No WWW-Authenticate header returned.');
  }
  if (challenge && challenge.scheme.toLowerCase() !== 'bearer') {
    observations.push(`WWW-Authenticate scheme is "${challenge.scheme}"; expected Bearer (RFC 6750 §3).`);
  }
  if (prmUrl) {
    observations.push(`resource_metadata URL: ${prmUrl}`);
  } else if (wwwAuth) {
    observations.push('WWW-Authenticate present but no resource_metadata parameter (RFC 9728 §5.1).');
  }
  if (errorParam !== null) {
    if (!VALID_BEARER_ERRORS.has(errorParam)) {
      observations.push(`WWW-Authenticate error="${errorParam}" is not a valid RFC 6750 §3.1 value (invalid_request | invalid_token | insufficient_scope).`);
    } else if (errorParam !== EXPECTED_UNAUTH_ERROR) {
      observations.push(`WWW-Authenticate error="${errorParam}" deviates from RFC 6750 §3.1; invalid_token is the correct value for an unauthenticated request.`);
    }
  }

  const passed = response.status === 401 && prmUrl !== null;

  const finding: Finding = {
    id: DISCOVERY_PROBE_ID,
    title: 'Discovery probe (RFC 9728)',
    severity: passed ? 'info' : 'finding',
    passed,
    observations
  };

  const result: ProbeResult = {
    findings: [finding],
    evidence: [{ name: DISCOVERY_PROBE_ID, evidence }]
  };
  if (prmUrl) {
    result.contextUpdates = { protectedResourceMetadataUrl: prmUrl };
  }
  return result;
}

export interface WwwAuthChallenge {
  scheme: string;
  params: Map<string, string>;
}

/**
 * Parse a single Bearer WWW-Authenticate challenge per RFC 7235 §2.1.
 *
 * Handles token and quoted-string param values, quoted-pair escaping,
 * and optional whitespace around "=" and ",". Multi-challenge responses
 * (comma-joined challenges) are not supported; Bearer is the only scheme
 * MCP servers should emit.
 */
export function parseWwwAuthenticate(header: string): WwwAuthChallenge | null {
  let rest = header.trim();
  if (!rest) return null;

  const schemeMatch = /^([A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]*)(\s+|$)/.exec(rest);
  if (!schemeMatch) return null;
  const scheme = schemeMatch[1] ?? '';
  rest = rest.slice(schemeMatch[0].length).replace(/^\s+/, '');

  const params = new Map<string, string>();
  while (rest.length > 0) {
    const parsed = consumeParam(rest);
    if (!parsed) break;
    params.set(parsed.key.toLowerCase(), parsed.value);
    rest = parsed.rest.replace(/^[\s,]+/, '');
  }
  return { scheme, params };
}

function consumeParam(input: string): { key: string; value: string; rest: string } | null {
  const keyMatch = /^([A-Za-z0-9!#$%&'*+.^_`|~-]+)\s*=\s*/.exec(input);
  if (!keyMatch) return null;
  const key = keyMatch[1] ?? '';
  let r = input.slice(keyMatch[0].length);

  let value: string;
  if (r.startsWith('"')) {
    let i = 1;
    let v = '';
    while (i < r.length) {
      const ch = r.charAt(i);
      if (ch === '\\' && i + 1 < r.length) {
        v += r.charAt(i + 1);
        i += 2;
      } else if (ch === '"') {
        i += 1;
        break;
      } else {
        v += ch;
        i += 1;
      }
    }
    value = v;
    r = r.slice(i);
  } else {
    const tokenMatch = /^[A-Za-z0-9!#$%&'*+.^_`|~\/\-=]+/.exec(r);
    if (!tokenMatch) return null;
    value = tokenMatch[0];
    r = r.slice(tokenMatch[0].length);
  }
  return { key, value, rest: r };
}
