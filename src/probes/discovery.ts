import type { AuditContext, Evidence, Finding, ProbeResult } from '../types.js';

export const DISCOVERY_PROBE_STEM = '01-discovery';

const A1_FINDING_ID = `${DISCOVERY_PROBE_STEM}-auth-challenge`;
const A2_FINDING_ID = `${DISCOVERY_PROBE_STEM}-prm-advertisement`;
const A3_FINDING_ID = `${DISCOVERY_PROBE_STEM}-error-code-absent`;

const A1_TITLE = 'Bearer authentication challenge on unauthenticated request (RFC 6750)';
const A2_TITLE = 'PRM advertisement in WWW-Authenticate (RFC 9728 §5.1)';
const A3_TITLE = 'No error code in unauthenticated Bearer challenge (RFC 6750 §3.1)';

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

/**
 * Probe 1: Discovery.
 *
 * Sends an unauthenticated MCP initialize request and evaluates three
 * independent assertions against the response:
 *
 *   A1 (RFC 6750 §3):   401 Unauthorized with a Bearer WWW-Authenticate
 *                       challenge.
 *   A2 (RFC 9728 §5.1): `resource_metadata` parameter present in that
 *                       challenge.
 *   A3 (RFC 6750 §3.1): no `error`, `error_description`, or `error_uri`
 *                       parameter present on a no-credentials challenge.
 *
 * The A1/A2/A3 split lets a target that returns a compliant Bearer
 * challenge but omits `resource_metadata` (issue #8 motivating case)
 * or includes an error code on a no-credentials request (issue #18)
 * show partial compliance instead of a single undifferentiated
 * failure. A2 and A3 are skipped when A1 fails.
 *
 * `contextUpdates.protectedResourceMetadataUrl` is set whenever the
 * challenge carries a `resource_metadata` URL, independent of the
 * severity assigned to A1, A2, or A3, so downstream probes can consume
 * the PRM URL even in partially-compliant scenarios.
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

  // --- Assertion 1: auth challenge (RFC 6750 §3) ---

  const a1Passed =
    response.status === 401 &&
    challenge !== null &&
    challenge.scheme.toLowerCase() === 'bearer';

  const a1Observations: string[] = [];
  a1Observations.push(`HTTP ${response.status} ${response.statusText}`);
  if (wwwAuth) {
    a1Observations.push(`WWW-Authenticate: ${wwwAuth}`);
  } else {
    a1Observations.push('No WWW-Authenticate header returned.');
  }
  if (challenge && challenge.scheme.toLowerCase() !== 'bearer') {
    a1Observations.push(
      `WWW-Authenticate scheme is '${challenge.scheme}'; expected Bearer (RFC 6750 §3).`
    );
  }

  const a1Finding: Finding = {
    stem: A1_FINDING_ID,
    title: A1_TITLE,
    severity: a1Passed ? 'info' : 'issue',
    passed: a1Passed,
    observations: a1Observations,
    evidence: [DISCOVERY_PROBE_STEM]
  };

  // --- Assertion 2: PRM advertisement (RFC 9728 §5.1) ---

  let a2Finding: Finding;
  if (!a1Passed) {
    a2Finding = {
      stem: A2_FINDING_ID,
      title: A2_TITLE,
      severity: 'skipped',
      passed: false,
      observations: ['Skipped: A1 (auth challenge) did not pass.']
    };
  } else if (prmUrl !== null) {
    a2Finding = {
      stem: A2_FINDING_ID,
      title: A2_TITLE,
      severity: 'info',
      passed: true,
      observations: [`resource_metadata URL: ${prmUrl}`],
      evidence: [DISCOVERY_PROBE_STEM]
    };
  } else {
    a2Finding = {
      stem: A2_FINDING_ID,
      title: A2_TITLE,
      severity: 'warn',
      passed: false,
      observations: [
        'WWW-Authenticate present but no resource_metadata parameter (RFC 9728 §5.1).'
      ],
      evidence: [DISCOVERY_PROBE_STEM]
    };
  }

  // --- Assertion 3: error code absent on no-credentials challenge (RFC 6750 §3.1) ---

  let a3Finding: Finding;
  if (!a1Passed || challenge === null || wwwAuth === null) {
    a3Finding = {
      stem: A3_FINDING_ID,
      title: A3_TITLE,
      severity: 'skipped',
      passed: false,
      observations: ['Skipped: A1 (auth challenge) did not pass.']
    };
  } else {
    const errorPresent = challenge.params.has('error');
    const errorDescPresent = challenge.params.has('error_description');
    const errorUriPresent = challenge.params.has('error_uri');
    const anyErrorParam = errorPresent || errorDescPresent || errorUriPresent;

    const a3Observations: string[] = [];
    a3Observations.push(`WWW-Authenticate: ${wwwAuth}`);

    if (anyErrorParam) {
      const offendingParams: string[] = [];
      if (errorPresent) offendingParams.push('error');
      if (errorDescPresent) offendingParams.push('error_description');
      if (errorUriPresent) offendingParams.push('error_uri');
      for (const param of offendingParams) {
        a3Observations.push(
          `WWW-Authenticate includes '${param}' parameter; RFC 6750 §3.1 states the resource server SHOULD NOT include error information on a request that lacks authentication credentials.`
        );
      }
      a3Finding = {
        stem: A3_FINDING_ID,
        title: A3_TITLE,
        severity: 'warn',
        passed: false,
        observations: a3Observations,
        evidence: [DISCOVERY_PROBE_STEM]
      };
    } else {
      a3Observations.push(
        'No error, error_description, or error_uri parameter present.'
      );
      a3Finding = {
        stem: A3_FINDING_ID,
        title: A3_TITLE,
        severity: 'info',
        passed: true,
        observations: a3Observations,
        evidence: [DISCOVERY_PROBE_STEM]
      };
    }
  }

  const result: ProbeResult = {
    findings: [a1Finding, a2Finding, a3Finding],
    evidence: [{ name: DISCOVERY_PROBE_STEM, evidence }]
  };
  if (prmUrl !== null) {
    result.contextUpdates = { protectedResourceMetadataUrl: prmUrl };
  }
  return result;
}

export interface WwwAuthChallenge {
  scheme: string;
  params: Map<string, string>;
}

/**
 * Parse a single Bearer WWW-Authenticate challenge per RFC 9110 §11.1
 * (Challenge and Response; RFC 7235 was obsoleted by RFC 9110).
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
