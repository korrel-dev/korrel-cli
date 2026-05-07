import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import type { AuditContext, Evidence, Finding, NamedEvidence, ProbeResult } from '../types.js';

export const PKCE_PROBE_STEM = '05-pkce-enforcement';
export const PKCE_NO_CHALLENGE_FINDING_ID = '05-pkce-enforcement-no-challenge';
export const PKCE_PLAIN_FINDING_ID = '05-pkce-enforcement-plain';
export const PKCE_STATE_ECHO_FINDING_ID = '05-pkce-enforcement-state-echo';
export const PKCE_VERIFIER_MISMATCH_FINDING_ID = '05-pkce-enforcement-verifier-mismatch';

const EVIDENCE_NAME_NO_CHALLENGE = '05-pkce-enforcement-no-challenge';
const EVIDENCE_NAME_PLAIN = '05-pkce-enforcement-plain';

const FALLBACK_REDIRECT_URI = 'https://korrel.dev/callback';
const PLAIN_TEST_CHALLENGE = 'plain-test-challenge-string-min-43-chars-aaaaaaa';

const RFC_CLAUSE_NO_CHALLENGE = 'RFC 7636 §4.4.1 MUST';
const RFC_CLAUSE_PLAIN = 'RFC 7636 §7 SHOULD NOT';

/**
 * Footprint: probe 5 sent two GET requests to the authorization endpoint
 * with intentionally non-conforming PKCE parameters; both will appear in
 * the AS's access logs as failed authorization attempts. No tokens were
 * issued. No persistent state was created.
 */

const RegisteredClientSchema = z
  .object({
    client_id: z.string().min(1),
    redirect_uris: z.array(z.string().url()).optional()
  })
  .passthrough();

interface TestParams {
  testLabel: string;
  primaryFindingId: string;
  primaryFindingTitleSubject: string;
  evidenceName: string;
  rfcClause: string;
  codeIssuedTitle: string;
}

/**
 * Probe 5: PKCE enforcement at the authorization endpoint.
 *
 * Behavioral complement to probe 3's passive A4 finding: sends authorization
 * requests with intentionally non-conforming PKCE parameters and inspects the
 * immediate response (3xx Location header or 4xx body) before any consent step.
 *
 * Headless-CLI constraint: a CLI cannot complete the authorization code flow
 * (no browser, no user consent), so the probe can only observe the AS's
 * immediate decision. It emits `issue` only on direct evidence of
 * non-enforcement (an authorization code returned in the redirect query
 * string); ambiguous responses (consent/login redirect, HTML page) are
 * recorded as `warn`.
 *
 * Test 1 (always runs when probe runs): GET authorization_endpoint with
 *   code_challenge omitted.
 * Test 2 (runs only when AS does not advertise plain): GET with
 *   code_challenge_method=plain.
 */
export async function pkceEnforcementProbe(ctx: AuditContext): Promise<ProbeResult> {
  const findings: Finding[] = [];
  const evidence: NamedEvidence[] = [];

  // Guard 1: AS metadata required.
  const as = ctx.authorizationServerMetadata;
  const authzEndpoint = ctx.authorizationEndpoint;
  if (!as || !authzEndpoint) {
    findings.push({
      id: PKCE_PROBE_STEM,
      title: 'PKCE enforcement probe skipped: AS metadata not available',
      severity: 'skipped',
      passed: false,
      observations: [
        'Probe 3 did not populate authorizationServerMetadata; probe 5 cannot run.'
      ]
    });
    return { findings, evidence };
  }

  // Guard 2: registered client required.
  const clientResult = RegisteredClientSchema.safeParse(ctx.registeredClient);
  if (!clientResult.success) {
    findings.push({
      id: PKCE_PROBE_STEM,
      title: 'PKCE enforcement probe skipped: no registered client',
      severity: 'skipped',
      passed: false,
      observations: [
        'Probe 4 did not populate registeredClient; probe 5 cannot run.'
      ]
    });
    return { findings, evidence };
  }
  const client = clientResult.data;

  // Guard 3: PKCE not advertised.
  const pkceMethods = as.code_challenge_methods_supported;
  if (!pkceMethods || pkceMethods.length === 0) {
    findings.push({
      id: PKCE_PROBE_STEM,
      title: 'PKCE not advertised; enforcement test not applicable',
      severity: 'info',
      passed: false,
      observations: [
        'AS metadata does not advertise code_challenge_methods_supported. Probe 3 already records this. Probe 5 has nothing to enforce.'
      ]
    });
    return { findings, evidence };
  }

  const redirectUri = client.redirect_uris?.[0] ?? FALLBACK_REDIRECT_URI;
  const expectedRedirectHost = safeHost(redirectUri);
  const scope = as.scopes_supported?.[0];

  // --- Test 1: missing code_challenge ---
  {
    const state = generateState();
    const url = buildAuthzUrl(authzEndpoint, {
      response_type: 'code',
      client_id: client.client_id,
      redirect_uri: redirectUri,
      state,
      ...(scope ? { scope } : {})
    });
    const result = await getNoFollow(url);
    evidence.push({ name: EVIDENCE_NAME_NO_CHALLENGE, evidence: result.evidence });

    const params: TestParams = {
      testLabel: 'request lacking code_challenge',
      primaryFindingId: PKCE_NO_CHALLENGE_FINDING_ID,
      primaryFindingTitleSubject: 'request lacking code_challenge',
      evidenceName: EVIDENCE_NAME_NO_CHALLENGE,
      rfcClause: RFC_CLAUSE_NO_CHALLENGE,
      codeIssuedTitle: 'Authorization endpoint issued authorization code without code_challenge'
    };
    classifyAndEmit(findings, result, expectedRedirectHost, state, params);
  }

  // --- Test 2: code_challenge_method=plain (skipped when plain advertised) ---
  if (pkceMethods.includes('plain')) {
    findings.push({
      id: PKCE_PLAIN_FINDING_ID,
      title: 'Plain method enforcement test skipped: plain is advertised',
      severity: 'skipped',
      passed: false,
      observations: [
        'AS metadata advertises plain in code_challenge_methods_supported; the test is not applicable.'
      ]
    });
  } else {
    const state = generateState();
    const url = buildAuthzUrl(authzEndpoint, {
      response_type: 'code',
      client_id: client.client_id,
      redirect_uri: redirectUri,
      state,
      code_challenge: PLAIN_TEST_CHALLENGE,
      code_challenge_method: 'plain',
      ...(scope ? { scope } : {})
    });
    const result = await getNoFollow(url);
    evidence.push({ name: EVIDENCE_NAME_PLAIN, evidence: result.evidence });

    const params: TestParams = {
      testLabel: 'code_challenge_method=plain',
      primaryFindingId: PKCE_PLAIN_FINDING_ID,
      primaryFindingTitleSubject: 'code_challenge_method=plain',
      evidenceName: EVIDENCE_NAME_PLAIN,
      rfcClause: RFC_CLAUSE_PLAIN,
      codeIssuedTitle: 'Authorization endpoint issued authorization code with code_challenge_method=plain'
    };
    classifyAndEmit(findings, result, expectedRedirectHost, state, params);
  }

  // Verifier-mismatch deferral (always emitted when probe ran tests).
  findings.push({
    id: PKCE_VERIFIER_MISMATCH_FINDING_ID,
    title: 'Verifier-mismatch test deferred to future probe',
    severity: 'skipped',
    passed: false,
    observations: [
      'Verifier-mismatch test requires obtaining an authorization code, which requires user consent. Headless probe cannot complete this test in v0. Tracked for future browser-harness probe.'
    ]
  });

  return { findings, evidence };
}

interface AuthzAttempt {
  status: number;
  statusText: string;
  body: string;
  location: string | null;
  evidence: Evidence;
}

async function getNoFollow(url: string): Promise<AuthzAttempt> {
  const requestHeaders: Record<string, string> = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'User-Agent': 'korrel-cli/0.0.0'
  };

  const response = await fetch(url, {
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
      url,
      headers: requestHeaders
    },
    response: {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
      body: responseBody
    }
  };

  return {
    status: response.status,
    statusText: response.statusText,
    body: responseBody,
    location: response.headers.get('location'),
    evidence
  };
}

function classifyAndEmit(
  findings: Finding[],
  result: AuthzAttempt,
  expectedRedirectHost: string | null,
  sentState: string,
  params: TestParams
): void {
  const isRedirect = result.status >= 300 && result.status < 400;

  if (isRedirect && result.location && expectedRedirectHost) {
    const locationUrl = safeUrl(result.location);
    if (locationUrl && locationUrl.host === expectedRedirectHost) {
      const query = locationUrl.searchParams;
      const error = query.get('error');
      const errorDescription = query.get('error_description');
      const code = query.get('code');

      if (error) {
        findings.push({
          id: params.primaryFindingId,
          title: `Authorization endpoint rejected ${params.primaryFindingTitleSubject}`,
          severity: 'info',
          passed: true,
          observations: [
            `Response was 3xx redirect to redirect_uri with error=${error}, error_description=${errorDescription ?? '(absent)'}. ${params.rfcClause} satisfied.`
          ],
          evidence: [params.evidenceName]
        });
      } else if (code) {
        findings.push({
          id: params.primaryFindingId,
          title: params.codeIssuedTitle,
          severity: 'issue',
          passed: false,
          observations: [
            `Response was 3xx redirect to redirect_uri with code parameter present. ${params.rfcClause}: this is a direct violation. The AS issued an authorization code without enforcing PKCE.`
          ],
          evidence: [params.evidenceName]
        });
      } else {
        findings.push({
          id: params.primaryFindingId,
          title: 'Authorization endpoint redirected to redirect_uri without code or error',
          severity: 'warn',
          passed: false,
          observations: [
            `Response was 3xx redirect to redirect_uri but query string contained neither error nor code. PKCE enforcement could not be confirmed.`
          ],
          evidence: [params.evidenceName]
        });
      }

      // Secondary state-echo check: only when redirect lands at expected host.
      const echoedState = query.get('state');
      if (echoedState !== sentState) {
        findings.push({
          id: PKCE_STATE_ECHO_FINDING_ID,
          title: 'Authorization endpoint did not echo state parameter correctly',
          severity: 'warn',
          passed: false,
          observations: [
            'Response redirect to redirect_uri did not include the state parameter sent in the request, or included a different value. RFC 6749 §10.12 recommends state for CSRF protection.'
          ],
          evidence: [params.evidenceName]
        });
      }
      return;
    }

    // Off-host redirect (consent/login page).
    findings.push({
      id: params.primaryFindingId,
      title: `PKCE enforcement could not be confirmed for ${params.primaryFindingTitleSubject}`,
      severity: 'warn',
      passed: false,
      observations: [
        `Response was 3xx redirect to ${locationUrl?.host ?? '(unparseable Location)'} (likely consent or login page). Headless probe cannot complete the consent flow. ${params.rfcClause} requires explicit rejection at the authorization endpoint.`
      ],
      evidence: [params.evidenceName]
    });
    return;
  }

  if (result.status === 200 || result.status === 401 || result.status === 403) {
    findings.push({
      id: params.primaryFindingId,
      title: `PKCE enforcement could not be confirmed for ${params.primaryFindingTitleSubject}`,
      severity: 'warn',
      passed: false,
      observations: [
        `Response was HTTP ${result.status} (likely an interactive consent or login page). Headless probe cannot complete the flow.`
      ],
      evidence: [params.evidenceName]
    });
    return;
  }

  if (result.status === 400 || result.status === 422) {
    if (bodyMentionsPkce(result.body)) {
      findings.push({
        id: params.primaryFindingId,
        title: `Authorization endpoint rejected ${params.primaryFindingTitleSubject} with HTTP ${result.status}`,
        severity: 'info',
        passed: true,
        observations: [
          `AS returned ${result.status} with body indicating PKCE-related rejection.`
        ],
        evidence: [params.evidenceName]
      });
    } else {
      findings.push({
        id: params.primaryFindingId,
        title: `Authorization endpoint returned HTTP ${result.status} for ${params.primaryFindingTitleSubject}`,
        severity: 'warn',
        passed: false,
        observations: [
          `AS returned ${result.status} but the body does not clearly indicate PKCE-related rejection.`
        ],
        evidence: [params.evidenceName]
      });
    }
    return;
  }

  findings.push({
    id: params.primaryFindingId,
    title: `Authorization endpoint returned unexpected response for ${params.primaryFindingTitleSubject}`,
    severity: 'warn',
    passed: false,
    observations: [
      `HTTP ${result.status}. PKCE enforcement could not be confirmed.`
    ],
    evidence: [params.evidenceName]
  });
}

function bodyMentionsPkce(body: string): boolean {
  const lower = body.toLowerCase();
  return lower.includes('code_challenge') || lower.includes('pkce') || lower.includes('invalid_request');
}

function buildAuthzUrl(endpoint: string, params: Record<string, string>): string {
  const url = new URL(endpoint);
  for (const [key, value] of Object.entries(params)) {
    url.searchParams.set(key, value);
  }
  return url.toString();
}

function generateState(): string {
  return randomBytes(16).toString('hex');
}

function safeUrl(raw: string): URL | null {
  try {
    return new URL(raw);
  } catch {
    return null;
  }
}

function safeHost(raw: string): string | null {
  return safeUrl(raw)?.host ?? null;
}
