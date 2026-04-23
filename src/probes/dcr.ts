import { z } from 'zod';
import type {
  AuditContext,
  Evidence,
  Finding,
  NamedEvidence,
  ProbeResult
} from '../types.js';

export const DCR_PROBE_ID = '04-dcr';

const EVIDENCE_NAME_VALID = '04-dcr-register-valid';
const EVIDENCE_NAME_HTTP_REDIRECT = '04-dcr-register-http-redirect';
const EVIDENCE_NAME_HOST_MISMATCH = '04-dcr-register-host-mismatch';

const CLIENT_NAME = 'korrel-cli audit probe';
const CLIENT_URI = 'https://korrel.dev';

const BODY_EXCERPT_MAX_LEN = 200;

/**
 * Minimal successful RFC 7591 §3.2.1 registration response schema. Only
 * `client_id` is required; the full spec includes `client_secret`,
 * `registration_access_token`, etc. Passthrough preserves any extra
 * fields the orchestrator may forward to probes 5 and 6 via
 * `AuditContext.registeredClient`.
 */
const RegistrationSuccessSchema = z
  .object({
    client_id: z.string().min(1)
  })
  .passthrough();

interface DcrRegistrationPayload {
  client_name: string;
  client_uri: string;
  redirect_uris: string[];
  grant_types: string[];
  response_types: string[];
  token_endpoint_auth_method: string;
}

/**
 * Probe 4: DCR endpoint validation and CIMD advertisement.
 *
 * Methodology step 3 (client registration surface). Covers:
 *   (a) Presence/TLS of `registration_endpoint` (RFC 7591 §3).
 *   (b) Active redirect-URI validation via three POSTs (RFC 7591 §5).
 *   (c) Passive CIMD flag advertisement
 *       (draft-ietf-oauth-client-id-metadata-document-01 §5).
 *
 * Three POSTs exactly when DCR is advertised; zero otherwise. POST 1
 * (valid baseline) creates one stale OAuth client record per target;
 * cleanup is out of scope and disclosed in PROBE-4-SCOPE.md Footprint.
 */
export async function dcrProbe(ctx: AuditContext): Promise<ProbeResult> {
  const as = ctx.authorizationServerMetadata;
  if (!as) {
    const skipFinding: Finding = {
      id: DCR_PROBE_ID,
      title: 'DCR/CIMD probe skipped: AS metadata not available',
      severity: 'skipped',
      passed: false,
      observations: [
        'Probe 3 did not populate authorizationServerMetadata; probe 4 cannot run.'
      ]
    };
    return { findings: [skipFinding], evidence: [] };
  }

  const findings: Finding[] = [];
  const evidence: NamedEvidence[] = [];

  // --- Concern (c): CIMD flag check (passive) ---
  const cimdSupportedRaw = as['client_id_metadata_document_supported'];
  const cimdSupported = cimdSupportedRaw === true;
  if (cimdSupported) {
    findings.push({
      id: DCR_PROBE_ID,
      title: 'CIMD advertised',
      severity: 'info',
      passed: true,
      observations: [
        'AS metadata sets client_id_metadata_document_supported=true.'
      ]
    });
  } else {
    findings.push({
      id: DCR_PROBE_ID,
      title: 'CIMD not advertised',
      severity: 'info',
      passed: false,
      observations: [
        'client_id_metadata_document_supported absent or false in AS metadata.'
      ]
    });
  }

  // --- Concern (a): DCR endpoint discovery (passive) ---
  const registrationEndpoint = as.registration_endpoint;
  if (!registrationEndpoint) {
    findings.push({
      id: DCR_PROBE_ID,
      title: 'DCR not advertised',
      severity: 'info',
      passed: false,
      observations: [
        'AS metadata does not include registration_endpoint.'
      ]
    });
    return { findings, evidence };
  }

  if (!registrationEndpoint.startsWith('https://')) {
    findings.push({
      id: DCR_PROBE_ID,
      title: 'DCR endpoint not TLS-protected',
      severity: 'issue',
      passed: false,
      observations: [
        `registration_endpoint=${registrationEndpoint} uses non-HTTPS scheme (RFC 7591 §3 MUST).`
      ]
    });
  }

  findings.push({
    id: DCR_PROBE_ID,
    title: 'DCR advertised',
    severity: 'info',
    passed: true,
    observations: [
      `AS metadata registration_endpoint=${registrationEndpoint}.`
    ]
  });

  // --- Concern (b): active redirect URI validation ---
  let contextUpdates: Partial<AuditContext> | undefined;

  // POST 1: valid baseline registration.
  const payload1: DcrRegistrationPayload = {
    client_name: CLIENT_NAME,
    client_uri: CLIENT_URI,
    redirect_uris: ['https://korrel.dev/callback'],
    grant_types: ['authorization_code'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none'
  };
  const attempt1 = await postRegistration(registrationEndpoint, payload1);
  evidence.push({ name: EVIDENCE_NAME_VALID, evidence: attempt1.evidence });

  const body1Parsed = parseJson(attempt1.body);
  const body1Validated = body1Parsed !== undefined
    ? RegistrationSuccessSchema.safeParse(body1Parsed)
    : null;

  if (attempt1.status === 201) {
    if (body1Validated?.success) {
      findings.push({
        id: DCR_PROBE_ID,
        title: 'DCR valid registration accepted',
        severity: 'info',
        passed: true,
        observations: [
          `POST returned 201 with client_id=${body1Validated.data.client_id}.`
        ]
      });
      contextUpdates = { registeredClient: body1Validated.data };
    } else {
      findings.push({
        id: DCR_PROBE_ID,
        title: 'DCR valid registration not accepted',
        severity: 'info',
        passed: false,
        observations: [
          `POST returned HTTP ${attempt1.status}; body: ${bodyExcerpt(attempt1.body)}.`
        ]
      });
    }
  } else if (attempt1.status === 200) {
    if (body1Validated?.success) {
      findings.push({
        id: DCR_PROBE_ID,
        title: 'DCR registration response uses HTTP 200 instead of 201',
        severity: 'warn',
        passed: false,
        observations: [
          `POST returned 200 with client_id=${body1Validated.data.client_id}. RFC 7591 §3.2.1 MUST requires HTTP 201 for successful registration. Context populated; downstream probes may proceed.`
        ]
      });
      contextUpdates = { registeredClient: body1Validated.data };
    } else {
      findings.push({
        id: DCR_PROBE_ID,
        title: 'DCR registration returned 200 but response lacks valid client_id',
        severity: 'issue',
        passed: false,
        observations: [
          'POST returned 200 but body does not contain a valid client_id. RFC 7591 §3.2.1 MUST requires HTTP 201 and a client_id in the response body. Context not populated.'
        ]
      });
    }
  } else {
    findings.push({
      id: DCR_PROBE_ID,
      title: 'DCR valid registration not accepted',
      severity: 'info',
      passed: false,
      observations: [
        `POST returned HTTP ${attempt1.status}; body: ${bodyExcerpt(attempt1.body)}.`
      ]
    });
  }

  // POST 2: HTTP redirect URI for confidential client (MUST violation probe).
  // redirect_uri uses HTTP scheme; host matches client_uri so the scheme is
  // the sole isolated variable.
  const payload2: DcrRegistrationPayload = {
    client_name: CLIENT_NAME,
    client_uri: CLIENT_URI,
    redirect_uris: ['http://korrel.dev/callback'],
    grant_types: ['authorization_code'],
    response_types: ['code'],
    token_endpoint_auth_method: 'client_secret_basic'
  };
  const attempt2 = await postRegistration(registrationEndpoint, payload2);
  evidence.push({ name: EVIDENCE_NAME_HTTP_REDIRECT, evidence: attempt2.evidence });

  if (attempt2.status === 201) {
    findings.push({
      id: DCR_PROBE_ID,
      title: 'DCR accepted HTTP redirect URI for confidential client',
      severity: 'issue',
      passed: false,
      observations: [
        'POST returned 201; HTTP redirect URIs must be rejected for confidential clients (RFC 7591 §5 MUST).'
      ]
    });
  } else {
    findings.push({
      id: DCR_PROBE_ID,
      title: 'DCR rejected HTTP redirect URI for confidential client',
      severity: 'info',
      passed: true,
      observations: [
        `POST returned HTTP ${attempt2.status} as expected (RFC 7591 §5).`
      ]
    });
  }

  // POST 3: host mismatch between client_uri and redirect_uri
  // (SHOULD violation probe).
  const payload3: DcrRegistrationPayload = {
    client_name: CLIENT_NAME,
    client_uri: CLIENT_URI,
    redirect_uris: ['https://other-host.example.com/callback'],
    grant_types: ['authorization_code'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none'
  };
  const attempt3 = await postRegistration(registrationEndpoint, payload3);
  evidence.push({ name: EVIDENCE_NAME_HOST_MISMATCH, evidence: attempt3.evidence });

  if (attempt3.status === 201) {
    findings.push({
      id: DCR_PROBE_ID,
      title: 'DCR accepted host-mismatched redirect URI',
      severity: 'warn',
      passed: false,
      observations: [
        'POST returned 201; redirect_uri host differs from client_uri host. AS SHOULD reject this (RFC 7591 §5 SHOULD).'
      ]
    });
  } else {
    findings.push({
      id: DCR_PROBE_ID,
      title: 'DCR rejected host-mismatched redirect URI',
      severity: 'info',
      passed: true,
      observations: [
        `POST returned HTTP ${attempt3.status}. Host mismatch check is enforced.`
      ]
    });
  }

  const result: ProbeResult = { findings, evidence };
  if (contextUpdates) {
    result.contextUpdates = contextUpdates;
  }
  return result;
}

interface RegistrationAttempt {
  status: number;
  statusText: string;
  body: string;
  evidence: Evidence;
}

async function postRegistration(
  url: string,
  payload: DcrRegistrationPayload
): Promise<RegistrationAttempt> {
  const requestHeaders: Record<string, string> = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'User-Agent': 'korrel-cli/0.0.0'
  };
  const body = JSON.stringify(payload);

  const response = await fetch(url, {
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
      url,
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

  return {
    status: response.status,
    statusText: response.statusText,
    body: responseBody,
    evidence
  };
}

function parseJson(body: string): unknown {
  try {
    return JSON.parse(body);
  } catch {
    return undefined;
  }
}

function bodyExcerpt(body: string): string {
  const trimmed = body.trim();
  if (trimmed.length <= BODY_EXCERPT_MAX_LEN) {
    return trimmed;
  }
  return `${trimmed.slice(0, BODY_EXCERPT_MAX_LEN)}... (truncated)`;
}
