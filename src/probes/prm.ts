import { z } from 'zod';
import type { AuditContext, Evidence, Finding, NamedEvidence, ProbeResult } from '../types.js';

export const PRM_PROBE_STEM = '02-prm';

/**
 * Protected Resource Metadata, per RFC 9728 §2.
 *
 * Required: resource.
 * Recommended: scopes_supported.
 * Optional: authorization_servers, bearer_methods_supported,
 * resource_documentation, resource_signing_alg_values_supported,
 * jwks_uri, and others.
 *
 * Passthrough: RFC 9728 §2 permits additional parameters; the schema
 * must not reject unknown keys.
 */
export const PrmSchema = z.object({
  resource: z.string().url(),
  authorization_servers: z.array(z.string().url()).min(1).optional(),
  scopes_supported: z.array(z.string()).optional(),
  bearer_methods_supported: z.array(z.string()).optional(),
  resource_documentation: z.string().url().optional(),
  resource_signing_alg_values_supported: z.array(z.string()).optional()
}).passthrough();

export type Prm = z.infer<typeof PrmSchema>;

const RECOMMENDED_FIELDS = ['scopes_supported'] as const;

/**
 * Probe 2: Protected Resource Metadata fetch and validation (RFC 9728).
 *
 * When probe 1 extracted `resource_metadata` from WWW-Authenticate, fetch
 * that URL directly. When that parameter is absent (see MCP 2025-11-25
 * §2.3.1 SHOULD), derive the well-known URL per RFC 9728 §3.1. §3.1
 * selects the form by whether the resource identifier has a path or query
 * component. With a path or query, the well-known suffix is inserted
 * between the host and the path (any terminating slash after the host
 * removed first); without one, the suffix sits at the top level. The
 * probe queries the path-insertion form, the §3.1 location for a resource
 * with a path, and only if that does not resolve additionally tries the
 * top-level form to locate metadata published at the non-mandated
 * location. Emits an info-finding when fallback resolves the document, or
 * an issue-finding when neither derived form returns 2xx.
 */
export async function prmProbe(ctx: AuditContext): Promise<ProbeResult> {
  const prmUrl = ctx.protectedResourceMetadataUrl;
  if (prmUrl) {
    return fetchAndValidate(ctx, prmUrl, PRM_PROBE_STEM);
  }

  return runFallback(ctx);
}

/**
 * RFC 9728 §3.1 fallback when WWW-Authenticate lacked resource_metadata.
 *
 * §3.1 selects the well-known URL form by whether the resource identifier
 * has a path or query component. With a path or query, the suffix is
 * inserted between host and the remaining path (any terminating slash
 * after the host removed first); without one, the suffix sits at the top
 * level. The probe queries the path-insertion form, the §3.1 location for
 * a resource with a path, and only if that does not resolve additionally
 * tries the top-level form to locate metadata published at the
 * non-mandated location. When the target has no path component both forms
 * collapse to the same URL and only one request is made.
 */
async function runFallback(ctx: AuditContext): Promise<ProbeResult> {
  const { pathInsert, topLevel } = wellKnownUrls(ctx.target);
  const collapsed = pathInsert === topLevel;

  if (collapsed) {
    const attempt = await fetchPrm(pathInsert);
    if (attempt.response.status >= 200 && attempt.response.status < 300) {
      return fallbackSuccess(ctx, pathInsert, attempt, '02-prm-wellknown');
    }
    return fallbackAllFailed({
      collapsed: true,
      pathInsertUrl: pathInsert,
      pathInsertStatus: attempt.response.status,
      pathInsertEvidence: { name: '02-prm-wellknown', evidence: attempt.evidence },
      topLevelUrl: pathInsert,
      topLevelStatus: attempt.response.status,
      topLevelEvidence: null
    });
  }

  const first = await fetchPrm(pathInsert);
  if (first.response.status >= 200 && first.response.status < 300) {
    return fallbackSuccess(ctx, pathInsert, first, '02-prm-wellknown-pathinsert');
  }

  const second = await fetchPrm(topLevel);
  if (second.response.status >= 200 && second.response.status < 300) {
    return fallbackSuccessWithPrior(
      ctx,
      topLevel,
      second,
      '02-prm-wellknown-toplevel',
      { name: '02-prm-wellknown-pathinsert', evidence: first.evidence }
    );
  }

  return fallbackAllFailed({
    collapsed: false,
    pathInsertUrl: pathInsert,
    pathInsertStatus: first.response.status,
    pathInsertEvidence: { name: '02-prm-wellknown-pathinsert', evidence: first.evidence },
    topLevelUrl: topLevel,
    topLevelStatus: second.response.status,
    topLevelEvidence: { name: '02-prm-wellknown-toplevel', evidence: second.evidence }
  });
}

interface FetchAttempt {
  response: { status: number; statusText: string; body: string };
  evidence: Evidence;
}

async function fetchPrm(url: string): Promise<FetchAttempt> {
  const requestHeaders: Record<string, string> = {
    'Accept': 'application/json',
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
    response: { status: response.status, statusText: response.statusText, body: responseBody },
    evidence
  };
}

/**
 * Existing direct-URL path: probe the advertised URL, validate, emit a
 * single finding with a single evidence file named `evidenceName`.
 */
async function fetchAndValidate(
  ctx: AuditContext,
  url: string,
  evidenceName: string
): Promise<ProbeResult> {
  const attempt = await fetchPrm(url);
  const validation = validatePrmResponse(ctx, attempt);

  const finding: Finding = {
    stem: PRM_PROBE_STEM,
    title: 'Protected Resource Metadata (RFC 9728)',
    severity: validation.passed ? 'info' : 'warn',
    passed: validation.passed,
    observations: validation.observations
  };
  if (validation.passed) {
    finding.evidence = [evidenceName];
  }

  const result: ProbeResult = {
    findings: [finding],
    evidence: [{ name: evidenceName, evidence: attempt.evidence }]
  };
  if (validation.contextUpdates) {
    result.contextUpdates = validation.contextUpdates;
  }
  return result;
}

/**
 * Fallback resolved the document on the first attempt (path-insertion, or
 * the collapsed single-URL case). Emit the validation finding plus an
 * info-finding flagging that WWW-Authenticate should have advertised the
 * URL.
 */
function fallbackSuccess(
  ctx: AuditContext,
  url: string,
  attempt: FetchAttempt,
  evidenceName: string
): ProbeResult {
  const validation = validatePrmResponse(ctx, attempt);

  const validationFinding: Finding = {
    stem: PRM_PROBE_STEM,
    title: 'Protected Resource Metadata (RFC 9728)',
    severity: validation.passed ? 'info' : 'warn',
    passed: validation.passed,
    observations: validation.observations
  };
  if (validation.passed) {
    validationFinding.evidence = [evidenceName];
  }

  const infoFinding: Finding = {
    stem: PRM_PROBE_STEM,
    title: 'PRM discovery required well-known URL fallback',
    severity: 'info',
    passed: true,
    observations: [
      `WWW-Authenticate did not include resource_metadata parameter. PRM resolved at ${url}. MCP spec 2025-11-25 §2.3.1 recommends (SHOULD) that servers include resource_metadata on 401/403 responses.`
    ]
  };

  const result: ProbeResult = {
    findings: [validationFinding, infoFinding],
    evidence: [{ name: evidenceName, evidence: attempt.evidence }]
  };
  if (validation.contextUpdates) {
    result.contextUpdates = validation.contextUpdates;
  }
  return result;
}

/**
 * Fallback resolved the document on the top-level form after the
 * path-insertion form returned a non-2xx status. Evidence for both
 * requests is written.
 */
function fallbackSuccessWithPrior(
  ctx: AuditContext,
  url: string,
  attempt: FetchAttempt,
  evidenceName: string,
  priorEvidence: NamedEvidence
): ProbeResult {
  const base = fallbackSuccess(ctx, url, attempt, evidenceName);
  return {
    ...base,
    evidence: [priorEvidence, ...base.evidence]
  };
}

interface FallbackFailureInput {
  collapsed: boolean;
  pathInsertUrl: string;
  pathInsertStatus: number;
  pathInsertEvidence: NamedEvidence;
  topLevelUrl: string;
  topLevelStatus: number;
  topLevelEvidence: NamedEvidence | null;
}

function fallbackAllFailed(input: FallbackFailureInput): ProbeResult {
  const detail = input.collapsed
    ? `WWW-Authenticate lacks resource_metadata parameter. Well-known URL (${input.pathInsertUrl}) returned ${input.pathInsertStatus}; target has no path component so path-insertion and top-level forms are identical. A spec-compliant client cannot complete discovery.`
    : `WWW-Authenticate lacks resource_metadata parameter. Well-known URL path-insertion form (${input.pathInsertUrl}) returned ${input.pathInsertStatus}; top-level form (${input.topLevelUrl}) returned ${input.topLevelStatus}. A spec-compliant client cannot complete discovery.`;

  const finding: Finding = {
    stem: PRM_PROBE_STEM,
    title: 'No RFC 9728 discovery path resolves',
    severity: 'issue',
    passed: false,
    observations: [detail]
  };

  const evidence: NamedEvidence[] = [input.pathInsertEvidence];
  if (input.topLevelEvidence) {
    evidence.push(input.topLevelEvidence);
  }

  return { findings: [finding], evidence };
}

interface ValidationOutcome {
  passed: boolean;
  observations: string[];
  contextUpdates?: Partial<AuditContext>;
}

/**
 * Runs the existing zod schema + RFC 9728 §2 RECOMMENDED-field and §3.3
 * scope checks against a fetched PRM response. Behavior is unchanged from
 * the pre-fallback implementation; extracted so both the direct-URL and
 * fallback paths share the same validation.
 */
function validatePrmResponse(ctx: AuditContext, attempt: FetchAttempt): ValidationOutcome {
  const observations: string[] = [];
  observations.push(`HTTP ${attempt.response.status} ${attempt.response.statusText}`);

  let passed = false;
  let contextUpdates: Partial<AuditContext> | undefined;

  if (attempt.response.status !== 200) {
    observations.push('PRM endpoint did not return 200; cannot validate.');
    return { passed, observations };
  }

  let json: unknown;
  try {
    json = JSON.parse(attempt.response.body);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    observations.push(`PRM body is not valid JSON: ${message}`);
    return { passed, observations };
  }

  const parseResult = PrmSchema.safeParse(json);
  if (!parseResult.success) {
    for (const issue of parseResult.error.issues) {
      const path = issue.path.length > 0 ? issue.path.join('.') : '(root)';
      observations.push(`PRM schema: ${path}: ${issue.message} (RFC 9728 §2)`);
    }
    return { passed, observations };
  }

  const prm = parseResult.data;
  observations.push(`resource: ${prm.resource}`);
  if (prm.authorization_servers !== undefined) {
    observations.push(`authorization_servers: ${prm.authorization_servers.join(', ')}`);
  }

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
      observations.push(`RFC 9728 §2 recommends "${field}"; not present.`);
    }
  }

  passed = originMatch && pathMatch;
  contextUpdates = {
    protectedResourceMetadata: prm
  };
  if (prm.authorization_servers !== undefined) {
    contextUpdates.authorizationServers = prm.authorization_servers;
  }

  return { passed, observations, contextUpdates };
}

/**
 * RFC 9728 §3.1 well-known URL derivation. The spec requires any
 * terminating slash after the host component to be stripped before
 * inserting `/.well-known/oauth-protected-resource` between host and
 * the remaining path. When the target URL has no path component both
 * forms collapse to a single URL; callers probe it once.
 */
export function wellKnownUrls(target: URL): { pathInsert: string; topLevel: string } {
  const topLevel = `${target.origin}/.well-known/oauth-protected-resource`;
  const path = target.pathname;
  if (path === '' || path === '/') {
    return { pathInsert: topLevel, topLevel };
  }
  // RFC 9728 §3.1: strip any trailing slash from the host component's
  // following path before inserting the well-known suffix. The inserted
  // segment goes between host and the path+query.
  const trimmedPath = path.replace(/\/+$/, '');
  const pathInsert = `${target.origin}/.well-known/oauth-protected-resource${trimmedPath}${target.search}`;
  return { pathInsert, topLevel };
}

function safeUrl(raw: string): URL | null {
  try {
    return new URL(raw);
  } catch {
    return null;
  }
}
