import type { AuditContext, Finding, ProbeResult } from '../types.js';

export const TOKEN_HYGIENE_PROBE_ID = '06-token-hygiene';
export const TOKEN_HYGIENE_JWKS_URI_FINDING_ID = '06-token-hygiene-jwks-uri';
export const TOKEN_HYGIENE_REVOCATION_FINDING_ID = '06-token-hygiene-revocation-endpoint';
export const TOKEN_HYGIENE_INTROSPECTION_FINDING_ID = '06-token-hygiene-introspection-endpoint';
export const TOKEN_HYGIENE_BEARER_METHODS_FINDING_ID = '06-token-hygiene-bearer-methods';
export const TOKEN_HYGIENE_LIVE_TOKEN_DEFERRED_FINDING_ID = '06-token-hygiene-live-token-deferred';

const JWKS_URI_TITLE_SKIPPED = 'JWKS URI advertisement (RFC 8414 §2)';
const REVOCATION_TITLE_SKIPPED = 'Revocation endpoint advertisement (RFC 7009)';
const INTROSPECTION_TITLE_SKIPPED = 'Introspection endpoint advertisement (RFC 7662)';
const BEARER_METHODS_TITLE_SKIPPED = 'Bearer methods advertisement (RFC 6750 §2.3)';

/**
 * Probe 6: token-hygiene metadata signals.
 *
 * Methodology v1.0 step 5. The full token-hygiene surface (audience-claim
 * binding per RFC 8707, token expiry, storage practices) requires a real
 * access token, which a headless CLI cannot obtain. Probe 6 therefore
 * restricts itself to four assertions (B1-B4) about field presence and
 * advertised values in already-fetched AS metadata (RFC 8414 §2) and PRM
 * (RFC 9728 §3), plus an always-emitted deferral finding documenting the
 * live-token gap. Mirrors the verifier-mismatch deferral in probe 5.
 *
 * No network requests. No evidence files. No contextUpdates. Always emits
 * exactly five findings: one per assertion ID plus the deferral.
 */
export async function tokenHygieneProbe(ctx: AuditContext): Promise<ProbeResult> {
  const findings: Finding[] = [];

  // --- B1, B2, B3: AS metadata required ---
  const as = ctx.authorizationServerMetadata;
  if (!as) {
    findings.push({
      id: TOKEN_HYGIENE_JWKS_URI_FINDING_ID,
      title: JWKS_URI_TITLE_SKIPPED,
      severity: 'skipped',
      passed: false,
      observations: ['Skipped: probe 3 did not populate authorizationServerMetadata.']
    });
    findings.push({
      id: TOKEN_HYGIENE_REVOCATION_FINDING_ID,
      title: REVOCATION_TITLE_SKIPPED,
      severity: 'skipped',
      passed: false,
      observations: ['Skipped: AS metadata not available.']
    });
    findings.push({
      id: TOKEN_HYGIENE_INTROSPECTION_FINDING_ID,
      title: INTROSPECTION_TITLE_SKIPPED,
      severity: 'skipped',
      passed: false,
      observations: ['Skipped: AS metadata not available.']
    });
  } else {
    // AsMetadataSchema uses .passthrough(); jwks_uri / revocation_endpoint /
    // introspection_endpoint are not named on the schema, so bracket access
    // yields `unknown`. Narrow with typeof === 'string' before interpolation.
    const jwksUri = as['jwks_uri'];
    const revocationEndpoint = as['revocation_endpoint'];
    const introspectionEndpoint = as['introspection_endpoint'];

    // --- B1: jwks_uri ---
    if (typeof jwksUri === 'string') {
      findings.push({
        id: TOKEN_HYGIENE_JWKS_URI_FINDING_ID,
        title: 'JWKS URI advertised',
        severity: 'info',
        passed: true,
        observations: [
          `jwks_uri: ${jwksUri}`,
          'AS advertises JWT token format; offline validation is possible.'
        ]
      });
    } else {
      findings.push({
        id: TOKEN_HYGIENE_JWKS_URI_FINDING_ID,
        title: 'JWKS URI not advertised',
        severity: 'info',
        passed: false,
        observations: [
          'jwks_uri absent from AS metadata.',
          'Tokens may be opaque; offline JWT validation not available. Opaque-token design is legitimate.'
        ]
      });
    }

    // --- B2: revocation_endpoint ---
    if (typeof revocationEndpoint === 'string') {
      findings.push({
        id: TOKEN_HYGIENE_REVOCATION_FINDING_ID,
        title: 'Revocation endpoint advertised (RFC 7009)',
        severity: 'info',
        passed: true,
        observations: [
          `revocation_endpoint: ${revocationEndpoint}`,
          'Token revocation is available.'
        ]
      });
    } else {
      findings.push({
        id: TOKEN_HYGIENE_REVOCATION_FINDING_ID,
        title: 'Revocation endpoint not advertised (RFC 7009)',
        severity: 'warn',
        passed: false,
        observations: [
          'revocation_endpoint absent from AS metadata.',
          'RFC 7009 revocation not available. Issued tokens cannot be invalidated before expiry.',
          'This gap requires a live token to confirm in practice; metadata signal only.'
        ]
      });
    }

    // --- B3: introspection_endpoint ---
    if (typeof introspectionEndpoint === 'string') {
      findings.push({
        id: TOKEN_HYGIENE_INTROSPECTION_FINDING_ID,
        title: 'Introspection endpoint advertised (RFC 7662)',
        severity: 'info',
        passed: true,
        observations: [
          `introspection_endpoint: ${introspectionEndpoint}`,
          'Resource servers can validate opaque tokens without storing them.'
        ]
      });
    } else {
      findings.push({
        id: TOKEN_HYGIENE_INTROSPECTION_FINDING_ID,
        title: 'Introspection endpoint not advertised (RFC 7662)',
        severity: 'info',
        passed: false,
        observations: [
          'introspection_endpoint absent from AS metadata.',
          'Opaque-token validation by Resource Servers requires out-of-band means.'
        ]
      });
    }
  }

  // --- B4: PRM required ---
  const prm = ctx.protectedResourceMetadata;
  if (!prm) {
    findings.push({
      id: TOKEN_HYGIENE_BEARER_METHODS_FINDING_ID,
      title: BEARER_METHODS_TITLE_SKIPPED,
      severity: 'skipped',
      passed: false,
      observations: ['Skipped: probe 2 did not populate protectedResourceMetadata.']
    });
  } else {
    // bearer_methods_supported is a named field on PrmSchema, typed
    // string[] | undefined. No bracket access needed.
    const methods = prm.bearer_methods_supported;

    if (methods === undefined) {
      findings.push({
        id: TOKEN_HYGIENE_BEARER_METHODS_FINDING_ID,
        title: 'bearer_methods_supported not advertised',
        severity: 'info',
        passed: false,
        observations: [
          'bearer_methods_supported absent from PRM.',
          'RFC 6750 default allows all three bearer methods (header, query, form).',
          'No explicit restriction; URL-borne token risk cannot be ruled out from metadata alone.'
        ]
      });
    } else {
      const joined = methods.join(', ');
      const hasQuery = methods.includes('query');
      const hasForm = methods.includes('form');

      if (hasQuery) {
        findings.push({
          id: TOKEN_HYGIENE_BEARER_METHODS_FINDING_ID,
          title: 'bearer_methods_supported includes query',
          severity: 'warn',
          passed: false,
          observations: [
            `bearer_methods_supported: [${joined}]`,
            'query method accepted. Bearer tokens in URI query strings appear in access logs and Referer headers.',
            'RFC 6750 §5.3 advises against URL query string bearer tokens.'
          ]
        });
      } else if (hasForm) {
        findings.push({
          id: TOKEN_HYGIENE_BEARER_METHODS_FINDING_ID,
          title: 'bearer_methods_supported includes form but not query',
          severity: 'info',
          passed: false,
          observations: [
            `bearer_methods_supported: [${joined}]`,
            'form method accepted. Lower risk than query; not logged in access logs by default.'
          ]
        });
      } else {
        findings.push({
          id: TOKEN_HYGIENE_BEARER_METHODS_FINDING_ID,
          title: 'bearer_methods_supported restricts to header only',
          severity: 'info',
          passed: true,
          observations: [
            `bearer_methods_supported: [${joined}]`,
            'URL-borne bearer token methods not advertised. RFC 6750 §5.3 recommendation satisfied.'
          ]
        });
      }
    }
  }

  // --- Deferral finding (always emitted) ---
  findings.push({
    id: TOKEN_HYGIENE_LIVE_TOKEN_DEFERRED_FINDING_ID,
    title: 'Live-token hygiene tests deferred to future probe',
    severity: 'skipped',
    passed: false,
    observations: [
      'Live-token tests (aud-claim binding, token expiry, storage practices) require obtaining an access token, which requires user consent. Headless probe cannot complete these tests in v0. Tracked for future browser-harness probe.'
    ]
  });

  return { findings, evidence: [] };
}
