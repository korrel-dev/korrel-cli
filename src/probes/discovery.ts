import type { Evidence, Finding } from '../types.js';

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

export interface DiscoveryResult {
  finding: Finding;
  evidence: Evidence;
}

/**
 * Probe 1: Discovery.
 *
 * Sends an unauthenticated MCP initialize request and expects:
 *   - HTTP 401 Unauthorized
 *   - WWW-Authenticate: Bearer ... resource_metadata="<PRM URL>"
 *
 * Per RFC 9728 (OAuth 2.0 Protected Resource Metadata) and the MCP
 * auth spec (2025-06-18 onwards).
 */
export async function discoveryProbe(target: URL): Promise<DiscoveryResult> {
  const requestHeaders: Record<string, string> = {
    'Content-Type': 'application/json',
    'Accept': 'application/json, text/event-stream',
    'User-Agent': 'korrel-cli/0.0.0'
  };
  const body = JSON.stringify(MCP_INITIALIZE_BODY);

  const response = await fetch(target, {
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
      url: target.toString(),
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
  const prmUrl = wwwAuth ? extractResourceMetadata(wwwAuth) : null;

  const observations: string[] = [];
  observations.push(`HTTP ${response.status} ${response.statusText}`);
  if (wwwAuth) {
    observations.push(`WWW-Authenticate: ${wwwAuth}`);
  } else {
    observations.push('No WWW-Authenticate header returned.');
  }
  if (prmUrl) {
    observations.push(`resource_metadata URL: ${prmUrl}`);
  } else if (wwwAuth) {
    observations.push('WWW-Authenticate present but no resource_metadata parameter (RFC 9728 §5.1).');
  }

  const passed = response.status === 401 && prmUrl !== null;

  const finding: Finding = {
    id: '01-discovery',
    title: 'Discovery probe (RFC 9728)',
    severity: passed ? 'info' : 'finding',
    passed,
    observations
  };

  return { finding, evidence };
}

function extractResourceMetadata(wwwAuthenticate: string): string | null {
  const match = /resource_metadata="([^"]+)"/i.exec(wwwAuthenticate);
  return match ? match[1] ?? null : null;
}
