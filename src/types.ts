export interface RequestRecord {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
}

export interface ResponseRecord {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
}

export interface Evidence {
  request: RequestRecord;
  response: ResponseRecord;
}

export type Severity = 'info' | 'finding' | 'issue' | 'critical';

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  passed: boolean;
  observations: string[];
}

import type { Prm } from './probes/prm.js';

export interface AuditContext {
  target: URL;
  protectedResourceMetadataUrl?: string;
  protectedResourceMetadata?: Prm;
  authorizationServers?: string[];
  // TODO: type after probe 3 defines schema
  authorizationServerMetadata?: unknown;
  registrationEndpoint?: string;
  tokenEndpoint?: string;
  authorizationEndpoint?: string;
  registeredClient?: unknown;
}

export interface NamedEvidence {
  name: string;
  evidence: Evidence;
}

export interface ProbeResult {
  findings: Finding[];
  evidence: NamedEvidence[];
  contextUpdates?: Partial<AuditContext>;
}

export type Probe = (ctx: AuditContext) => Promise<ProbeResult>;
