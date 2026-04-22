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
