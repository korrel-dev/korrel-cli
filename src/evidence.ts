import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { Evidence } from './types.js';

export async function writeEvidence(
  dir: string,
  name: string,
  evidence: Evidence
): Promise<void> {
  const content = formatHttpFile(evidence);
  await writeFile(join(dir, `${name}.http`), content, 'utf-8');
}

function formatHttpFile(evidence: Evidence): string {
  const { request, response } = evidence;
  const parsedUrl = new URL(request.url);

  const requestLines: string[] = [];
  requestLines.push(`${request.method} ${parsedUrl.pathname || '/'}${parsedUrl.search} HTTP/1.1`);
  requestLines.push(`Host: ${parsedUrl.host}`);
  for (const [key, value] of Object.entries(request.headers)) {
    requestLines.push(`${key}: ${value}`);
  }
  requestLines.push('');
  if (request.body) {
    requestLines.push(request.body);
  }

  const responseLines: string[] = [];
  responseLines.push(`HTTP/1.1 ${response.status} ${response.statusText}`);
  for (const [key, value] of Object.entries(response.headers)) {
    responseLines.push(`${key}: ${value}`);
  }
  responseLines.push('');
  responseLines.push(response.body);

  return requestLines.join('\n') + '\n\n---\n\n' + responseLines.join('\n') + '\n';
}
