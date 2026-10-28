import { writeFileSync } from 'fs';
import { ScanReport, ActionConfig } from '../config';

export function buildReport(config: ActionConfig): ScanReport {
  return {
    tool: 'webcheck-action',
    version: config.version,
    timestamp: new Date().toISOString(),
    target: config.url,
    overall: 'passed',
    http: {
      statusCode: null,
      statusMessage: null,
      finalURL: null,
      redirectChain: [],
      redirectCount: 0,
      responseTimeMs: null,
      error: null,
      transportError: false,
      headers: {},
      bodySize: 0,
    },
    tls: {
      enabled: false,
      certificate: null,
      handshakeError: null,
      hostnameMismatch: false,
      error: null,
    },
    headers: {
      headers: [],
      missingRequired: [],
      present: [],
      error: null,
    },
    routes: [],
    findings: [],
    policyEvaluations: [],
    errors: [],
    warnings: [],
  };
}

export function writeReport(report: ScanReport, outputFile: string): void {
  const json = JSON.stringify(report, null, 2);
  writeFileSync(outputFile, json, 'utf8');
}

export function serializeReport(report: ScanReport): string {
  return JSON.stringify(report, null, 2);
}
