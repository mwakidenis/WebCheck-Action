import { readFileSync } from 'fs';
import { Finding, ScanReport } from '../config';

export interface BaselineComparison {
  baselineFile: string;
  compared: boolean;
  newFindings: Finding[];
  resolvedFindings: Finding[];
  unchangedFindings: Finding[];
  summary: {
    new: number;
    resolved: number;
    unchanged: number;
    total: number;
  };
  error: string | null;
}

interface NormalizedFinding {
  key: string;
  category: 'http' | 'tls' | 'headers' | 'route' | 'policy' | 'config';
  message: string;
}

function normalizeFindings(report: ScanReport): NormalizedFinding[] {
  const findings: NormalizedFinding[] = [];

  // HTTP findings (volatile timestamps and response times excluded).
  const http = report.http;
  if (http.transportError) {
    findings.push({ key: 'http:transportError:true', category: 'http', message: `HTTP transport error: ${http.error ?? 'unknown'}` });
  } else {
    findings.push({ key: 'http:transportError:false', category: 'http', message: 'HTTP transport OK' });
  }
  if (http.statusCode !== null) {
    findings.push({ key: `http:statusCode:${http.statusCode}`, category: 'http', message: `HTTP status ${http.statusCode}` });
  }
  findings.push({ key: `http:redirectCount:${http.redirectCount}`, category: 'http', message: `HTTP redirect count ${http.redirectCount}` });

  // TLS findings.
  if (report.tls.enabled) {
    findings.push({ key: 'tls:enabled:true', category: 'tls', message: 'TLS enabled' });
    if (report.tls.certificate) {
      findings.push({ key: `tls:authorized:${report.tls.certificate.authorized}`, category: 'tls', message: `Certificate authorized ${report.tls.certificate.authorized}` });
    }
    findings.push({ key: `tls:hostnameMismatch:${report.tls.hostnameMismatch}`, category: 'tls', message: `TLS hostname mismatch ${report.tls.hostnameMismatch}` });
    if (report.tls.error) {
      findings.push({ key: 'tls:error:true', category: 'tls', message: `TLS error: ${report.tls.error}` });
    }
  } else {
    findings.push({ key: 'tls:enabled:false', category: 'tls', message: 'TLS not enabled (non-HTTPS target)' });
  }

  // Header findings.
  for (const h of report.headers.headers) {
    findings.push({ key: `headers:${h.name}:${h.status}`, category: 'headers', message: `Header ${h.name} ${h.status}` });
  }

  // Route findings.
  for (const r of report.routes) {
    if (r.transportError || r.error) {
      findings.push({ key: `routes:${r.route}:error:true`, category: 'route', message: `Route ${r.route} error: ${r.error ?? 'transport error'}` });
    } else if (r.statusCode !== null) {
      findings.push({ key: `routes:${r.route}:statusCode:${r.statusCode}`, category: 'route', message: `Route ${r.route} status ${r.statusCode}` });
    }
  }

  return findings;
}

function findingKey(f: NormalizedFinding): string {
  return f.key;
}

export function compareBaseline(current: ScanReport, baseline: ScanReport): BaselineComparison {
  const currentFindings = normalizeFindings(current);
  const baselineFindings = normalizeFindings(baseline);

  const currentKeys = new Set(currentFindings.map(findingKey));
  const baselineKeys = new Set(baselineFindings.map(findingKey));

  const newFindings: Finding[] = [];
  const resolvedFindings: Finding[] = [];
  const unchangedFindings: Finding[] = [];

  for (const f of currentFindings) {
    if (!baselineKeys.has(f.key)) {
      newFindings.push({ type: 'warning', category: f.category, message: `New finding (regression): ${f.message}` });
    } else {
      unchangedFindings.push({ type: 'warning', category: f.category, message: `Unchanged: ${f.message}` });
    }
  }

  for (const f of baselineFindings) {
    if (!currentKeys.has(f.key)) {
      resolvedFindings.push({ type: 'warning', category: f.category, message: `Resolved: ${f.message}` });
    }
  }

  return {
    baselineFile: '',
    compared: true,
    newFindings,
    resolvedFindings,
    unchangedFindings,
    summary: {
      new: newFindings.length,
      resolved: resolvedFindings.length,
      unchanged: unchangedFindings.length,
      total: currentFindings.length,
    },
    error: null,
  };
}

export function loadBaseline(filePath: string): ScanReport | null {
  try {
    const content = readFileSync(filePath, 'utf8');
    return JSON.parse(content) as ScanReport;
  } catch {
    return null;
  }
}
