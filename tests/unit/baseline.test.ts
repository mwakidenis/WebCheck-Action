import { describe, it, expect } from 'vitest';
import { compareBaseline, loadBaseline } from '../../src/baseline/compare';
import { ScanReport } from '../../src/config';

function makeReport(overrides: Partial<ScanReport>): ScanReport {
  return {
    tool: 'webcheck-action',
    version: '1.0.0',
    timestamp: '2026-11-02T00:00:00.000Z',
    target: 'https://example.com',
    overall: 'passed',
    http: {
      statusCode: 200,
      statusMessage: 'OK',
      finalURL: 'https://example.com/',
      redirectChain: ['https://example.com/'],
      redirectCount: 0,
      responseTimeMs: 100,
      error: null,
      transportError: false,
      headers: {},
      bodySize: 0,
    },
    tls: {
      enabled: true,
      certificate: {
        subject: { CN: 'example.com' },
        issuer: { CN: 'R3' },
        validFrom: '2026-01-01T00:00:00Z',
        validTo: '2027-01-01T00:00:00Z',
        daysRemaining: 100,
        expiryDate: '2027-01-01T00:00:00Z',
        fingerprint: 'AB:CD',
        authorized: true,
        authorizationError: null,
        error: null,
      },
      handshakeError: null,
      hostnameMismatch: false,
      error: null,
    },
    headers: {
      headers: [
        { name: 'strict-transport-security', required: true, present: true, value: 'max-age=31536000', status: 'present', notes: [] },
      ],
      missingRequired: [],
      present: [
        { name: 'strict-transport-security', required: true, present: true, value: 'max-age=31536000', status: 'present', notes: [] },
      ],
      error: null,
    },
    routes: [
      { route: '/', url: 'https://example.com/', statusCode: 200, error: null, transportError: false, redirected: false, redirectCount: 0, finalURL: 'https://example.com/' },
    ],
    findings: [],
    policyEvaluations: [],
    baselineComparison: null,
    errors: [],
    warnings: [],
    ...overrides,
  };
}

describe('compareBaseline', () => {
  it('detects new findings (regressions), resolved findings, and unchanged findings', () => {
    const baseline = makeReport({
      http: { ...makeReport().http, statusCode: 200, redirectCount: 0 },
      headers: {
        headers: [
          { name: 'strict-transport-security', required: true, present: true, value: 'max-age=31536000', status: 'present', notes: [] },
          { name: 'content-security-policy', required: false, present: true, value: "default-src 'self'", status: 'present', notes: [] },
        ],
        missingRequired: [],
        present: [
          { name: 'strict-transport-security', required: true, present: true, value: 'max-age=31536000', status: 'present', notes: [] },
          { name: 'content-security-policy', required: false, present: true, value: "default-src 'self'", status: 'present', notes: [] },
        ],
        error: null,
      },
      routes: [
        { route: '/', url: 'https://example.com/', statusCode: 200, error: null, transportError: false, redirected: false, redirectCount: 0, finalURL: 'https://example.com/' },
      ],
    });

    const current = makeReport({
      http: { ...makeReport().http, statusCode: 500, redirectCount: 1 },
      headers: {
        headers: [
          { name: 'strict-transport-security', required: true, present: false, value: null, status: 'missing', notes: [] },
        ],
        missingRequired: [{ name: 'strict-transport-security', required: true, present: false, value: null, status: 'missing', notes: [] }],
        present: [],
        error: null,
      },
      routes: [
        { route: '/', url: 'https://example.com/', statusCode: 500, error: null, transportError: false, redirected: false, redirectCount: 0, finalURL: 'https://example.com/' },
        { route: '/health', url: 'https://example.com/health', statusCode: 200, error: null, transportError: false, redirected: false, redirectCount: 0, finalURL: 'https://example.com/health' },
      ],
    });

    const result = compareBaseline(current, baseline);

    expect(result.compared).toBe(true);
    expect(result.error).toBeNull();
    // New: HTTP status 500, redirectCount 1, HSTS missing, route / status 500, route /health new
    expect(result.summary.new).toBeGreaterThan(0);
    // Resolved: CSP header present (gone), route / status 200 (changed to 500), redirectCount 0 (changed to 1)
    expect(result.summary.resolved).toBeGreaterThan(0);
    // Unchanged: TLS enabled, etc.
    expect(result.summary.unchanged).toBeGreaterThan(0);

    const newMessages = result.newFindings.map((f) => f.message);
    expect(newMessages.some((m) => m.includes('HTTP status 500'))).toBe(true);
    expect(result.newFindings.some((f) => f.category === 'http')).toBe(true);
    expect(result.resolvedFindings.some((f) => f.category === 'headers')).toBe(true);
  });

  it('reports unchanged findings when reports are identical', () => {
    const report = makeReport();
    const result = compareBaseline(report, report);

    expect(result.compared).toBe(true);
    expect(result.summary.new).toBe(0);
    expect(result.summary.resolved).toBe(0);
    expect(result.summary.unchanged).toBeGreaterThan(0);
    expect(result.newFindings.length).toBe(0);
    expect(result.resolvedFindings.length).toBe(0);
  });

  it('loadBaseline returns null for missing file', () => {
    expect(loadBaseline('/nonexistent/baseline.json')).toBeNull();
  });
});
