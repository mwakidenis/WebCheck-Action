import { describe, it, expect } from 'vitest';
import { generateSummary } from '../../src/report/summary';
import { ScanReport } from '../../src/config';

const baseReport: ScanReport = {
  tool: 'webcheck-action',
  version: '1.0.0',
  timestamp: '2026-10-28T00:00:00.000Z',
  target: 'https://example.com',
  overall: 'passed',
  http: {
    statusCode: 200,
    statusMessage: 'OK',
    finalURL: 'https://example.com/',
    redirectChain: ['https://example.com/'],
    redirectCount: 0,
    responseTimeMs: 120,
    error: null,
    transportError: false,
    headers: {},
    bodySize: 0,
  },
  tls: {
    enabled: true,
    certificate: {
      subject: { CN: 'example.com', O: 'Example Inc' },
      issuer: { CN: 'R3', O: 'Let\'s Encrypt' },
      validFrom: '2026-01-01T00:00:00Z',
      validTo: '2027-01-01T00:00:00Z',
      expiryDate: '2027-01-01T00:00:00Z',
      daysRemaining: 70,
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
  policyEvaluations: [
    { name: 'fail-on-http-error', enabled: true, violated: false, message: null },
    { name: 'fail-on-redirect', enabled: false, violated: false, message: null },
  ],
  errors: [],
  warnings: [],
};

describe('generateSummary', () => {
  it('generates a markdown summary', () => {
    const summary = generateSummary({ report: baseReport, config: {} as any });
    expect(summary).toContain('# WebCheck Action Report');
    expect(summary).toContain('https://example.com');
    expect(summary).toContain('Passed');
    expect(summary).toContain('## HTTP');
    expect(summary).toContain('## TLS / Certificate');
    expect(summary).toContain('## Security Headers');
    expect(summary).toContain('## Routes');
    expect(summary).toContain('## Failure Policies');
  });

  it('escapes markdown-special characters in target URL', () => {
    const report: ScanReport = { ...baseReport, target: 'https://example.com/a|b' };
    const summary = generateSummary({ report, config: {} as any });
    expect(summary).toContain('https://example.com/a\\|b');
  });

  it('does not inject workflow commands', () => {
    const report: ScanReport = { ...baseReport, target: 'https://example.com::set-output::name::evil' };
    const summary = generateSummary({ report, config: {} as any });
    expect(summary).not.toContain('::set-output::');
  });

  it('marks failed overall correctly', () => {
    const report: ScanReport = { ...baseReport, overall: 'failed' };
    const summary = generateSummary({ report, config: {} as any });
    expect(summary).toContain('Failed');
  });
});
