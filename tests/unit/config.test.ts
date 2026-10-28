import { describe, it, expect } from 'vitest';
import { parseInputs } from '../../src/config';

describe('parseInputs', () => {
  const base = {
    url: 'https://example.com',
  };

  it('parses defaults', () => {
    const c = parseInputs(base);
    expect(c.url).toBe('https://example.com');
    expect(c.routes).toEqual(['/']);
    expect(c.expectedStatusCodes).toEqual([200]);
    expect(c.timeoutSeconds).toBe(10);
    expect(c.maxRedirects).toBe(10);
    expect(c.requiredHeaders).toEqual([]);
    expect(c.failOnHTTpError).toBe(true);
    expect(c.failOnRedirect).toBe(false);
    expect(c.failOnMissingHeaders).toBe(false);
    expect(c.failOnTLSError).toBe(true);
    expect(c.failOnCertificateExpiry).toBe(true);
    expect(c.failOnRouteError).toBe(true);
    expect(c.outputFile).toBe('webcheck-report.json');
  });

  it('parses custom values', () => {
    const c = parseInputs({
      ...base,
      routes: '/health\n/api/status\n/',
      'expected-status-codes': '200,204',
      timeout: '30',
      'max-redirects': '5',
      'required-headers': 'strict-transport-security, content-security-policy',
      'certificate-warning-days': '30',
      'certificate-failure-days': '7',
      'fail-on-redirect': 'true',
      'fail-on-missing-headers': 'true',
      'fail-on-http-error': 'false',
      'output-file': 'custom-report.json',
    });
    expect(c.routes).toEqual(['/health', '/api/status', '/']);
    expect(c.expectedStatusCodes).toEqual([200, 204]);
    expect(c.timeoutSeconds).toBe(30);
    expect(c.maxRedirects).toBe(5);
    expect(c.requiredHeaders).toEqual(['strict-transport-security', 'content-security-policy']);
    expect(c.certificateWarningDays).toBe(30);
    expect(c.certificateFailureDays).toBe(7);
    expect(c.failOnRedirect).toBe(true);
    expect(c.failOnMissingHeaders).toBe(true);
    expect(c.failOnHTTpError).toBe(false);
    expect(c.outputFile).toBe('custom-report.json');
  });

  it('fails on missing url', () => {
    expect(() => parseInputs({})).toThrow();
  });

  it('fails on invalid status codes', () => {
    expect(() => parseInputs({ ...base, 'expected-status-codes': '999' })).toThrow();
    expect(() => parseInputs({ ...base, 'expected-status-codes': 'abc' })).toThrow();
  });

  it('fails on invalid booleans', () => {
    expect(() => parseInputs({ ...base, 'fail-on-http-error': 'yes' })).toThrow();
  });

  it('fails when failure-days exceeds warning-days', () => {
    expect(() =>
      parseInputs({ ...base, 'certificate-warning-days': '7', 'certificate-failure-days': '14' })
    ).toThrow();
  });
});
