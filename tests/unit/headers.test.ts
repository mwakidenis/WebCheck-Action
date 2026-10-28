import { describe, it, expect } from 'vitest';
import { checkSecurityHeaders, HeaderFinding } from '../../src/checks/headers';

describe('checkSecurityHeaders', () => {
  it('reports missing required headers', () => {
    const res = checkSecurityHeaders({}, ['strict-transport-security', 'content-security-policy']);
    expect(res.missingRequired.length).toBe(2);
    expect(res.missingRequired.map((h) => h.name)).toEqual(
      expect.arrayContaining(['strict-transport-security', 'content-security-policy'])
    );
    for (const h of res.missingRequired) {
      expect(h.present).toBe(false);
      expect(h.status).toBe('missing');
    }
  });

  it('reports present required headers', () => {
    const res = checkSecurityHeaders(
      { 'strict-transport-security': 'max-age=31536000; includeSubDomains' },
      ['strict-transport-security']
    );
    expect(res.missingRequired.length).toBe(0);
    expect(res.present.length).toBe(1);
    expect(res.present[0].status).toBe('present');
    expect(res.present[0].value).toBe('max-age=31536000; includeSubDomains');
  });

  it('flags HSTS without max-age as misconfigured', () => {
    const res = checkSecurityHeaders({ 'strict-transport-security': '' }, ['strict-transport-security']);
    expect(res.present[0].status).toBe('misconfigured');
  });

  it('flags x-content-type-options not nosniff as misconfigured', () => {
    const res = checkSecurityHeaders({ 'x-content-type-options': 'nosniff' }, ['x-content-type-options']);
    expect(res.present[0].status).toBe('present');

    const res2 = checkSecurityHeaders({ 'x-content-type-options': 'other' }, ['x-content-type-options']);
    expect(res2.present[0].status).toBe('misconfigured');
  });

  it('reports optional known headers present but not required', () => {
    const res = checkSecurityHeaders({ 'referrer-policy': 'no-referrer' }, []);
    expect(res.headers.some((h) => h.name === 'referrer-policy' && h.required === false)).toBe(true);
  });

  it('normalizes header case', () => {
    const res = checkSecurityHeaders({ 'Strict-Transport-Security': 'max-age=100' }, ['strict-transport-security']);
    expect(res.missingRequired.length).toBe(0);
  });
});
