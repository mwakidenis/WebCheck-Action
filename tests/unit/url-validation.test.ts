import { describe, it, expect } from 'vitest';
import { parseAndValidateURL, validatePath, URLValidationError } from '../../src/security/url-validation';

describe('parseAndValidateURL', () => {
  it('accepts a valid https URL', () => {
    const v = parseAndValidateURL('https://example.com/health');
    expect(v.protocol).toBe('https:');
    expect(v.hostname).toBe('example.com');
    expect(v.port).toBe(443);
    expect(v.isSecure).toBe(true);
  });

  it('accepts a valid http URL with default port', () => {
    const v = parseAndValidateURL('http://example.com/');
    expect(v.port).toBe(80);
    expect(v.isSecure).toBe(false);
  });

  it('rejects non-http(s) protocol', () => {
    expect(() => parseAndValidateURL('ftp://example.com/')).toThrow(URLValidationError);
  });

  it('rejects malformed URL', () => {
    expect(() => parseAndValidateURL('not a url')).toThrow(URLValidationError);
  });

  it('rejects embedded credentials', () => {
    expect(() => parseAndValidateURL('http://user:pass@example.com/')).toThrow(URLValidationError);
  });

  it('rejects control characters', () => {
    expect(() => parseAndValidateURL('http://example.com/\n/')).toThrow(URLValidationError);
  });

  it('blocks loopback address', () => {
    expect(() => parseAndValidateURL('http://127.0.0.1/')).toThrow(URLValidationError);
  });

  it('blocks private IPv4', () => {
    expect(() => parseAndValidateURL('http://10.0.0.1/')).toThrow(URLValidationError);
    expect(() => parseAndValidateURL('http://192.168.1.1/')).toThrow(URLValidationError);
    expect(() => parseAndValidateURL('http://172.16.0.1/')).toThrow(URLValidationError);
  });

  it('blocks link-local and multicast', () => {
    expect(() => parseAndValidateURL('http://169.254.169.254/')).toThrow(URLValidationError);
    expect(() => parseAndValidateURL('http://224.0.0.1/')).toThrow(URLValidationError);
  });

  it('blocks IPv6 loopback and link-local', () => {
    expect(() => parseAndValidateURL('http://[::1]/')).toThrow(URLValidationError);
    expect(() => parseAndValidateURL('http://[fe80::1]/')).toThrow(URLValidationError);
  });

  it('allows public IPv4 when not prohibited', () => {
    const v = parseAndValidateURL('http://93.184.216.34/');
    expect(v.hostname).toBe('93.184.216.34');
  });

  it('validates port range', () => {
    expect(() => parseAndValidateURL('http://example.com:99999/')).toThrow(URLValidationError);
    expect(() => parseAndValidateURL('http://example.com:0/')).toThrow(URLValidationError);
  });
});

describe('validatePath', () => {
  it('normalizes a route', () => {
    expect(validatePath('/health')).toBe('/health');
    expect(validatePath('/')).toBe('/');
    expect(validatePath('//api//status//')).toBe('/api/status');
  });

  it('rejects route not starting with slash', () => {
    expect(() => validatePath('health')).toThrow(URLValidationError);
  });

  it('rejects empty route', () => {
    expect(() => validatePath('')).toThrow(URLValidationError);
  });

  it('rejects control characters', () => {
    expect(() => validatePath('/\n')).toThrow(URLValidationError);
  });
});
