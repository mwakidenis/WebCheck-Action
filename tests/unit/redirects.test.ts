import { describe, it, expect } from 'vitest';
import { analyzeRedirectChain, isRedirectStatus } from '../../src/http/redirects';

describe('analyzeRedirectChain', () => {
  it('detects no loop and no limit exceeded', () => {
    const res = analyzeRedirectChain(
      ['http://example.com/', 'http://example.com/a', 'http://example.com/b'],
      10,
      () => false
    );
    expect(res.hasLoop).toBe(false);
    expect(res.exceededLimit).toBe(false);
    expect(res.count).toBe(2);
    expect(res.finalDestination).toBe('http://example.com/b');
  });

  it('detects a loop', () => {
    const url = 'http://example.com/loop';
    const res = analyzeRedirectChain([url, url], 10, () => false);
    expect(res.hasLoop).toBe(true);
  });

  it('detects limit exceeded', () => {
    const res = analyzeRedirectChain(
      ['http://example.com/0', 'http://example.com/1', 'http://example.com/2'],
      1,
      () => false
    );
    expect(res.exceededLimit).toBe(true);
    expect(res.count).toBe(2);
  });

  it('identifies first prohibited hop', () => {
    const res = analyzeRedirectChain(
      ['http://example.com/', 'http://127.0.0.1/'],
      10,
      (u) => u.includes('127.0.0.1')
    );
    expect(res.firstProhibitedHop).toBe('http://127.0.0.1/');
  });
});

describe('isRedirectStatus', () => {
  it('identifies redirect statuses', () => {
    expect(isRedirectStatus(301)).toBe(true);
    expect(isRedirectStatus(302)).toBe(true);
    expect(isRedirectStatus(308)).toBe(true);
    expect(isRedirectStatus(200)).toBe(false);
    expect(isRedirectStatus(404)).toBe(false);
  });
});
