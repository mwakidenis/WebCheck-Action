import { describe, it, expect } from 'vitest';
import { checkIP, isProhibitedAddress } from '../../src/security/ip-validation';

describe('checkIP', () => {
  it('identifies public IPv4', () => {
    expect(checkIP('93.184.216.34').isProhibited).toBe(false);
    expect(checkIP('1.1.1.1').isProhibited).toBe(false);
  });

  it('identifies loopback', () => {
    expect(checkIP('127.0.0.1').category).toBe('loopback');
    expect(checkIP('127.0.0.1').isProhibited).toBe(true);
  });

  it('identifies private IPv4 ranges', () => {
    expect(checkIP('10.0.0.5').category).toBe('private');
    expect(checkIP('172.16.0.5').category).toBe('private');
    expect(checkIP('172.31.255.255').category).toBe('private');
    expect(checkIP('192.168.1.1').category).toBe('private');
    expect(checkIP('10.0.0.5').isProhibited).toBe(true);
    expect(checkIP('192.168.1.1').isProhibited).toBe(true);
  });

  it('identifies link-local IPv4', () => {
    expect(checkIP('169.254.169.254').category).toBe('link-local');
    expect(checkIP('169.254.169.254').isProhibited).toBe(true);
  });

  it('identifies multicast IPv4', () => {
    expect(checkIP('224.0.0.1').category).toBe('multicast');
    expect(checkIP('224.0.0.1').isProhibited).toBe(true);
  });

  it('identifies reserved IPv4', () => {
    expect(checkIP('240.0.0.1').isProhibited).toBe(true);
    expect(checkIP('0.0.0.0').isProhibited).toBe(true);
  });

  it('identifies IPv6 loopback', () => {
    expect(checkIP('::1').category).toBe('loopback');
    expect(checkIP('::1').isProhibited).toBe(true);
  });

  it('identifies IPv6 link-local', () => {
    expect(checkIP('fe80::1').category).toBe('link-local');
    expect(checkIP('fe80::1').isProhibited).toBe(true);
  });

  it('identifies IPv6 unique local', () => {
    expect(checkIP('fc00::1').category).toBe('private');
    expect(checkIP('fc00::1').isProhibited).toBe(true);
  });

  it('identifies IPv6 multicast', () => {
    expect(checkIP('ff02::1').category).toBe('multicast');
    expect(checkIP('ff02::1').isProhibited).toBe(true);
  });

  it('identifies public IPv6', () => {
    expect(checkIP('2001:4860:4860::8888').isProhibited).toBe(false);
  });

  it('isProhibitedAddress boolean', () => {
    expect(isProhibitedAddress('127.0.0.1')).toBe(true);
    expect(isProhibitedAddress('::1')).toBe(true);
    expect(isProhibitedAddress('93.184.216.34')).toBe(false);
  });
});
