import { lookup } from 'dns';
import { promisify } from 'util';

const dnsLookup = promisify(lookup);

// Address families
export const IPV4 = 4;
export const IPV6 = 6;

// Prohibited IP categories (SSRF protection).
// These are blocked unless local-testing mode is explicitly enabled.
export interface IPRangeCheck {
  isProhibited: boolean;
  category: string;
  family: number;
}

function ipv4ToInteger(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    const num = Number(part);
    if (!Number.isInteger(num) || num < 0 || num > 255) return null;
    value = (value << 8) | num;
  }
  return value >>> 0;
}

function ipv6ToSegments(ip: string): number[] | null {
  const hasDoubleColon = ip.includes('::');
  let parts: string[];

  if (hasDoubleColon) {
    const [left, right] = ip.split('::', 2);
    const leftParts = left === '' ? [] : left.split(':');
    const rightParts = right === '' ? [] : right.split(':');
    const zerosNeeded = 8 - leftParts.length - rightParts.length;
    if (zerosNeeded < 0) return null;
    parts = [...leftParts, ...Array(zerosNeeded).fill('0'), ...rightParts];
  } else {
    parts = ip.split(':');
    if (parts.length !== 8) return null;
  }

  const segs: number[] = [];
  for (const p of parts) {
    if (p === '') return null;
    const v = parseInt(p, 16);
    if (isNaN(v) || v < 0 || v > 0xffff) return null;
    segs.push(v);
  }
  return segs.length === 8 ? segs : null;
}

function isIPv4Prohibited(ip: string): IPRangeCheck | null {
  const value = ipv4ToInteger(ip);
  if (value === null) return null;

  // Loopback: 127.0.0.0/8
  if (((value & 0xff000000) >>> 0) === (0x7f000000 >>> 0)) {
    return { isProhibited: true, category: 'loopback', family: IPV4 };
  }
  // Private: 10.0.0.0/8
  if (((value & 0xff000000) >>> 0) === (0x0a000000 >>> 0)) {
    return { isProhibited: true, category: 'private', family: IPV4 };
  }
  // Private: 172.16.0.0/12
  if (((value & 0xfff00000) >>> 0) === (0xac100000 >>> 0)) {
    return { isProhibited: true, category: 'private', family: IPV4 };
  }
  // Private: 192.168.0.0/16
  if (((value & 0xffff0000) >>> 0) === (0xc0a80000 >>> 0)) {
    return { isProhibited: true, category: 'private', family: IPV4 };
  }
  // Link-local: 169.254.0.0/16
  if (((value & 0xffff0000) >>> 0) === (0xa9fe0000 >>> 0)) {
    return { isProhibited: true, category: 'link-local', family: IPV4 };
  }
  // Multicast: 224.0.0.0/4
  if (((value & 0xf0000000) >>> 0) === (0xe0000000 >>> 0)) {
    return { isProhibited: true, category: 'multicast', family: IPV4 };
  }
  // Broadcast / reserved: 240.0.0.0/4
  if (((value & 0xf0000000) >>> 0) === (0xf0000000 >>> 0)) {
    return { isProhibited: true, category: 'reserved', family: IPV4 };
  }
  // 0.0.0.0/8
  if (((value & 0xff000000) >>> 0) === (0x00000000 >>> 0)) {
    return { isProhibited: true, category: 'reserved', family: IPV4 };
  }

  return { isProhibited: false, category: 'public', family: IPV4 };
}

function isIPv6Prohibited(ip: string): IPRangeCheck | null {
  const segs = ipv6ToSegments(ip);
  if (segs === null) return null;

  const [a] = segs;

  // Loopback: ::1/128
  if (ip === '::1') {
    return { isProhibited: true, category: 'loopback', family: IPV6 };
  }
  // Unspecified: ::/128
  if (ip === '::') {
    return { isProhibited: true, category: 'reserved', family: IPV6 };
  }
  // Link-local: fe80::/10
  if ((a & 0xffc0) === 0xfe80) {
    return { isProhibited: true, category: 'link-local', family: IPV6 };
  }
  // Multicast: ff00::/8
  if ((a & 0xff00) === 0xff00) {
    return { isProhibited: true, category: 'multicast', family: IPV6 };
  }
  // Unique local: fc00::/7
  if ((a & 0xfe00) === 0xfc00) {
    return { isProhibited: true, category: 'private', family: IPV6 };
  }

  return { isProhibited: false, category: 'public', family: IPV6 };
}

export function checkIP(ip: string): IPRangeCheck {
  // Strip IPv6 literal brackets, e.g. "[::1]" -> "::1".
  if (ip.startsWith('[') && ip.endsWith(']')) {
    ip = ip.slice(1, -1);
  }
  if (ip.includes(':')) {
    const result = isIPv6Prohibited(ip);
    return result ?? { isProhibited: false, category: 'unknown', family: IPV6 };
  }
  const result = isIPv4Prohibited(ip);
  return result ?? { isProhibited: false, category: 'unknown', family: IPV4 };
}

export async function resolveAndCheckHostname(
  hostname: string,
  options: { allowProhibited?: boolean; family?: number } = {}
): Promise<{ ip: string; family: number; check: IPRangeCheck; resolvedVia: string }> {
  const family = options.family ?? 0; // 0 = both
  const result = await dnsLookup(hostname, { family, all: true } as any);
  const results = Array.isArray(result) ? result : [result];
  const addresses = results.map((r: any) => ({ address: String(r.address), family: Number(r.family) }));

  if (addresses.length === 0) {
    throw new Error(`No DNS records found for hostname: ${hostname}`);
  }

  // Prefer the first non-prohibited address if available; otherwise use the first.
  let selected = addresses[0];
  if (!options.allowProhibited) {
    const nonProhibited = addresses.find((addr) => !checkIP(addr.address).isProhibited);
    if (nonProhibited) selected = nonProhibited;
  }

  const check = checkIP(selected.address);
  if (check.isProhibited && !options.allowProhibited) {
    throw new Error(
      `DNS resolution for ${hostname} resolved to a prohibited address (${selected.address}, category: ${check.category}). ` +
        'SSRF protection blocks loopback, private, link-local, multicast, and reserved addresses.'
    );
  }

  return {
    ip: selected.address,
    family: selected.family,
    check,
    resolvedVia: 'dns',
  };
}

export function isProhibitedAddress(ip: string): boolean {
  return checkIP(ip).isProhibited;
}
