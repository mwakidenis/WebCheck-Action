import { lookup } from 'dns';
import { promisify } from 'util';

const dnsLookup = promisify(lookup);

export interface DNSResult {
  resolved: boolean;
  addresses: string[];
  families: number[];
  error: string | null;
}

export async function checkDNS(hostname: string): Promise<DNSResult> {
  try {
    const results = await dnsLookup(hostname, { all: true });
    const addresses = Array.isArray(results) ? results : [results];
    const addrs = addresses.map((r: { address: string; family: number }) => r.address);
    const families = addresses.map((r: { address: string; family: number }) => r.family);
    return {
      resolved: addrs.length > 0,
      addresses: addrs,
      families,
      error: null,
    };
  } catch (err) {
    return {
      resolved: false,
      addresses: [],
      families: [],
      error: err instanceof Error ? err.message : 'DNS lookup failed',
    };
  }
}
