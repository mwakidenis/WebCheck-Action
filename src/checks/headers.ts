export interface HeaderFinding {
  name: string;
  required: boolean;
  present: boolean;
  value: string | null;
  status: 'present' | 'missing' | 'misconfigured';
  notes: string[];
}

export interface SecurityHeadersResult {
  headers: HeaderFinding[];
  missingRequired: HeaderFinding[];
  present: HeaderFinding[];
  error: string | null;
}

export const KNOWN_SECURITY_HEADERS = [
  'strict-transport-security',
  'content-security-policy',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
] as const;

export type SecurityHeaderName = (typeof KNOWN_SECURITY_HEADERS)[number];

export function normalizeHeaderName(name: string): string {
  return name.trim().toLowerCase();
}

export function isKnownSecurityHeader(name: string): boolean {
  return KNOWN_SECURITY_HEADERS.includes(name as SecurityHeaderName);
}

function isLikelyMisconfigured(name: string, value: string | null): boolean {
  if (value === null || value === '') return true;
  const lower = value.toLowerCase();
  switch (name) {
    case 'strict-transport-security':
      // HSTS should include max-age; without it the header is ineffective.
      return !/max-age\s*=\s*\d+/i.test(lower);
    case 'x-content-type-options':
      return lower !== 'nosniff';
    case 'content-security-policy':
      return false; // presence is meaningful; value complexity is out of scope
    case 'referrer-policy':
      return false;
    case 'permissions-policy':
      return false;
    default:
      return false;
  }
}

export function checkSecurityHeaders(
  headers: Record<string, string>,
  required: string[]
): SecurityHeadersResult {
  const result: SecurityHeadersResult = {
    headers: [],
    missingRequired: [],
    present: [],
    error: null,
  };

  const lowerHeaders: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    lowerHeaders[key.toLowerCase()] = value;
  }

  const requiredSet = new Set(required.map(normalizeHeaderName));

  // Check required headers first.
  for (const name of requiredSet) {
    const value = lowerHeaders[name] ?? null;
    const present = value !== null;
    const notes: string[] = [];
    let status: 'present' | 'missing' | 'misconfigured' = 'missing';

    if (present) {
      status = 'present';
      if (isLikelyMisconfigured(name, value)) {
        status = 'misconfigured';
        notes.push(`Header present but may be misconfigured: ${name}`);
      }
    } else {
      notes.push(`Required header missing: ${name}`);
    }

    const finding: HeaderFinding = { name, required: true, present, value, status, notes };
    result.headers.push(finding);
    if (!present) result.missingRequired.push(finding);
    else result.present.push(finding);
  }

  // Also report any known security headers that are present but not required.
  for (const known of KNOWN_SECURITY_HEADERS) {
    if (requiredSet.has(known)) continue;
    const value = lowerHeaders[known] ?? null;
    if (value === null) continue;
    const notes: string[] = [];
    let status: 'present' | 'missing' | 'misconfigured' = 'present';
    if (isLikelyMisconfigured(known, value)) {
      status = 'misconfigured';
      notes.push(`Header present but may be misconfigured: ${known}`);
    }
    const finding: HeaderFinding = { name: known, required: false, present: true, value, status, notes };
    result.headers.push(finding);
    result.present.push(finding);
  }

  return result;
}
