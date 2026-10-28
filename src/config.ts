export type PolicyName =
  | 'fail-on-http-error'
  | 'fail-on-redirect'
  | 'fail-on-missing-headers'
  | 'fail-on-tls-error'
  | 'fail-on-certificate-expiry'
  | 'fail-on-route-error';

export interface HTTPResult {
  statusCode: number | null;
  statusMessage: string | null;
  finalURL: string | null;
  redirectChain: string[];
  redirectCount: number;
  responseTimeMs: number | null;
  error: string | null;
  transportError: boolean;
  headers: Record<string, string>;
  bodySize: number;
}

export interface TLSCertificateInfo {
  subject: Record<string, string> | null;
  issuer: Record<string, string> | null;
  validFrom: string | null;
  validTo: string | null;
  expiryDate: string | null;
  daysRemaining: number | null;
  fingerprint: string | null;
  authorized: boolean;
  authorizationError: string | null;
  error: string | null;
}

export interface TLSResult {
  enabled: boolean;
  certificate: TLSCertificateInfo | null;
  handshakeError: string | null;
  hostnameMismatch: boolean;
  error: string | null;
}

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

export interface RouteResult {
  route: string;
  url: string;
  statusCode: number | null;
  error: string | null;
  transportError: boolean;
  redirected: boolean;
  redirectCount: number;
  finalURL: string | null;
}

export interface Finding {
  type: 'warning' | 'error';
  category: 'http' | 'tls' | 'headers' | 'route' | 'policy' | 'config';
  message: string;
  route?: string;
}

export interface PolicyEvaluation {
  name: PolicyName;
  enabled: boolean;
  violated: boolean;
  message: string | null;
}

export interface ScanReport {
  tool: string;
  version: string;
  timestamp: string;
  target: string;
  overall: 'passed' | 'failed';
  http: HTTPResult;
  tls: TLSResult;
  headers: SecurityHeadersResult;
  routes: RouteResult[];
  findings: Finding[];
  policyEvaluations: PolicyEvaluation[];
  errors: string[];
  warnings: string[];
}

export interface ActionConfig {
  url: string;
  routes: string[];
  expectedStatusCodes: number[];
  timeoutSeconds: number;
  maxRedirects: number;
  requiredHeaders: string[];
  certificateWarningDays: number;
  certificateFailureDays: number;
  failOnHTTpError: boolean;
  failOnRedirect: boolean;
  failOnMissingHeaders: boolean;
  failOnTLSError: boolean;
  failOnCertificateExpiry: boolean;
  failOnRouteError: boolean;
  outputFile: string;
  baselineFile: string;
  allowProhibitedIPs: boolean;
  version: string;
}

export interface ParseInputsOptions {
  allowProhibitedIPs?: boolean;
}

export function parseInputs(raw: Record<string, string>, options: ParseInputsOptions = {}): ActionConfig {
  const url = raw.url?.trim();
  if (!url) {
    throw new Error('Input "url" is required.');
  }

  const routesRaw = (raw.routes || '/').trim();
  const routes = routesRaw
    .split('\n')
    .map((r) => r.trim())
    .filter(Boolean);
  if (routes.length === 0) {
    throw new Error('Input "routes" must contain at least one route.');
  }

  const expectedStatusCodesRaw = (raw['expected-status-codes'] || '200').trim();
  const expectedStatusCodes = parseCSVNumbers(expectedStatusCodesRaw, 'expected-status-codes');
  if (expectedStatusCodes.length === 0) {
    throw new Error('Input "expected-status-codes" must contain at least one status code.');
  }
  for (const code of expectedStatusCodes) {
    if (code < 100 || code > 599) {
      throw new Error(`Invalid expected status code: ${code}. Must be between 100 and 599.`);
    }
  }

  const timeoutSeconds = parseIntPositive(raw.timeout || '10', 'timeout', 1, 300);
  const maxRedirects = parseIntPositive(raw['max-redirects'] || '10', 'max-redirects', 0, 50);

  const requiredHeadersRaw = (raw['required-headers'] || '').trim();
  const requiredHeaders = requiredHeadersRaw
    ? requiredHeadersRaw.split(',').map((h) => h.trim().toLowerCase()).filter(Boolean)
    : [];

  const certificateWarningDays = parseIntPositive(
    raw['certificate-warning-days'] || '14',
    'certificate-warning-days',
    0,
    3650
  );
  const certificateFailureDays = parseIntPositive(
    raw['certificate-failure-days'] || '7',
    'certificate-failure-days',
    0,
    3650
  );

  if (certificateFailureDays > certificateWarningDays) {
    throw new Error(
      'certificate-failure-days must not exceed certificate-warning-days (failure threshold should be tighter).'
    );
  }

  const parseBool = (key: string, def: boolean): boolean => {
    const val = raw[key];
    if (val === undefined || val === '') return def;
    const lower = val.trim().toLowerCase();
    if (lower === 'true' || lower === '1') return true;
    if (lower === 'false' || lower === '0') return false;
    throw new Error(`Input "${key}" must be a boolean (true/false), got: ${val}`);
  };

  const failOnHTTpError = parseBool('fail-on-http-error', true);
  const failOnRedirect = parseBool('fail-on-redirect', false);
  const failOnMissingHeaders = parseBool('fail-on-missing-headers', false);
  const failOnTLSError = parseBool('fail-on-tls-error', true);
  const failOnCertificateExpiry = parseBool('fail-on-certificate-expiry', true);
  const failOnRouteError = parseBool('fail-on-route-error', true);

  const outputFile = (raw['output-file'] || 'webcheck-report.json').trim() || 'webcheck-report.json';
  const baselineFile = (raw['baseline-file'] || '').trim();

  return {
    url,
    routes,
    expectedStatusCodes,
    timeoutSeconds,
    maxRedirects,
    requiredHeaders,
    certificateWarningDays,
    certificateFailureDays,
    failOnHTTpError,
    failOnRedirect,
    failOnMissingHeaders,
    failOnTLSError,
    failOnCertificateExpiry,
    failOnRouteError,
    outputFile,
    baselineFile,
    allowProhibitedIPs: !!options.allowProhibitedIPs,
    version: '1.0.0',
  };
}

function parseCSVNumbers(input: string, fieldName: string): number[] {
  return input
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => {
      const n = Number(s);
      if (!Number.isInteger(n)) {
        throw new Error(`Invalid ${fieldName} value: "${s}". Must be an integer.`);
      }
      return n;
    });
}

function parseIntPositive(input: string, fieldName: string, min: number, max: number): number {
  const n = Number(input);
  if (!Number.isInteger(n) || n < min || n > max) {
    throw new Error(`Input "${fieldName}" must be an integer between ${min} and ${max}, got: ${input}`);
  }
  return n;
}
