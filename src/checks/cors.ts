export interface CORSResult {
  allowOrigin: string | null;
  allowCredentials: boolean | null;
  allowMethods: string | null;
  allowHeaders: string | null;
  exposeHeaders: string | null;
  status: 'secure' | 'warning' | 'error';
  notes: string[];
}

export function checkCORS(headers: Record<string, string>): CORSResult {
  const result: CORSResult = {
    allowOrigin: null,
    allowCredentials: null,
    allowMethods: null,
    allowHeaders: null,
    exposeHeaders: null,
    status: 'secure',
    notes: [],
  };

  const allowOrigin = headers['access-control-allow-origin'];
  const allowCredentials = headers['access-control-allow-credentials'];
  const allowMethods = headers['access-control-allow-methods'];
  const allowHeaders = headers['access-control-allow-headers'];
  const exposeHeaders = headers['access-control-expose-headers'];

  result.allowOrigin = allowOrigin ?? null;
  result.allowCredentials = allowCredentials ? allowCredentials.toLowerCase() === 'true' : null;
  result.allowMethods = allowMethods ?? null;
  result.allowHeaders = allowHeaders ?? null;
  result.exposeHeaders = exposeHeaders ?? null;

  // Dangerous: wildcard origin with credentials
  if (allowOrigin === '*' && result.allowCredentials === true) {
    result.status = 'error';
    result.notes.push('Access-Control-Allow-Origin is wildcard (*) with credentials enabled');
  }
  // Warning: wildcard origin without credentials
  else if (allowOrigin === '*') {
    result.status = 'warning';
    result.notes.push('Access-Control-Allow-Origin is wildcard (*)');
  }
  // Warning: credentials enabled without specific origin
  else if (result.allowCredentials === true && (!allowOrigin || allowOrigin === '')) {
    result.status = 'warning';
    result.notes.push('Credentials enabled without explicit origin');
  }

  return result;
}
