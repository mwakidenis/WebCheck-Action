export interface CookieFinding {
  name: string;
  secure: boolean | null;
  httpOnly: boolean | null;
  sameSite: string | null;
  prefix: string | null;
  status: 'secure' | 'warning' | 'error';
  notes: string[];
}

export interface CookieSecurityResult {
  cookies: CookieFinding[];
  totalCookies: number;
  secureCount: number;
  httpOnlyCount: number;
  sameSiteCount: number;
  error: string | null;
}

function parseSetCookie(header: string): { name: string; attributes: Record<string, string> } {
  const parts = header.split(';').map((p) => p.trim());
  const nameValue = parts[0] ?? '';
  const eqIdx = nameValue.indexOf('=');
  const name = eqIdx === -1 ? nameValue.trim() : nameValue.slice(0, eqIdx).trim();
  const attributes: Record<string, string> = {};
  for (let i = 1; i < parts.length; i++) {
    const part = parts[i];
    const eqIdx2 = part.indexOf('=');
    if (eqIdx2 === -1) {
      attributes[part.trim().toLowerCase()] = '';
    } else {
      attributes[part.slice(0, eqIdx2).trim().toLowerCase()] = part.slice(eqIdx2 + 1).trim();
    }
  }
  return { name, attributes };
}

function cookiePrefix(name: string): string | null {
  if (name.startsWith('__Host-')) return '__Host-';
  if (name.startsWith('__Secure-')) return '__Secure-';
  return null;
}

export function checkCookieSecurity(setCookieHeaders: string[] | null): CookieSecurityResult {
  const result: CookieSecurityResult = {
    cookies: [],
    totalCookies: 0,
    secureCount: 0,
    httpOnlyCount: 0,
    sameSiteCount: 0,
    error: null,
  };

  if (!setCookieHeaders || setCookieHeaders.length === 0) {
    return result;
  }

  for (const header of setCookieHeaders) {
    const { name, attributes } = parseSetCookie(header);
    const secure = attributes['secure'] !== undefined;
    const httpOnly = attributes['httponly'] !== undefined;
    const sameSite = attributes['samesite'] ?? null;
    const prefix = cookiePrefix(name);

    const notes: string[] = [];
    let status: 'secure' | 'warning' | 'error' = 'secure';

    if (!secure) {
      notes.push('Cookie lacks Secure flag');
      status = 'warning';
    }
    if (!httpOnly) {
      notes.push('Cookie lacks HttpOnly flag');
      status = status === 'secure' ? 'warning' : status;
    }
    if (!sameSite) {
      notes.push('Cookie lacks SameSite attribute');
      status = 'warning';
    } else if (sameSite.toLowerCase() === 'none' && !secure) {
      notes.push('SameSite=None requires Secure flag');
      status = 'error';
    } else if (sameSite.toLowerCase() === 'lax' && prefix === '__Host-') {
      notes.push('__Host- cookies should use SameSite=Strict');
      status = status === 'secure' ? 'warning' : status;
    }
    if (prefix === '__Host-' && (!secure || !httpOnly || !sameSite || sameSite.toLowerCase() !== 'strict')) {
      notes.push('__Host- cookie missing Secure, HttpOnly, or SameSite=Strict');
      status = 'error';
    }

    result.cookies.push({
      name,
      secure,
      httpOnly,
      sameSite,
      prefix,
      status,
      notes,
    });

    result.totalCookies++;
    if (secure) result.secureCount++;
    if (httpOnly) result.httpOnlyCount++;
    if (sameSite) result.sameSiteCount++;
  }

  return result;
}
