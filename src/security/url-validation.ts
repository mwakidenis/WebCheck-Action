import { URL } from 'url';
import { isProhibitedAddress, resolveAndCheckHostname } from './ip-validation';

export interface ValidatedURL {
  url: string;
  protocol: 'http:' | 'https:';
  hostname: string;
  port: number;
  pathname: string;
  isSecure: boolean;
}

export interface URLValidationOptions {
  allowProhibitedIPs?: boolean;
}

export class URLValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'URLValidationError';
  }
}

export function parseAndValidateURL(input: string, options: URLValidationOptions = {}): ValidatedURL {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new URLValidationError(`Malformed URL: ${input}`);
  }

  const protocol = url.protocol as 'http:' | 'https:';
  if (protocol !== 'http:' && protocol !== 'https:') {
    throw new URLValidationError(`Unsupported protocol: ${protocol}. Only http and https are allowed.`);
  }

  if (!url.hostname) {
    throw new URLValidationError(`URL missing hostname: ${input}`);
  }

  // Reject embedded credentials (user:password@host) to avoid leaking secrets.
  if (url.username || url.password) {
    throw new URLValidationError('URL must not contain embedded credentials.');
  }

  // Reject whitespace/control characters that could enable header injection.
  if (/[\r\n\t]/.test(input)) {
    throw new URLValidationError('URL must not contain control characters.');
  }

  let port: number;
  if (url.port) {
    const parsed = Number(url.port);
    if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
      throw new URLValidationError(`Invalid port: ${url.port}`);
    }
    port = parsed;
  } else {
    port = protocol === 'https:' ? 443 : 80;
  }

  const pathname = url.pathname || '/';

  // Validate hostname/IP against SSRF rules.
  const hostname = url.hostname;
  if (!options.allowProhibitedIPs && isProhibitedAddress(hostname)) {
    throw new URLValidationError(
      `URL hostname resolves to a prohibited address (${hostname}). SSRF protection blocks loopback, private, ` +
        'link-local, multicast, and reserved addresses.'
    );
  }

  return {
    url: input,
    protocol,
    hostname,
    port,
    pathname,
    isSecure: protocol === 'https:',
  };
}

export function validatePath(route: string): string {
  if (typeof route !== 'string' || route.length === 0) {
    throw new URLValidationError('Route must be a non-empty string.');
  }
  if (!route.startsWith('/')) {
    throw new URLValidationError(`Route must start with "/": ${route}`);
  }
  if (/[\r\n]/.test(route)) {
    throw new URLValidationError(`Route must not contain control characters: ${route}`);
  }
  // Normalize: collapse duplicate slashes but keep leading slash.
  let normalized = route.replace(/\/+/g, '/');
  if (normalized.length > 1 && normalized.endsWith('/')) {
    normalized = normalized.slice(0, -1);
  }
  return normalized || '/';
}

export async function validateRedirectDestination(
  location: string,
  baseURL: ValidatedURL,
  options: URLValidationOptions = {}
): Promise<{ url: string; validated: ValidatedURL; allowed: boolean; reason?: string }> {
  let resolved: URL;
  try {
    resolved = new URL(location, `${baseURL.protocol}//${baseURL.hostname}:${baseURL.port}`);
  } catch {
    return { url: location, validated: null as any, allowed: false, reason: 'Invalid redirect location URL.' };
  }

  if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') {
    return { url: location, validated: null as any, allowed: false, reason: 'Redirect to unsupported protocol.' };
  }

  if (resolved.username || resolved.password) {
    return { url: location, validated: null as any, allowed: false, reason: 'Redirect contains embedded credentials.' };
  }

  const hostname = resolved.hostname;
  if (!options.allowProhibitedIPs && isProhibitedAddress(hostname)) {
    return {
      url: location,
      validated: null as any,
      allowed: false,
      reason: `Redirect to prohibited address (${hostname}).`,
    };
  }

  const validated: ValidatedURL = {
    url: resolved.toString(),
    protocol: resolved.protocol as 'http:' | 'https:',
    hostname,
    port: resolved.port ? Number(resolved.port) : resolved.protocol === 'https:' ? 443 : 80,
    pathname: resolved.pathname || '/',
    isSecure: resolved.protocol === 'https:',
  };

  return { url: resolved.toString(), validated, allowed: true };
}

export { resolveAndCheckHostname };
