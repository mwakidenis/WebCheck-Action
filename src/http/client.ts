import * as http from 'http';
import * as https from 'https';
import type { RequestOptions } from 'http';
import { URL } from 'url';
import { checkIP } from '../security/ip-validation';

export interface HTTPRequestOptions {
  method?: string;
  timeoutMs: number;
  maxRedirects: number;
  maxResponseSize?: number;
  followRedirects: boolean;
  rejectUnauthorized: boolean;
  servername?: string;
}

export interface HTTPResponse {
  statusCode: number;
  statusMessage: string;
  headers: Record<string, string>;
  body: string;
  size: number;
  url: string;
}

export class HTTPError extends Error {
  public readonly statusCode: number | null;
  public readonly transportError: boolean;
  constructor(message: string, statusCode: number | null, transportError: boolean) {
    super(message);
    this.name = 'HTTPError';
    this.statusCode = statusCode ?? null;
    this.transportError = transportError;
  }
}

function getModule(protocol: string) {
  return protocol === 'https:' ? https : http;
}

function buildOptions(parsed: URL, opts: HTTPRequestOptions): RequestOptions {
  const defaultPort = parsed.protocol === 'https:' ? 443 : 80;
  const port = parsed.port ? Number(parsed.port) : defaultPort;
  return {
    protocol: parsed.protocol,
    hostname: parsed.hostname,
    port,
    path: parsed.pathname + (parsed.search || ''),
    method: opts.method ?? 'GET',
    rejectUnauthorized: opts.rejectUnauthorized,
    servername: opts.servername ?? parsed.hostname,
    headers: {
      'User-Agent': 'WebCheck-Action/1.0.0',
      Accept: '*/*',
      Connection: 'close',
    },
  } as RequestOptions;
}

function readBody(response: http.IncomingMessage, maxSize: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    response.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > maxSize) {
        response.destroy();
        reject(new Error(`Response body exceeds maximum size of ${maxSize} bytes`));
        return;
      }
      chunks.push(chunk);
    });
    response.on('end', () => resolve(Buffer.concat(chunks, total)));
    response.on('error', reject);
  });
}

function requestOnce(
  parsed: URL,
  opts: HTTPRequestOptions
): Promise<{ response: HTTPResponse; location: string | null }> {
  return new Promise((resolve, reject) => {
    const options = buildOptions(parsed, opts);
    const req = getModule(parsed.protocol).request(options, (res: http.IncomingMessage) => {
      const headers: Record<string, string> = {};
      for (const [key, value] of Object.entries(res.headers)) {
        headers[String(key)] = Array.isArray(value) ? value.join(', ') : String(value);
      }

      readBody(res, opts.maxResponseSize ?? MAX_RESPONSE_SIZE)
        .then((body) => {
          clearTimer();
          const response: HTTPResponse = {
            statusCode: res.statusCode ?? 0,
            statusMessage: res.statusMessage ?? '',
            headers,
            body: body.toString('utf8'),
            size: body.length,
            url: parsed.toString(),
          };
          const location = (headers['location'] || headers['Location']) ?? null;
          resolve({ response, location });
        })
        .catch((err: Error) => {
          clearTimer();
          reject(err);
        });
    });

    let timeoutTimer: NodeJS.Timeout | null = setTimeout(() => {
      timeoutTimer = null;
      req.destroy(new Error('Request timed out'));
    }, opts.timeoutMs);

    const clearTimer = () => {
      if (timeoutTimer) {
        clearTimeout(timeoutTimer);
        timeoutTimer = null;
      }
    };

    req.on('error', (err: Error) => {
      clearTimer();
      reject(new HTTPError(err.message, null, true));
    });

    req.end();
  });
}

const MAX_RESPONSE_SIZE = 10 * 1024 * 1024;

export async function fetchURL(
  inputURL: string,
  opts: HTTPRequestOptions
): Promise<{
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
}> {
  const startTime = Date.now();
  const redirectChain: string[] = [inputURL];
  let currentURL = inputURL;
  let redirectCount = 0;
  let lastResponse: HTTPResponse | null = null;
  let transportError = false;
  let error: string | null = null;

  try {
    for (;;) {
      const parsed = new URL(currentURL);
      const { response, location } = await requestOnce(parsed, opts);
      lastResponse = response;

      if (opts.followRedirects && location && response.statusCode >= 300 && response.statusCode < 400) {
        if (redirectCount >= opts.maxRedirects) {
          error = `Redirect limit exceeded (${opts.maxRedirects}).`;
          transportError = true;
          break;
        }
        let resolved: URL;
        try {
          resolved = new URL(location, currentURL);
        } catch {
          error = `Invalid redirect location: ${location}`;
          transportError = true;
          break;
        }
        const destCheck = checkIP(resolved.hostname);
        // Block cross-host redirects to prohibited addresses (SSRF). Same-host
        // redirects are allowed so local testing against loopback can work.
        if (destCheck.isProhibited && resolved.hostname !== parsed.hostname) {
          error = `Redirect to prohibited address (${resolved.hostname}, category: ${destCheck.category}).`;
          transportError = true;
          break;
        }
        if (redirectChain.includes(resolved.toString())) {
          error = 'Redirect loop detected.';
          transportError = true;
          break;
        }
        redirectCount++;
        redirectChain.push(resolved.toString());
        currentURL = resolved.toString();
        continue;
      }

      break;
    }
  } catch (err) {
    if (err instanceof HTTPError) {
      transportError = err.transportError;
      error = err.message;
    } else if (err instanceof Error) {
      transportError = true;
      error = err.message;
    } else {
      transportError = true;
      error = 'Unknown request error.';
    }
  }

  const responseTimeMs = Date.now() - startTime;

  return {
    statusCode: lastResponse ? lastResponse.statusCode : null,
    statusMessage: lastResponse ? lastResponse.statusMessage : null,
    finalURL: lastResponse ? lastResponse.url : currentURL,
    redirectChain,
    redirectCount,
    responseTimeMs,
    error,
    transportError,
    headers: lastResponse ? lastResponse.headers : {},
    bodySize: lastResponse ? lastResponse.size : 0,
  };
}
