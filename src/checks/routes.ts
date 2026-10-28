import { URL } from 'url';
import { fetchURL } from '../http/client';
import { HTTPRequestOptions } from '../http/client';
import { validatePath } from '../security/url-validation';
import { isProhibitedAddress } from '../security/ip-validation';
import { RouteResult } from '../config';

export interface RouteCheckOptions {
  baseURL: string;
  routes: string[];
  timeoutMs: number;
  maxRedirects: number;
  rejectUnauthorized: boolean;
  allowCrossOriginRedirects: boolean;
}

export async function checkRoutes(options: RouteCheckOptions): Promise<RouteResult[]> {
  const { baseURL, routes, timeoutMs, maxRedirects, rejectUnauthorized, allowCrossOriginRedirects } = options;

  const baseParsed = new URL(baseURL);
  const baseOrigin = `${baseParsed.protocol}//${baseParsed.host}`;

  const results: RouteResult[] = [];

  for (const rawRoute of routes) {
    let route: string;
    try {
      route = validatePath(rawRoute);
    } catch (err) {
      results.push({
        route: rawRoute,
        url: baseURL,
        statusCode: null,
        error: err instanceof Error ? err.message : 'Invalid route.',
        transportError: true,
        redirected: false,
        redirectCount: 0,
        finalURL: null,
      });
      continue;
    }

    const routeURL = new URL(route, baseOrigin).toString();
    const parsedRoute = new URL(routeURL);

    // SSRF: block routes resolving to a prohibited address, except same-host
    // routes (e.g. local testing against loopback).
    if (isProhibitedAddress(parsedRoute.hostname) && parsedRoute.hostname !== baseParsed.hostname) {
      results.push({
        route,
        url: routeURL,
        statusCode: null,
        error: `Route resolves to a prohibited address (${parsedRoute.hostname}).`,
        transportError: true,
        redirected: false,
        redirectCount: 0,
        finalURL: null,
      });
      continue;
    }

    const clientOpts: HTTPRequestOptions = {
      timeoutMs,
      maxRedirects,
      followRedirects: true,
      rejectUnauthorized,
      servername: parsedRoute.hostname,
    };

    const res = await fetchURL(routeURL, clientOpts);

    let redirected = false;
    let crossOriginWarning = '';
    if (res.finalURL) {
      try {
        const finalHost = new URL(res.finalURL).host;
        if (finalHost !== baseParsed.host) {
          redirected = true;
          if (!allowCrossOriginRedirects) {
            crossOriginWarning = `Route redirected to a different host (${finalHost}).`;
          }
        } else if (res.redirectCount > 0) {
          redirected = true;
        }
        } catch {
          // ignore unparseable final URL
        }
      }

    const errorParts: string[] = [];
    if (res.error) errorParts.push(res.error);
    if (crossOriginWarning) errorParts.push(crossOriginWarning);

    results.push({
      route,
      url: routeURL,
      statusCode: res.statusCode,
      error: errorParts.length > 0 ? errorParts.join('; ') : null,
      transportError: res.transportError,
      redirected: res.redirectCount > 0 || redirected,
      redirectCount: res.redirectCount,
      finalURL: res.finalURL ?? null,
    });
  }

  return results;
}
