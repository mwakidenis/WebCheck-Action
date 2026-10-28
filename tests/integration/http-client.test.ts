import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { fetchURL } from '../../src/http/client';
import { startTestServer, stopTestServer } from './server';

describe('HTTP client (local server)', () => {
  let port: number;
  let baseURL: string;
  let server: any;

  beforeAll(async () => {
    const hangHandler = () => ({ status: 200, body: 'hang', hang: true }); // never ends response
    const { server: s, port: p, baseURL: b } = await startTestServer({
      '/': () => ({ status: 200, body: 'ok' }),
      '/health': () => ({ status: 200, body: 'healthy' }),
      '/api/status': () => ({ status: 200, body: JSON.stringify({ ok: true }), headers: { 'Content-Type': 'application/json' } }),
      '/notfound': () => ({ status: 404, body: 'not found' }),
      '/server-error': () => ({ status: 500, body: 'error' }),
      '/redirect-one': () => ({ status: 302, body: '', headers: { Location: '/redirect-two' } }),
      '/redirect-two': () => ({ status: 302, body: '', headers: { Location: '/final' } }),
      '/final': () => ({ status: 200, body: 'final' }),
      '/redirect-loop': () => ({ status: 302, body: '', headers: { Location: '/redirect-loop' } }),
      '/redirect-to-loopback': () => ({ status: 302, body: '', headers: { Location: `http://127.0.0.1:${p}/` } }),
      '/hang': hangHandler,
    });
    server = s;
    port = p;
    baseURL = b;
  });

  afterAll(async () => {
    await stopTestServer(server);
  });

  it('returns 200 for a valid GET', async () => {
    const res = await fetchURL(`${baseURL}/`, { timeoutMs: 5000, maxRedirects: 5, followRedirects: true, rejectUnauthorized: true });
    expect(res.transportError).toBe(false);
    expect(res.statusCode).toBe(200);
    expect(res.error).toBeNull();
  });

  it('returns 404', async () => {
    const res = await fetchURL(`${baseURL}/notfound`, { timeoutMs: 5000, maxRedirects: 5, followRedirects: true, rejectUnauthorized: true });
    expect(res.statusCode).toBe(404);
    expect(res.transportError).toBe(false);
  });

  it('returns 500', async () => {
    const res = await fetchURL(`${baseURL}/server-error`, { timeoutMs: 5000, maxRedirects: 5, followRedirects: true, rejectUnauthorized: true });
    expect(res.statusCode).toBe(500);
  });

  it('follows a redirect chain and reports final destination', async () => {
    const res = await fetchURL(`${baseURL}/redirect-one`, { timeoutMs: 5000, maxRedirects: 5, followRedirects: true, rejectUnauthorized: true });
    expect(res.statusCode).toBe(200);
    expect(res.redirectCount).toBe(2);
    expect(res.finalURL).toBe(`${baseURL}/final`);
    expect(res.redirectChain).toContain(`${baseURL}/redirect-two`);
  });

  it('detects a redirect loop', async () => {
    const res = await fetchURL(`${baseURL}/redirect-loop`, { timeoutMs: 5000, maxRedirects: 5, followRedirects: true, rejectUnauthorized: true });
    expect(res.transportError).toBe(true);
    expect(res.error).toContain('loop');
  });

  it('enforces redirect limit', async () => {
    const res = await fetchURL(`${baseURL}/redirect-one`, { timeoutMs: 5000, maxRedirects: 1, followRedirects: true, rejectUnauthorized: true });
    expect(res.transportError).toBe(true);
    expect(res.error).toContain('limit');
  });

  it('blocks redirects to loopback/prohibited addresses', async () => {
    const res = await fetchURL(`http://localhost:${port}/redirect-to-loopback`, { timeoutMs: 5000, maxRedirects: 5, followRedirects: true, rejectUnauthorized: true });
    expect(res.transportError).toBe(true);
    expect(res.error).toContain('prohibited');
  });

  it('reports a DNS error as transport error', async () => {
    const res = await fetchURL('http://nonexistent-domain-for-webcheck.invalid/', { timeoutMs: 5000, maxRedirects: 5, followRedirects: true, rejectUnauthorized: true });
    expect(res.transportError).toBe(true);
    expect(res.statusCode).toBeNull();
    expect(res.error).not.toBeNull();
  });

  it('reports connection refused as transport error', async () => {
    const res = await fetchURL('http://127.0.0.1:1/', { timeoutMs: 3000, maxRedirects: 5, followRedirects: true, rejectUnauthorized: true });
    expect(res.transportError).toBe(true);
    expect(res.statusCode).toBeNull();
  });

  it('enforces request timeout on a hanging endpoint', async () => {
    const res = await fetchURL(`${baseURL}/hang`, { timeoutMs: 100, maxRedirects: 5, followRedirects: true, rejectUnauthorized: true });
    expect(res.transportError).toBe(true);
    expect(res.error).toContain('timed out');
  });

  it('distinguishes transport failure from HTTP status failure', async () => {
    const statusRes = await fetchURL(`${baseURL}/server-error`, { timeoutMs: 5000, maxRedirects: 5, followRedirects: true, rejectUnauthorized: true });
    expect(statusRes.transportError).toBe(false);
    expect(statusRes.statusCode).toBe(500);
    expect(statusRes.error).toBeNull();

    const dnsRes = await fetchURL('http://nonexistent-domain-for-webcheck.invalid/', { timeoutMs: 5000, maxRedirects: 5, followRedirects: true, rejectUnauthorized: true });
    expect(dnsRes.transportError).toBe(true);
    expect(dnsRes.statusCode).toBeNull();
  });
});
