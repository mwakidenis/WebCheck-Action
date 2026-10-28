import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { checkRoutes } from '../../src/checks/routes';
import { startTestServer, stopTestServer } from './server';

describe('checkRoutes (local server)', () => {
  let port: number;
  let baseURL: string;
  let server: any;

  beforeAll(async () => {
    const { server: s, port: p, baseURL: b } = await startTestServer({
      '/': () => ({ status: 200, body: 'ok' }),
      '/health': () => ({ status: 200, body: 'healthy' }),
      '/api/status': () => ({ status: 200, body: JSON.stringify({ ok: true }), headers: { 'Content-Type': 'application/json' } }),
      '/missing': () => ({ status: 404, body: 'missing' }),
    });
    server = s;
    port = p;
    baseURL = b;
  });

  afterAll(async () => {
    await stopTestServer(server);
  });

  it('returns success for configured routes', async () => {
    const results = await checkRoutes({
      baseURL,
      routes: ['/', '/health', '/api/status'],
      timeoutMs: 5000,
      maxRedirects: 5,
      rejectUnauthorized: true,
      allowCrossOriginRedirects: false,
    });
    expect(results.length).toBe(3);
    for (const r of results) {
      expect(r.transportError).toBe(false);
      expect(r.error).toBeNull();
      expect(r.statusCode).toBe(200);
    }
  });

  it('reports route failure', async () => {
    const results = await checkRoutes({
      baseURL,
      routes: ['/missing'],
      timeoutMs: 5000,
      maxRedirects: 5,
      rejectUnauthorized: true,
      allowCrossOriginRedirects: false,
    });
    expect(results[0].statusCode).toBe(404);
  });

  it('validates routes', async () => {
    const results = await checkRoutes({
      baseURL,
      routes: ['invalid-route'],
      timeoutMs: 5000,
      maxRedirects: 5,
      rejectUnauthorized: true,
      allowCrossOriginRedirects: false,
    });
    expect(results[0].transportError).toBe(true);
    expect(results[0].error).not.toBeNull();
  });
});
