import { describe, it, expect, vi, afterEach } from 'vitest';
import { checkTLS } from '../../src/checks/tls';

function makeFakeSocket(cert: any, authorized: boolean, authorizationError?: string) {
  const events: Record<string, Array<() => void>> = {};
  const socket = {
    authorized,
    authorizationError,
    getPeerCertificate: () => cert,
    setTimeout: vi.fn(),
    on: vi.fn((event: string, handler: () => void) => {
      if (!events[event]) events[event] = [];
      events[event].push(handler);
      return socket;
    }),
    destroy: vi.fn(),
    emit: (event: string, ...args: any[]) => {
      (events[event] ?? []).forEach((h) => h(...args));
    },
  } as any;
  return { socket, events };
}

describe('checkTLS (mocked)', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('reports authorized certificate details', async () => {
    const cert = {
      subject: { CN: 'example.com' },
      issuerCertificate: { CN: 'R3', O: "Let's Encrypt" },
      valid_from: 'Jan  1 00:00:00 2026 GMT',
      valid_to: 'Jan  1 00:00:00 2030 GMT',
      fingerprint: 'AB:CD',
    };
    const { socket } = makeFakeSocket(cert, true);
    const connect = vi.fn((_opts: any, cb: () => void) => {
      process.nextTick(() => cb());
      return socket;
    });
    vi.spyOn(require('tls'), 'connect').mockImplementation(connect as any);

    const res = await checkTLS({ hostname: 'example.com', port: 443, timeoutMs: 5000 });

    expect(connect).toHaveBeenCalled();
    expect(res.certificate?.authorized).toBe(true);
    expect(res.certificate?.subject?.CN).toBe('example.com');
    expect(res.hostnameMismatch).toBe(false);
    expect(res.error).toBeNull();
    expect(socket.destroy).toHaveBeenCalled();
  });

  it('reports unauthorized certificate', async () => {
    const cert = { subject: { CN: 'example.com' } };
    const { socket } = makeFakeSocket(cert, false, 'unable to verify');
    const connect = vi.fn((_opts: any, cb: () => void) => {
      process.nextTick(() => cb());
      return socket;
    });
    vi.spyOn(require('tls'), 'connect').mockImplementation(connect as any);

    const res = await checkTLS({ hostname: 'example.com', port: 443, timeoutMs: 5000 });

    expect(res.certificate?.authorized).toBe(false);
    expect(res.error).toContain('certificate verification failed');
    expect(res.hostnameMismatch).toBe(false);
  });

  it('reports handshake error on connect error', async () => {
    const { socket } = makeFakeSocket({}, false);
    const connect = vi.fn((_opts: any, _cb: () => void) => {
      process.nextTick(() => socket.emit('error', new Error('connect failed')));
      return socket;
    });
    vi.spyOn(require('tls'), 'connect').mockImplementation(connect as any);

    const res = await checkTLS({ hostname: 'example.com', port: 443, timeoutMs: 5000 });

    expect(res.handshakeError).toContain('TLS handshake error');
  });
});
