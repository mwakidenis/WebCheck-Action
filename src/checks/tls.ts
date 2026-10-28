import tls from 'tls';

export interface TLSCheckOptions {
  hostname: string;
  port: number;
  servername?: string;
  timeoutMs: number;
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

type CertLike = Record<string, any>;

function parseCertificateFields(cert: CertLike): Record<string, string> {
  const fields: Record<string, string> = {};
  const subject = cert.subject;
  if (subject) {
    if (typeof subject === 'string') {
      fields['raw'] = subject;
    } else if (typeof subject === 'object') {
      for (const [key, value] of Object.entries(subject as Record<string, string>)) {
        if (value !== undefined && value !== '') fields[String(key)] = String(value);
      }
    }
  }
  return fields;
}

function parseSubjectAltName(cert: CertLike): string[] {
  const san = cert.subjectaltname;
  if (!san || typeof san !== 'string') return [];
  return san
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.startsWith('DNS:'))
    .map((entry) => entry.slice(4).trim())
    .filter(Boolean);
}

function wildcardMatch(pattern: string, hostname: string): boolean {
  if (pattern.startsWith('*.')) {
    const suffix = pattern.slice(1);
    const idx = hostname.indexOf('.');
    if (idx === -1) return false;
    return hostname.slice(idx) === suffix;
  }
  return pattern === hostname;
}

function hostnameMatchesCert(hostname: string, cert: CertLike): boolean {
  const sans = parseSubjectAltName(cert);
  if (sans.length > 0) {
    return sans.some((san) => wildcardMatch(san, hostname));
  }
  const subject = cert.subject;
  const cn = subject && typeof subject === 'object' ? (subject as Record<string, string>)['CN'] : undefined;
  if (cn) return wildcardMatch(cn, hostname);
  return false;
}

function computeDaysRemaining(validTo: string | null): number | null {
  if (!validTo) return null;
  const expiry = new Date(validTo);
  if (isNaN(expiry.getTime())) return null;
  const now = new Date();
  const diffMs = expiry.getTime() - now.getTime();
  return Math.ceil(diffMs / (1000 * 60 * 60 * 24));
}

export async function checkTLS(options: TLSCheckOptions): Promise<TLSResult> {
  const { hostname, port, servername = hostname, timeoutMs } = options;

  const result: TLSResult = {
    enabled: true,
    certificate: null,
    handshakeError: null,
    hostnameMismatch: false,
    error: null,
  };

  const connectOptions: tls.ConnectionOptions = {
    host: hostname,
    port,
    servername,
    rejectUnauthorized: false, // always inspect cert; authorization status reported separately
  };

  return new Promise((resolve) => {
    let socket: tls.TLSSocket | null = null;
    let settled = false;

    const settle = (res: TLSResult) => {
      if (settled) return;
      settled = true;
      try {
        socket?.destroy();
      } catch {
        // ignore destroy errors
      }
      resolve(res);
    };

    const timer = setTimeout(() => {
      settle({
        ...result,
        error: `TLS handshake timed out after ${timeoutMs} ms`,
        handshakeError: `TLS handshake timed out after ${timeoutMs} ms`,
      });
    }, timeoutMs);

    socket = tls.connect(connectOptions, () => {
      clearTimeout(timer);
      const sock = socket;
      if (!sock) {
        settle({ ...result, error: 'TLS socket was not established', handshakeError: 'TLS socket was not established' });
        return;
      }
      try {
        sock.setTimeout(timeoutMs);
        sock.on('timeout', () => {
          if (!settled) {
            settle({
              ...result,
              error: `TLS handshake timed out after ${timeoutMs} ms`,
              handshakeError: `TLS handshake timed out after ${timeoutMs} ms`,
            });
          }
        });
        const cert = sock.getPeerCertificate() as CertLike;
        const authorized = Boolean(sock.authorized);
        const authorizationError = sock.authorizationError ?? null;

        let certInfo: TLSCertificateInfo | null = null;
        if (cert && Object.keys(cert).length > 0) {
          const issuerCert = cert.issuerCertificate || cert;
          certInfo = {
            subject: parseCertificateFields(cert),
            issuer: parseCertificateFields(issuerCert),
            validFrom: cert.valid_from ?? null,
            validTo: cert.valid_to ?? null,
            expiryDate: cert.valid_to ?? null,
            daysRemaining: computeDaysRemaining(cert.valid_to ?? null),
            fingerprint: cert.fingerprint ?? null,
            authorized,
            authorizationError: sock.authorizationError ? String(sock.authorizationError) : null,
            error: authorized ? null : `Certificate not authorized: ${authorizationError ?? 'unknown reason'}`,
          };
        }

        const hostnameMismatch = certInfo ? !hostnameMatchesCert(hostname, cert) : false;

        let error: string | null = null;
        let handshakeError: string | null = null;
        if (!authorized) {
          const reason = authorizationError ?? 'certificate verification failed';
          error = `TLS certificate verification failed: ${reason}`;
          handshakeError = error;
        }
        if (hostnameMismatch) {
          error = `TLS hostname mismatch: certificate does not match ${hostname}`;
          handshakeError = handshakeError || error;
        }

        settle({
          ...result,
          certificate: certInfo,
          handshakeError,
          hostnameMismatch,
          error,
        });
      } catch (err) {
        settle({
          ...result,
          error: err instanceof Error ? err.message : 'TLS certificate inspection failed',
          handshakeError: err instanceof Error ? err.message : 'TLS certificate inspection failed',
        });
      }
    });

    socket.on('error', (err: Error) => {
      clearTimeout(timer);
      settle({
        ...result,
        error: `TLS handshake error: ${err.message}`,
        handshakeError: `TLS handshake error: ${err.message}`,
      });
    });
  });
}
