import { createServer, Server } from 'http';
import { AddressInfo } from 'net';

export async function startTestServer(routes: Record<string, (req: import('http').IncomingMessage) => { status: number; body: string; headers?: Record<string, string>; hang?: boolean }>): Promise<{ server: Server; port: number; baseURL: string }> {
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', `http://localhost`);
    const handler = routes[url.pathname];
    if (!handler) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('not found');
      return;
    }
    const result = handler(req);
    if (result.hang) {
      return;
    }
    res.writeHead(result.status, result.headers ?? { 'Content-Type': 'text/plain' });
    res.end(result.body);
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address() as AddressInfo;
  return { server, port: addr.port, baseURL: `http://127.0.0.1:${addr.port}` };
}

export async function stopTestServer(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
}
