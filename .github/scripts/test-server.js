const http = require('http');

const PORT = Number(process.argv[2]) || 8999;
const HOST = '127.0.0.1';

const routes = {
  '/': { status: 200, body: 'ok', headers: { 'content-type': 'text/plain' } },
  '/health': { status: 200, body: 'healthy', headers: { 'content-type': 'text/plain' } },
  '/api/status': {
    status: 200,
    body: JSON.stringify({ ok: true }),
    headers: { 'content-type': 'application/json' },
  },
  '/notfound': { status: 404, body: 'not found', headers: { 'content-type': 'text/plain' } },
  '/server-error': { status: 500, body: 'error', headers: { 'content-type': 'text/plain' } },
  '/redirect-one': {
    status: 302,
    body: '',
    headers: { location: '/redirect-two' },
  },
  '/redirect-two': {
    status: 302,
    body: '',
    headers: { location: '/final' },
  },
  '/final': { status: 200, body: 'final', headers: { 'content-type': 'text/plain' } },
  '/redirect-loop': {
    status: 302,
    body: '',
    headers: { location: '/redirect-loop' },
  },
  '/hang': null,
};

const server = http.createServer((req, res) => {
  const url = new URL(req.url || '/', `http://${HOST}:${PORT}`);
  const route = routes[url.pathname];
  if (!route) {
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found');
    return;
  }
  if (!route) {
    // hang route: never respond
    return;
  }
  res.writeHead(route.status, route.headers);
  res.end(route.body);
});

server.listen(PORT, HOST, () => {
  console.log(`Test server listening on ${HOST}:${PORT}`);
});

process.on('SIGTERM', () => server.close());
process.on('SIGINT', () => server.close());
