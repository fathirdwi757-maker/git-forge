// app.ts — the forge's HTTP server: routing, bearer-token auth and the
// cross-surface protocol rules. The git smart-HTTP endpoints, REST v3,
// GraphQL v4 and the MCP endpoint all hang off the one store in forge.ts, so
// state is shared across surfaces. /healthz is the env's boot probe and is
// the only route that answers without the shop token.

import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { advertise, receivePack, uploadPack } from './githttp.ts';
import { handleGraphQL } from './graphql.ts';
import { handleMCP } from './mcp.ts';
import { routeRest } from './rest.ts';
import { findRepo } from './forge.ts';
import { parseJsonBody, type Reply } from './web.ts';

const MAX_BODY_BYTES = 256 * 1024 * 1024;
let requestSeq = 0;

function expectedToken(): string | undefined {
  const token = process.env.MAKEFUN_SHOP_TOKEN;
  return token === undefined || token === '' ? undefined : token;
}

function authorized(req: IncomingMessage): boolean {
  const token = expectedToken();
  if (token === undefined) return true;
  const header = req.headers.authorization;
  return header === `Bearer ${token}`;
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function sendJson(res: ServerResponse, status: number, value: unknown, headers: Record<string, string> = {}): void {
  const body = Buffer.from(JSON.stringify(value), 'utf8');
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': body.length, ...headers });
  res.end(body);
}

function sendReply(res: ServerResponse, reply: Reply, headers: Record<string, string> = {}): void {
  const merged = { ...headers, ...(reply.headers ?? {}) };
  if (reply.raw) {
    res.writeHead(reply.status, {
      'content-type': reply.contentType ?? 'application/octet-stream',
      'content-length': reply.raw.length,
      ...merged,
    });
    res.end(reply.raw);
    return;
  }
  if (reply.json !== undefined) {
    sendJson(res, reply.status, reply.json, merged);
    return;
  }
  res.writeHead(reply.status, merged);
  res.end();
}

async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const method = req.method ?? 'GET';
  const url = new URL(req.url ?? '/', 'http://forge.invalid');
  const path = url.pathname;
  requestSeq += 1;
  const requestId = `git-forge-${requestSeq}`;

  if (path === '/healthz') {
    if (method === 'GET' || method === 'HEAD') sendJson(res, 200, { ok: true });
    else sendJson(res, 404, { message: 'Not Found' });
    return;
  }

  // REST v3: every reply is JSON and carries a request id, errors included.
  if (path === '/api/v3' || path.startsWith('/api/v3/')) {
    const v3Headers = { 'x-github-request-id': requestId, 'x-oauth-scopes': 'repo, read:org' };
    if (!authorized(req)) {
      sendJson(res, 401, { message: 'Unauthorized' }, v3Headers);
      return;
    }
    const raw = method === 'GET' ? Buffer.alloc(0) : await readBody(req);
    let body: unknown;
    if (raw.length > 0) {
      const parsed = parseJsonBody(raw);
      if (!parsed.ok) {
        sendJson(res, 400, { message: 'Problems parsing JSON' }, v3Headers);
        return;
      }
      body = parsed.value;
    }
    const segments = path
      .slice('/api/v3'.length)
      .split('/')
      .filter((segment) => segment !== '')
      .map((segment) => decodeURIComponent(segment));
    const host = req.headers.host ?? 'forge.invalid';
    const reply = routeRest({ method, segments, query: url.searchParams, body, origin: `http://${host}` });
    sendReply(res, reply, v3Headers);
    return;
  }

  if (path === '/api/graphql') {
    if (method !== 'POST') {
      sendJson(res, 404, { message: 'Not Found' });
      return;
    }
    if (!authorized(req)) {
      sendJson(res, 401, { message: 'Unauthorized' });
      return;
    }
    const raw = await readBody(req);
    sendReply(res, handleGraphQL(raw));
    return;
  }

  if (path === '/mcp') {
    if (method !== 'POST') {
      sendJson(res, 405, { jsonrpc: '2.0', id: null, error: { code: -32601, message: 'Method not found' } });
      return;
    }
    if (!authorized(req)) {
      sendJson(res, 401, { jsonrpc: '2.0', id: null, error: { code: -32001, message: 'Unauthorized' } });
      return;
    }
    const raw = await readBody(req);
    sendReply(res, handleMCP(raw));
    return;
  }

  // Git smart HTTP: /<owner>/<repo>.git/<endpoint>
  const gitMatch = /^\/([^/]+)\/([^/]+)\.git\/(info\/refs|git-upload-pack|git-receive-pack)$/.exec(path);
  if (gitMatch) {
    const owner = decodeURIComponent(gitMatch[1]);
    const name = decodeURIComponent(gitMatch[2]);
    const endpoint = gitMatch[3];
    if (!authorized(req)) {
      sendJson(res, 401, { message: 'Unauthorized' });
      return;
    }
    const repo = findRepo(owner, name);
    if (!repo) {
      sendJson(res, 404, { message: 'Not Found' });
      return;
    }
    const protocolHeader = req.headers['git-protocol'];
    const protocolV2 = typeof protocolHeader === 'string' && protocolHeader.split(':').includes('version=2');
    try {
      if (endpoint === 'info/refs' && method === 'GET') {
        const service = url.searchParams.get('service');
        if (service !== 'git-upload-pack' && service !== 'git-receive-pack') {
          sendJson(res, 400, { message: 'Missing or unknown service' });
          return;
        }
        const body = advertise(repo, service, protocolV2);
        res.writeHead(200, {
          'content-type': `application/x-${service}-advertisement`,
          'content-length': body.length,
          'cache-control': 'no-cache',
        });
        res.end(body);
        return;
      }
      if (endpoint === 'git-upload-pack' && method === 'POST') {
        const raw = await readBody(req);
        const body = uploadPack(repo, raw, protocolV2);
        res.writeHead(200, { 'content-type': 'application/x-git-upload-pack-result', 'content-length': body.length });
        res.end(body);
        return;
      }
      if (endpoint === 'git-receive-pack' && method === 'POST') {
        const raw = await readBody(req);
        const body = receivePack(repo, raw);
        res.writeHead(200, { 'content-type': 'application/x-git-receive-pack-result', 'content-length': body.length });
        res.end(body);
        return;
      }
    } catch (err) {
      // A malformed body must never take the server down.
      const text = Buffer.from(`error: ${err instanceof Error ? err.message : String(err)}\n`, 'utf8');
      res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8', 'content-length': text.length });
      res.end(text);
      return;
    }
    sendJson(res, 404, { message: 'Not Found' });
    return;
  }

  sendJson(res, 404, { message: 'Not Found' });
}

export function createApp(): Server {
  const server = createHttpServer((req, res) => {
    handle(req, res).catch(() => {
      if (!res.headersSent) sendJson(res, 500, { message: 'Internal Server Error' });
      else res.end();
    });
  });
  server.keepAliveTimeout = 75_000;
  return server;
}
