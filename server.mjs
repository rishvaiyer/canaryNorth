import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { DEMO_CAPABILITIES, authorize, hashReceipt, signReceipt } from './src/policy.mjs';

const root = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(root, 'public');
const port = Number(process.env.PORT || 4178);
const isProduction = process.env.NODE_ENV === 'production';
const demoMode = process.env.CONTEXTSEAL_DEMO_MODE === '1' || !isProduction;
const requireAuth = !demoMode && (isProduction || process.env.CONTEXTSEAL_REQUIRE_AUTH === '1');
const signingSecret = process.env.RECEIPT_SIGNING_KEY || (isProduction ? null : 'context-seal-dev-signing-key');
const authToken = process.env.CONTEXTSEAL_AUTH_TOKEN || null;
if (isProduction && !demoMode && (!signingSecret || signingSecret.length < 32)) throw new Error('RECEIPT_SIGNING_KEY must be at least 32 characters in production');
if (requireAuth && (!authToken || authToken.length < 32)) throw new Error('CONTEXTSEAL_AUTH_TOKEN must be at least 32 characters when authentication is enabled');
const startedAt = new Date().toISOString();
const receipts = [];
let sequence = 0;
const requestWindows = new Map();
const MAX_REQUESTS_PER_MINUTE = 60;

function securityHeaders() { return { 'content-security-policy': "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'", 'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY', 'referrer-policy': 'no-referrer', 'permissions-policy': 'camera=(), microphone=(), geolocation=()' }; }
function json(res, status, body) { res.writeHead(status, { ...securityHeaders(), 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }); res.end(JSON.stringify(body)); }
function graph() {
  return { nodes: [
    { id: 'agent', label: 'Agent context', type: 'agent', note: 'opaque refs only' }, { id: 'proxy', label: 'ContextSeal', type: 'proxy', note: 'policy + DLP + expiry' },
    { id: 'weather', label: 'weather.get_forecast', type: 'tool', note: 'allowlisted' }, { id: 'tickets', label: 'tickets.update', type: 'tool', note: 'scoped resource' },
    { id: 'vault', label: 'Secret vault', type: 'vault', note: 'never enters context' }, { id: 'ledger', label: 'Receipt ledger', type: 'ledger', note: 'hash chained' }
  ], edges: [
    { from: 'agent', to: 'proxy', label: 'cap_*' }, { from: 'proxy', to: 'weather', label: 'permit' }, { from: 'proxy', to: 'tickets', label: 'permit' },
    { from: 'vault', to: 'proxy', label: 'server-side lookup' }, { from: 'proxy', to: 'ledger', label: 'signed receipt' }
  ] };
}
async function body(req) {
  let raw = '';
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 100_000) throw new Error('payload-too-large');
  }
  return raw ? JSON.parse(raw) : {};
}
function clientKey(req) { return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown'; }
function rateLimited(req) {
  const now = Date.now();
  const key = clientKey(req);
  const window = requestWindows.get(key) || { startedAt: now, count: 0 };
  if (now - window.startedAt >= 60_000) { window.startedAt = now; window.count = 0; }
  window.count += 1;
  requestWindows.set(key, window);
  return window.count > MAX_REQUESTS_PER_MINUTE;
}
function authorized(req) {
  if (!requireAuth) return true;
  const header = req.headers.authorization || '';
  const provided = header.startsWith('Bearer ') ? Buffer.from(header.slice(7)) : Buffer.alloc(0);
  const expected = Buffer.from(authToken);
  return provided.length === expected.length && crypto.timingSafeEqual(provided, expected);
}
function validateAuthorizationRequest(request) {
  if (!request || Array.isArray(request) || typeof request !== 'object') throw new Error('request-object-required');
  if ('now' in request) throw new Error('server-time-only');
  for (const field of ['capabilityId', 'action', 'resource']) if (typeof request[field] !== 'string' || request[field].length < 1 || request[field].length > 256) throw new Error(`invalid-${field}`);
  if (request.input !== undefined && typeof request.input !== 'string' && (typeof request.input !== 'object' || request.input === null)) throw new Error('invalid-input');
  const input = request.input === undefined ? '' : request.input;
  if (JSON.stringify(input).length > 50_000) throw new Error('input-too-large');
  const demoControls = request.demoControls === undefined ? undefined : request.demoControls;
  if (demoControls !== undefined && (!demoMode || !demoControls || typeof demoControls !== 'object' || Array.isArray(demoControls))) throw new Error('demo-controls-disabled');
  if (demoControls && Object.values(demoControls).some((value) => typeof value !== 'boolean')) throw new Error('invalid-demo-controls');
  return { capabilityId: request.capabilityId, action: request.action, resource: request.resource, input, demoControls };
}
function makeReceipt(result, request) {
  const prior = receipts.at(-1)?.receiptHash || 'GENESIS';
  const base = { id: `rcpt_${String(++sequence).padStart(4, '0')}`, timestamp: new Date().toISOString(), principal: result.capability?.principal || 'unknown', action: request.action || 'unknown', resource: request.resource || 'unknown', decision: result.allowed ? 'allow' : 'deny', reasonCode: result.allowed ? 'policy-passed' : result.code, capabilityId: request.capabilityId || null, previousReceipt: prior };
  const receiptHash = hashReceipt(base);
  return { ...base, receiptHash, signature: signReceipt({ ...base, receiptHash }, signingSecret) };
}
function staticFile(res, pathname) {
  const safe = pathname === '/' ? '/index.html' : pathname;
  const file = path.normalize(path.join(publicDir, safe));
  const relative = path.relative(publicDir, file);
  if (relative.startsWith('..') || path.isAbsolute(relative)) return json(res, 403, { error: 'forbidden' });
  fs.readFile(file, (err, content) => { if (err) return json(res, 404, { error: 'not-found' }); const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml' }; res.writeHead(200, { ...securityHeaders(), 'content-type': types[path.extname(file)] || 'text/plain; charset=utf-8', 'cache-control': 'no-store' }); res.end(content); });
}
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  try {
    if (req.method === 'GET' && url.pathname === '/health') return json(res, 200, { ok: true, service: 'context-seal', mode: demoMode ? 'synthetic-demo' : (isProduction ? 'production' : 'local-demo') });
    if (url.pathname.startsWith('/api/') || url.pathname === '/mcp/audit') {
      if (!authorized(req)) return json(res, 401, { error: 'authentication-required' });
      if (rateLimited(req)) return json(res, 429, { error: 'rate-limit-exceeded' });
    }
    if (req.method === 'GET' && url.pathname === '/api/bootstrap') return json(res, 200, { capabilities: DEMO_CAPABILITIES.map(({ id, principal, label, tool, resource, scopes, expiresAt, status, reason }) => ({ id, principal, label, tool, resource, scopes, expiresAt, status, reason })), graph: graph(), receipts });
    if (req.method === 'GET' && url.pathname === '/api/receipts') return json(res, 200, { receipts });
    if (req.method === 'POST' && url.pathname === '/api/authorize') { const request = validateAuthorizationRequest(await body(req)); const result = authorize(request); const receipt = makeReceipt(result, request); receipts.push({ receipt, execution: result.allowed ? 'would-forward-to-tool' : 'quarantined' }); return json(res, result.allowed ? 200 : 403, { allowed: result.allowed, reason: result.reason, code: result.code, inspection: result.inspection, receipt: { ...receipt, signature: `${receipt.signature.slice(0, 14)}…` } }); }
    if (req.method === 'POST' && url.pathname === '/mcp/audit') { const request = await body(req); if (request.method !== 'contextseal.audit') return json(res, 400, { error: 'read-only-audit-method-required' }); return json(res, 200, { jsonrpc: '2.0', result: { service: 'context-seal', capabilities: DEMO_CAPABILITIES.length, receipts: receipts.map(({ receipt }) => receipt), policy: 'deny-by-default' }, id: request.id ?? 1 }); }
    if (req.method === 'GET') return staticFile(res, url.pathname);
    return json(res, 405, { error: 'method-not-allowed' });
  } catch (error) { return json(res, error.message === 'payload-too-large' ? 413 : 400, { error: 'invalid-request', detail: error.message }); }
});
server.requestTimeout = 15_000;
server.headersTimeout = 10_000;
server.listen(port, () => console.log(`ContextSeal listening on http://localhost:${port}${requireAuth ? ' (auth required)' : ' (demo mode)'}`));
process.on('SIGTERM', () => server.close());
