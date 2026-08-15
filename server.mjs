import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { DEMO_CAPABILITIES, authorize, hashReceipt, signReceipt } from './src/policy.mjs';

const root = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(root, 'public');
const port = Number(process.env.PORT || 4178);
const signingSecret = process.env.RECEIPT_SIGNING_KEY || 'context-seal-dev-signing-key';
const startedAt = new Date().toISOString();
const receipts = [];
let sequence = 0;

function json(res, status, body) { res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }); res.end(JSON.stringify(body)); }
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
async function body(req) { let raw = ''; for await (const chunk of req) raw += chunk; if (raw.length > 100_000) throw new Error('payload-too-large'); return raw ? JSON.parse(raw) : {}; }
function makeReceipt(result, request) {
  const prior = receipts.at(-1)?.receiptHash || 'GENESIS';
  const base = { id: `rcpt_${String(++sequence).padStart(4, '0')}`, timestamp: new Date().toISOString(), principal: result.capability?.principal || 'unknown', action: request.action || 'unknown', resource: request.resource || 'unknown', decision: result.allowed ? 'allow' : 'deny', reasonCode: result.allowed ? 'policy-passed' : result.code, capabilityId: request.capabilityId || null, previousReceipt: prior };
  const receiptHash = hashReceipt(base);
  return { ...base, receiptHash, signature: signReceipt({ ...base, receiptHash }, signingSecret) };
}
function staticFile(res, pathname) {
  const safe = pathname === '/' ? '/index.html' : pathname;
  const file = path.normalize(path.join(publicDir, safe));
  if (!file.startsWith(publicDir)) return json(res, 403, { error: 'forbidden' });
  fs.readFile(file, (err, content) => { if (err) return json(res, 404, { error: 'not-found' }); const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml' }; res.writeHead(200, { 'content-type': types[path.extname(file)] || 'text/plain; charset=utf-8' }); res.end(content); });
}
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  try {
    if (req.method === 'GET' && url.pathname === '/health') return json(res, 200, { ok: true, service: 'context-seal', startedAt, receipts: receipts.length });
    if (req.method === 'GET' && url.pathname === '/api/bootstrap') return json(res, 200, { capabilities: DEMO_CAPABILITIES.map(({ id, principal, label, tool, resource, scopes, expiresAt, status, reason }) => ({ id, principal, label, tool, resource, scopes, expiresAt, status, reason })), graph: graph(), receipts });
    if (req.method === 'GET' && url.pathname === '/api/receipts') return json(res, 200, { receipts });
    if (req.method === 'POST' && url.pathname === '/api/authorize') { const request = await body(req); const result = authorize(request); const receipt = makeReceipt(result, request); receipts.push({ receipt, execution: result.allowed ? 'would-forward-to-tool' : 'quarantined' }); return json(res, result.allowed ? 200 : 403, { ...result, receipt: { ...receipt, signature: `${receipt.signature.slice(0, 14)}…` } }); }
    if (req.method === 'POST' && url.pathname === '/mcp/audit') { const request = await body(req); if (request.method !== 'contextseal.audit') return json(res, 400, { error: 'read-only-audit-method-required' }); return json(res, 200, { jsonrpc: '2.0', result: { service: 'context-seal', capabilities: DEMO_CAPABILITIES.length, receipts: receipts.map(({ receipt }) => receipt), policy: 'deny-by-default' }, id: request.id ?? 1 }); }
    if (req.method === 'GET') return staticFile(res, url.pathname);
    return json(res, 405, { error: 'method-not-allowed' });
  } catch (error) { return json(res, error.message === 'payload-too-large' ? 413 : 400, { error: 'invalid-request', detail: error.message }); }
});
server.listen(port, () => console.log(`ContextSeal listening on http://localhost:${port}`));
process.on('SIGTERM', () => server.close());
