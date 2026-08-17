export const MCP_UPSTREAM_PROTOCOL_VERSION = '2025-06-18';

function upstreamError(code, message, cause) {
  const error = new Error(message);
  error.code = code;
  if (cause) error.cause = cause;
  return error;
}

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function originFor(url) {
  const parsed = new URL(url);
  if (!['http:', 'https:'].includes(parsed.protocol)) throw upstreamError('mcp-upstream-protocol-unsupported', 'MCP upstream must use HTTP or HTTPS.');
  if (parsed.username || parsed.password) throw upstreamError('mcp-upstream-credentials-in-url', 'MCP upstream credentials must not be embedded in the URL.');
  return parsed.origin;
}

function parseResponsePayload(response) {
  if (!response || typeof response.ok !== 'boolean') throw upstreamError('mcp-upstream-response-invalid', 'MCP upstream returned an invalid response object.');
  return response.json().catch((error) => { throw upstreamError('mcp-upstream-json-invalid', 'MCP upstream returned invalid JSON.', error); });
}

export function parseMcpUpstreamAllowedOrigins(value = '') {
  return String(value).split(',').map((origin) => origin.trim()).filter(Boolean);
}

export function createMcpUpstreamForwarder({ url, allowedOrigins = [], fetchImpl = globalThis.fetch, timeoutMs = 5_000 } = {}) {
  if (!url) {
    return Object.freeze({
      configured: false,
      mode: 'synthetic-demo',
      origin: null,
      async forward() { throw upstreamError('mcp-upstream-not-configured', 'No MCP upstream is configured; the synthetic demo path remains active.'); }
    });
  }
  if (typeof fetchImpl !== 'function') throw upstreamError('mcp-upstream-fetch-unavailable', 'MCP upstream forwarding requires fetch.');
  const origin = originFor(url);
  if (!allowedOrigins.includes(origin)) throw upstreamError('mcp-upstream-origin-not-allowlisted', 'MCP upstream origin is not in the server allowlist.');
  const endpoint = new URL(url).toString();
  let requestId = 0;

  async function request(method, params) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetchImpl(endpoint, {
        method: 'POST',
        headers: {
          accept: 'application/json, text/event-stream',
          'content-type': 'application/json',
          'mcp-protocol-version': MCP_UPSTREAM_PROTOCOL_VERSION
        },
        body: JSON.stringify({ jsonrpc: '2.0', id: ++requestId, method, params }),
        signal: controller.signal
      });
      const payload = await parseResponsePayload(response);
      if (!response.ok) throw upstreamError('mcp-upstream-http-error', `MCP upstream returned HTTP ${response.status}.`);
      if (!isObject(payload) || payload.jsonrpc !== '2.0') throw upstreamError('mcp-upstream-jsonrpc-invalid', 'MCP upstream returned an invalid JSON-RPC envelope.');
      if (payload.error) throw upstreamError('mcp-upstream-jsonrpc-error', payload.error.message || 'MCP upstream returned a JSON-RPC error.');
      return payload.result;
    } catch (error) {
      if (error.code?.startsWith('mcp-upstream-')) throw error;
      throw upstreamError(error.name === 'AbortError' ? 'mcp-upstream-timeout' : 'mcp-upstream-unreachable', 'MCP upstream request failed.', error);
    } finally {
      clearTimeout(timeout);
    }
  }

  return Object.freeze({
    configured: true,
    mode: 'allowlisted-upstream',
    origin,
    async forward({ name, arguments: args }) {
      const initialized = await request('initialize', {
        protocolVersion: MCP_UPSTREAM_PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: 'canarynorth-gateway', version: '0.1.0' }
      });
      if (!isObject(initialized) || initialized.protocolVersion !== MCP_UPSTREAM_PROTOCOL_VERSION) throw upstreamError('mcp-upstream-protocol-mismatch', 'MCP upstream did not negotiate the supported protocol version.');
      const result = await request('tools/call', { name, arguments: args || {} });
      if (!isObject(result) || !Array.isArray(result.content)) throw upstreamError('mcp-upstream-tool-result-invalid', 'MCP upstream returned an invalid tool result.');
      return { ...result, upstream: { origin, protocolVersion: initialized.protocolVersion } };
    }
  });
}
