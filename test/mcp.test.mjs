import test from 'node:test';
import assert from 'node:assert/strict';
import { createMcpHandler, MCP_PROTOCOL_VERSION } from '../src/mcp.mjs';

function handlerFor(callTool = async () => ({ content: [{ type: 'text', text: 'ok' }] })) {
  return createMcpHandler({ callTool });
}

test('MCP initialize negotiates the supported protocol and tool capability', async () => {
  const result = await handlerFor()({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: MCP_PROTOCOL_VERSION } });
  assert.equal(result.result.protocolVersion, MCP_PROTOCOL_VERSION);
  assert.deepEqual(result.result.capabilities, { tools: { listChanged: false } });
  assert.equal(result.result.serverInfo.name, 'canarynorth-mcp-gateway');
});

test('MCP initialize rejects an unsupported protocol version', async () => {
  const result = await handlerFor()({ jsonrpc: '2.0', id: 'init', method: 'initialize', params: { protocolVersion: '1999-01-01' } });
  assert.equal(result.error.code, -32602);
  assert.deepEqual(result.error.data.supported, [MCP_PROTOCOL_VERSION]);
});

test('MCP tools/list exposes the synthetic guarded forecast tool', async () => {
  const result = await handlerFor()({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
  assert.equal(result.result.tools[0].name, 'weather.get_forecast');
  assert.deepEqual(result.result.tools[0].inputSchema.required, ['capabilityId', 'resource', 'input', 'nonce']);
});

test('MCP tools/call forwards the tool name and arguments to the policy adapter', async () => {
  let received;
  const handler = handlerFor(async (call) => {
    received = call;
    return { content: [{ type: 'text', text: 'synthetic result' }], structuredContent: { allowed: true } };
  });
  const result = await handler({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'weather.get_forecast', arguments: { capabilityId: 'cap_weather_read_7f3d' } } });
  assert.equal(received.name, 'weather.get_forecast');
  assert.deepEqual(received.arguments, { capabilityId: 'cap_weather_read_7f3d' });
  assert.deepEqual(result.result.structuredContent, { allowed: true });
});

test('MCP tool denials remain tool results and preserve the receipt-shaped explanation', async () => {
  const handler = handlerFor(async () => ({ isError: true, content: [{ type: 'text', text: '{"allowed":false,"code":"prompt-injection"}' }], structuredContent: { allowed: false, code: 'prompt-injection' } }));
  const result = await handler({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'weather.get_forecast', arguments: {} } });
  assert.equal(result.result.isError, true);
  assert.equal(result.result.structuredContent.code, 'prompt-injection');
});

test('unknown MCP tool errors map to invalid-params', async () => {
  const handler = handlerFor(async () => {
    const error = new Error('unknown tool');
    error.code = 'mcp-tool-not-found';
    throw error;
  });
  const result = await handler({ jsonrpc: '2.0', id: 4.5, method: 'tools/call', params: { name: 'unknown.tool', arguments: {} } });
  assert.equal(result.error.code, -32602);
  assert.equal(result.error.data.code, 'mcp-tool-not-found');
});

test('MCP notifications do not produce a response', async () => {
  const result = await handlerFor()({ jsonrpc: '2.0', method: 'notifications/initialized' });
  assert.equal(result, null);
});

test('unknown MCP methods return a JSON-RPC method error', async () => {
  const result = await handlerFor()({ jsonrpc: '2.0', id: 5, method: 'resources/list', params: {} });
  assert.equal(result.error.code, -32601);
});
