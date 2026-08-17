export const MCP_PROTOCOL_VERSION = '2025-06-18';

export const MCP_SERVER_INFO = Object.freeze({
  name: 'canarynorth-mcp-gateway',
  version: '0.1.0'
});

export const MCP_TOOLS = Object.freeze([
  Object.freeze({
    name: 'weather.get_forecast',
    description: 'Return a synthetic forecast after CanaryNorth policy checks. No external weather service is called.',
    inputSchema: Object.freeze({
      type: 'object',
      additionalProperties: false,
      properties: Object.freeze({
        capabilityId: { type: 'string', description: 'Opaque capability reference resolved by the policy boundary.' },
        resource: { type: 'string', description: 'Exact resource named by the capability, for example weather://nyc.' },
        input: { type: 'string', description: 'Synthetic request text checked for policy and content signals.' },
        nonce: { type: 'string', description: 'One-time request nonce used for replay protection.' },
        principal: { type: 'string', description: 'Workload principal. Required outside synthetic demo mode.' },
        audience: { type: 'string', description: 'Intended service audience. Required outside synthetic demo mode.' },
        tenantId: { type: 'string', description: 'Tenant scope. Required outside synthetic demo mode.' },
        workspaceId: { type: 'string', description: 'Workspace scope. Required outside synthetic demo mode.' },
        policyVersion: { type: 'string', description: 'Policy version bound to the capability.' }
      }),
      required: ['capabilityId', 'resource', 'input', 'nonce']
    })
  })
]);

function response(id, result) {
  return { jsonrpc: '2.0', id, result };
}

function errorResponse(id, code, message, data) {
  return { jsonrpc: '2.0', id, error: { code, message, ...(data === undefined ? {} : { data }) } };
}

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function requestId(message) {
  return Object.prototype.hasOwnProperty.call(message, 'id') ? message.id : null;
}

function validRequestId(id) {
  return id === null || typeof id === 'string' || typeof id === 'number';
}

export function createMcpHandler({ callTool, tools = MCP_TOOLS, serverInfo = MCP_SERVER_INFO, protocolVersion = MCP_PROTOCOL_VERSION } = {}) {
  if (typeof callTool !== 'function') throw new Error('mcp-call-tool-required');

  return async function handleMcpMessage(message, context = {}) {
    const hasId = isObject(message) && Object.prototype.hasOwnProperty.call(message, 'id');
    if (!isObject(message) || message.jsonrpc !== '2.0' || typeof message.method !== 'string' || (hasId && !validRequestId(message.id))) {
      return errorResponse(null, -32600, 'Invalid JSON-RPC request.');
    }

    const id = requestId(message);
    const notification = !Object.prototype.hasOwnProperty.call(message, 'id');
    const params = message.params === undefined ? {} : message.params;
    if (!isObject(params)) return notification ? null : errorResponse(id, -32602, 'Request params must be an object.');

    if (message.method === 'notifications/initialized') return null;
    if (message.method === 'ping') return notification ? null : response(id, {});

    if (message.method === 'initialize') {
      if (params.protocolVersion !== undefined && params.protocolVersion !== protocolVersion) {
        return notification ? null : errorResponse(id, -32602, 'Unsupported MCP protocol version.', { supported: [protocolVersion] });
      }
      return notification ? null : response(id, {
        protocolVersion,
        capabilities: { tools: { listChanged: false } },
        serverInfo,
        instructions: 'All tool calls pass through CanaryNorth policy checks and produce a receipt. The weather tool is synthetic only.'
      });
    }

    if (message.method === 'tools/list') {
      if (params.cursor !== undefined) return notification ? null : errorResponse(id, -32602, 'Pagination is not implemented for the synthetic tool catalog.');
      return notification ? null : response(id, { tools });
    }

    if (message.method === 'tools/call') {
      if (typeof params.name !== 'string' || params.name.length < 1 || params.name.length > 128) {
        return notification ? null : errorResponse(id, -32602, 'Tool name is required.');
      }
      if (params.arguments !== undefined && !isObject(params.arguments)) {
        return notification ? null : errorResponse(id, -32602, 'Tool arguments must be an object.');
      }
      if (notification) {
        await callTool({ name: params.name, arguments: params.arguments || {}, context });
        return null;
      }
      try {
        const result = await callTool({ name: params.name, arguments: params.arguments || {}, context });
        if (!isObject(result) || !Array.isArray(result.content)) throw new Error('mcp-tool-result-invalid');
        return response(id, result);
      } catch (toolError) {
        const code = ['mcp-invalid-params', 'mcp-tool-not-found', 'mcp-scope-binding-required'].includes(toolError.code) ? -32602 : -32603;
        return errorResponse(id, code, code === -32602 ? 'Invalid MCP tool arguments.' : 'MCP tool call failed.', { code: toolError.code || 'mcp-tool-failed' });
      }
    }

    return notification ? null : errorResponse(id, -32601, `Method not found: ${message.method}`);
  };
}
