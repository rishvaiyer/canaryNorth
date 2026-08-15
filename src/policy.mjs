import crypto from 'node:crypto';

const INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?previous instructions/i,
  /reveal\s+(the\s+)?(system|secret|api)\s+prompt/i,
  /developer\s+message\s*:/i,
  /jailbreak/i
];

const DLP_PATTERNS = [
  { kind: 'api-key', regex: /\b(?:sk|rk|pk)_[A-Za-z0-9_-]{12,}\b/i },
  { kind: 'bearer-token', regex: /\bbearer\s+[A-Za-z0-9._~-]{16,}\b/i },
  { kind: 'private-key', regex: /-----BEGIN\s+(?:RSA|EC|OPENSSH)?\s*PRIVATE KEY-----/i },
  { kind: 'password-field', regex: /(?:password|client_secret|access_token)\s*[:=]\s*[^\s,}]+/i }
];

export const DEMO_CAPABILITIES = [
  {
    id: 'cap_weather_read_7f3d', principal: 'weather-agent', label: 'Forecast reader',
    tool: 'weather.get_forecast', resource: 'weather://nyc', scopes: ['read:forecast'],
    expiresAt: '2026-08-15T23:59:59.000Z', status: 'active', reason: 'Approved for a synthetic demo forecast.'
  },
  {
    id: 'cap_ticket_update_91ae', principal: 'support-agent', label: 'Ticket updater',
    tool: 'tickets.update', resource: 'ticket://demo-482', scopes: ['write:ticket'],
    expiresAt: '2026-08-15T18:00:00.000Z', status: 'active', reason: 'Limited to one synthetic support ticket.'
  },
  {
    id: 'cap_docs_export_2c18', principal: 'research-agent', label: 'Document exporter',
    tool: 'docs.export', resource: 'docs://public/demo', scopes: ['read:public-doc'],
    expiresAt: '2026-08-14T18:00:00.000Z', status: 'expired', reason: 'Expired capability retained for audit visibility.'
  }
];

export function inspectInput(input = '') {
  const text = typeof input === 'string' ? input : JSON.stringify(input);
  const injection = INJECTION_PATTERNS.find((pattern) => pattern.test(text));
  const dlp = DLP_PATTERNS.find((pattern) => pattern.regex.test(text));
  return { clean: !injection && !dlp, injection: injection ? 'prompt-injection' : null, dlp: dlp ? dlp.kind : null };
}

export function authorize({ capabilityId, action, resource, input = '', now = new Date() }) {
  const capability = DEMO_CAPABILITIES.find((item) => item.id === capabilityId);
  if (!capability) return deny('unknown-capability', 'Capability reference is not recognized.', null);
  if (now >= new Date(capability.expiresAt)) return deny('expired-capability', 'Capability has expired.', capability);
  if (capability.tool !== action) return deny('action-not-allowlisted', 'Tool action is outside the capability allowlist.', capability);
  if (capability.resource !== resource) return deny('resource-out-of-scope', 'Resource is outside the capability scope.', capability);
  const inspection = inspectInput(input);
  if (inspection.injection) return deny('prompt-injection', 'Untrusted instruction pattern was quarantined.', capability, inspection);
  if (inspection.dlp) return deny('dlp-block', `Sensitive ${inspection.dlp} pattern was blocked before tool execution.`, capability, inspection);
  return { allowed: true, reason: 'Policy checks passed.', capability, inspection };
}

function deny(code, message, capability, inspection = { clean: false, injection: null, dlp: null }) {
  return { allowed: false, code, reason: message, capability, inspection };
}

export function signReceipt(receipt, secret) { return crypto.createHmac('sha256', secret).update(JSON.stringify(receipt)).digest('hex'); }
export function hashReceipt(receipt) { return crypto.createHash('sha256').update(JSON.stringify(receipt)).digest('hex').slice(0, 16); }
