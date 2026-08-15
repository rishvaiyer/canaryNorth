export const DEFAULT_POSITIONS = Object.freeze({ agent: [145, 300], proxy: [420, 300], weather: [735, 205], tickets: [735, 410], vault: [420, 95], ledger: [735, 510] });
export const NODE_DETAILS = Object.freeze({
  agent: { type: 'agent', typeLabel: 'SOURCE', title: 'Agent context', what: 'This is the AI request. It carries an opaque capability reference, not a provider password or API key.', security: 'The model can request an action, but it cannot read the vault or widen its own permissions.' },
  proxy: { type: 'proxy', typeLabel: 'BOUNDARY', title: 'ContextSeal policy proxy', what: 'This is the checkpoint. It checks identity, expiry, action, resource, and content before anything could be forwarded.', security: 'Default deny: a request needs every check to pass. Failed input is quarantined here.' },
  weather: { type: 'tool', typeLabel: 'TOOL', title: 'weather.get_forecast', what: 'A synthetic weather tool that could receive an approved forecast request. It never sees a blocked request.', security: 'Allowlisted only for weather://nyc through the forecast capability.' },
  tickets: { type: 'tool', typeLabel: 'TOOL', title: 'tickets.update', what: 'A separate synthetic tool with a different capability. It demonstrates that one permission does not unlock every tool.', security: 'Scoped to one demo ticket and write:ticket; the weather capability cannot reach it.' },
  vault: { type: 'vault', typeLabel: 'SECRET STORE', title: 'Secret vault', what: 'Provider credentials live here on the server. The proxy can look them up after policy passes, but the agent never receives them.', security: 'Never serialized into model context, receipts, or the public demo payload.' },
  ledger: { type: 'ledger', typeLabel: 'EVIDENCE', title: 'Signed receipt ledger', what: 'Each decision leaves a small receipt with a hash and a link to the previous receipt.', security: 'A tamper-evident chain makes silent edits detectable. This demo ledger is in memory and resets on restart.' }
});
export function clampPosition([x, y]) { return [Math.max(52, Math.min(948, Number(x))), Math.max(52, Math.min(508, Number(y)))]; }
export function demoPath(step, allowed = true) {
  const allowedSteps = [['agent', 'proxy'], ['proxy', 'weather'], ['proxy', 'ledger']];
  const deniedSteps = [['agent', 'proxy'], ['proxy'], ['proxy', 'ledger']];
  return (allowed ? allowedSteps : deniedSteps)[step] || [];
}
