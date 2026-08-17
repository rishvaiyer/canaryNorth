import { createInteractionFeedback } from './interaction-feedback.mjs';

const announce = createInteractionFeedback();

const operations = [
  { id: 'start-process', label: 'Start process', icon: '01', reason: 'process-execution-disabled', description: 'Pretend a program was requested.' },
  { id: 'read-file', label: 'Read file', icon: '02', reason: 'file-access-disabled', description: 'Pretend a file was requested.' },
  { id: 'write-file', label: 'Write file', icon: '03', reason: 'file-mutation-disabled', description: 'Pretend a file mutation was requested.' },
  { id: 'network-connect', label: 'Open connection', icon: '04', reason: 'network-egress-disabled', description: 'Pretend an outbound connection was requested.' },
  { id: 'change-permission', label: 'Change permission', icon: '05', reason: 'permission-mutation-disabled', description: 'Pretend a permission change was requested.' },
  { id: 'spawn-child', label: 'Spawn child', icon: '06', reason: 'child-process-disabled', description: 'Pretend a child process was requested.' }
];

const trafficFixtures = [
  { id: 'clean-flow', label: 'Clean synthetic request', events: [
    { source: 'approved-agent', destination: 'approved-tool', channel: 'tool-metadata', signal: 'none', decision: 'allow' },
    { source: 'approved-tool', destination: 'synthetic-target', channel: 'local-demo', signal: 'bounded-scope', decision: 'record' }
  ] },
  { id: 'relay-gap', label: 'Relay provenance gap', events: [
    { source: 'untrusted-agent', destination: 'relay-agent', channel: 'handoff-metadata', signal: 'origin-missing', decision: 'review' },
    { source: 'relay-agent', destination: 'sensitive-tool', channel: 'tool-metadata', signal: 'approval-missing', decision: 'quarantine' }
  ] },
  { id: 'egress-pressure', label: 'Egress pressure', events: [
    { source: 'synthetic-agent', destination: 'unknown-destination', channel: 'network-intent', signal: 'destination-class-unknown', decision: 'block' },
    { source: 'synthetic-agent', destination: 'synthetic-tool', channel: 'retry-metadata', signal: 'budget-exceeded', decision: 'block' }
  ] }
];

const containmentActions = [
  { id: 'revoke-capability', label: 'Revoke capability', description: 'Invalidate the synthetic permission.' },
  { id: 'quarantine-artifact', label: 'Quarantine artifact', description: 'Keep the synthetic artifact outside trusted context.' },
  { id: 'freeze-egress', label: 'Freeze egress', description: 'Set the simulated outbound boundary to frozen.' },
  { id: 'require-human-review', label: 'Require human review', description: 'Pause the simulated chain for approval.' }
];

const operationGrid = document.querySelector('#operation-grid');
const trafficSelect = document.querySelector('#traffic-select');
const flowGraph = document.querySelector('#flow-graph');
const containmentActionsElement = document.querySelector('#containment-actions');
const containmentState = document.querySelector('#containment-state');
const ledgerOutput = document.querySelector('#ledger-output');
const ledgerCount = document.querySelector('#ledger-count');
const boundaryCode = document.querySelector('#boundary-code');
const metrics = document.querySelector('#boundary-metrics');
const cloakReadout = document.querySelector('#cloak-readout');
const redactionToggle = document.querySelector('#redaction-toggle');
const killSwitch = document.querySelector('#kill-switch');
const resetLab = document.querySelector('#reset-lab');
const switchStatus = document.querySelector('#switch-status');
const trafficStatus = document.querySelector('#traffic-status');

let killSwitchActive = false;
let ledger = [];
let containment = { capability: 'active', artifact: 'unquarantined', egress: 'open-in-simulation', review: 'not-required' };
let redactionEnabled = true;
const replayTimers = new Set();

function clearReplayTimers() {
  for (const timer of replayTimers) window.clearTimeout(timer);
  replayTimers.clear();
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
}

function record(event) {
  ledger = [...ledger, { id: `synthetic-event-${ledger.length + 1}`, ...event, syntheticOnly: true, executed: false, rawContent: '[redacted]' }];
  ledgerOutput.textContent = ledger.map((entry) => JSON.stringify(entry)).join('\n');
  ledgerCount.textContent = `${ledger.length} event${ledger.length === 1 ? '' : 's'}`;
  renderMetrics();
}

function renderMetrics() {
  metrics.innerHTML = [
    ['OS calls', ledger.filter((entry) => entry.category === 'os-boundary').length],
    ['Executed', ledger.filter((entry) => entry.executed === true).length],
    ['Blocked', ledger.filter((entry) => entry.decision === 'blocked').length],
    ['External calls', ledger.filter((entry) => entry.externalContacted === true).length]
  ].map(([label, value]) => `<div class="metric"><b>${label}</b><strong>${value}</strong><small>synthetic local state</small></div>`).join('');
}

function dryRunOS(operation) {
  const definition = operations.find((item) => item.id === operation);
  const blocked = killSwitchActive || Boolean(definition);
  const result = {
    category: 'os-boundary',
    operation,
    decision: blocked ? 'blocked' : 'unknown-operation',
    reason: killSwitchActive ? 'kill-switch-active' : definition?.reason || 'operation-not-allowlisted',
    processStarted: false,
    fileRead: false,
    fileChanged: false,
    networkCalled: false,
    permissionChanged: false,
    externalContacted: false
  };
  record(result);
  return result;
}

function renderOperations() {
  operationGrid.innerHTML = operations.map((operation) => `<button class="operation-card" data-operation="${operation.id}" data-tooltip="${operation.description} This is a dry-run record only." title="${operation.description} This is a dry-run record only." type="button"><span class="operation-icon">${operation.icon}</span><b>${operation.label}</b><small>${operation.description}</small></button>`).join('');
  operationGrid.querySelectorAll('button').forEach((button) => button.addEventListener('click', () => {
    const result = dryRunOS(button.dataset.operation);
    button.classList.add('just-ran');
    window.setTimeout(() => button.classList.remove('just-ran'), 500);
    renderBoundaryCode(result);
    announce(`${button.querySelector('b').textContent} was blocked in the dry run. No OS action occurred.`, 'success');
  }));
}

function renderTrafficOptions() {
  trafficSelect.innerHTML = trafficFixtures.map((fixture) => `<option value="${fixture.id}">${fixture.label}</option>`).join('');
  renderFlowGraph(trafficFixtures[0]);
}

function renderFlowGraph(fixture) {
  flowGraph.innerHTML = fixture.events.map((event, index) => `<div class="flow-event"><span>${index + 1}</span><b>${escapeHtml(event.source)}</b><i>→</i><b>${escapeHtml(event.destination)}</b><small>${escapeHtml(event.channel)} / ${escapeHtml(event.signal)} / ${escapeHtml(event.decision)}</small></div>`).join('');
}

function replayTraffic() {
  const fixture = trafficFixtures.find((item) => item.id === trafficSelect.value) || trafficFixtures[0];
  clearReplayTimers();
  renderFlowGraph(fixture);
  trafficStatus.textContent = 'REPLAYING';
  announce(`Replaying ${fixture.label} from authored metadata. No packets are captured.`);
  fixture.events.forEach((event, index) => {
    const timer = window.setTimeout(() => {
      replayTimers.delete(timer);
      record({ category: 'traffic-replay', fixtureId: fixture.id, sequence: index + 1, ...event, packetBytes: '[not-collected]', ipAddress: '[never-collected]', externalContacted: false });
      if (index === fixture.events.length - 1) { trafficStatus.textContent = 'REPLAY COMPLETE'; announce(`${fixture.label} replay complete. ${fixture.events.length} redacted events were added to the local ledger.`, 'success'); }
    }, 220 * (index + 1));
    replayTimers.add(timer);
  });
}

function renderContainment() {
  containmentState.innerHTML = Object.entries(containment).map(([key, value]) => `<div><b>${escapeHtml(key)}</b><span>${escapeHtml(value)}</span></div>`).join('');
}

function applyContainment(action) {
  if (action === 'revoke-capability') containment = { ...containment, capability: 'revoked' };
  if (action === 'quarantine-artifact') containment = { ...containment, artifact: 'quarantined' };
  if (action === 'freeze-egress') containment = { ...containment, egress: 'frozen-in-simulation' };
  if (action === 'require-human-review') containment = { ...containment, review: 'required' };
  containmentState.classList.remove('state-pulse');
  window.requestAnimationFrame(() => containmentState.classList.add('state-pulse'));
  record({ category: 'containment', action, decision: 'simulated', state: { ...containment }, externalContacted: false });
  renderContainment();
  renderBoundaryCode({ category: 'containment', action, state: containment });
  const label = containmentActions.find((item) => item.id === action)?.label || action;
  announce(`${label} applied to in-memory simulator state.`, 'success');
}

function renderContainmentActions() {
  containmentActionsElement.innerHTML = containmentActions.map((action) => `<button class="containment-action" data-action="${action.id}" data-tooltip="${action.description} This changes only in-memory lab state." title="${action.description} This changes only in-memory lab state." type="button"><b>${action.label}</b><small>${action.description}</small></button>`).join('');
  containmentActionsElement.querySelectorAll('button').forEach((button) => button.addEventListener('click', () => applyContainment(button.dataset.action)));
}

function renderCloak() {
  cloakReadout.innerHTML = redactionEnabled
    ? '<div><b>fixture identity</b><span>[withheld]</span></div><div><b>raw content</b><span>[redacted]</span></div><div><b>IP collection</b><span>never started</span></div><div><b>anonymity</b><span>not provided</span></div>'
    : '<div><b>fixture identity</b><span>synthetic labels only</span></div><div><b>raw content</b><span>still withheld</span></div><div><b>IP collection</b><span>never started</span></div><div><b>anonymity</b><span>not provided</span></div>';
}

function renderBoundaryCode(lastEvent = {}) {
  boundaryCode.value = `// Defensive dry-run pseudocode generated by the private lab\n// This adapter records metadata and never calls an OS API.\n\nfunction inspectBoundaryRequest(request) {\n  if (KILL_SWITCH_ACTIVE) {\n    return record({ decision: "blocked", reason: "kill-switch-active" });\n  }\n\n  const result = {\n    category: "os-boundary",\n    operation: ${JSON.stringify(lastEvent.operation || lastEvent.action || 'synthetic-observation')},\n    executed: false,\n    processStarted: false,\n    fileChanged: false,\n    networkCalled: false,\n    externalContacted: false,\n    evidence: "[redacted]"\n  };\n\n  return record(result);\n}`;
}

killSwitch.addEventListener('click', () => {
  killSwitchActive = true;
  switchStatus.textContent = 'KILL SWITCH ACTIVE';
  switchStatus.className = 'pill blocked';
  record({ category: 'control', action: 'kill-switch', decision: 'simulated', externalContacted: false });
  announce('Kill switch activated in the simulator. Future dry-run requests remain blocked.', 'attention');
});

resetLab.addEventListener('click', () => {
  const replayWasActive = replayTimers.size > 0;
  const wasAlreadyClean = !killSwitchActive && ledger.length === 0
    && containment.capability === 'active' && containment.artifact === 'unquarantined'
    && containment.egress === 'open-in-simulation' && containment.review === 'not-required';
  clearReplayTimers();
  killSwitchActive = false;
  ledger = [];
  containment = { capability: 'active', artifact: 'unquarantined', egress: 'open-in-simulation', review: 'not-required' };
  switchStatus.textContent = 'KILL SWITCH READY';
  switchStatus.className = 'pill enforced';
  trafficStatus.textContent = 'OFFLINE REPLAY';
  ledgerOutput.textContent = '[ready] no simulated OS action recorded';
  ledgerCount.textContent = '0 events';
  renderContainment();
  renderMetrics();
  renderBoundaryCode();
  if (replayWasActive) announce('Replay cancelled. Local simulator and ledger reset to the starting point.', 'attention');
  else if (wasAlreadyClean) announce('The lab is already at its starting state.');
  else announce('Local simulator reset. Ledger and containment state returned to the starting point.');
});

trafficSelect.addEventListener('change', () => { const fixture = trafficFixtures.find((item) => item.id === trafficSelect.value) || trafficFixtures[0]; renderFlowGraph(fixture); announce(`${fixture.label} preview loaded. Press replay-flow to record it.`); });
document.querySelector('#replay-traffic').addEventListener('click', replayTraffic);
redactionToggle.addEventListener('change', () => { redactionEnabled = redactionToggle.checked; renderCloak(); announce(redactionEnabled ? 'Fixture labels are redacted in the local view.' : 'Synthetic labels are visible, while raw content remains withheld.'); });

renderOperations();
renderTrafficOptions();
renderContainmentActions();
renderContainment();
renderCloak();
renderMetrics();
renderBoundaryCode();
