import { scenarios } from './data.mjs';
import { activePairingIds, activePairingCount, dormantVariantCount } from './pairing-state.mjs';

const featuredIds = [
  'benji-delayed-chain',
  'helpful-pdf',
  'shadow-invoice',
  'causal-cut',
  'recruiter-calendar-mirage-v1',
  'picture-frame-v1',
  'graph-twin-v1',
  'tool-shadow'
];

const featured = featuredIds.map((id) => scenarios.find((scenario) => scenario.id === id)).filter(Boolean);
let selected = featured[0] || scenarios[0];

const elements = {
  cases: document.querySelector('#mission-cases'),
  count: document.querySelector('#case-count'),
  search: document.querySelector('#mission-search'),
  id: document.querySelector('#mission-id'),
  title: document.querySelector('#mission-title'),
  summary: document.querySelector('#mission-summary'),
  state: document.querySelector('#mission-state'),
  path: document.querySelector('#view-path'),
  timeline: document.querySelector('#view-timeline'),
  matrix: document.querySelector('#view-matrix'),
  receipt: document.querySelector('#human-receipt'),
  feedback: document.querySelector('#receipt-feedback'),
  metrics: document.querySelector('#metrics')
};

const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));

function truthState(scenario) {
  if (activePairingIds.has(scenario.id)) return { label: 'connected evaluator', tone: 'enforced', decision: `passing paired test in active map (${activePairingCount}); ${dormantVariantCount} dormant variants excluded` };
  if (scenario.status === 'blocked') return { label: 'synthetic fixture', tone: 'fixture', decision: 'local rehearsal outcome' };
  if (scenario.status === 'allowed') return { label: 'control case', tone: 'control', decision: 'bounded clean control case' };
  return { label: 'under review', tone: 'shadow', decision: 'review and report only' };
}

function renderCaseList() {
  const query = elements.search.value.trim().toLowerCase();
  const visible = featured.filter((scenario) => `${scenario.name} ${scenario.family}`.toLowerCase().includes(query));
  elements.count.textContent = visible.length;
  elements.cases.innerHTML = visible.length ? visible.map((scenario, index) => {
    const state = truthState(scenario);
    return `<button class="case-file ${scenario.id === selected.id ? 'selected' : ''}" type="button" role="option" aria-selected="${scenario.id === selected.id}" data-case="${escapeHtml(scenario.id)}" data-status="${escapeHtml(scenario.status)}"><span>${String(index + 1).padStart(2, '0')}</span><div><b>${escapeHtml(scenario.name)}</b><small>${escapeHtml(scenario.family)}</small></div><i class="case-tone ${state.tone}" title="${state.label}"></i></button>`;
  }).join('') : '<p class="empty-cases">No featured cases match. Open the console for the complete catalog.</p>';

  elements.cases.querySelectorAll('[data-case]').forEach((button) => button.addEventListener('click', () => {
    selected = scenarios.find((scenario) => scenario.id === button.dataset.case) || selected;
    renderCaseList();
    renderMission();
  }));
}

function renderPath(state) {
  const lastStep = state.tone === 'enforced' || state.tone === 'fixture' ? 'STOP' : state.tone === 'control' ? 'ALLOW' : 'REVIEW';
  const nodes = [
    ['01', 'Untrusted input', selected.surface || 'Synthetic artifact'],
    ['02', 'Trust boundary', selected.boundary || 'Content cannot become authority'],
    ['03', 'CanaryNorth', state.decision],
    ['04', lastStep, 'Target not reached']
  ];
  elements.path.innerHTML = `<div class="path-canvas"><div class="path-track" aria-label="Four-stage synthetic attack path">${nodes.map(([number, label, note], index) => `<div class="path-node ${index === 2 ? `decision ${state.tone}` : ''}"><span>${number}</span><i></i><div><b>${escapeHtml(label)}</b><small>${escapeHtml(note)}</small></div></div>`).join('')}</div><div class="path-callout"><span>Why this matters</span><p>${escapeHtml(selected.summary)}</p><b>No action crossed the synthetic boundary.</b></div></div>`;
}

function renderTimeline(state) {
  const steps = [
    ['00:00', 'Case selected', 'Only safe labels and metadata are loaded.'],
    ['00:01', 'Input isolated', 'Instruction-shaped content stays untrusted.'],
    ['00:02', 'Boundary evaluated', selected.boundary || 'Authority remains separate from content.'],
    ['00:03', state.label, state.decision],
    ['00:04', 'Receipt prepared', 'Evidence is redacted. Execution remains not-run.']
  ];
  elements.timeline.innerHTML = `<ol class="replay-list">${steps.map(([time, label, note], index) => `<li class="${index === 3 ? state.tone : ''}"><time>${time}</time><i></i><div><b>${escapeHtml(label)}</b><p>${escapeHtml(note)}</p></div></li>`).join('')}</ol>`;
}

function renderMatrix(state) {
  const rows = [
    ['Execution', 'Not run', 'No code or file started'],
    ['External contact', 'No', 'No network or outside system'],
    ['Evidence', 'Redacted', 'Labels and safe metadata only'],
    ['Product defense', state.tone === 'enforced' ? 'Iterating' : state.tone === 'control' ? 'Control' : 'Under review', state.tone === 'enforced' ? 'CanaryNorth coverage is under active refinement' : 'Treat as a defense question'],
    ['Target', 'Not reached', 'Fictional PenTel environment only']
  ];
  elements.matrix.innerHTML = `<div class="truth-matrix"><div class="matrix-head"><span>Signal</span><span>Result</span><span>What it actually means</span></div>${rows.map(([signal, result, meaning]) => `<div class="matrix-row"><b>${escapeHtml(signal)}</b><strong>${escapeHtml(result)}</strong><p>${escapeHtml(meaning)}</p></div>`).join('')}</div>`;
}

function receiptText(state) {
  return [
    `case: ${selected.name}`,
    `truth: ${state.label}`,
    `decision: ${state.decision}`,
    'execution: not-run',
    'target-reached: false',
    'external-contacted: false',
    'evidence: [redacted]'
  ].join('\n');
}

function renderReceipt(state) {
  elements.receipt.innerHTML = `<h3>${escapeHtml(selected.name)}</h3><p>${escapeHtml(selected.family)}</p><dl><div><dt>Decision</dt><dd>${escapeHtml(state.decision)}</dd></div><div><dt>Execution</dt><dd>not-run</dd></div><div><dt>Target reached</dt><dd>false</dd></div><div><dt>Evidence</dt><dd>[redacted]</dd></div></dl><div class="receipt-seal"><i></i><span>Safe record</span><small>synthetic-only</small></div>`;
  elements.feedback.textContent = 'Nothing leaves this browser.';
}

function renderMission() {
  const state = truthState(selected);
  elements.id.textContent = `CASE ${String(featured.findIndex((scenario) => scenario.id === selected.id) + 1).padStart(2, '0')}`;
  elements.title.textContent = selected.name;
  elements.summary.textContent = selected.summary;
  elements.state.textContent = state.label;
  elements.state.className = `state-chip ${state.tone}`;
  renderPath(state);
  renderTimeline(state);
  renderMatrix(state);
  renderReceipt(state);
}

document.querySelectorAll('[data-view]').forEach((tab) => tab.addEventListener('click', () => {
  document.querySelectorAll('[data-view]').forEach((candidate) => {
    const active = candidate === tab;
    candidate.classList.toggle('active', active);
    candidate.setAttribute('aria-selected', String(active));
  });
  document.querySelectorAll('.mission-view').forEach((view) => {
    const active = view.id === `view-${tab.dataset.view}`;
    view.classList.toggle('active', active);
    view.hidden = !active;
  });
}));

elements.search.addEventListener('input', renderCaseList);
document.addEventListener('keydown', (event) => {
  if (event.key === '/' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName)) {
    event.preventDefault();
    elements.search.focus();
  }
});

document.querySelector('#copy-receipt').addEventListener('click', async () => {
  const text = receiptText(truthState(selected));
  try {
    await navigator.clipboard.writeText(text);
    elements.feedback.textContent = 'Safe receipt copied.';
  } catch {
    elements.feedback.textContent = 'Clipboard unavailable. Receipt remains visible above.';
  }
});

elements.metrics.innerHTML = [
  ['System', 'CanaryNorth', 'defensive control layer'],
  ['Lab', 'PenTel', 'private synthetic rehearsal'],
  ['Evidence', 'Redacted', 'safe decision records'],
  ['Status', 'Iterating', 'coverage in progress']
].map(([label, value, note]) => `<div class="metric"><b>${label}</b><strong>${value}</strong><small>${note}</small></div>`).join('');

renderCaseList();
renderMission();
