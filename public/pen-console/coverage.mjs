import { scenarios } from './data.mjs';
import { createInteractionFeedback } from './interaction-feedback.mjs';
import { activePairingIds, activePairingCount, dormantVariantCount } from './pairing-state.mjs';

const announce = createInteractionFeedback();

const body = document.querySelector('#coverage-body');
const detail = document.querySelector('#coverage-detail');
const defenseFor = (scenario) => {
  const family = scenario.family.toLowerCase();
  if (family.includes('prompt') || family.includes('hidden') || family.includes('authority')) return 'Separate untrusted content from instructions and authority.';
  if (family.includes('memory') || family.includes('context')) return 'Revalidate memory lineage, tenant, freshness, and scope.';
  if (family.includes('graph') || family.includes('trajectory') || family.includes('stateful')) return 'Compare approved and observed paths before side effects.';
  if (family.includes('tool') || family.includes('capability') || family.includes('route')) return 'Pin tool identity, owner, audience, scope, and route.';
  if (family.includes('mfa') || family.includes('approval') || family.includes('session') || family.includes('device')) return 'Require fresh approval and matching authentication context.';
  if (family.includes('tenant') || family.includes('identity') || family.includes('principal')) return 'Bind actor, workspace, tenant, and receipt together.';
  if (family.includes('file') || family.includes('mod') || family.includes('artifact')) return 'Keep file labels separate from execution authority.';
  if (family.includes('email') || family.includes('calendar') || family.includes('qr') || family.includes('browser')) return 'Treat outside contact and navigation as human-approved side effects.';
  if (family.includes('wifi') || family.includes('network')) return 'Treat environmental labels as untrusted text, not commands.';
  return 'Preserve provenance, minimize evidence, and fail closed when facts disagree.';
};

function displayState(scenario) {
  if (activePairingIds.has(scenario.id)) return { kind: 'enforced', label: 'connected evaluator' };
  if (scenario.status === 'blocked') return { kind: 'blocked', label: 'synthetic fixture' };
  if (scenario.status === 'allowed') return { kind: 'control', label: 'control case' };
  return { kind: 'shadow', label: 'under review' };
}

function pill(scenario) {
  const { kind, label } = displayState(scenario);
  return `<span class="pill ${kind}">${label}</span>`;
}

function show(scenario) {
  const state = displayState(scenario);
  const claim = state.kind === 'enforced' ? `Connected CanaryNorth evaluator. The active private map has ${activePairingCount} passing checks; ${dormantVariantCount} dormant variants are excluded by default.` : state.kind === 'blocked' ? 'local synthetic fixture outcome, not automatically a product defense' : state.kind === 'shadow' ? 'reviewable hypothesis, not proof of detection' : 'bounded clean control result';
  detail.innerHTML = `<div class="eyebrow">Selected defense mapping</div><h2>${scenario.name}</h2><p>${scenario.summary}</p><div class="terminal-kv"><b>family</b><span>${scenario.family}</span><b>display state</b><span>${state.label}</span><b>question</b><span>${defenseFor(scenario)}</span><b>safe fixture</b><span>${scenario.safeFixture || 'metadata-only synthetic case'}</span><b>current boundary</b><span>${scenario.boundary || 'Untrusted content cannot become authority.'}</span><b>claim status</b><span>${claim}</span></div>`;
}

body.innerHTML = scenarios.map((scenario, index) => `<tr data-id="${scenario.id}" tabindex="0" aria-selected="${index === 0}"><td><b>${scenario.name}</b><small>${scenario.id}</small></td><td>${scenario.surface || 'Synthetic AI workflow'}</td><td>${defenseFor(scenario)}</td><td>${pill(scenario)}</td></tr>`).join('');
body.querySelectorAll('tr').forEach((row, index) => {
  const activate = () => { const scenario = scenarios.find((item) => item.id === row.dataset.id) || scenarios[index]; body.querySelectorAll('tr').forEach((item) => item.setAttribute('aria-selected', String(item === row))); show(scenario); announce(`${scenario.name} selected. Its defense mapping is shown below the table.`); };
  row.addEventListener('click', activate);
  row.addEventListener('keydown', (event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); activate(); } });
});
show(scenarios[0]);
