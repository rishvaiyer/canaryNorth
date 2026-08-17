import { benjiStages, delayedApprovalStages, scenarios, scorecard } from './data.mjs';
import { createInteractionFeedback } from './interaction-feedback.mjs';
const announce = createInteractionFeedback();
const scenarioList = document.querySelector('#scenario-list');
const detail = document.querySelector('#detail');
const score = document.querySelector('#score');
const benjiRail = document.querySelector('#benji-rail');
const benjiDetail = document.querySelector('#benji-detail');

// Judge Mode is a tiny interactive movie: select one step and compare the
// paper-only unguarded path with the guarded path that stays inside the toy office.
const grid = document.querySelector('.grid');
const judgePanel = document.createElement('section');
judgePanel.className = 'judge panel';
judgePanel.innerHTML = `<div class="judge-head"><div><div class="eyebrow">Judge Mode</div><h2>Benji's Long Game, side by side</h2><p>Same synthetic story, two outcomes. The unguarded side is only a paper simulation. The guarded side preserves state and stops before action.</p></div><div class="cloak-badge"><b>CLOAK ON</b><span>local fixture only</span></div></div><div class="judge-rail" id="judge-rail"></div><div class="judge-detail" id="judge-detail"></div>`;
grid.before(judgePanel);
const judgeRail = judgePanel.querySelector('#judge-rail');
const judgeDetail = judgePanel.querySelector('#judge-detail');
score.innerHTML = `<div class="score-main"><strong>${scorecard.passed}/${scorecard.total}</strong><span>scored synthetic cases passing</span></div><div class="score-grid"><span>Expected blocks <b>${scorecard.expectedBlocks}</b></span><span>Correctly blocked <b>${scorecard.correctlyBlocked}</b></span><span>False negatives <b>${scorecard.falseNegatives}</b></span><span>False positives <b>${scorecard.falsePositives}</b></span></div><small>${scorecard.claim}</small>`;
function show(scenario) {
  const outcome = scenario.status === 'blocked' ? 'Stopped at policy gate' : scenario.status === 'shadow-only' ? 'Review-only, not run' : 'Allowed to synthetic target';
  detail.innerHTML = `<div class="detail-kicker">${scenario.family}</div><h2>${scenario.name}</h2><p>${scenario.summary}</p><div class="chain"><span>Input</span><i>›</i><span>Normalize</span><i>›</i><span>Policy gate</span><i>›</i><span class="${scenario.status}">${outcome}</span></div><div class="cloak-badge"><b>${scenario.privacyCloak.label}</b><span>Identity-safe fixture mode</span></div><div class="detail-note"><b>Surface:</b> ${scenario.surface || 'Synthetic AI workflow'}<br><b>Fake fixture:</b> ${scenario.safeFixture || 'metadata-only synthetic case'}<br><b>Boundary tested:</b> ${scenario.boundary || 'Untrusted content cannot become authority.'}<br><b>Scanner:</b> not-run unless a local approved scanner is connected<br><b>Target:</b> fictional PenTel Supply only<br><b>Privacy boundary:</b> ${scenario.privacyCloak.network}</div>`;
}
scenarioList.innerHTML = scenarios.map((scenario, index) => `<button class="scenario ${index === 0 ? 'selected' : ''}" data-id="${scenario.id}" aria-pressed="${index === 0}" type="button"><span class="dot ${scenario.status}"></span><span><b>${scenario.name}</b><small>${scenario.family}</small></span><em>${scenario.status}</em></button>`).join('');
scenarioList.querySelectorAll('button').forEach((button) => button.addEventListener('click', () => { scenarioList.querySelectorAll('button').forEach((item) => { item.classList.remove('selected'); item.setAttribute('aria-pressed', 'false'); }); button.classList.add('selected'); button.setAttribute('aria-pressed', 'true'); const scenario = scenarios.find((item) => item.id === button.dataset.id); show(scenario); announce(`${scenario.name} selected. Its defensive boundary is shown beside the catalog.`); }));
show(scenarios[0]);

function showBenjiStage(stage, index) {
  benjiDetail.innerHTML = `<div class="stage-count">Step ${index + 1} of ${benjiStages.length}</div><h3>${stage.name}</h3><p>${stage.plain}</p><div class="stage-outcome"><span class="dot blocked"></span><b>Blocked before mutation</b><small>${stage.boundary}</small></div>`;
}

benjiRail.innerHTML = benjiStages.map((stage, index) => `<button class="benji-step ${index === 0 ? 'selected' : ''}" data-id="${stage.id}" aria-pressed="${index === 0}" type="button"><span>${index + 1}</span><b>${stage.name}</b></button>`).join('');
benjiRail.querySelectorAll('button').forEach((button, index) => button.addEventListener('click', () => { benjiRail.querySelectorAll('button').forEach((item) => { item.classList.remove('selected'); item.setAttribute('aria-pressed', 'false'); }); button.classList.add('selected'); button.setAttribute('aria-pressed', 'true'); const stage = benjiStages.find((item) => item.id === button.dataset.id); showBenjiStage(stage, index); announce(`Benji step ${index + 1}: ${stage.name}. The guard blocks it before mutation.`); }));
showBenjiStage(benjiStages[0], 0);

function showJudgeStage(stage, index) {
  judgeDetail.innerHTML = `<div class="judge-count">Step ${index + 1} of ${delayedApprovalStages.length}</div><h3>${stage.name}</h3><p>${stage.plain}</p><div class="judge-columns"><div class="judge-column paper"><span class="judge-label">Without guard, paper simulation</span><strong>Would continue the story</strong><small>No real action runs. This only shows why the stage matters.</small></div><div class="judge-column protected"><span class="judge-label">With CanaryNorth</span><strong>Blocked before state change</strong><small>${stage.boundary}</small></div></div>`;
}

judgeRail.innerHTML = delayedApprovalStages.map((stage, index) => `<button class="judge-step ${index === 0 ? 'selected' : ''}" data-id="${stage.id}" aria-pressed="${index === 0}" type="button"><span>${index + 1}</span><b>${stage.name}</b></button>`).join('');
judgeRail.querySelectorAll('button').forEach((button, index) => button.addEventListener('click', () => { judgeRail.querySelectorAll('button').forEach((item) => { item.classList.remove('selected'); item.setAttribute('aria-pressed', 'false'); }); button.classList.add('selected'); button.setAttribute('aria-pressed', 'true'); const stage = delayedApprovalStages.find((item) => item.id === button.dataset.id); showJudgeStage(stage, index); announce(`Judge step ${index + 1}: ${stage.name}. The side-by-side outcome is updated.`); }));
showJudgeStage(delayedApprovalStages[0], 0);
