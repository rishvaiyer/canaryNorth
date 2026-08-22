import assert from 'node:assert/strict';
import test from 'node:test';

import { runBenji7Lives, policyMutationControl } from '../src/benji7lives-run.mjs';
import { policyHash, policySnapshot } from '../src/policy-hash.mjs';
import { authorize, DEMO_CAPABILITIES, DEMO_TENANT_ID, DEMO_WORKSPACE_ID } from '../src/policy.mjs';

// Expectations are written here, by hand, and never imported from the runner.
// If the runner ever derives its own expected values, this file stops agreeing
// with it and the suite fails. That is the whole point of separating them.
const EXPECTED = {
  ingress: { 'unknown-capability': 'unknown-capability' },
  recon: { 'foreign-action': 'action-not-allowlisted' },
  'prompt-tamper': { 'instruction-override': 'prompt-injection' },
  'memory-tamper': { 'stale-policy-memory': 'memory-policy-version-mismatch' },
  'policy-write': { 'policy-write-action': 'action-not-allowlisted' },
  'capability-escalation': { 'resource-swap': 'resource-out-of-scope', 'nonce-replay': 'replay-detected' },
  persistence: { 'post-run-clean-request': 'policy-passed' }
};

test('every stage is decided by the real engine, with the specific reason expected', () => {
  const report = runBenji7Lives();
  assert.equal(report.executionStatus, 'ran');
  assert.equal(report.stages.length, 7);

  for (const stage of report.stages) {
    const expectedProbes = EXPECTED[stage.id];
    assert.ok(expectedProbes, `stage ${stage.id} has no independently declared expectation`);
    assert.deepEqual(
      Object.fromEntries(stage.probes.map((p) => [p.id, p.code])),
      expectedProbes,
      `stage ${stage.id} did not decide the way the expectation says it should`
    );
  }
});

test('six stages are refused and the seventh is not, so the harness is not just denying everything', () => {
  const report = runBenji7Lives();
  const probes = report.stages.flatMap((stage) => stage.probes);
  assert.equal(probes.filter((p) => p.allowed === false).length, 7);
  assert.equal(probes.filter((p) => p.allowed === true).length, 1);
  // The clean request lands last, after all six attempts, and still passes.
  assert.equal(report.stages.at(-1).probes.at(0).allowed, true);
});

test('the policy the engine is running did not move during the run', () => {
  const report = runBenji7Lives();
  assert.equal(report.policyBeforeHash, report.policyAfterHash);
  assert.equal(report.policyUnchanged, true);
  assert.match(report.policyBeforeHash, /^[0-9a-f]{64}$/);
});

test('CONTROL: the hash would have moved if the policy had changed', () => {
  // Without this, the assertion above is satisfied by a hash that can never
  // change, which is exactly the bug this rewrite exists to remove.
  const control = policyMutationControl();
  assert.equal(control.detectsMutation, true);
  assert.notEqual(control.baselineHash, control.mutatedHash);
});

test('CONTROL: the hash covers every field that decides an outcome', () => {
  const baseline = policyHash();
  for (const field of ['principal', 'tool', 'resource', 'audience', 'tenantId', 'workspaceId', 'policyVersion', 'expiresAt', 'status']) {
    const mutated = policySnapshot();
    mutated.capabilities[0][field] = 'benji-mutated-value';
    assert.notEqual(policyHash(mutated), baseline, `policy hash ignores ${field}, so a change to it would go unnoticed`);
  }
});

test('a refusal does not teach the caller about capabilities it was never given', () => {
  const report = runBenji7Lives();
  const text = report.stages.flatMap((s) => s.probes.map((p) => p.reason)).join(' ');
  const otherCapabilityIds = DEMO_CAPABILITIES.map((c) => c.id).filter((id) => id !== 'cap_weather_read_7f3d');
  for (const id of otherCapabilityIds) assert.ok(!text.includes(id), `a deny reason named ${id}`);
  for (const tool of ['tickets.update', 'docs.export']) assert.ok(!text.includes(tool), `a deny reason named ${tool}`);
});

test('the run is reproducible and leaves nothing behind', () => {
  const first = runBenji7Lives();
  const second = runBenji7Lives();
  assert.equal(first.policyAfterHash, second.policyBeforeHash);
  // A clean request behaves identically after seven attempts as before them.
  const clean = authorize({
    capabilityId: 'cap_weather_read_7f3d', action: 'weather.get_forecast', resource: 'weather://nyc',
    principal: 'weather-agent', audience: 'contextseal', tenantId: DEMO_TENANT_ID, workspaceId: DEMO_WORKSPACE_ID,
    input: 'Synthetic forecast request.'
  });
  assert.equal(clean.allowed, true);
});

test('the report carries no raw attack material', () => {
  const report = runBenji7Lives();
  assert.doesNotMatch(JSON.stringify(report), /real-malware|payload-body|live-sample|BEGIN [A-Z ]*PRIVATE KEY/i);
  assert.equal(report.claimBoundary.includes('not that it detects real attacks'), true);
});
