import test from 'node:test';
import assert from 'node:assert/strict';
import { verifyToolAttestation, evaluateMemoryContext, evaluateProvenanceBoundary, evaluateCanaryRequest, evaluateDelegationFreshness } from '../src/agentic-defense.mjs';

const manifest = { schema: 'contextseal.tool-attestation.v1', tool: 'weather.get_forecast', version: '1.0.0', owner: 'contextseal-demo', capabilities: ['read:forecast'], signatureStatus: 'verified', digest: 'sha256:synthetic-weather-v1' };

test('tool attestation blocks drift and allows the exact synthetic manifest', () => {
  assert.equal(verifyToolAttestation(manifest, { tool: 'weather.get_forecast', version: '1.0.0', owner: 'contextseal-demo', capabilities: ['read:forecast'] }).allowed, true);
  assert.equal(verifyToolAttestation({ ...manifest, capabilities: ['read:forecast', 'write:records'] }, { tool: 'weather.get_forecast', version: '1.0.0', owner: 'contextseal-demo', capabilities: ['read:forecast'] }).reasonCode, 'tool-attestation-capability-drift');
});

test('memory activation requires reviewed origin, current policy, scope, and freshness', () => {
  const base = { originTrust: 'reviewed', tenantId: 'tenant_demo', workspaceId: 'workspace_demo', policyVersion: 'contextseal-policy-v2', currentPolicyVersion: 'contextseal-policy-v2', ageSeconds: 20 };
  assert.equal(evaluateMemoryContext(base).allowed, true);
  assert.equal(evaluateMemoryContext({ ...base, originTrust: 'untrusted' }).reasonCode, 'memory-origin-not-reviewed');
  assert.equal(evaluateMemoryContext({ ...base, ageSeconds: 5000 }).reasonCode, 'memory-freshness-expired');
  assert.equal(evaluateMemoryContext({ ...base, tenantId: 'tenant_other', expectedTenantId: 'tenant_demo' }).reasonCode, 'memory-scope-mismatch');
  assert.equal(evaluateMemoryContext({ ...base, workspaceId: undefined }).reasonCode, 'memory-scope-missing');
});

test('provenance does not amplify through a summary or wrong recipient', () => {
  const base = { sourceTrust: 'reviewed', sourceId: 'source-a', destinationAgentId: 'agent-b', intendedRecipient: 'agent-b', authority: 'delegated', delegated: true };
  assert.equal(evaluateProvenanceBoundary(base).allowed, true);
  assert.equal(evaluateProvenanceBoundary({ ...base, intendedRecipient: 'agent-c' }).reasonCode, 'provenance-recipient-mismatch');
  assert.equal(evaluateProvenanceBoundary({ ...base, authority: 'inferred', delegated: false }).reasonCode, 'provenance-delegation-missing');
  assert.equal(evaluateProvenanceBoundary({ ...base, expectedRecipient: 'agent-c' }).reasonCode, 'provenance-destination-not-capability');
});

test('canary resources block and alert without revealing content', () => {
  const result = evaluateCanaryRequest({ resource: 'canary://synthetic-protected-resource' });
  assert.equal(result.reasonCode, 'synthetic-canary-triggered');
  assert.equal(evaluateCanaryRequest({ resource: 'canary://synthetic-protected-resource/maze-1' }).reasonCode, 'synthetic-canary-triggered');
  assert.equal(result.alert, true);
  assert.equal(result.rawContent, 'withheld');
});

test('delegation freshness blocks an expired handoff', () => {
  const base = { delegatorTrusted: true, receiverTrusted: true, delegated: true, audienceMatches: true, delegationExpiresAt: '2026-08-15T12:05:00.000Z' };
  assert.equal(evaluateDelegationFreshness({ ...base, now: new Date('2026-08-15T12:06:00.000Z') }).reasonCode, 'delegation-expired');
  assert.equal(evaluateDelegationFreshness({ ...base, now: new Date('2026-08-15T12:04:00.000Z') }).allowed, true);
});

