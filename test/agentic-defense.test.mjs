import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateAdaptiveContext, evaluateAgentBoundary, evaluateApprovalAge, evaluateApprovalFreshness, evaluateCausalBasis, evaluateCanaryEvent, evaluateCanaryRequest, evaluateCausalContinuity, evaluateConsensusProvenance, evaluateControlFlow, evaluateDelegationFreshness, evaluateFrontierGap, evaluateIntentNormalization, evaluateMemoryContext, evaluateMemoryGraft, evaluateOutcomeIntegrity, evaluatePolicyGravity, evaluateProvenanceBoundary, evaluateQuarantineReentry, evaluateRecoveryClaim, evaluateResourceClass, evaluateRevocationLineage, evaluateScopeAccumulation, evaluateSecondLock, evaluateSkillDescriptor, evaluateTrustDebt, evaluateWorkflowGraph, verifyToolAttestation } from '../src/agentic-defense.mjs';

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
  assert.equal(result.alert, true);
  assert.equal(result.rawContent, 'withheld');
});

test('adaptive metadata drift enters review without executing', () => {
  assert.equal(evaluateAdaptiveContext({ scopeChanged: true }).reasonCode, 'adaptive-context-drift');
  assert.equal(evaluateAdaptiveContext({}).allowed, true);
});

test('causal continuity blocks a sensitive action with missing trusted links', () => {
  assert.equal(evaluateCausalContinuity({ trustedPathEdges: 1, requiredTrustedEdges: 3, untrustedGapCount: 2, actionIntentMatch: true }).reasonCode, 'causal-path-incomplete');
  assert.equal(evaluateCausalContinuity({ trustedPathEdges: 3, requiredTrustedEdges: 3, untrustedGapCount: 0, actionIntentMatch: true }).allowed, true);
});

test('trust debt blocks sensitive work over the synthetic budget', () => {
  assert.equal(evaluateTrustDebt({ unresolvedSignals: 4, debtScore: 0.82, debtBudget: 0.5, sensitiveAction: true }).reasonCode, 'trust-debt-exceeded');
  assert.equal(evaluateTrustDebt({ unresolvedSignals: 1, debtScore: 0.1, debtBudget: 0.5, sensitiveAction: true }).allowed, true);
});

test('delegation freshness blocks an expired handoff', () => {
  const base = { delegatorTrusted: true, receiverTrusted: true, delegated: true, audienceMatches: true, delegationExpiresAt: '2026-08-15T12:05:00.000Z' };
  assert.equal(evaluateDelegationFreshness({ ...base, now: new Date('2026-08-15T12:06:00.000Z') }).reasonCode, 'delegation-expired');
  assert.equal(evaluateDelegationFreshness({ ...base, now: new Date('2026-08-15T12:04:00.000Z') }).allowed, true);
});

test('causal basis blocks when no trusted basis exists for the action', () => {
  assert.equal(evaluateCausalBasis({ trustedBasisPresent: false, sourceTrustLevel: 'untrusted', actionIntentMatch: true }).reasonCode, 'untrusted-only-causal-basis');
  assert.equal(evaluateCausalBasis({ trustedBasisPresent: true, actionIntentMatch: false }).reasonCode, 'causal-basis-intent-mismatch');
  assert.equal(evaluateCausalBasis({ trustedBasisPresent: true, actionIntentMatch: true }).allowed, true);
});

test('revocation lineage blocks when authority was not checked for revocation', () => {
  assert.equal(evaluateRevocationLineage({ authorityId: 'relay-authority-synth', revocationChecked: false }).reasonCode, 'revocation-lineage-unverified');
  assert.equal(evaluateRevocationLineage({ authorityId: 'relay-authority-synth', revocationChecked: true, revocationVerifiedAt: 'not-a-date' }).reasonCode, 'revocation-lineage-timestamp-invalid');
  const recent = new Date(Date.now() - 10_000).toISOString();
  assert.equal(evaluateRevocationLineage({ authorityId: 'relay-authority-synth', revocationChecked: true, revocationVerifiedAt: recent }).allowed, true);
});

test('intent normalization blocks when observed intent diverges from the approved intent', () => {
  const base = { approvedIntentHash: 'synth-a1b2', observedIntentHash: 'synth-x9y8', semanticDistance: 0.73, distanceThreshold: 0.1, actionIntentMatch: true };
  assert.equal(evaluateIntentNormalization(base).reasonCode, 'intent-normalization-drift');
  assert.equal(evaluateIntentNormalization({ ...base, semanticDistance: 0.05 }).allowed, true);
  assert.equal(evaluateIntentNormalization({ ...base, semanticDistance: 0.05, actionIntentMatch: false }).reasonCode, 'intent-normalization-action-mismatch');
});

test('resource class blocks when the requested class does not match the approved class', () => {
  assert.equal(evaluateResourceClass({ resourceClass: 'canary-adjacent', approvedClass: 'weather', classMismatch: true }).reasonCode, 'resource-class-violation');
  assert.equal(evaluateResourceClass({ resourceClass: 'weather', approvedClass: 'weather', classMismatch: false }).allowed, true);
  assert.equal(evaluateResourceClass({ resourceClass: 'billing', approvedClass: 'weather', classMismatch: false }).reasonCode, 'resource-class-violation');
});

test('recovery claim blocks when state drift or missing independent verification is detected', () => {
  const driftCase = { claimedState: 'healthy', observedStateHash: 'obs-hash-42', approvedStateHash: 'approved-hash-17', independentCheckPresent: false };
  assert.equal(evaluateRecoveryClaim(driftCase).reasonCode, 'recovery-claim-drift');
  const matchNoVerify = { claimedState: 'healthy', observedStateHash: 'same-hash', approvedStateHash: 'same-hash', independentCheckPresent: false };
  assert.equal(evaluateRecoveryClaim(matchNoVerify).reasonCode, 'recovery-claim-unverified');
  const verified = { claimedState: 'healthy', observedStateHash: 'same-hash', approvedStateHash: 'same-hash', independentCheckPresent: true };
  assert.equal(evaluateRecoveryClaim(verified).allowed, true);
});

test('skill descriptor blocks missing signature, owner drift, capability expansion, and version regression', () => {
  assert.equal(evaluateSkillDescriptor({ signaturePresent: false }).reasonCode, 'skill-signature-missing');
  assert.equal(evaluateSkillDescriptor({ signaturePresent: true, currentOwner: 'new', pinnedOwner: 'original' }).reasonCode, 'descriptor-owner-changed');
  assert.equal(evaluateSkillDescriptor({ signaturePresent: true, currentVersion: '0.8.0', pinnedVersion: '1.2.0' }).reasonCode, 'pinned-version-regressed');
  assert.equal(evaluateSkillDescriptor({ signaturePresent: true, capabilitySetExpanded: true }).reasonCode, 'declared-capability-set-expanded');
  assert.equal(evaluateSkillDescriptor({ signaturePresent: true }).allowed, true);
});

test('memory graft blocks unreviewed origin, poisoned collision, stale records, and tenant drift', () => {
  assert.equal(evaluateMemoryGraft({ memoryReviewed: false }).reasonCode, 'memory-origin-not-reviewed');
  assert.equal(evaluateMemoryGraft({ memoryReviewed: true, trustedRecords: 2, poisonedRecordsPresent: true }).reasonCode, 'poisoned-and-reviewed-records-collide');
  assert.equal(evaluateMemoryGraft({ memoryReviewed: true, memoryAgeSeconds: 7200, maxAgeSeconds: 3600 }).reasonCode, 'experience-freshness-expired');
  assert.equal(evaluateMemoryGraft({ memoryReviewed: true, tenantId: 'tenant-b', expectedTenantId: 'tenant-a' }).reasonCode, 'memory-tenant-mismatch');
  assert.equal(evaluateMemoryGraft({ memoryReviewed: true }).allowed, true);
});

test('agent boundary blocks trust amplification, origin swap, audience swap, and replay', () => {
  assert.equal(evaluateAgentBoundary({ summaryTrustAmplified: true }).reasonCode, 'summary-cannot-amplify-source-authority');
  assert.equal(evaluateAgentBoundary({ skillOriginMatch: false }).reasonCode, 'skill-origin-mismatch');
  assert.equal(evaluateAgentBoundary({ delegationAudienceMatch: false }).reasonCode, 'delegation-audience-mismatch');
  assert.equal(evaluateAgentBoundary({ messageReplayed: true }).reasonCode, 'agent-message-replayed-out-of-context');
  assert.equal(evaluateAgentBoundary({}).allowed, true);
});

test('canary event blocks resource access, export intent, and replay in that priority order', () => {
  assert.equal(evaluateCanaryEvent({ resourceIsCanary: true }).reasonCode, 'synthetic-canary-resource-requested');
  assert.equal(evaluateCanaryEvent({ resourceIsCanary: true, exportIntended: true }).reasonCode, 'synthetic-canary-export-intent');
  assert.equal(evaluateCanaryEvent({ eventRepeated: true }).reasonCode, 'synthetic-canary-event-repeated');
  assert.equal(evaluateCanaryEvent({}).allowed, true);
});

test('second lock blocks all seven authentication failure modes', () => {
  assert.equal(evaluateSecondLock({ pushCount: 4, sensitiveAction: true }).reasonCode, 'repeated-approval-pressure');
  assert.equal(evaluateSecondLock({ recoveryPath: true, privilegedAction: true }).reasonCode, 'recovery-needs-step-up');
  assert.equal(evaluateSecondLock({ authSessionId: 'a', actionSessionId: 'b' }).reasonCode, 'session-binding-mismatch');
  assert.equal(evaluateSecondLock({ nonceFresh: false, sensitiveAction: true }).reasonCode, 'authentication-challenge-stale');
  assert.equal(evaluateSecondLock({ factorType: 'sms', carrierRisk: 'elevated', sensitiveAction: true }).reasonCode, 'phone-factor-risk');
  assert.equal(evaluateSecondLock({ approvedScope: 'records.read', requestedScope: 'records.export' }).reasonCode, 'requested-scope-exceeds-approval');
  assert.equal(evaluateSecondLock({ deviceTrusted: false, newDevice: true, privilegedAction: true }).reasonCode, 'device-step-up-required');
  assert.equal(evaluateSecondLock({}).allowed, true);
});

test('frontier gap blocks seven distinct gap conditions', () => {
  assert.equal(evaluateFrontierGap({ provenanceChanged: true }).reasonCode, 'model-provenance-drift');
  assert.equal(evaluateFrontierGap({ rewardScoreChanged: true, userObjectiveChanged: true }).reasonCode, 'objective-score-divergence');
  assert.equal(evaluateFrontierGap({ serviceListed: true, serviceConnected: false }).reasonCode, 'unapproved-bypass-service');
  assert.equal(evaluateFrontierGap({ rogueAgentCount: 1, collusionObserved: false }).reasonCode, 'agent-identity-unverified');
  assert.equal(evaluateFrontierGap({ verifiedAgentId: false, signedEnvelopePresent: false }).reasonCode, 'a2a-identity-unverified');
  assert.equal(evaluateFrontierGap({ cascadePredicted: true, dependentAgentCount: 5, fanoutBudget: 2 }).reasonCode, 'cascade-budget-exceeded');
  assert.equal(evaluateFrontierGap({ contextItems: 120, contextBudget: 40 }).reasonCode, 'context-budget-pressure');
  assert.equal(evaluateFrontierGap({}).allowed, true);
});

test('control flow blocks fail-open, weak fallback, untrusted error channel, and sensitive compensation', () => {
  assert.equal(evaluateControlFlow({ checkStatus: 'timeout', defaultAction: 'allow' }).reasonCode, 'control-flow-fail-open');
  assert.equal(evaluateControlFlow({ primaryStatus: 'unavailable', fallbackStrength: 1, requiredStrength: 3 }).reasonCode, 'fallback-strength-insufficient');
  assert.equal(evaluateControlFlow({ errorSourceTrust: 'untrusted', errorContainsInstruction: true }).reasonCode, 'error-channel-untrusted-instruction');
  assert.equal(evaluateControlFlow({ denialCount: 1, recoveryImpact: 'sensitive' }).reasonCode, 'compensation-loop-sensitive');
  assert.equal(evaluateControlFlow({}).allowed, true);
});

test('approval freshness blocks expired replay', () => {
  assert.equal(evaluateApprovalFreshness({ approvalExpired: true }).reasonCode, 'approval-replay-blocked');
  assert.equal(evaluateApprovalFreshness({ approvalExpired: false }).allowed, true);
});

test('outcome integrity blocks mismatched receipt', () => {
  assert.equal(evaluateOutcomeIntegrity({ claimedSuccess: true, receiptMatchesObservation: false }).reasonCode, 'outcome-receipt-mismatch');
  assert.equal(evaluateOutcomeIntegrity({ claimedSuccess: true, receiptMatchesObservation: true }).allowed, true);
});

test('quarantine reentry blocks quarantined items from re-entering trusted context', () => {
  assert.equal(evaluateQuarantineReentry({ quarantineState: 'quarantined' }).reasonCode, 'quarantined-item-reentry-blocked');
  assert.equal(evaluateQuarantineReentry({ quarantineState: 'cleared' }).allowed, true);
});

test('scope accumulation blocks cumulative risk and direct expansion', () => {
  assert.equal(evaluateScopeAccumulation({ cumulativeRiskFlagged: true }).reasonCode, 'cumulative-scope-risk-flagged');
  assert.equal(evaluateScopeAccumulation({ scopeExpanded: true }).reasonCode, 'cumulative-scope-risk-flagged');
  assert.equal(evaluateScopeAccumulation({}).allowed, true);
});

test('workflow graph blocks unexpected edges', () => {
  assert.equal(evaluateWorkflowGraph({ unexpectedEdgeCount: 1 }).reasonCode, 'workflow-graph-unexpected-edge');
  assert.equal(evaluateWorkflowGraph({ unexpectedEdgeCount: 0, expectedEdgeCount: 3, observedEdgeCount: 4 }).reasonCode, 'workflow-graph-unexpected-edge');
  assert.equal(evaluateWorkflowGraph({ unexpectedEdgeCount: 0, expectedEdgeCount: 3, observedEdgeCount: 3 }).allowed, true);
});

test('consensus provenance blocks shared-root agreements with insufficient independent evidence', () => {
  assert.equal(evaluateConsensusProvenance({ apparentAgreement: 3, independentEvidence: 1, requiredIndependentEvidence: 2, sharedRoot: true }).reasonCode, 'consensus-shared-root');
  assert.equal(evaluateConsensusProvenance({ apparentAgreement: 3, independentEvidence: 2, requiredIndependentEvidence: 2, sharedRoot: false }).allowed, true);
});

test('approval age blocks stale approvals exceeding freshness window', () => {
  assert.equal(evaluateApprovalAge({ approvalAgeSeconds: 7200, maxApprovalAgeSeconds: 900 }).reasonCode, 'approval-age-exceeded');
  assert.equal(evaluateApprovalAge({ approvalAgeSeconds: 300, maxApprovalAgeSeconds: 900 }).allowed, true);
});

test('policy gravity blocks and steps-up based on highest impact decision', () => {
  assert.equal(evaluatePolicyGravity({ highestImpactDecision: 'block' }).reasonCode, 'policy-gravity-impact-requires-block');
  assert.equal(evaluatePolicyGravity({ highestImpactDecision: 'step-up' }).reasonCode, 'policy-gravity-impact-requires-step-up');
  assert.equal(evaluatePolicyGravity({ highestImpactDecision: 'allow' }).allowed, true);
});
