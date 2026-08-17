import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateAdaptiveContext, evaluateAgentBoundary, evaluateAgenticSsrf, evaluateApprovalAge, evaluateApprovalCarousel, evaluateApprovalFreshness, evaluateAudienceMismatch, evaluateBlastRadius, evaluateBrowserOriginClaim, evaluateCausalBasis, evaluateCanaryEvent, evaluateCanaryRequest, evaluateCausalContinuity, evaluateClockSplit, evaluateConsensusProvenance, evaluateContextFanout, evaluateControlFlow, evaluateCorpusTaint, evaluateDelegationFreshness, evaluateDependencyDoppelganger, evaluateEvidenceMasquerade, evaluateEvidenceShadow, evaluateExecutionBoundary, evaluateExportDrift, evaluateFrontierGap, evaluateHiddenCaptureState, evaluateIntentNormalization, evaluateIntentTrajectory, evaluateKeystreamRetention, evaluateLifecycleHook, evaluateLongGame, evaluateMcpScopeCrosswire, evaluateMemoryContext, evaluateMemoryGraft, evaluateMemoryPermissionShadow, evaluateModelExposure, evaluateModelIdentityMirage, evaluateOutcomeIntegrity, evaluatePassportSmuggle, evaluatePlatformPassport, evaluatePolicyGravity, evaluatePromptwareRelay, evaluateProvenanceBoundary, evaluateQuarantineReentry, evaluateQuietPermission, evaluateRecoveryClaim, evaluateRecoveryTrapdoor, evaluateBackgroundListener, evaluateRedactionGap, evaluateReconstructionRisk, evaluateResourceClass, evaluateRetrievalRanking, evaluateRevocationLineage, evaluateRouteAmbiguity, evaluateObservationActionGap, evaluateSchedulerDrift, evaluateSchemaAuthority, evaluateScopeAccumulation, evaluateSecondLock, evaluateSecretFocus, evaluateSkillDescriptor, evaluateTenantMirror, evaluateTokenFurnace, evaluateToolInventory, evaluateToolPivot, evaluateTrajectoryFork, evaluateTrustDebt, evaluateWorkflowGraph, verifyToolAttestation } from '../src/agentic-defense.mjs';

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

// Batch I: compound-boundary
test('intent trajectory blocks when fragments accumulate to sensitive intent drift', () => {
  assert.equal(evaluateIntentTrajectory({ fragmentCount: 3, finalSensitivity: 'sensitive', intentDrift: true }).reasonCode, 'intent-trajectory-triggered');
  assert.equal(evaluateIntentTrajectory({ fragmentCount: 2, finalSensitivity: 'sensitive', intentDrift: true }).allowed, true);
  assert.equal(evaluateIntentTrajectory({ fragmentCount: 3, finalSensitivity: 'benign', intentDrift: true }).allowed, true);
  assert.equal(evaluateIntentTrajectory({ fragmentCount: -1 }).reasonCode, 'intent-trajectory-metadata-invalid');
});

test('clock split blocks when primary expired and secondary valid but clocks disagree', () => {
  assert.equal(evaluateClockSplit({ primaryExpired: true, secondaryValid: true, clockAgreement: false }).reasonCode, 'clock-disagreement-blocked');
  assert.equal(evaluateClockSplit({ primaryExpired: true, secondaryValid: true, clockAgreement: true }).allowed, true);
  assert.equal(evaluateClockSplit({ primaryExpired: false, secondaryValid: true, clockAgreement: false }).allowed, true);
});

test('tenant mirror blocks when label matches but tenants differ', () => {
  assert.equal(evaluateTenantMirror({ resourceLabelMatches: true, resourceTenant: 'a', requestTenant: 'b' }).reasonCode, 'tenant-label-binding-mismatch');
  assert.equal(evaluateTenantMirror({ resourceLabelMatches: true, resourceTenant: 'a', requestTenant: 'a' }).allowed, true);
  assert.equal(evaluateTenantMirror({ resourceLabelMatches: false, resourceTenant: 'a', requestTenant: 'b' }).allowed, true);
});

test('evidence masquerade blocks when claimed approval lacks authoritative provenance', () => {
  assert.equal(evaluateEvidenceMasquerade({ claimedApproval: true, authoritativeRecord: 'missing', provenanceVerified: false }).reasonCode, 'claimed-approval-provenance-missing');
  assert.equal(evaluateEvidenceMasquerade({ claimedApproval: true, authoritativeRecord: 'present', provenanceVerified: false }).reasonCode, 'claimed-approval-provenance-missing');
  assert.equal(evaluateEvidenceMasquerade({ claimedApproval: true, authoritativeRecord: 'present', provenanceVerified: true }).allowed, true);
  assert.equal(evaluateEvidenceMasquerade({ claimedApproval: false, authoritativeRecord: 'missing' }).allowed, true);
});

// Batch J: input-capture
test('secret focus blocks keyboard observer on secret field without consent', () => {
  assert.equal(evaluateSecretFocus({ channel: 'keyboard', secretFieldFocused: true, consent: 'missing' }).reasonCode, 'secret-field-observer-blocked');
  assert.equal(evaluateSecretFocus({ channel: 'keyboard', secretFieldFocused: true, consent: 'granted' }).allowed, true);
  assert.equal(evaluateSecretFocus({ channel: 'mouse', secretFieldFocused: true, consent: 'missing' }).allowed, true);
});

test('background listener blocks when scope is background and owner has not approved', () => {
  assert.equal(evaluateBackgroundListener({ scope: 'background', ownerApproved: false }).reasonCode, 'background-listener-unapproved');
  assert.equal(evaluateBackgroundListener({ scope: 'background', ownerApproved: true }).allowed, true);
  assert.equal(evaluateBackgroundListener({ scope: 'foreground', ownerApproved: false }).allowed, true);
});

test('keystream retention blocks durable keyboard retention without declared purpose', () => {
  assert.equal(evaluateKeystreamRetention({ channel: 'keyboard', retention: 'durable', purposeDeclared: false }).reasonCode, 'keystroke-retention-purpose-missing');
  assert.equal(evaluateKeystreamRetention({ channel: 'keyboard', retention: 'durable', purposeDeclared: true }).allowed, true);
  assert.equal(evaluateKeystreamRetention({ channel: 'keyboard', retention: 'ephemeral', purposeDeclared: false }).allowed, true);
});

test('hidden capture state blocks when capture is active but hidden', () => {
  assert.equal(evaluateHiddenCaptureState({ visibility: 'hidden', captureState: 'active' }).reasonCode, 'hidden-capture-active');
  assert.equal(evaluateHiddenCaptureState({ visibility: 'visible', captureState: 'active' }).allowed, true);
  assert.equal(evaluateHiddenCaptureState({ visibility: 'hidden', captureState: 'inactive' }).allowed, true);
});

// Batch K: forensic-leak
test('redaction gap blocks sensitive field in report without redaction marker', () => {
  assert.equal(evaluateRedactionGap({ sensitiveFieldPresent: true, redactionMarkerPresent: false }).reasonCode, 'report-redaction-gap');
  assert.equal(evaluateRedactionGap({ sensitiveFieldPresent: true, redactionMarkerPresent: true }).allowed, true);
  assert.equal(evaluateRedactionGap({ sensitiveFieldPresent: false, redactionMarkerPresent: false }).allowed, true);
});

test('audience mismatch blocks private evidence on a public export audience', () => {
  assert.equal(evaluateAudienceMismatch({ audience: 'public', evidenceClass: 'private' }).reasonCode, 'evidence-audience-mismatch');
  assert.equal(evaluateAudienceMismatch({ audience: 'private', evidenceClass: 'private' }).allowed, true);
  assert.equal(evaluateAudienceMismatch({ audience: 'public', evidenceClass: 'public' }).allowed, true);
});

test('reconstruction risk blocks when linkable field count and identity risk are elevated', () => {
  assert.equal(evaluateReconstructionRisk({ linkableFieldCount: 3, identityRisk: 'elevated' }).reasonCode, 'linkage-reconstruction-risk');
  assert.equal(evaluateReconstructionRisk({ linkableFieldCount: 2, identityRisk: 'elevated' }).allowed, true);
  assert.equal(evaluateReconstructionRisk({ linkableFieldCount: 3, identityRisk: 'low' }).allowed, true);
  assert.equal(evaluateReconstructionRisk({ linkableFieldCount: -1 }).reasonCode, 'reconstruction-metadata-invalid');
});

test('export drift blocks when source is redacted but export is not', () => {
  assert.equal(evaluateExportDrift({ sourceRedacted: true, exportRedacted: false }).reasonCode, 'export-redaction-drift');
  assert.equal(evaluateExportDrift({ sourceRedacted: true, exportRedacted: true }).allowed, true);
  assert.equal(evaluateExportDrift({ sourceRedacted: false, exportRedacted: false }).allowed, true);
});

// Batch L: research-attack-2026
test('tool pivot blocks a second un-scoped tool requested after a trusted first tool', () => {
  assert.equal(evaluateToolPivot({ firstToolTrusted: true, secondToolRequested: true, secondToolScopeApproved: false }).reasonCode, 'tool-scope-escalation-blocked');
  assert.equal(evaluateToolPivot({ firstToolTrusted: true, secondToolRequested: true, secondToolScopeApproved: true }).allowed, true);
  assert.equal(evaluateToolPivot({ firstToolTrusted: false, secondToolRequested: true, secondToolScopeApproved: false }).allowed, true);
});

test('memory permission shadow blocks when any permission dimension is unverified', () => {
  assert.equal(evaluateMemoryPermissionShadow({ ownerVerified: false, modeSafe: true, tenantBound: true, freshnessVerified: true }).reasonCode, 'memory-permission-shadow');
  assert.equal(evaluateMemoryPermissionShadow({ ownerVerified: true, modeSafe: true, tenantBound: true, freshnessVerified: true }).allowed, true);
  assert.equal(evaluateMemoryPermissionShadow({ ownerVerified: true, modeSafe: false, tenantBound: true, freshnessVerified: true }).reasonCode, 'memory-permission-shadow');
});

test('schema authority blocks parameter-controlled destination without policy validation', () => {
  assert.equal(evaluateSchemaAuthority({ parameterControlsDestination: true, destinationPolicyValidated: false }).reasonCode, 'schema-parameter-authority-split');
  assert.equal(evaluateSchemaAuthority({ parameterControlsDestination: true, destinationPolicyValidated: true }).allowed, true);
  assert.equal(evaluateSchemaAuthority({ parameterControlsDestination: false, destinationPolicyValidated: false }).allowed, true);
});

test('mcp scope crosswire blocks read scope reaching a mutating handler', () => {
  assert.equal(evaluateMcpScopeCrosswire({ requestedScope: 'read', handlerMutates: true }).reasonCode, 'mcp-scope-handler-mismatch');
  assert.equal(evaluateMcpScopeCrosswire({ requestedScope: 'read', handlerMutates: false }).allowed, true);
  assert.equal(evaluateMcpScopeCrosswire({ requestedScope: 'write', handlerMutates: true }).allowed, true);
});

test('lifecycle hook blocks unapproved lifecycle change affecting future runs', () => {
  assert.equal(evaluateLifecycleHook({ lifecycleChanged: true, futureRunAffected: true, ownerApproval: false }).reasonCode, 'lifecycle-hook-unapproved');
  assert.equal(evaluateLifecycleHook({ lifecycleChanged: true, futureRunAffected: true, ownerApproval: true }).allowed, true);
  assert.equal(evaluateLifecycleHook({ lifecycleChanged: true, futureRunAffected: false, ownerApproval: false }).allowed, true);
});

test('agentic ssrf blocks user-controlled or unknown destination class', () => {
  assert.equal(evaluateAgenticSsrf({ destinationUserControlled: true, destinationClass: 'internal' }).reasonCode, 'destination-class-unauthorized');
  assert.equal(evaluateAgenticSsrf({ destinationUserControlled: false, destinationClass: 'unknown' }).reasonCode, 'destination-class-unauthorized');
  assert.equal(evaluateAgenticSsrf({ destinationUserControlled: false, destinationClass: 'approved' }).allowed, true);
});

test('context fanout blocks when branch, retry, agent, or token budget is exceeded', () => {
  assert.equal(evaluateContextFanout({ branchCount: 8, branchBudget: 3, retryCount: 0, retryBudget: 5, delegatedAgentCount: 0, agentBudget: 5 }).reasonCode, 'context-fanout-budget-exceeded');
  assert.equal(evaluateContextFanout({ tokenBudgetExceeded: true }).reasonCode, 'context-fanout-budget-exceeded');
  assert.equal(evaluateContextFanout({ branchCount: 2, branchBudget: 3, retryCount: 1, retryBudget: 2, delegatedAgentCount: 0, agentBudget: 1 }).allowed, true);
});

test('retrieval ranking blocks dominant unverified top result', () => {
  assert.equal(evaluateRetrievalRanking({ rankingDominance: true, topResultTrust: 'unverified' }).reasonCode, 'retrieval-rank-authority-gap');
  assert.equal(evaluateRetrievalRanking({ rankingDominance: true, topResultTrust: 'verified' }).allowed, true);
  assert.equal(evaluateRetrievalRanking({ rankingDominance: false, topResultTrust: 'unverified' }).allowed, true);
});

test('observation action gap blocks when evidence digest or independent evidence is missing', () => {
  assert.equal(evaluateObservationActionGap({ evidenceDigestMatches: false, independentEvidence: true }).reasonCode, 'observation-action-gap');
  assert.equal(evaluateObservationActionGap({ evidenceDigestMatches: true, independentEvidence: false }).reasonCode, 'observation-action-gap');
  assert.equal(evaluateObservationActionGap({ evidenceDigestMatches: true, independentEvidence: true }).allowed, true);
});

test('promptware relay blocks external content crossing boundary without origin preservation and sensitive action', () => {
  assert.equal(evaluatePromptwareRelay({ externalContent: true, originPreserved: false, sensitiveAction: true }).reasonCode, 'promptware-origin-not-preserved');
  assert.equal(evaluatePromptwareRelay({ externalContent: true, originPreserved: true, sensitiveAction: true }).allowed, true);
  assert.equal(evaluatePromptwareRelay({ externalContent: true, originPreserved: false, sensitiveAction: false }).allowed, true);
});

// Batch M: future-agentic A
test('trajectory fork blocks when observed branches exceed approved or unexpected branch is flagged', () => {
  assert.equal(evaluateTrajectoryFork({ unexpectedBranch: true }).reasonCode, 'trajectory-unexpected-branch');
  assert.equal(evaluateTrajectoryFork({ approvedBranchCount: 1, observedBranchCount: 2, unexpectedBranch: false }).reasonCode, 'trajectory-unexpected-branch');
  assert.equal(evaluateTrajectoryFork({ approvedBranchCount: 2, observedBranchCount: 2, unexpectedBranch: false }).allowed, true);
});

test('passport smuggle blocks when ownership, audience, capability, or approval changes across boundary', () => {
  assert.equal(evaluatePassportSmuggle({ ownerVerified: false, audienceChanged: false, capabilitySetChanged: false, approvalInherited: true }).reasonCode, 'capability-passport-drift');
  assert.equal(evaluatePassportSmuggle({ ownerVerified: true, audienceChanged: true, capabilitySetChanged: false, approvalInherited: true }).reasonCode, 'capability-passport-drift');
  assert.equal(evaluatePassportSmuggle({ ownerVerified: true, audienceChanged: false, capabilitySetChanged: false, approvalInherited: true }).allowed, true);
});

test('browser origin claim blocks when origin claim is unverified or boundary is untrusted', () => {
  assert.equal(evaluateBrowserOriginClaim({ originClaimVerified: false, boundaryTrusted: true }).reasonCode, 'origin-claim-insufficient');
  assert.equal(evaluateBrowserOriginClaim({ originClaimVerified: true, boundaryTrusted: false }).reasonCode, 'origin-claim-insufficient');
  assert.equal(evaluateBrowserOriginClaim({ originClaimVerified: true, boundaryTrusted: true }).allowed, true);
});

test('token furnace blocks credential-shaped metadata presence', () => {
  assert.equal(evaluateTokenFurnace({ tokenLikeMetadataPresent: true, secretMaterialPresent: false }).reasonCode, 'token-like-metadata-flagged');
  assert.equal(evaluateTokenFurnace({ tokenLikeMetadataPresent: false, secretMaterialPresent: false }).allowed, true);
});

test('route ambiguity blocks when route is ambiguous or no route is selected', () => {
  assert.equal(evaluateRouteAmbiguity({ routeAmbiguous: true, selectedRoute: null }).reasonCode, 'route-selection-ambiguous');
  assert.equal(evaluateRouteAmbiguity({ routeAmbiguous: false, selectedRoute: null }).reasonCode, 'route-selection-ambiguous');
  assert.equal(evaluateRouteAmbiguity({ routeAmbiguous: false, selectedRoute: 'route-a' }).allowed, true);
});

// Batch M: future-agentic B
test('quiet permission blocks high-impact composed scope without fresh approval', () => {
  assert.equal(evaluateQuietPermission({ componentScopeCount: 3, composedImpact: 'high', freshApproval: false }).reasonCode, 'composed-scope-impact-elevated');
  assert.equal(evaluateQuietPermission({ componentScopeCount: 3, composedImpact: 'high', freshApproval: true }).allowed, true);
  assert.equal(evaluateQuietPermission({ componentScopeCount: 2, composedImpact: 'high', freshApproval: false }).allowed, true);
});

test('scheduler drift blocks when multiple time sources disagree on freshness', () => {
  assert.equal(evaluateSchedulerDrift({ timeSources: 2, freshnessAgreement: false }).reasonCode, 'freshness-scheduler-disagreement');
  assert.equal(evaluateSchedulerDrift({ timeSources: 2, freshnessAgreement: true }).allowed, true);
  assert.equal(evaluateSchedulerDrift({ timeSources: 1, freshnessAgreement: false }).allowed, true);
});

test('evidence shadow blocks when evidence items exceed verified items and provenance is not visible', () => {
  assert.equal(evaluateEvidenceShadow({ evidenceItems: 2, verifiedItems: 0, provenanceVisible: false }).reasonCode, 'evidence-provenance-shadow');
  assert.equal(evaluateEvidenceShadow({ evidenceItems: 2, verifiedItems: 2, provenanceVisible: false }).allowed, true);
  assert.equal(evaluateEvidenceShadow({ evidenceItems: 2, verifiedItems: 0, provenanceVisible: true }).allowed, true);
});

test('model identity mirage blocks when identity match fails or identity classes differ', () => {
  assert.equal(evaluateModelIdentityMirage({ identityMatch: false }).reasonCode, 'model-identity-class-mismatch');
  assert.equal(evaluateModelIdentityMirage({ identityMatch: true, approvedIdentityClass: 'reviewer', observedIdentityClass: 'unverified' }).reasonCode, 'model-identity-class-mismatch');
  assert.equal(evaluateModelIdentityMirage({ identityMatch: true, approvedIdentityClass: 'reviewer', observedIdentityClass: 'reviewer' }).allowed, true);
});

// Batch N: owasp-gap
test('platform passport blocks when multiple platforms disagree on permissions or provenance', () => {
  assert.equal(evaluatePlatformPassport({ platformCount: 4, permissionAgreement: false, provenanceAgreement: false }).reasonCode, 'platform-permission-disagreement');
  assert.equal(evaluatePlatformPassport({ platformCount: 4, permissionAgreement: true, provenanceAgreement: false }).reasonCode, 'platform-permission-disagreement');
  assert.equal(evaluatePlatformPassport({ platformCount: 1, permissionAgreement: false, provenanceAgreement: false }).allowed, true);
  assert.equal(evaluatePlatformPassport({ platformCount: 4, permissionAgreement: true, provenanceAgreement: true }).allowed, true);
});

test('execution boundary blocks when execution is requested but boundary or content disallows it', () => {
  assert.equal(evaluateExecutionBoundary({ executionRequested: true, executableContentPresent: false, executionAllowed: true }).reasonCode, 'execution-boundary-enforced');
  assert.equal(evaluateExecutionBoundary({ executionRequested: true, executableContentPresent: true, executionAllowed: false }).reasonCode, 'execution-boundary-enforced');
  assert.equal(evaluateExecutionBoundary({ executionRequested: false, executableContentPresent: false, executionAllowed: false }).allowed, true);
  assert.equal(evaluateExecutionBoundary({ executionRequested: true, executableContentPresent: true, executionAllowed: true }).allowed, true);
});

test('corpus taint blocks when training source split or corpus version changes', () => {
  assert.equal(evaluateCorpusTaint({ sourceSplitMismatch: true, corpusVersionChanged: false }).reasonCode, 'corpus-provenance-tainted');
  assert.equal(evaluateCorpusTaint({ sourceSplitMismatch: false, corpusVersionChanged: true }).reasonCode, 'corpus-provenance-tainted');
  assert.equal(evaluateCorpusTaint({ sourceSplitMismatch: false, corpusVersionChanged: false }).allowed, true);
});

test('tool inventory blocks when tool is not in registry or inventory does not match', () => {
  assert.equal(evaluateToolInventory({ inventoryMatch: false, registryRecordPresent: false }).reasonCode, 'tool-not-in-registry');
  assert.equal(evaluateToolInventory({ inventoryMatch: true, registryRecordPresent: false }).reasonCode, 'tool-not-in-registry');
  assert.equal(evaluateToolInventory({ inventoryMatch: true, registryRecordPresent: true }).allowed, true);
});

test('model exposure blocks when extraction is requested or weights are included', () => {
  assert.equal(evaluateModelExposure({ extractionRequested: true, weightsIncluded: false }).reasonCode, 'model-extraction-unauthorized');
  assert.equal(evaluateModelExposure({ extractionRequested: false, weightsIncluded: true }).reasonCode, 'model-extraction-unauthorized');
  assert.equal(evaluateModelExposure({ extractionRequested: false, weightsIncluded: false }).allowed, true);
});

// Batch O: top-ten
test('approval carousel blocks high approval count with sensitive action', () => {
  assert.equal(evaluateApprovalCarousel({ approvalCount: 5, sensitiveAction: true }).reasonCode, 'approval-carousel-step-up');
  assert.equal(evaluateApprovalCarousel({ approvalCount: 4, sensitiveAction: true }).allowed, true);
  assert.equal(evaluateApprovalCarousel({ approvalCount: 5, sensitiveAction: false }).allowed, true);
  assert.equal(evaluateApprovalCarousel({ approvalCount: -1 }).reasonCode, 'approval-carousel-metadata-invalid');
});

test('blast radius blocks projected actions exceeding action budget', () => {
  assert.equal(evaluateBlastRadius({ projectedActions: 4, actionBudget: 3 }).reasonCode, 'blast-radius-budget-exceeded');
  assert.equal(evaluateBlastRadius({ projectedActions: 3, actionBudget: 3 }).allowed, true);
  assert.equal(evaluateBlastRadius({ projectedActions: -1 }).reasonCode, 'blast-radius-metadata-invalid');
});

test('recovery trapdoor blocks when recovery strength is weaker than session strength', () => {
  assert.equal(evaluateRecoveryTrapdoor({ recoveryStrength: 1, sessionStrength: 3 }).reasonCode, 'recovery-strength-insufficient');
  assert.equal(evaluateRecoveryTrapdoor({ recoveryStrength: 3, sessionStrength: 3 }).allowed, true);
  assert.equal(evaluateRecoveryTrapdoor({ recoveryStrength: 'strong', sessionStrength: 3 }).reasonCode, 'recovery-trapdoor-metadata-invalid');
});

test('long game blocks multi-step chain reaching a sensitive action at stage limit', () => {
  assert.equal(evaluateLongGame({ stageCount: 7, sensitiveAction: true }).reasonCode, 'long-game-stage-limit');
  assert.equal(evaluateLongGame({ stageCount: 6, sensitiveAction: true }).allowed, true);
  assert.equal(evaluateLongGame({ stageCount: 7, sensitiveAction: false }).allowed, true);
  assert.equal(evaluateLongGame({ stageCount: -1 }).reasonCode, 'long-game-metadata-invalid');
});

test('dependency doppelganger blocks when owner, digest, or execution permission changes', () => {
  assert.equal(evaluateDependencyDoppelganger({ ownerChanged: true, digestChanged: false, executionPermissionChanged: false }).reasonCode, 'dependency-identity-drift');
  assert.equal(evaluateDependencyDoppelganger({ ownerChanged: false, digestChanged: true, executionPermissionChanged: false }).reasonCode, 'dependency-identity-drift');
  assert.equal(evaluateDependencyDoppelganger({ ownerChanged: false, digestChanged: false, executionPermissionChanged: false }).allowed, true);
});
