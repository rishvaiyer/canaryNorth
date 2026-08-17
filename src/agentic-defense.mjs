// Optional policy gates for research-backed agentic threat families.
// These checks consume typed metadata only. They never inspect or execute payloads.

export const TOOL_ATTESTATION_SCHEMA = 'contextseal.tool-attestation.v1';
export const MEMORY_TRUST_LEVELS = Object.freeze(['reviewed', 'trusted']);

function result(allowed, reasonCode, details = {}) {
  return { allowed, reasonCode, ...details, rawContent: 'withheld' };
}

export function verifyToolAttestation(manifest, expected = {}) {
  if (!manifest || typeof manifest !== 'object') return result(false, 'tool-attestation-missing');
  if (manifest.schema !== TOOL_ATTESTATION_SCHEMA) return result(false, 'tool-attestation-schema-mismatch');
  if (manifest.signatureStatus !== 'verified') return result(false, 'tool-attestation-unverified-signature');
  if (expected.tool && manifest.tool !== expected.tool) return result(false, 'tool-attestation-tool-mismatch');
  if (expected.version && manifest.version !== expected.version) return result(false, 'tool-attestation-version-mismatch');
  if (expected.owner && manifest.owner !== expected.owner) return result(false, 'tool-attestation-owner-mismatch');
  const expectedCapabilities = [...(expected.capabilities || [])].sort();
  const actualCapabilities = [...(manifest.capabilities || [])].sort();
  if (expectedCapabilities.length && JSON.stringify(expectedCapabilities) !== JSON.stringify(actualCapabilities)) return result(false, 'tool-attestation-capability-drift');
  if (typeof manifest.digest !== 'string' || !manifest.digest.startsWith('sha256:')) return result(false, 'tool-attestation-digest-missing');
  return result(true, 'tool-attestation-passed', { tool: manifest.tool, version: manifest.version, verificationMode: 'structural-metadata-only' });
}

export function evaluateMemoryContext({ originTrust, tenantId, workspaceId, policyVersion, currentPolicyVersion, ageSeconds, maxAgeSeconds = 3600, expectedTenantId, expectedWorkspaceId } = {}) {
  if (!MEMORY_TRUST_LEVELS.includes(originTrust)) return result(false, 'memory-origin-not-reviewed');
  if (!tenantId || !workspaceId) return result(false, 'memory-scope-missing');
  if ((expectedTenantId && tenantId !== expectedTenantId) || (expectedWorkspaceId && workspaceId !== expectedWorkspaceId)) return result(false, 'memory-scope-mismatch');
  if (policyVersion !== currentPolicyVersion) return result(false, 'memory-policy-version-mismatch');
  if (typeof ageSeconds !== 'number' || ageSeconds < 0 || ageSeconds > maxAgeSeconds) return result(false, 'memory-freshness-expired');
  return result(true, 'memory-context-revalidated', { tenantScoped: true, freshnessChecked: true });
}

export function evaluateProvenanceBoundary({ sourceTrust, sourceId, destinationAgentId, intendedRecipient, authority, delegated, expectedRecipient } = {}) {
  if (sourceTrust !== 'reviewed' && sourceTrust !== 'trusted') return result(false, 'provenance-source-untrusted');
  if (!sourceId || !destinationAgentId || destinationAgentId !== intendedRecipient) return result(false, 'provenance-recipient-mismatch');
  if (expectedRecipient && destinationAgentId !== expectedRecipient) return result(false, 'provenance-destination-not-capability');
  if (authority !== 'delegated' || delegated !== true) return result(false, 'provenance-delegation-missing');
  return result(true, 'provenance-boundary-passed', { authorityPreserved: true, verificationMode: 'metadata-only' });
}

export function evaluateCanaryRequest({ resource, canaryResource = 'canary://synthetic-protected-resource' } = {}) {
  if (resource !== canaryResource) return result(true, 'not-a-canary-resource', { alert: false });
  return result(false, 'synthetic-canary-triggered', { alert: true, action: 'block-and-record' });
}

export function evaluateAdaptiveContext({ provenanceDrift, scopeChanged, timingShift, wrapperShift } = {}) {
  const drift = [provenanceDrift, scopeChanged, timingShift, wrapperShift].some((value) => value === true);
  return drift ? result(false, 'adaptive-context-drift', { reviewRequired: true }) : result(true, 'adaptive-context-stable', { reviewRequired: false });
}

export function evaluateCausalContinuity({ trustedPathEdges = 0, requiredTrustedEdges = 1, untrustedGapCount = 0, actionIntentMatch = false } = {}) {
  if (![trustedPathEdges, requiredTrustedEdges, untrustedGapCount].every((value) => Number.isInteger(value) && value >= 0)) return result(false, 'causal-metadata-invalid', { reviewRequired: true });
  if (actionIntentMatch !== true) return result(false, 'causal-intent-mismatch', { reviewRequired: true });
  if (trustedPathEdges < requiredTrustedEdges || untrustedGapCount > 0) return result(false, 'causal-path-incomplete', { reviewRequired: true });
  return result(true, 'causal-path-complete', { reviewRequired: false, trustedPathVerified: true });
}

export function evaluateTrustDebt({ unresolvedSignals = 0, debtScore, debtBudget = 0.5, sensitiveAction = false } = {}) {
  if (!Number.isInteger(unresolvedSignals) || unresolvedSignals < 0 || !Number.isFinite(debtScore) || debtScore < 0 || debtScore > 1 || !Number.isFinite(debtBudget) || debtBudget < 0 || debtBudget > 1) return result(false, 'trust-debt-metadata-invalid', { reviewRequired: true });
  if (sensitiveAction === true && debtScore > debtBudget) return result(false, 'trust-debt-exceeded', { reviewRequired: true, debtScore, debtBudget, unresolvedSignals });
  return result(true, 'trust-debt-within-budget', { reviewRequired: false, debtScore, debtBudget, unresolvedSignals });
}

export function evaluateDelegationFreshness({ delegatorTrusted, receiverTrusted, delegated, audienceMatches, delegationExpiresAt, now = new Date() } = {}) {
  if (delegatorTrusted !== true || receiverTrusted !== true || delegated !== true || audienceMatches !== true) return result(false, 'delegation-trust-or-audience-mismatch', { reviewRequired: true });
  const expiry = new Date(delegationExpiresAt);
  if (!delegationExpiresAt || Number.isNaN(expiry.getTime())) return result(false, 'delegation-expiry-invalid', { reviewRequired: true });
  if (!(now instanceof Date) || Number.isNaN(now.getTime()) || now >= expiry) return result(false, 'delegation-expired', { reviewRequired: true });
  return result(true, 'delegation-fresh', { reviewRequired: false, freshnessChecked: true });
}

export function evaluateCausalBasis({ trustedBasisPresent = false, sourceTrustLevel = 'unknown', actionIntentMatch = false } = {}) {
  if (typeof trustedBasisPresent !== 'boolean' || typeof actionIntentMatch !== 'boolean') return result(false, 'causal-basis-metadata-invalid', { reviewRequired: true });
  if (!trustedBasisPresent) return result(false, 'untrusted-only-causal-basis', { reviewRequired: true, sourceTrustLevel });
  if (!actionIntentMatch) return result(false, 'causal-basis-intent-mismatch', { reviewRequired: true });
  return result(true, 'trusted-causal-basis', { reviewRequired: false });
}

export function evaluateRevocationLineage({ authorityId, revocationChecked = false, revocationVerifiedAt, maxRevocationAgeSeconds = 300, now = new Date() } = {}) {
  if (!authorityId || typeof authorityId !== 'string') return result(false, 'revocation-lineage-authority-missing', { reviewRequired: true });
  if (!revocationChecked) return result(false, 'revocation-lineage-unverified', { reviewRequired: true });
  if (!revocationVerifiedAt) return result(false, 'revocation-lineage-timestamp-missing', { reviewRequired: true });
  const verifiedAt = new Date(revocationVerifiedAt);
  if (Number.isNaN(verifiedAt.getTime())) return result(false, 'revocation-lineage-timestamp-invalid', { reviewRequired: true });
  const ageSeconds = (now.getTime() - verifiedAt.getTime()) / 1000;
  if (ageSeconds < 0 || ageSeconds > maxRevocationAgeSeconds) return result(false, 'revocation-lineage-stale', { reviewRequired: true });
  return result(true, 'revocation-lineage-current', { reviewRequired: false });
}

export function evaluateIntentNormalization({ approvedIntentHash, observedIntentHash, semanticDistance, distanceThreshold = 0.1, actionIntentMatch = false } = {}) {
  if (typeof approvedIntentHash !== 'string' || !approvedIntentHash || typeof observedIntentHash !== 'string' || !observedIntentHash) return result(false, 'intent-normalization-hash-missing', { reviewRequired: true });
  if (!Number.isFinite(semanticDistance) || semanticDistance < 0 || semanticDistance > 1) return result(false, 'intent-normalization-metadata-invalid', { reviewRequired: true });
  if (semanticDistance > distanceThreshold) return result(false, 'intent-normalization-drift', { reviewRequired: true, semanticDistance, distanceThreshold });
  if (!actionIntentMatch) return result(false, 'intent-normalization-action-mismatch', { reviewRequired: true });
  return result(true, 'intent-normalization-passed', { reviewRequired: false });
}

export function evaluateResourceClass({ resourceClass, approvedClass, classMismatch = false } = {}) {
  if (typeof resourceClass !== 'string' || !resourceClass || typeof approvedClass !== 'string' || !approvedClass) return result(false, 'resource-class-missing', { reviewRequired: true });
  if (classMismatch === true || resourceClass !== approvedClass) return result(false, 'resource-class-violation', { reviewRequired: true });
  return result(true, 'resource-class-matched', { reviewRequired: false });
}

export function evaluateRecoveryClaim({ claimedState, observedStateHash, approvedStateHash, independentCheckPresent = false } = {}) {
  if (!claimedState || typeof claimedState !== 'string') return result(false, 'recovery-claim-missing', { reviewRequired: true });
  if (!observedStateHash || typeof observedStateHash !== 'string' || !approvedStateHash || typeof approvedStateHash !== 'string') return result(false, 'recovery-claim-hash-missing', { reviewRequired: true });
  if (observedStateHash !== approvedStateHash) return result(false, 'recovery-claim-drift', { reviewRequired: true });
  if (!independentCheckPresent) return result(false, 'recovery-claim-unverified', { reviewRequired: true });
  return result(true, 'recovery-claim-verified', { reviewRequired: false });
}

export function evaluateSkillDescriptor({ signaturePresent = false, currentOwner, pinnedOwner, currentVersion, pinnedVersion, capabilitySetExpanded = false } = {}) {
  if (!signaturePresent) return result(false, 'skill-signature-missing', { reviewRequired: true });
  if (pinnedOwner !== undefined && currentOwner !== pinnedOwner) return result(false, 'descriptor-owner-changed', { reviewRequired: true });
  if (pinnedVersion !== undefined && currentVersion !== undefined && currentVersion < pinnedVersion) return result(false, 'pinned-version-regressed', { reviewRequired: true });
  if (capabilitySetExpanded) return result(false, 'declared-capability-set-expanded', { reviewRequired: true });
  return result(true, 'skill-descriptor-valid', { reviewRequired: false });
}

export function evaluateMemoryGraft({ memoryReviewed = false, trustedRecords = 0, poisonedRecordsPresent = false, memoryAgeSeconds, maxAgeSeconds = 3600, tenantId, expectedTenantId } = {}) {
  if (!memoryReviewed) return result(false, 'memory-origin-not-reviewed', { reviewRequired: true });
  if (trustedRecords > 0 && poisonedRecordsPresent) return result(false, 'poisoned-and-reviewed-records-collide', { reviewRequired: true });
  if (typeof memoryAgeSeconds === 'number' && memoryAgeSeconds > maxAgeSeconds) return result(false, 'experience-freshness-expired', { reviewRequired: true });
  if (expectedTenantId !== undefined && tenantId !== expectedTenantId) return result(false, 'memory-tenant-mismatch', { reviewRequired: true });
  return result(true, 'memory-graft-clear', { reviewRequired: false });
}

export function evaluateAgentBoundary({ summaryTrustAmplified = false, skillOriginMatch = true, delegationAudienceMatch = true, messageReplayed = false } = {}) {
  if (summaryTrustAmplified) return result(false, 'summary-cannot-amplify-source-authority', { reviewRequired: true });
  if (!skillOriginMatch) return result(false, 'skill-origin-mismatch', { reviewRequired: true });
  if (!delegationAudienceMatch) return result(false, 'delegation-audience-mismatch', { reviewRequired: true });
  if (messageReplayed) return result(false, 'agent-message-replayed-out-of-context', { reviewRequired: true });
  return result(true, 'agent-boundary-clear', { reviewRequired: false });
}

export function evaluateCanaryEvent({ resourceIsCanary = false, exportIntended = false, eventRepeated = false } = {}) {
  if (eventRepeated) return result(false, 'synthetic-canary-event-repeated', { alert: true });
  if (exportIntended && resourceIsCanary) return result(false, 'synthetic-canary-export-intent', { alert: true });
  if (resourceIsCanary) return result(false, 'synthetic-canary-resource-requested', { alert: true });
  return result(true, 'canary-event-clear', { alert: false });
}

export function evaluateSecondLock({ pushCount = 0, sensitiveAction = false, recoveryPath = false, privilegedAction = false, authSessionId, actionSessionId, nonceFresh = true, factorType, carrierRisk, approvedScope, requestedScope, deviceTrusted = true, newDevice = false } = {}) {
  if (pushCount >= 3 && sensitiveAction) return result(false, 'repeated-approval-pressure', { reviewRequired: true });
  if (recoveryPath && privilegedAction) return result(false, 'recovery-needs-step-up', { reviewRequired: true });
  if (authSessionId !== undefined && actionSessionId !== undefined && authSessionId !== actionSessionId) return result(false, 'session-binding-mismatch', { reviewRequired: true });
  if (!nonceFresh && sensitiveAction) return result(false, 'authentication-challenge-stale', { reviewRequired: true });
  if (factorType === 'sms' && carrierRisk === 'elevated' && sensitiveAction) return result(false, 'phone-factor-risk', { reviewRequired: true });
  if (approvedScope !== undefined && requestedScope !== undefined && requestedScope !== approvedScope) return result(false, 'requested-scope-exceeds-approval', { reviewRequired: true });
  if (!deviceTrusted && newDevice && privilegedAction) return result(false, 'device-step-up-required', { reviewRequired: true });
  return result(true, 'second-lock-passed', { reviewRequired: false });
}

export function evaluateFrontierGap({ provenanceChanged, rewardScoreChanged, userObjectiveChanged, serviceListed, serviceConnected, rogueAgentCount, collusionObserved, verifiedAgentId, signedEnvelopePresent, cascadePredicted, dependentAgentCount, fanoutBudget, contextItems, contextBudget } = {}) {
  if (provenanceChanged === true) return result(false, 'model-provenance-drift', { reviewRequired: true });
  if (rewardScoreChanged === true && userObjectiveChanged === true) return result(false, 'objective-score-divergence', { reviewRequired: true });
  if (serviceListed === true && serviceConnected !== true) return result(false, 'unapproved-bypass-service', { reviewRequired: true });
  if ((typeof rogueAgentCount === 'number' && rogueAgentCount > 0) || collusionObserved === true) return result(false, 'agent-identity-unverified', { reviewRequired: true });
  if (verifiedAgentId !== undefined && (verifiedAgentId !== true || signedEnvelopePresent !== true)) return result(false, 'a2a-identity-unverified', { reviewRequired: true });
  if (cascadePredicted === true && typeof dependentAgentCount === 'number' && typeof fanoutBudget === 'number' && dependentAgentCount > fanoutBudget) return result(false, 'cascade-budget-exceeded', { reviewRequired: true });
  if (typeof contextItems === 'number' && typeof contextBudget === 'number' && contextItems > contextBudget) return result(false, 'context-budget-pressure', { reviewRequired: true });
  return result(true, 'frontier-gap-clear', { reviewRequired: false });
}
