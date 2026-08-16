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
