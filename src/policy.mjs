import crypto from 'node:crypto';
import { evaluateAdaptiveContext, evaluateCausalBasis, evaluateCanaryRequest, evaluateCausalContinuity, evaluateDelegationFreshness, evaluateIntentNormalization, evaluateMemoryContext, evaluateProvenanceBoundary, evaluateRecoveryClaim, evaluateResourceClass, evaluateRevocationLineage, evaluateTrustDebt, verifyToolAttestation } from './agentic-defense.mjs';

export const POLICY_VERSION = 'contextseal-policy-v2';
export const DEMO_TENANT_ID = 'tenant_demo';
export const DEMO_WORKSPACE_ID = 'workspace_demo';
const NONCE_PATTERN = /^[A-Za-z0-9._~-]{16,128}$/;

const INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?previous instructions/i,
  /reveal\s+(the\s+)?(system|secret|api)\s+prompt/i,
  /developer\s+message\s*:/i,
  /jailbreak/i
];

const HIDDEN_CONTENT_PATTERN = /[\u200B\u2060\uFEFF\u202A-\u202E]/;
const TOOL_METADATA_PATTERN = /(?:tool|function)\s*(?:name|call|schema|description)\s*[:=].*(?:approve|execute|admin|ignore|bypass)/is;
const MEMORY_POISONING_PATTERN = /\b(?:remember|save|persist|update\s+(?:the\s+)?memory|write\s+(?:to\s+)?memory)\b.*\b(?:approve|allow|bypass|ignore|disable|always)\b/is;
const EXFILTRATION_PATTERN = /\b(?:export|dump|reveal|send|include|print)\b.*\b(?:system\s+prompt|secrets?|credentials?|private\s+notes?|hidden\s+fields?|api\s+keys?)\b/is;
const OUTPUT_FORMAT_PATTERN = /(?:raw\s+html|active\s+content|executable\s+markup|javascript:|<script\b)/i;

const DLP_PATTERNS = [
  { kind: 'api-key', regex: /\b(?:sk|rk|pk)_[A-Za-z0-9_-]{12,}\b/i },
  { kind: 'bearer-token', regex: /\bbearer\s+[A-Za-z0-9._~-]{16,}\b/i },
  { kind: 'private-key', regex: /-----BEGIN\s+(?:RSA|EC|OPENSSH)?\s*PRIVATE KEY-----/i },
  { kind: 'password-field', regex: /(?:password|client_secret|access_token)\s*[:=]\s*[^\s,}]+/i }
];

export const DEMO_CAPABILITIES = [
  {
    id: 'cap_weather_read_7f3d', principal: 'weather-agent', label: 'Forecast reader',
    tool: 'weather.get_forecast', resource: 'weather://nyc', scopes: ['read:forecast'],
    audience: 'contextseal', tenantId: DEMO_TENANT_ID, workspaceId: DEMO_WORKSPACE_ID, policyVersion: POLICY_VERSION,
    expiresAt: '2030-08-15T23:59:59.000Z', status: 'active', reason: 'Approved for a synthetic demo forecast.'
  },
  {
    id: 'cap_ticket_update_91ae', principal: 'support-agent', label: 'Ticket updater',
    tool: 'tickets.update', resource: 'ticket://demo-482', scopes: ['write:ticket'],
    audience: 'contextseal', tenantId: DEMO_TENANT_ID, workspaceId: DEMO_WORKSPACE_ID, policyVersion: POLICY_VERSION,
    expiresAt: '2030-08-15T18:00:00.000Z', status: 'active', reason: 'Limited to one synthetic support ticket.'
  },
  {
    id: 'cap_docs_export_2c18', principal: 'research-agent', label: 'Document exporter',
    tool: 'docs.export', resource: 'docs://public/demo', scopes: ['read:public-doc'],
    audience: 'contextseal', tenantId: DEMO_TENANT_ID, workspaceId: DEMO_WORKSPACE_ID, policyVersion: POLICY_VERSION,
    expiresAt: '2025-08-14T18:00:00.000Z', status: 'expired', reason: 'Expired capability retained for audit visibility.'
  }
];

export function inspectInput(input = '') {
  const text = typeof input === 'string' ? input : JSON.stringify(input);
  const signals = [];
  const injection = INJECTION_PATTERNS.find((pattern) => pattern.test(text));
  const dlp = DLP_PATTERNS.find((pattern) => pattern.regex.test(text));
  if (injection) signals.push('prompt-injection');
  if (dlp) signals.push(`dlp:${dlp.kind}`);
  if (HIDDEN_CONTENT_PATTERN.test(text)) signals.push('hidden-content');
  if (TOOL_METADATA_PATTERN.test(text)) signals.push('tool-metadata');
  if (MEMORY_POISONING_PATTERN.test(text)) signals.push('memory-poisoning');
  if (EXFILTRATION_PATTERN.test(text)) signals.push('exfiltration-intent');
  if (OUTPUT_FORMAT_PATTERN.test(text)) signals.push('unsafe-output-format');
  return {
    clean: signals.length === 0,
    injection: injection ? 'prompt-injection' : null,
    dlp: dlp ? dlp.kind : null,
    signals
  };
}

export function authorize({ capabilityId, action, resource, input = '', now = new Date(), principal, audience, tenantId, workspaceId, policyVersion = POLICY_VERSION, nonce, replayDetected = false, toolManifest, memoryContext, provenance, canaryContext, adaptiveContext, causalContext, trustDebtContext, delegationContext, causalBasisContext, revocationLineageContext, intentNormContext, resourceClassContext, recoveryClaimContext, demoControls = {} }) {
  const capability = DEMO_CAPABILITIES.find((item) => item.id === capabilityId);
  if (!capability) return deny('unknown-capability', 'Capability reference is not recognized.', null);
  if (canaryContext !== undefined) {
    const canary = evaluateCanaryRequest({ resource, ...canaryContext });
    if (!canary.allowed) return deny(canary.reasonCode, 'Synthetic canary resource was blocked and recorded.', capability, { clean: false, signals: [canary.reasonCode], agenticDefense: canary });
  }
  if (policyVersion !== POLICY_VERSION || capability.policyVersion !== POLICY_VERSION) return deny('policy-version-mismatch', 'Capability and request policy versions do not match.', capability);
  if (principal !== undefined && principal !== capability.principal) return deny('principal-mismatch', 'Request principal does not match the capability principal.', capability);
  if (audience !== undefined && audience !== capability.audience) return deny('audience-mismatch', 'Request audience does not match the capability audience.', capability);
  if (tenantId !== undefined && tenantId !== capability.tenantId) return deny('tenant-mismatch', 'Request tenant does not match the capability tenant.', capability);
  if (workspaceId !== undefined && workspaceId !== capability.workspaceId) return deny('workspace-mismatch', 'Request workspace does not match the capability workspace.', capability);
  if (nonce !== undefined && !NONCE_PATTERN.test(nonce)) return deny('invalid-nonce', 'Nonce format is invalid.', capability);
  if (replayDetected) return deny('replay-detected', 'Nonce was already used for this principal.', capability);
  if (demoControls.expiry !== false && now >= new Date(capability.expiresAt)) return deny('expired-capability', 'Capability has expired.', capability);
  if (capability.tool !== action) return deny('action-not-allowlisted', 'Tool action is outside the capability allowlist.', capability);
  if (capability.resource !== resource) return deny('resource-out-of-scope', 'Resource is outside the capability scope.', capability);
  if (toolManifest !== undefined) {
    const attestation = verifyToolAttestation(toolManifest, { tool: capability.tool, capabilities: capability.scopes });
    if (!attestation.allowed) return deny(attestation.reasonCode, 'Tool attestation did not match the approved capability.', capability, { clean: false, signals: [attestation.reasonCode], agenticDefense: attestation });
  }
  if (memoryContext !== undefined) {
    const memory = evaluateMemoryContext({ ...memoryContext, tenantId: memoryContext.tenantId || tenantId, workspaceId: memoryContext.workspaceId || workspaceId, expectedTenantId: capability.tenantId, expectedWorkspaceId: capability.workspaceId, currentPolicyVersion: POLICY_VERSION });
    if (!memory.allowed) return deny(memory.reasonCode, 'Memory context failed activation-time revalidation.', capability, { clean: false, signals: [memory.reasonCode], agenticDefense: memory });
  }
  if (provenance !== undefined) {
    const provenanceResult = evaluateProvenanceBoundary({ ...provenance, expectedRecipient: capability.principal });
    if (!provenanceResult.allowed) return deny(provenanceResult.reasonCode, 'Provenance did not prove delegated authority for this action.', capability, { clean: false, signals: [provenanceResult.reasonCode], agenticDefense: provenanceResult });
  }
  if (adaptiveContext !== undefined) {
    const adaptive = evaluateAdaptiveContext(adaptiveContext);
    if (!adaptive.allowed) return deny(adaptive.reasonCode, 'Adaptive context drift requires review before action.', capability, { clean: false, signals: [adaptive.reasonCode], agenticDefense: adaptive });
  }
  if (causalContext !== undefined) {
    const causal = evaluateCausalContinuity(causalContext);
    if (!causal.allowed) return deny(causal.reasonCode, 'Trusted causal evidence was incomplete for this action.', capability, { clean: false, signals: [causal.reasonCode], agenticDefense: causal });
  }
  if (trustDebtContext !== undefined) {
    const debt = evaluateTrustDebt(trustDebtContext);
    if (!debt.allowed) return deny(debt.reasonCode, 'Unresolved synthetic risk exceeded the action budget.', capability, { clean: false, signals: [debt.reasonCode], agenticDefense: debt });
  }
  if (delegationContext !== undefined) {
    const delegation = evaluateDelegationFreshness({ ...delegationContext, now });
    if (!delegation.allowed) return deny(delegation.reasonCode, 'Delegated authority was not fresh and bound at action time.', capability, { clean: false, signals: [delegation.reasonCode], agenticDefense: delegation });
  }
  if (causalBasisContext !== undefined) {
    const basis = evaluateCausalBasis(causalBasisContext);
    if (!basis.allowed) return deny(basis.reasonCode, 'No trusted causal basis exists for this action.', capability, { clean: false, signals: [basis.reasonCode], agenticDefense: basis });
  }
  if (revocationLineageContext !== undefined) {
    const revocation = evaluateRevocationLineage({ ...revocationLineageContext, now });
    if (!revocation.allowed) return deny(revocation.reasonCode, 'Revocation status of the originating authority was not verified.', capability, { clean: false, signals: [revocation.reasonCode], agenticDefense: revocation });
  }
  if (intentNormContext !== undefined) {
    const intentNorm = evaluateIntentNormalization(intentNormContext);
    if (!intentNorm.allowed) return deny(intentNorm.reasonCode, 'Observed intent diverges from the approved normalized intent.', capability, { clean: false, signals: [intentNorm.reasonCode], agenticDefense: intentNorm });
  }
  if (resourceClassContext !== undefined) {
    const resourceClass = evaluateResourceClass(resourceClassContext);
    if (!resourceClass.allowed) return deny(resourceClass.reasonCode, 'Requested resource falls outside the approved resource class.', capability, { clean: false, signals: [resourceClass.reasonCode], agenticDefense: resourceClass });
  }
  if (recoveryClaimContext !== undefined) {
    const recovery = evaluateRecoveryClaim(recoveryClaimContext);
    if (!recovery.allowed) return deny(recovery.reasonCode, 'Recovery claim could not be independently verified.', capability, { clean: false, signals: [recovery.reasonCode], agenticDefense: recovery });
  }
  const inspection = demoControls.contentFirewall === false ? { clean: true, injection: null, dlp: null, signals: [], bypassed: true } : inspectInput(input);
  if (inspection.injection) return deny('prompt-injection', 'Untrusted instruction pattern was quarantined.', capability, inspection);
  if (inspection.dlp) return deny('dlp-block', `Sensitive ${inspection.dlp} pattern was blocked before tool execution.`, capability, inspection);
  if (inspection.signals.includes('hidden-content')) return deny('hidden-content', 'Hidden or direction-changing content was quarantined for review.', capability, inspection);
  if (inspection.signals.includes('tool-metadata')) return deny('tool-metadata', 'Tool-shaped metadata is not trusted as an executable tool request.', capability, inspection);
  if (inspection.signals.includes('memory-poisoning')) return deny('memory-poisoning', 'Unverified durable-memory mutation was blocked.', capability, inspection);
  if (inspection.signals.includes('exfiltration-intent')) return deny('exfiltration-intent', 'Broad protected-data export intent was blocked.', capability, inspection);
  if (inspection.signals.includes('unsafe-output-format')) return deny('unsafe-output-format', 'Active or executable-looking output format was blocked.', capability, inspection);
  return { allowed: true, reason: 'Policy checks passed.', capability, inspection };
}

function deny(code, message, capability, inspection = { clean: false, injection: null, dlp: null }) {
  return { allowed: false, code, reason: message, capability, inspection };
}

export function signReceipt(receipt, secret) { return crypto.createHmac('sha256', secret).update(JSON.stringify(receipt)).digest('hex'); }
export function hashReceipt(receipt) { return crypto.createHash('sha256').update(JSON.stringify(receipt)).digest('hex'); }
