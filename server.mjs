import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { DEMO_CAPABILITIES, POLICY_VERSION, authorize, hashReceipt } from './src/policy.mjs';
import { artifactManifest, verifyApprovedArtifact, verifyArtifact } from './src/artifacts.mjs';
import { createReceiptStore } from './src/storage.mjs';
import { createApprovalStore } from './src/approvals.mjs';
import { createEvidenceEvent, createEvidencePackage } from './src/evidence.mjs';
import { createSigner, ed25519Enabled } from './src/signing.mjs';
import { createMcpHandler, MCP_PROTOCOL_VERSION } from './src/mcp.mjs';
import { createMcpUpstreamForwarder, parseMcpUpstreamAllowedOrigins } from './src/mcp-upstream.mjs';

const root = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(root, 'public');
const port = Number(process.env.PORT || 4178);
const isProduction = process.env.NODE_ENV === 'production';
const host = process.env.HOST || (isProduction ? '0.0.0.0' : '127.0.0.1');
const demoMode = process.env.CONTEXTSEAL_DEMO_MODE === '1' || !isProduction;
const requireAuth = !demoMode && (isProduction || process.env.CONTEXTSEAL_REQUIRE_AUTH === '1');
const signingSecret = process.env.RECEIPT_SIGNING_KEY || (isProduction ? null : 'context-seal-dev-signing-key');
const authToken = process.env.CONTEXTSEAL_AUTH_TOKEN || null;
const penGatePassword = process.env.PENTEL_LAB_PASSWORD || null;
const penGateSessions = new Map();
const PEN_GATE_COOKIE = 'pentel_session';
const PEN_GATE_SESSION_TTL_MS = 12 * 60 * 60 * 1000;
// Ed25519 signer. Receipts are signed with the private key; the public key is
// served at /api/signing-key so anyone can verify a receipt without it.
// An ephemeral key is allowed only outside production, and /health reports it,
// because an ephemeral key means receipts stop verifying after a restart.
// Ed25519 signing is OFF by default; see the toggle block in src/signing.mjs.
// While off, `signer` is a legacy HMAC signer and every path below behaves
// exactly as it did before Ed25519 existed.
const signer = createSigner({
  enabled: ed25519Enabled(),
  privateKey: process.env.CONTEXTSEAL_SIGNING_KEY,
  allowEphemeral: !isProduction || demoMode,
  legacySecret: signingSecret
});
function parseEvidenceWrappingKey(value) {
  if (!value) return null;
  const key = /^[0-9a-f]{64}$/i.test(value) ? Buffer.from(value, 'hex') : Buffer.from(value, 'base64');
  if (key.length !== 32) throw new Error('CONTEXTSEAL_EVIDENCE_WRAPPING_KEY must decode to exactly 32 bytes');
  return key;
}
const evidenceWrappingKey = parseEvidenceWrappingKey(process.env.CONTEXTSEAL_EVIDENCE_WRAPPING_KEY);
if (isProduction && !demoMode && (!signingSecret || signingSecret.length < 32)) throw new Error('RECEIPT_SIGNING_KEY must be at least 32 characters in production');
if (requireAuth && (!authToken || authToken.length < 32)) throw new Error('CONTEXTSEAL_AUTH_TOKEN must be at least 32 characters when authentication is enabled');
const databaseUrl = process.env.DATABASE_URL || null;
const ledgerPath = process.env.RECEIPT_LEDGER_PATH || null;
if (isProduction && !demoMode && !databaseUrl && !ledgerPath) throw new Error('DATABASE_URL or RECEIPT_LEDGER_PATH is required outside synthetic demo mode');
const receiptStore = await createReceiptStore({ databaseUrl, ledgerPath });
await receiptStore.initialize();
const mcpUpstream = createMcpUpstreamForwarder({
  url: process.env.CONTEXTSEAL_MCP_UPSTREAM_URL || null,
  allowedOrigins: parseMcpUpstreamAllowedOrigins(process.env.CONTEXTSEAL_MCP_UPSTREAM_ALLOWED_ORIGINS)
});
const approvalTtlMs = Number(process.env.CONTEXTSEAL_APPROVAL_TTL_MS || 5 * 60 * 1000);
const approvalStore = createApprovalStore({ ttlMs: approvalTtlMs });
const requestWindows = new Map();
const configuredRateLimit = Number(process.env.CONTEXTSEAL_MAX_REQUESTS_PER_MINUTE || 60);
const MAX_REQUESTS_PER_MINUTE = Number.isFinite(configuredRateLimit) && configuredRateLimit > 0 ? configuredRateLimit : 60;
const SYNTHETIC_EVIDENCE_EVENTS = Object.freeze([
  { id: 'syn-evt-001', type: 'prompt-injection', severity: 'high', summary: 'Instruction-conflict example stopped at the policy boundary.', details: { payload: '[REDACTED]' }, metadata: { status: 'blocked', source: 'synthetic-demo' } },
  { id: 'syn-evt-002', type: 'dlp', severity: 'high', summary: 'Secret-like pattern example stopped before tool forwarding.', details: { matchedValue: '[REDACTED]' }, metadata: { status: 'blocked', source: 'synthetic-demo' } },
  { id: 'syn-evt-003', type: 'replay', severity: 'medium', summary: 'A synthetic nonce was presented a second time.', details: {}, metadata: { status: 'blocked', source: 'synthetic-demo' } },
  { id: 'syn-evt-004', type: 'approval', severity: 'medium', summary: 'A human decision is required before a synthetic ticket update.', details: {}, metadata: { status: 'pending-review', source: 'synthetic-demo' } },
  { id: 'syn-evt-005', type: 'steganography-signal', severity: 'low', summary: 'A synthetic signal is shown as a future review-queue entry.', details: {}, metadata: { status: 'example-only', detector: 'not-connected', source: 'synthetic-demo' } },
  { id: 'syn-evt-006', type: 'malware-scan', severity: 'low', summary: 'The ledger shape is present, but no malware scan is connected.', details: {}, metadata: { status: 'not-run', detector: 'not-connected', source: 'synthetic-demo' } }
]);
const syntheticEvidence = SYNTHETIC_EVIDENCE_EVENTS.map((event) => createEvidenceEvent(event));

function securityHeaders() { return { 'content-security-policy': "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'", 'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY', 'referrer-policy': 'no-referrer', 'permissions-policy': 'camera=(), microphone=(), geolocation=()', ...(isProduction ? { 'strict-transport-security': 'max-age=31536000; includeSubDomains' } : {}) }; }
function json(res, status, body) { res.writeHead(status, { ...securityHeaders(), 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }); res.end(JSON.stringify(body)); }
function mcpJson(res, status, body) { res.writeHead(status, { ...securityHeaders(), 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'mcp-protocol-version': MCP_PROTOCOL_VERSION }); res.end(JSON.stringify(body)); }
function graph() {
  return { nodes: [
    { id: 'agent', label: 'Agent context', type: 'agent', note: 'opaque refs only' }, { id: 'proxy', label: 'CanaryNorth', type: 'proxy', note: 'policy + DLP + expiry' },
    { id: 'weather', label: 'weather.get_forecast', type: 'tool', note: 'allowlisted' }, { id: 'tickets', label: 'tickets.update', type: 'tool', note: 'scoped resource' },
    { id: 'vault', label: 'Secret vault', type: 'vault', note: 'never enters context' }, { id: 'ledger', label: 'Receipt ledger', type: 'ledger', note: 'hash chained' }
  ], edges: [
    { from: 'agent', to: 'proxy', label: 'cap_*' }, { from: 'proxy', to: 'weather', label: 'permit' }, { from: 'proxy', to: 'tickets', label: 'permit' },
    { from: 'vault', to: 'proxy', label: 'server-side lookup' }, { from: 'proxy', to: 'ledger', label: 'signed receipt' }
  ] };
}
async function body(req) {
  let raw = '';
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 100_000) throw new Error('payload-too-large');
  }
  return raw ? JSON.parse(raw) : {};
}
function clientKey(req) { return req.socket.remoteAddress || 'unknown'; }
function rateLimited(req) {
  const now = Date.now();
  const key = clientKey(req);
  const window = requestWindows.get(key) || { startedAt: now, count: 0 };
  if (now - window.startedAt >= 60_000) { window.startedAt = now; window.count = 0; }
  window.count += 1;
  requestWindows.set(key, window);
  if (requestWindows.size > 10_000) for (const [entryKey, entry] of requestWindows) if (now - entry.startedAt >= 60_000) requestWindows.delete(entryKey);
  return window.count > MAX_REQUESTS_PER_MINUTE;
}
function authorized(req) {
  if (!requireAuth) return true;
  const header = req.headers.authorization || '';
  const provided = header.startsWith('Bearer ') ? Buffer.from(header.slice(7)) : Buffer.alloc(0);
  const expected = Buffer.from(authToken);
  return provided.length === expected.length && crypto.timingSafeEqual(provided, expected);
}
function mcpOriginAllowed(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  const configured = (process.env.CONTEXTSEAL_MCP_ALLOWED_ORIGINS || '').split(',').map((value) => value.trim()).filter(Boolean);
  if (configured.includes(origin)) return true;
  try {
    const parsed = new URL(origin);
    const host = String(req.headers.host || '').toLowerCase();
    const sameOrigin = `${secureCookie(req) ? 'https' : 'http'}://${host}`;
    if (origin === sameOrigin) return true;
    const loopbackHosts = new Set(['localhost', '127.0.0.1', '[::1]']);
    return loopbackHosts.has(parsed.hostname.toLowerCase()) && loopbackHosts.has(host.split(':')[0].toLowerCase()) && parsed.port === host.split(':').at(-1);
  } catch {
    return false;
  }
}
function cookieValue(req, name) {
  const cookies = req.headers.cookie || '';
  for (const part of cookies.split(';')) {
    const [key, ...value] = part.trim().split('=');
    if (key === name) return decodeURIComponent(value.join('='));
  }
  return null;
}
function penGateSessionValid(req) {
  if (!penGatePassword) return false;
  const token = cookieValue(req, PEN_GATE_COOKIE);
  if (!token) return false;
  const createdAt = penGateSessions.get(token);
  if (!createdAt || Date.now() - createdAt > PEN_GATE_SESSION_TTL_MS) {
    penGateSessions.delete(token);
    return false;
  }
  return true;
}
function constantTimeMatch(provided, expected) {
  const providedBytes = Buffer.from(provided);
  const expectedBytes = Buffer.from(expected);
  return providedBytes.length === expectedBytes.length && crypto.timingSafeEqual(providedBytes, expectedBytes);
}
function issuePenGateSession() {
  const token = crypto.randomBytes(32).toString('base64url');
  penGateSessions.set(token, Date.now());
  return token;
}
function secureCookie(req) { return isProduction || req.headers['x-forwarded-proto'] === 'https'; }
function isPenConsolePath(pathname) { return pathname === '/pen-console' || pathname.startsWith('/pen-console/'); }
function isPenGatePage(pathname) { return pathname === '/pen-console/gate.html'; }
function isHtmlRequest(req, pathname) { return pathname.endsWith('.html') || (req.headers.accept || '').includes('text/html'); }
function redirectToPenGate(res, pathname) {
  const returnTo = encodeURIComponent(pathname);
  res.writeHead(302, { ...securityHeaders(), location: `/pen-console/gate.html?returnTo=${returnTo}`, 'cache-control': 'no-store' });
  res.end();
}
function scopeForRequest(req) {
  const tenantId = req.headers['x-contextseal-tenant'];
  const workspaceId = req.headers['x-contextseal-workspace'];
  if (Array.isArray(tenantId) || Array.isArray(workspaceId)) throw new Error('invalid-scope-header');
  if (!!tenantId !== !!workspaceId) throw new Error('complete-scope-header-required');
  if (!demoMode && (!tenantId || !workspaceId)) throw new Error('scope-header-required');
  return { tenantId: tenantId || undefined, workspaceId: workspaceId || undefined };
}
function validateAgenticMetadata(request) {
  const optionalObject = (name) => {
    const value = request[name];
    if (value === undefined) return undefined;
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`invalid-${name}`);
    if (JSON.stringify(value).length > 8_000) throw new Error(`${name}-too-large`);
    return value;
  };
  const toolManifest = optionalObject('toolManifest');
  if (toolManifest) {
    for (const field of ['schema', 'tool', 'version', 'owner', 'signatureStatus', 'digest']) {
      if (typeof toolManifest[field] !== 'string' || toolManifest[field].length < 1 || toolManifest[field].length > 256) throw new Error(`invalid-tool-manifest-${field}`);
    }
    if (!Array.isArray(toolManifest.capabilities) || toolManifest.capabilities.length > 32 || toolManifest.capabilities.some((value) => typeof value !== 'string' || value.length < 1 || value.length > 128)) throw new Error('invalid-tool-manifest-capabilities');
  }
  const memoryContext = optionalObject('memoryContext');
  if (memoryContext) {
    for (const field of ['originTrust', 'tenantId', 'workspaceId', 'policyVersion']) {
      if (memoryContext[field] !== undefined && (typeof memoryContext[field] !== 'string' || memoryContext[field].length < 1 || memoryContext[field].length > 128)) throw new Error(`invalid-memory-${field}`);
    }
    for (const field of ['ageSeconds', 'maxAgeSeconds']) {
      if (memoryContext[field] !== undefined && (!Number.isFinite(memoryContext[field]) || memoryContext[field] < 0 || memoryContext[field] > 31_536_000)) throw new Error(`invalid-memory-${field}`);
    }
  }
  const provenance = optionalObject('provenance');
  if (provenance) {
    for (const field of ['sourceTrust', 'sourceId', 'destinationAgentId', 'intendedRecipient', 'authority']) {
      if (provenance[field] !== undefined && (typeof provenance[field] !== 'string' || provenance[field].length < 1 || provenance[field].length > 256)) throw new Error(`invalid-provenance-${field}`);
    }
    if (provenance.delegated !== undefined && typeof provenance.delegated !== 'boolean') throw new Error('invalid-provenance-delegated');
  }
  const canaryContext = optionalObject('canaryContext');
  if (canaryContext && canaryContext.resource !== undefined && (typeof canaryContext.resource !== 'string' || canaryContext.resource.length > 256)) throw new Error('invalid-canary-resource');
  const adaptiveContext = optionalObject('adaptiveContext');
  if (adaptiveContext && Object.values(adaptiveContext).some((value) => typeof value !== 'boolean')) throw new Error('invalid-adaptive-context');
  const causalContext = optionalObject('causalContext');
  if (causalContext) {
    for (const field of ['trustedPathEdges', 'requiredTrustedEdges', 'untrustedGapCount']) if (causalContext[field] !== undefined && (!Number.isInteger(causalContext[field]) || causalContext[field] < 0 || causalContext[field] > 128)) throw new Error(`invalid-causal-${field}`);
    if (causalContext.actionIntentMatch !== undefined && typeof causalContext.actionIntentMatch !== 'boolean') throw new Error('invalid-causal-action-intent');
  }
  const trustDebtContext = optionalObject('trustDebtContext');
  if (trustDebtContext) {
    if (trustDebtContext.unresolvedSignals !== undefined && (!Number.isInteger(trustDebtContext.unresolvedSignals) || trustDebtContext.unresolvedSignals < 0 || trustDebtContext.unresolvedSignals > 128)) throw new Error('invalid-trust-debt-signals');
    for (const field of ['debtScore', 'debtBudget']) if (trustDebtContext[field] !== undefined && (!Number.isFinite(trustDebtContext[field]) || trustDebtContext[field] < 0 || trustDebtContext[field] > 1)) throw new Error(`invalid-trust-debt-${field}`);
    if (trustDebtContext.sensitiveAction !== undefined && typeof trustDebtContext.sensitiveAction !== 'boolean') throw new Error('invalid-trust-debt-action');
  }
  const delegationContext = optionalObject('delegationContext');
  if (delegationContext) {
    if (delegationContext.delegationExpiresAt !== undefined && (typeof delegationContext.delegationExpiresAt !== 'string' || delegationContext.delegationExpiresAt.length < 1 || delegationContext.delegationExpiresAt.length > 128)) throw new Error('invalid-delegation-expiry');
    for (const field of ['delegatorTrusted', 'receiverTrusted', 'delegated', 'audienceMatches']) if (delegationContext[field] !== undefined && typeof delegationContext[field] !== 'boolean') throw new Error(`invalid-delegation-${field}`);
  }
  const causalBasisContext = optionalObject('causalBasisContext');
  if (causalBasisContext) {
    for (const field of ['trustedBasisPresent', 'actionIntentMatch']) if (causalBasisContext[field] !== undefined && typeof causalBasisContext[field] !== 'boolean') throw new Error(`invalid-causal-basis-${field}`);
    if (causalBasisContext.sourceTrustLevel !== undefined && (typeof causalBasisContext.sourceTrustLevel !== 'string' || causalBasisContext.sourceTrustLevel.length > 64)) throw new Error('invalid-causal-basis-trust-level');
  }
  const revocationLineageContext = optionalObject('revocationLineageContext');
  if (revocationLineageContext) {
    if (revocationLineageContext.authorityId !== undefined && (typeof revocationLineageContext.authorityId !== 'string' || revocationLineageContext.authorityId.length < 1 || revocationLineageContext.authorityId.length > 128)) throw new Error('invalid-revocation-authority-id');
    if (revocationLineageContext.revocationChecked !== undefined && typeof revocationLineageContext.revocationChecked !== 'boolean') throw new Error('invalid-revocation-checked');
    if (revocationLineageContext.revocationVerifiedAt !== undefined && (typeof revocationLineageContext.revocationVerifiedAt !== 'string' || revocationLineageContext.revocationVerifiedAt.length > 128)) throw new Error('invalid-revocation-verified-at');
    if (revocationLineageContext.maxRevocationAgeSeconds !== undefined && (!Number.isFinite(revocationLineageContext.maxRevocationAgeSeconds) || revocationLineageContext.maxRevocationAgeSeconds < 0)) throw new Error('invalid-revocation-max-age');
  }
  const intentNormContext = optionalObject('intentNormContext');
  if (intentNormContext) {
    for (const field of ['approvedIntentHash', 'observedIntentHash']) if (intentNormContext[field] !== undefined && (typeof intentNormContext[field] !== 'string' || intentNormContext[field].length > 128)) throw new Error(`invalid-intent-norm-${field}`);
    for (const field of ['semanticDistance', 'distanceThreshold']) if (intentNormContext[field] !== undefined && (!Number.isFinite(intentNormContext[field]) || intentNormContext[field] < 0 || intentNormContext[field] > 1)) throw new Error(`invalid-intent-norm-${field}`);
    if (intentNormContext.actionIntentMatch !== undefined && typeof intentNormContext.actionIntentMatch !== 'boolean') throw new Error('invalid-intent-norm-action-intent');
  }
  const resourceClassContext = optionalObject('resourceClassContext');
  if (resourceClassContext) {
    for (const field of ['resourceClass', 'approvedClass']) if (resourceClassContext[field] !== undefined && (typeof resourceClassContext[field] !== 'string' || resourceClassContext[field].length > 128)) throw new Error(`invalid-resource-class-${field}`);
    if (resourceClassContext.classMismatch !== undefined && typeof resourceClassContext.classMismatch !== 'boolean') throw new Error('invalid-resource-class-mismatch');
  }
  const recoveryClaimContext = optionalObject('recoveryClaimContext');
  if (recoveryClaimContext) {
    if (recoveryClaimContext.claimedState !== undefined && (typeof recoveryClaimContext.claimedState !== 'string' || recoveryClaimContext.claimedState.length > 64)) throw new Error('invalid-recovery-claimed-state');
    for (const field of ['observedStateHash', 'approvedStateHash']) if (recoveryClaimContext[field] !== undefined && (typeof recoveryClaimContext[field] !== 'string' || recoveryClaimContext[field].length > 128)) throw new Error(`invalid-recovery-${field}`);
    if (recoveryClaimContext.independentCheckPresent !== undefined && typeof recoveryClaimContext.independentCheckPresent !== 'boolean') throw new Error('invalid-recovery-independent-check');
  }
  const skillDescriptorContext = optionalObject('skillDescriptorContext');
  if (skillDescriptorContext) {
    for (const field of ['signaturePresent', 'capabilitySetExpanded']) if (skillDescriptorContext[field] !== undefined && typeof skillDescriptorContext[field] !== 'boolean') throw new Error(`invalid-skill-descriptor-${field}`);
    for (const field of ['currentOwner', 'pinnedOwner', 'currentVersion', 'pinnedVersion']) if (skillDescriptorContext[field] !== undefined && (typeof skillDescriptorContext[field] !== 'string' || skillDescriptorContext[field].length > 128)) throw new Error(`invalid-skill-descriptor-${field}`);
  }
  const memoryGraftContext = optionalObject('memoryGraftContext');
  if (memoryGraftContext) {
    for (const field of ['memoryReviewed', 'poisonedRecordsPresent']) if (memoryGraftContext[field] !== undefined && typeof memoryGraftContext[field] !== 'boolean') throw new Error(`invalid-memory-graft-${field}`);
    for (const field of ['trustedRecords', 'memoryAgeSeconds', 'maxAgeSeconds']) if (memoryGraftContext[field] !== undefined && (!Number.isInteger(memoryGraftContext[field]) || memoryGraftContext[field] < 0)) throw new Error(`invalid-memory-graft-${field}`);
    for (const field of ['tenantId', 'expectedTenantId']) if (memoryGraftContext[field] !== undefined && (typeof memoryGraftContext[field] !== 'string' || memoryGraftContext[field].length > 128)) throw new Error(`invalid-memory-graft-${field}`);
  }
  const agentBoundaryContext = optionalObject('agentBoundaryContext');
  if (agentBoundaryContext) {
    for (const field of ['summaryTrustAmplified', 'skillOriginMatch', 'delegationAudienceMatch', 'messageReplayed']) if (agentBoundaryContext[field] !== undefined && typeof agentBoundaryContext[field] !== 'boolean') throw new Error(`invalid-agent-boundary-${field}`);
  }
  const canaryEventContext = optionalObject('canaryEventContext');
  if (canaryEventContext) {
    for (const field of ['resourceIsCanary', 'exportIntended', 'eventRepeated']) if (canaryEventContext[field] !== undefined && typeof canaryEventContext[field] !== 'boolean') throw new Error(`invalid-canary-event-${field}`);
  }
  const secondLockContext = optionalObject('secondLockContext');
  if (secondLockContext) {
    for (const field of ['sensitiveAction', 'recoveryPath', 'privilegedAction', 'nonceFresh', 'deviceTrusted', 'newDevice']) if (secondLockContext[field] !== undefined && typeof secondLockContext[field] !== 'boolean') throw new Error(`invalid-second-lock-${field}`);
    if (secondLockContext.pushCount !== undefined && (!Number.isInteger(secondLockContext.pushCount) || secondLockContext.pushCount < 0)) throw new Error('invalid-second-lock-push-count');
    for (const field of ['authSessionId', 'actionSessionId', 'factorType', 'carrierRisk', 'approvedScope', 'requestedScope']) if (secondLockContext[field] !== undefined && (typeof secondLockContext[field] !== 'string' || secondLockContext[field].length > 128)) throw new Error(`invalid-second-lock-${field}`);
  }
  const frontierGapContext = optionalObject('frontierGapContext');
  if (frontierGapContext) {
    for (const field of ['provenanceChanged', 'rewardScoreChanged', 'userObjectiveChanged', 'serviceListed', 'serviceConnected', 'collusionObserved', 'verifiedAgentId', 'signedEnvelopePresent', 'cascadePredicted']) if (frontierGapContext[field] !== undefined && typeof frontierGapContext[field] !== 'boolean') throw new Error(`invalid-frontier-gap-${field}`);
    for (const field of ['rogueAgentCount', 'dependentAgentCount', 'fanoutBudget', 'contextItems', 'contextBudget']) if (frontierGapContext[field] !== undefined && (!Number.isInteger(frontierGapContext[field]) || frontierGapContext[field] < 0)) throw new Error(`invalid-frontier-gap-${field}`);
  }
  const controlFlowContext = optionalObject('controlFlowContext');
  if (controlFlowContext) {
    if (controlFlowContext.checkStatus !== undefined && (typeof controlFlowContext.checkStatus !== 'string' || controlFlowContext.checkStatus.length > 64)) throw new Error('invalid-control-flow-check-status');
    if (controlFlowContext.defaultAction !== undefined && (typeof controlFlowContext.defaultAction !== 'string' || controlFlowContext.defaultAction.length > 64)) throw new Error('invalid-control-flow-default-action');
    if (controlFlowContext.primaryStatus !== undefined && (typeof controlFlowContext.primaryStatus !== 'string' || controlFlowContext.primaryStatus.length > 64)) throw new Error('invalid-control-flow-primary-status');
    for (const field of ['fallbackStrength', 'requiredStrength', 'denialCount']) if (controlFlowContext[field] !== undefined && (!Number.isFinite(controlFlowContext[field]) || controlFlowContext[field] < 0)) throw new Error(`invalid-control-flow-${field}`);
    if (controlFlowContext.errorSourceTrust !== undefined && (typeof controlFlowContext.errorSourceTrust !== 'string' || controlFlowContext.errorSourceTrust.length > 64)) throw new Error('invalid-control-flow-error-source-trust');
    if (controlFlowContext.errorContainsInstruction !== undefined && typeof controlFlowContext.errorContainsInstruction !== 'boolean') throw new Error('invalid-control-flow-error-contains-instruction');
    if (controlFlowContext.recoveryImpact !== undefined && (typeof controlFlowContext.recoveryImpact !== 'string' || controlFlowContext.recoveryImpact.length > 64)) throw new Error('invalid-control-flow-recovery-impact');
  }
  const approvalFreshnessContext = optionalObject('approvalFreshnessContext');
  if (approvalFreshnessContext) {
    if (approvalFreshnessContext.approvalExpired !== undefined && typeof approvalFreshnessContext.approvalExpired !== 'boolean') throw new Error('invalid-approval-freshness-expired');
  }
  const outcomeIntegrityContext = optionalObject('outcomeIntegrityContext');
  if (outcomeIntegrityContext) {
    for (const field of ['claimedSuccess', 'receiptMatchesObservation']) if (outcomeIntegrityContext[field] !== undefined && typeof outcomeIntegrityContext[field] !== 'boolean') throw new Error(`invalid-outcome-integrity-${field}`);
  }
  const quarantineReentryContext = optionalObject('quarantineReentryContext');
  if (quarantineReentryContext) {
    if (quarantineReentryContext.quarantineState !== undefined && (typeof quarantineReentryContext.quarantineState !== 'string' || quarantineReentryContext.quarantineState.length > 64)) throw new Error('invalid-quarantine-reentry-state');
  }
  const scopeAccumulationContext = optionalObject('scopeAccumulationContext');
  if (scopeAccumulationContext) {
    for (const field of ['cumulativeRiskFlagged', 'scopeExpanded']) if (scopeAccumulationContext[field] !== undefined && typeof scopeAccumulationContext[field] !== 'boolean') throw new Error(`invalid-scope-accumulation-${field}`);
  }
  const workflowGraphContext = optionalObject('workflowGraphContext');
  if (workflowGraphContext) {
    for (const field of ['unexpectedEdgeCount', 'expectedEdgeCount', 'observedEdgeCount']) if (workflowGraphContext[field] !== undefined && (!Number.isInteger(workflowGraphContext[field]) || workflowGraphContext[field] < 0)) throw new Error(`invalid-workflow-graph-${field}`);
  }
  const consensusProvenanceContext = optionalObject('consensusProvenanceContext');
  if (consensusProvenanceContext) {
    for (const field of ['sharedRoot']) if (consensusProvenanceContext[field] !== undefined && typeof consensusProvenanceContext[field] !== 'boolean') throw new Error(`invalid-consensus-provenance-${field}`);
    for (const field of ['apparentAgreement', 'independentEvidence', 'requiredIndependentEvidence']) if (consensusProvenanceContext[field] !== undefined && (!Number.isInteger(consensusProvenanceContext[field]) || consensusProvenanceContext[field] < 0)) throw new Error(`invalid-consensus-provenance-${field}`);
  }
  const approvalAgeContext = optionalObject('approvalAgeContext');
  if (approvalAgeContext) {
    for (const field of ['approvalAgeSeconds', 'maxApprovalAgeSeconds']) if (approvalAgeContext[field] !== undefined && (!Number.isFinite(approvalAgeContext[field]) || approvalAgeContext[field] < 0)) throw new Error(`invalid-approval-age-${field}`);
  }
  const policyGravityContext = optionalObject('policyGravityContext');
  if (policyGravityContext) {
    if (policyGravityContext.highestImpactDecision !== undefined && (typeof policyGravityContext.highestImpactDecision !== 'string' || policyGravityContext.highestImpactDecision.length > 64)) throw new Error('invalid-policy-gravity-highest-impact');
    if (policyGravityContext.monotonicEvidence !== undefined && typeof policyGravityContext.monotonicEvidence !== 'boolean') throw new Error('invalid-policy-gravity-monotonic-evidence');
  }
  const intentTrajectoryContext = optionalObject('intentTrajectoryContext');
  if (intentTrajectoryContext) {
    if (intentTrajectoryContext.fragmentCount !== undefined && (typeof intentTrajectoryContext.fragmentCount !== 'number' || intentTrajectoryContext.fragmentCount < 0)) throw new Error('invalid-intent-trajectory-fragment-count');
    if (intentTrajectoryContext.finalSensitivity !== undefined && (typeof intentTrajectoryContext.finalSensitivity !== 'string' || intentTrajectoryContext.finalSensitivity.length > 64)) throw new Error('invalid-intent-trajectory-final-sensitivity');
    if (intentTrajectoryContext.intentDrift !== undefined && typeof intentTrajectoryContext.intentDrift !== 'boolean') throw new Error('invalid-intent-trajectory-intent-drift');
  }
  const clockSplitContext = optionalObject('clockSplitContext');
  if (clockSplitContext) {
    for (const field of ['primaryExpired', 'secondaryValid', 'clockAgreement']) if (clockSplitContext[field] !== undefined && typeof clockSplitContext[field] !== 'boolean') throw new Error(`invalid-clock-split-${field}`);
  }
  const tenantMirrorContext = optionalObject('tenantMirrorContext');
  if (tenantMirrorContext) {
    if (tenantMirrorContext.resourceLabelMatches !== undefined && typeof tenantMirrorContext.resourceLabelMatches !== 'boolean') throw new Error('invalid-tenant-mirror-resource-label-matches');
    for (const field of ['resourceTenant', 'requestTenant']) if (tenantMirrorContext[field] !== undefined && (typeof tenantMirrorContext[field] !== 'string' || tenantMirrorContext[field].length > 128)) throw new Error(`invalid-tenant-mirror-${field}`);
  }
  const evidenceMasqueradeContext = optionalObject('evidenceMasqueradeContext');
  if (evidenceMasqueradeContext) {
    if (evidenceMasqueradeContext.claimedApproval !== undefined && typeof evidenceMasqueradeContext.claimedApproval !== 'boolean') throw new Error('invalid-evidence-masquerade-claimed-approval');
    if (evidenceMasqueradeContext.authoritativeRecord !== undefined && (typeof evidenceMasqueradeContext.authoritativeRecord !== 'string' || evidenceMasqueradeContext.authoritativeRecord.length > 64)) throw new Error('invalid-evidence-masquerade-authoritative-record');
    if (evidenceMasqueradeContext.provenanceVerified !== undefined && typeof evidenceMasqueradeContext.provenanceVerified !== 'boolean') throw new Error('invalid-evidence-masquerade-provenance-verified');
  }
  const secretFocusContext = optionalObject('secretFocusContext');
  if (secretFocusContext) {
    if (secretFocusContext.channel !== undefined && (typeof secretFocusContext.channel !== 'string' || secretFocusContext.channel.length > 64)) throw new Error('invalid-secret-focus-channel');
    if (secretFocusContext.secretFieldFocused !== undefined && typeof secretFocusContext.secretFieldFocused !== 'boolean') throw new Error('invalid-secret-focus-secret-field-focused');
    if (secretFocusContext.consent !== undefined && (typeof secretFocusContext.consent !== 'string' || secretFocusContext.consent.length > 64)) throw new Error('invalid-secret-focus-consent');
  }
  const backgroundListenerContext = optionalObject('backgroundListenerContext');
  if (backgroundListenerContext) {
    if (backgroundListenerContext.scope !== undefined && (typeof backgroundListenerContext.scope !== 'string' || backgroundListenerContext.scope.length > 64)) throw new Error('invalid-background-listener-scope');
    if (backgroundListenerContext.ownerApproved !== undefined && typeof backgroundListenerContext.ownerApproved !== 'boolean') throw new Error('invalid-background-listener-owner-approved');
  }
  const keystreamRetentionContext = optionalObject('keystreamRetentionContext');
  if (keystreamRetentionContext) {
    if (keystreamRetentionContext.channel !== undefined && (typeof keystreamRetentionContext.channel !== 'string' || keystreamRetentionContext.channel.length > 64)) throw new Error('invalid-keystream-retention-channel');
    if (keystreamRetentionContext.retention !== undefined && (typeof keystreamRetentionContext.retention !== 'string' || keystreamRetentionContext.retention.length > 64)) throw new Error('invalid-keystream-retention-retention');
    if (keystreamRetentionContext.purposeDeclared !== undefined && typeof keystreamRetentionContext.purposeDeclared !== 'boolean') throw new Error('invalid-keystream-retention-purpose-declared');
  }
  const hiddenCaptureStateContext = optionalObject('hiddenCaptureStateContext');
  if (hiddenCaptureStateContext) {
    if (hiddenCaptureStateContext.visibility !== undefined && (typeof hiddenCaptureStateContext.visibility !== 'string' || hiddenCaptureStateContext.visibility.length > 64)) throw new Error('invalid-hidden-capture-state-visibility');
    if (hiddenCaptureStateContext.captureState !== undefined && (typeof hiddenCaptureStateContext.captureState !== 'string' || hiddenCaptureStateContext.captureState.length > 64)) throw new Error('invalid-hidden-capture-state-capture-state');
  }
  const redactionGapContext = optionalObject('redactionGapContext');
  if (redactionGapContext) {
    if (redactionGapContext.sensitiveFieldPresent !== undefined && typeof redactionGapContext.sensitiveFieldPresent !== 'boolean') throw new Error('invalid-redaction-gap-sensitive-field-present');
    if (redactionGapContext.redactionMarkerPresent !== undefined && typeof redactionGapContext.redactionMarkerPresent !== 'boolean') throw new Error('invalid-redaction-gap-redaction-marker-present');
  }
  const audienceMismatchContext = optionalObject('audienceMismatchContext');
  if (audienceMismatchContext) {
    if (audienceMismatchContext.audience !== undefined && (typeof audienceMismatchContext.audience !== 'string' || audienceMismatchContext.audience.length > 64)) throw new Error('invalid-audience-mismatch-audience');
    if (audienceMismatchContext.evidenceClass !== undefined && (typeof audienceMismatchContext.evidenceClass !== 'string' || audienceMismatchContext.evidenceClass.length > 64)) throw new Error('invalid-audience-mismatch-evidence-class');
  }
  const reconstructionRiskContext = optionalObject('reconstructionRiskContext');
  if (reconstructionRiskContext) {
    if (reconstructionRiskContext.linkableFieldCount !== undefined && (typeof reconstructionRiskContext.linkableFieldCount !== 'number' || reconstructionRiskContext.linkableFieldCount < 0)) throw new Error('invalid-reconstruction-risk-linkable-field-count');
    if (reconstructionRiskContext.identityRisk !== undefined && (typeof reconstructionRiskContext.identityRisk !== 'string' || reconstructionRiskContext.identityRisk.length > 64)) throw new Error('invalid-reconstruction-risk-identity-risk');
  }
  const exportDriftContext = optionalObject('exportDriftContext');
  if (exportDriftContext) {
    if (exportDriftContext.sourceRedacted !== undefined && typeof exportDriftContext.sourceRedacted !== 'boolean') throw new Error('invalid-export-drift-source-redacted');
    if (exportDriftContext.exportRedacted !== undefined && typeof exportDriftContext.exportRedacted !== 'boolean') throw new Error('invalid-export-drift-export-redacted');
  }
  const toolPivotContext = optionalObject('toolPivotContext');
  if (toolPivotContext) {
    for (const field of ['firstToolTrusted', 'secondToolRequested', 'secondToolScopeApproved']) if (toolPivotContext[field] !== undefined && typeof toolPivotContext[field] !== 'boolean') throw new Error(`invalid-tool-pivot-${field}`);
  }
  const memoryPermissionShadowContext = optionalObject('memoryPermissionShadowContext');
  if (memoryPermissionShadowContext) {
    for (const field of ['ownerVerified', 'modeSafe', 'tenantBound', 'freshnessVerified']) if (memoryPermissionShadowContext[field] !== undefined && typeof memoryPermissionShadowContext[field] !== 'boolean') throw new Error(`invalid-memory-permission-shadow-${field}`);
  }
  const schemaAuthorityContext = optionalObject('schemaAuthorityContext');
  if (schemaAuthorityContext) {
    if (schemaAuthorityContext.parameterControlsDestination !== undefined && typeof schemaAuthorityContext.parameterControlsDestination !== 'boolean') throw new Error('invalid-schema-authority-parameter-controls-destination');
    if (schemaAuthorityContext.destinationPolicyValidated !== undefined && typeof schemaAuthorityContext.destinationPolicyValidated !== 'boolean') throw new Error('invalid-schema-authority-destination-policy-validated');
  }
  const mcpScopeCrosswireContext = optionalObject('mcpScopeCrosswireContext');
  if (mcpScopeCrosswireContext) {
    if (mcpScopeCrosswireContext.requestedScope !== undefined && (typeof mcpScopeCrosswireContext.requestedScope !== 'string' || mcpScopeCrosswireContext.requestedScope.length > 64)) throw new Error('invalid-mcp-scope-crosswire-requested-scope');
    if (mcpScopeCrosswireContext.handlerMutates !== undefined && typeof mcpScopeCrosswireContext.handlerMutates !== 'boolean') throw new Error('invalid-mcp-scope-crosswire-handler-mutates');
  }
  const lifecycleHookContext = optionalObject('lifecycleHookContext');
  if (lifecycleHookContext) {
    for (const field of ['lifecycleChanged', 'futureRunAffected', 'ownerApproval']) if (lifecycleHookContext[field] !== undefined && typeof lifecycleHookContext[field] !== 'boolean') throw new Error(`invalid-lifecycle-hook-${field}`);
  }
  const agenticSsrfContext = optionalObject('agenticSsrfContext');
  if (agenticSsrfContext) {
    if (agenticSsrfContext.destinationUserControlled !== undefined && typeof agenticSsrfContext.destinationUserControlled !== 'boolean') throw new Error('invalid-agentic-ssrf-destination-user-controlled');
    if (agenticSsrfContext.destinationClass !== undefined && (typeof agenticSsrfContext.destinationClass !== 'string' || agenticSsrfContext.destinationClass.length > 64)) throw new Error('invalid-agentic-ssrf-destination-class');
  }
  const contextFanoutContext = optionalObject('contextFanoutContext');
  if (contextFanoutContext) {
    for (const field of ['branchCount', 'branchBudget', 'retryCount', 'retryBudget', 'delegatedAgentCount', 'agentBudget']) if (contextFanoutContext[field] !== undefined && (typeof contextFanoutContext[field] !== 'number' || contextFanoutContext[field] < 0)) throw new Error(`invalid-context-fanout-${field}`);
    if (contextFanoutContext.tokenBudgetExceeded !== undefined && typeof contextFanoutContext.tokenBudgetExceeded !== 'boolean') throw new Error('invalid-context-fanout-token-budget-exceeded');
  }
  const retrievalRankingContext = optionalObject('retrievalRankingContext');
  if (retrievalRankingContext) {
    if (retrievalRankingContext.rankingDominance !== undefined && typeof retrievalRankingContext.rankingDominance !== 'boolean') throw new Error('invalid-retrieval-ranking-ranking-dominance');
    if (retrievalRankingContext.topResultTrust !== undefined && (typeof retrievalRankingContext.topResultTrust !== 'string' || retrievalRankingContext.topResultTrust.length > 64)) throw new Error('invalid-retrieval-ranking-top-result-trust');
  }
  const observationActionGapContext = optionalObject('observationActionGapContext');
  if (observationActionGapContext) {
    for (const field of ['evidenceDigestMatches', 'independentEvidence']) if (observationActionGapContext[field] !== undefined && typeof observationActionGapContext[field] !== 'boolean') throw new Error(`invalid-observation-action-gap-${field}`);
  }
  const promptwareRelayContext = optionalObject('promptwareRelayContext');
  if (promptwareRelayContext) {
    for (const field of ['externalContent', 'originPreserved', 'sensitiveAction']) if (promptwareRelayContext[field] !== undefined && typeof promptwareRelayContext[field] !== 'boolean') throw new Error(`invalid-promptware-relay-${field}`);
  }
  const trajectoryForkContext = optionalObject('trajectoryForkContext');
  if (trajectoryForkContext) {
    for (const field of ['approvedBranchCount', 'observedBranchCount']) if (trajectoryForkContext[field] !== undefined && (typeof trajectoryForkContext[field] !== 'number' || trajectoryForkContext[field] < 0)) throw new Error(`invalid-trajectory-fork-${field}`);
    if (trajectoryForkContext.unexpectedBranch !== undefined && typeof trajectoryForkContext.unexpectedBranch !== 'boolean') throw new Error('invalid-trajectory-fork-unexpected-branch');
  }
  const passportSmuggleContext = optionalObject('passportSmuggleContext');
  if (passportSmuggleContext) {
    for (const field of ['ownerVerified', 'audienceChanged', 'capabilitySetChanged', 'approvalInherited']) if (passportSmuggleContext[field] !== undefined && typeof passportSmuggleContext[field] !== 'boolean') throw new Error(`invalid-passport-smuggle-${field}`);
  }
  const browserOriginClaimContext = optionalObject('browserOriginClaimContext');
  if (browserOriginClaimContext) {
    for (const field of ['originClaimVerified', 'boundaryTrusted']) if (browserOriginClaimContext[field] !== undefined && typeof browserOriginClaimContext[field] !== 'boolean') throw new Error(`invalid-browser-origin-claim-${field}`);
  }
  const tokenFurnaceContext = optionalObject('tokenFurnaceContext');
  if (tokenFurnaceContext) {
    for (const field of ['tokenLikeMetadataPresent', 'secretMaterialPresent']) if (tokenFurnaceContext[field] !== undefined && typeof tokenFurnaceContext[field] !== 'boolean') throw new Error(`invalid-token-furnace-${field}`);
  }
  const routeAmbiguityContext = optionalObject('routeAmbiguityContext');
  if (routeAmbiguityContext) {
    if (routeAmbiguityContext.routeAmbiguous !== undefined && typeof routeAmbiguityContext.routeAmbiguous !== 'boolean') throw new Error('invalid-route-ambiguity-route-ambiguous');
  }
  const quietPermissionContext = optionalObject('quietPermissionContext');
  if (quietPermissionContext) {
    if (quietPermissionContext.componentScopeCount !== undefined && (typeof quietPermissionContext.componentScopeCount !== 'number' || quietPermissionContext.componentScopeCount < 0)) throw new Error('invalid-quiet-permission-component-scope-count');
    if (quietPermissionContext.composedImpact !== undefined && (typeof quietPermissionContext.composedImpact !== 'string' || quietPermissionContext.composedImpact.length > 64)) throw new Error('invalid-quiet-permission-composed-impact');
    if (quietPermissionContext.freshApproval !== undefined && typeof quietPermissionContext.freshApproval !== 'boolean') throw new Error('invalid-quiet-permission-fresh-approval');
  }
  const schedulerDriftContext = optionalObject('schedulerDriftContext');
  if (schedulerDriftContext) {
    if (schedulerDriftContext.freshnessAgreement !== undefined && typeof schedulerDriftContext.freshnessAgreement !== 'boolean') throw new Error('invalid-scheduler-drift-freshness-agreement');
    if (schedulerDriftContext.timeSources !== undefined && (typeof schedulerDriftContext.timeSources !== 'number' || schedulerDriftContext.timeSources < 0)) throw new Error('invalid-scheduler-drift-time-sources');
  }
  const evidenceShadowContext = optionalObject('evidenceShadowContext');
  if (evidenceShadowContext) {
    for (const field of ['evidenceItems', 'verifiedItems']) if (evidenceShadowContext[field] !== undefined && (typeof evidenceShadowContext[field] !== 'number' || evidenceShadowContext[field] < 0)) throw new Error(`invalid-evidence-shadow-${field}`);
    if (evidenceShadowContext.provenanceVisible !== undefined && typeof evidenceShadowContext.provenanceVisible !== 'boolean') throw new Error('invalid-evidence-shadow-provenance-visible');
  }
  const modelIdentityMirageContext = optionalObject('modelIdentityMirageContext');
  if (modelIdentityMirageContext) {
    if (modelIdentityMirageContext.identityMatch !== undefined && typeof modelIdentityMirageContext.identityMatch !== 'boolean') throw new Error('invalid-model-identity-mirage-identity-match');
    for (const field of ['approvedIdentityClass', 'observedIdentityClass']) if (modelIdentityMirageContext[field] !== undefined && (typeof modelIdentityMirageContext[field] !== 'string' || modelIdentityMirageContext[field].length > 128)) throw new Error(`invalid-model-identity-mirage-${field}`);
  }
  const platformPassportContext = optionalObject('platformPassportContext');
  if (platformPassportContext) {
    if (platformPassportContext.platformCount !== undefined && (typeof platformPassportContext.platformCount !== 'number' || platformPassportContext.platformCount < 0)) throw new Error('invalid-platform-passport-platform-count');
    for (const field of ['permissionAgreement', 'provenanceAgreement']) if (platformPassportContext[field] !== undefined && typeof platformPassportContext[field] !== 'boolean') throw new Error(`invalid-platform-passport-${field}`);
  }
  const executionBoundaryContext = optionalObject('executionBoundaryContext');
  if (executionBoundaryContext) {
    for (const field of ['executionRequested', 'executableContentPresent', 'executionAllowed']) if (executionBoundaryContext[field] !== undefined && typeof executionBoundaryContext[field] !== 'boolean') throw new Error(`invalid-execution-boundary-${field}`);
  }
  const corpusTaintContext = optionalObject('corpusTaintContext');
  if (corpusTaintContext) {
    for (const field of ['sourceSplitMismatch', 'corpusVersionChanged']) if (corpusTaintContext[field] !== undefined && typeof corpusTaintContext[field] !== 'boolean') throw new Error(`invalid-corpus-taint-${field}`);
  }
  const toolInventoryContext = optionalObject('toolInventoryContext');
  if (toolInventoryContext) {
    for (const field of ['inventoryMatch', 'registryRecordPresent']) if (toolInventoryContext[field] !== undefined && typeof toolInventoryContext[field] !== 'boolean') throw new Error(`invalid-tool-inventory-${field}`);
  }
  const modelExposureContext = optionalObject('modelExposureContext');
  if (modelExposureContext) {
    for (const field of ['extractionRequested', 'weightsIncluded']) if (modelExposureContext[field] !== undefined && typeof modelExposureContext[field] !== 'boolean') throw new Error(`invalid-model-exposure-${field}`);
  }
  const approvalCarouselContext = optionalObject('approvalCarouselContext');
  if (approvalCarouselContext) {
    if (approvalCarouselContext.approvalCount !== undefined && (typeof approvalCarouselContext.approvalCount !== 'number' || approvalCarouselContext.approvalCount < 0)) throw new Error('invalid-approval-carousel-approval-count');
    if (approvalCarouselContext.sensitiveAction !== undefined && typeof approvalCarouselContext.sensitiveAction !== 'boolean') throw new Error('invalid-approval-carousel-sensitive-action');
  }
  const blastRadiusContext = optionalObject('blastRadiusContext');
  if (blastRadiusContext) {
    for (const field of ['projectedActions', 'actionBudget']) if (blastRadiusContext[field] !== undefined && (typeof blastRadiusContext[field] !== 'number' || blastRadiusContext[field] < 0)) throw new Error(`invalid-blast-radius-${field}`);
  }
  const recoveryTrapdoorContext = optionalObject('recoveryTrapdoorContext');
  if (recoveryTrapdoorContext) {
    for (const field of ['recoveryStrength', 'sessionStrength']) if (recoveryTrapdoorContext[field] !== undefined && typeof recoveryTrapdoorContext[field] !== 'number') throw new Error(`invalid-recovery-trapdoor-${field}`);
  }
  const longGameContext = optionalObject('longGameContext');
  if (longGameContext) {
    if (longGameContext.stageCount !== undefined && (typeof longGameContext.stageCount !== 'number' || longGameContext.stageCount < 0)) throw new Error('invalid-long-game-stage-count');
    if (longGameContext.sensitiveAction !== undefined && typeof longGameContext.sensitiveAction !== 'boolean') throw new Error('invalid-long-game-sensitive-action');
  }
  const dependencyDoppelgangerContext = optionalObject('dependencyDoppelgangerContext');
  if (dependencyDoppelgangerContext) {
    for (const field of ['ownerChanged', 'digestChanged', 'executionPermissionChanged']) if (dependencyDoppelgangerContext[field] !== undefined && typeof dependencyDoppelgangerContext[field] !== 'boolean') throw new Error(`invalid-dependency-doppelganger-${field}`);
  }
  return { toolManifest, memoryContext, provenance, canaryContext, adaptiveContext, causalContext, trustDebtContext, delegationContext, causalBasisContext, revocationLineageContext, intentNormContext, resourceClassContext, recoveryClaimContext, skillDescriptorContext, memoryGraftContext, agentBoundaryContext, canaryEventContext, secondLockContext, frontierGapContext, controlFlowContext, approvalFreshnessContext, outcomeIntegrityContext, quarantineReentryContext, scopeAccumulationContext, workflowGraphContext, consensusProvenanceContext, approvalAgeContext, policyGravityContext, intentTrajectoryContext, clockSplitContext, tenantMirrorContext, evidenceMasqueradeContext, secretFocusContext, backgroundListenerContext, keystreamRetentionContext, hiddenCaptureStateContext, redactionGapContext, audienceMismatchContext, reconstructionRiskContext, exportDriftContext, toolPivotContext, memoryPermissionShadowContext, schemaAuthorityContext, mcpScopeCrosswireContext, lifecycleHookContext, agenticSsrfContext, contextFanoutContext, retrievalRankingContext, observationActionGapContext, promptwareRelayContext, trajectoryForkContext, passportSmuggleContext, browserOriginClaimContext, tokenFurnaceContext, routeAmbiguityContext, quietPermissionContext, schedulerDriftContext, evidenceShadowContext, modelIdentityMirageContext, platformPassportContext, executionBoundaryContext, corpusTaintContext, toolInventoryContext, modelExposureContext, approvalCarouselContext, blastRadiusContext, recoveryTrapdoorContext, longGameContext, dependencyDoppelgangerContext };
}
function validateAuthorizationRequest(request) {
  if (!request || Array.isArray(request) || typeof request !== 'object') throw new Error('request-object-required');
  if ('now' in request) throw new Error('server-time-only');
  for (const field of ['capabilityId', 'action', 'resource']) if (typeof request[field] !== 'string' || request[field].length < 1 || request[field].length > 256) throw new Error(`invalid-${field}`);
  if (request.input !== undefined && typeof request.input !== 'string' && (typeof request.input !== 'object' || request.input === null)) throw new Error('invalid-input');
  const input = request.input === undefined ? '' : request.input;
  if (JSON.stringify(input).length > 50_000) throw new Error('input-too-large');
  for (const field of ['principal', 'audience', 'tenantId', 'workspaceId', 'policyVersion', 'nonce']) {
    if (request[field] !== undefined && (typeof request[field] !== 'string' || request[field].length < 1 || request[field].length > 128)) throw new Error(`invalid-${field}`);
  }
  if (!demoMode && !request.principal) throw new Error('principal-required');
  if (!demoMode && !request.audience) throw new Error('audience-required');
  if (!demoMode && !request.nonce) throw new Error('nonce-required');
  if (!demoMode && request.policyVersion !== POLICY_VERSION) throw new Error('policy-version-required');
  if (!demoMode && !request.tenantId) throw new Error('tenant-required');
  if (!demoMode && !request.workspaceId) throw new Error('workspace-required');
  const demoControls = request.demoControls === undefined ? undefined : request.demoControls;
  if (demoControls !== undefined && (!demoMode || !demoControls || typeof demoControls !== 'object' || Array.isArray(demoControls))) throw new Error('demo-controls-disabled');
  if (demoControls && Object.values(demoControls).some((value) => typeof value !== 'boolean')) throw new Error('invalid-demo-controls');
  const agenticMetadata = validateAgenticMetadata(request);
  return {
    capabilityId: request.capabilityId,
    action: request.action,
    resource: request.resource,
    input,
    principal: request.principal,
    audience: request.audience,
    tenantId: request.tenantId,
    workspaceId: request.workspaceId,
    policyVersion: request.policyVersion,
    nonce: request.nonce,
    demoControls,
    ...agenticMetadata
  };
}
function validateApprovalRequest(request) {
  const validated = validateAuthorizationRequest(request);
  if (!Object.prototype.hasOwnProperty.call(request, 'input')) throw new Error('approval-input-required');
  for (const field of ['principal', 'audience', 'tenantId', 'workspaceId', 'policyVersion', 'nonce']) {
    if (!validated[field]) throw new Error(`approval-${field}-required`);
  }
  if (validated.action !== 'tickets.update') throw new Error('approval-capability-not-supported');
  return validated;
}
function validateApprovalCommand(request, approvalId) {
  if (!request || Array.isArray(request) || typeof request !== 'object') throw new Error('request-object-required');
  if (request.approvalId !== undefined && (typeof request.approvalId !== 'string' || request.approvalId !== approvalId)) throw new Error('approval-id-mismatch');
  return request;
}
function validateAuditRequest(request) {
  if (!request || Array.isArray(request) || typeof request !== 'object' || request.method !== 'contextseal.audit') throw new Error('read-only-audit-method-required');
  if (request.id !== undefined && request.id !== null && !['string', 'number'].includes(typeof request.id)) throw new Error('invalid-jsonrpc-id');
  return request;
}
function validateArtifactRequest(request) {
  if (!request || Array.isArray(request) || typeof request !== 'object') throw new Error('request-object-required');
  if (typeof request.receiptId !== 'string' || request.receiptId.length > 64) throw new Error('invalid-receipt-id');
  if (typeof request.filename !== 'string' || !/^[a-zA-Z0-9._-]{1,120}$/.test(request.filename)) throw new Error('invalid-filename');
  if (typeof request.content !== 'string' || request.content.length > 100_000) throw new Error('invalid-artifact-content');
  for (const field of ['tenantId', 'workspaceId']) {
    if (request[field] !== undefined && (typeof request[field] !== 'string' || request[field].length < 1 || request[field].length > 128)) throw new Error(`invalid-${field}`);
  }
  if (!demoMode && (!request.tenantId || !request.workspaceId)) throw new Error('artifact-scope-required');
  return request;
}
function validateVerifyRequest(request) {
  if (!request || Array.isArray(request) || typeof request !== 'object') throw new Error('request-object-required');
  if (typeof request.filename !== 'string' || typeof request.content !== 'string' || !request.manifest || typeof request.manifest !== 'object') throw new Error('artifact-package-required');
  if (request.approved !== undefined) {
    if (!request.approved || typeof request.approved !== 'object' || typeof request.approved.filename !== 'string' || typeof request.approved.content !== 'string' || !request.approved.manifest || typeof request.approved.manifest !== 'object') throw new Error('approved-artifact-package-required');
    if (request.approved.content.length > 100_000 || request.content.length > 100_000) throw new Error('artifact-content-too-large');
  }
  return request;
}
function validateEvidencePackageRequest(request) {
  if (!request || Array.isArray(request) || typeof request !== 'object') throw new Error('request-object-required');
  if (request.eventIds !== undefined && (!Array.isArray(request.eventIds) || request.eventIds.some((id) => typeof id !== 'string'))) throw new Error('invalid-evidence-event-ids');
  return request;
}
function makeReceipt(result, request, { sequence, previousReceipt, approvalId, approvalDecision } = {}) {
  const base = {
    id: `rcpt_${String(sequence).padStart(4, '0')}`,
    timestamp: new Date().toISOString(),
    policyVersion: POLICY_VERSION,
    principal: result.capability?.principal || 'unknown',
    audience: result.capability?.audience || request.audience || null,
    tenantId: result.capability?.tenantId || request.tenantId || 'unscoped',
    workspaceId: result.capability?.workspaceId || request.workspaceId || 'unscoped',
    nonce: request.nonce || null,
    action: request.action || 'unknown',
    resource: request.resource || 'unknown',
    decision: result.allowed ? 'allow' : 'deny',
    reasonCode: result.allowed ? 'policy-passed' : result.code,
    capabilityId: request.capabilityId || null,
    previousReceipt
  };
  if (approvalId) {
    base.approvalId = approvalId;
    base.approvalDecision = approvalDecision;
  }
  const receiptHash = hashReceipt(base);
  const signed = { ...base, receiptHash };
  if (signer.legacy) return { ...signed, signature: signer.sign(signed) };
  return { ...signed, signatureAlgorithm: signer.algorithm, keyId: signer.keyId, signature: signer.sign(signed) };
}
function receiptForResponse(receipt) {
  // While Ed25519 is off, decision responses shorten the signature for display,
  // exactly as they did before. That is safe here because an HMAC signature is
  // not independently verifiable anyway. Once Ed25519 is on, the signature is
  // returned whole: a truncated one would be unverifiable against the published
  // public key, which would defeat the point of publishing it.
  if (!signer.legacy) return receipt;
  return { ...receipt, signature: `${receipt.signature.slice(0, 14)}\u2026` };
}
function mcpToolError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}
async function mcpCallTool({ name, arguments: args, context = {} }) {
  if (name !== 'weather.get_forecast') throw mcpToolError('mcp-tool-not-found', `Unknown MCP tool: ${name}`);
  if (!args || typeof args !== 'object' || Array.isArray(args)) throw mcpToolError('mcp-invalid-params', 'Tool arguments must be an object.');
  const request = validateAuthorizationRequest({ ...args, action: name });
  const scope = context.scope || {};
  if (scope.tenantId && (request.tenantId !== scope.tenantId || request.workspaceId !== scope.workspaceId)) throw mcpToolError('mcp-scope-binding-required', 'MCP request scope does not match the authenticated workspace.');
  let result = authorize(request);
  if (result.allowed && request.nonce && !(await receiptStore.claimNonce({ principal: result.capability.principal, nonce: request.nonce, expiresAt: result.capability.expiresAt }))) result = authorize({ ...request, replayDetected: true });
  const execution = result.allowed ? (mcpUpstream.configured ? 'forwarded-to-upstream' : 'would-forward-to-tool') : 'quarantined';
  const entry = await receiptStore.appendEntry(({ sequence, previousReceipt }) => ({ receipt: makeReceipt(result, request, { sequence, previousReceipt }), execution }));
  const receipt = receiptForResponse(entry.receipt);
  if (!result.allowed) {
    const blocked = { allowed: false, execution: 'quarantined', code: result.code, reason: result.reason, receipt };
    return { isError: true, structuredContent: blocked, content: [{ type: 'text', text: JSON.stringify(blocked) }] };
  }
  if (mcpUpstream.configured) {
    try {
      const upstreamResult = await mcpUpstream.forward({ name, arguments: args });
      const forwarded = {
        allowed: true,
        execution: 'forwarded-to-upstream',
        tool: name,
        resource: request.resource,
        upstream: upstreamResult.upstream,
        upstreamResult: upstreamResult.structuredContent || null,
        receipt
      };
      return { isError: upstreamResult.isError === true, structuredContent: forwarded, content: [{ type: 'text', text: JSON.stringify(forwarded) }] };
    } catch (error) {
      const failed = { allowed: true, execution: 'upstream-error', code: error.code || 'mcp-upstream-failed', reason: error.message, upstream: { origin: mcpUpstream.origin }, receipt };
      return { isError: true, structuredContent: failed, content: [{ type: 'text', text: JSON.stringify(failed) }] };
    }
  }
  const allowed = {
    allowed: true,
    execution: 'would-forward-to-tool',
    tool: name,
    resource: request.resource,
    syntheticResult: { city: 'New York', condition: 'clear skies', temperatureC: 22 },
    receipt
  };
  return { structuredContent: allowed, content: [{ type: 'text', text: JSON.stringify(allowed) }] };
}
const mcpHandler = createMcpHandler({ callTool: mcpCallTool });
function staticFile(res, pathname) {
  const safe = pathname === '/' ? '/index.html' : pathname;
  const file = path.normalize(path.join(publicDir, safe));
  const relative = path.relative(publicDir, file);
  if (relative.startsWith('..') || path.isAbsolute(relative)) return json(res, 403, { error: 'forbidden' });
  fs.readFile(file, (err, content) => { if (err) return json(res, 404, { error: 'not-found' }); const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp', '.gif': 'image/gif', '.ico': 'image/x-icon', '.avif': 'image/avif' }; res.writeHead(200, { ...securityHeaders(), 'content-type': types[path.extname(file).toLowerCase()] || 'text/plain; charset=utf-8', 'cache-control': 'no-store' }); res.end(content); });
}
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  try {
    if (req.method === 'GET' && url.pathname === '/health') return json(res, 200, { ok: true, service: 'context-seal', mode: demoMode ? 'synthetic-demo' : (isProduction ? 'production' : 'local-demo'), storage: receiptStore.mode, mcp: { upstream: { mode: mcpUpstream.mode, origin: mcpUpstream.origin } }, evidence: { ledger: 'synthetic-demo', encryptedExport: Boolean(evidenceWrappingKey) }, ...(signer.legacy ? {} : { signing: { algorithm: signer.algorithm, keyId: signer.keyId, ephemeralKey: signer.ephemeral } }) });
    // The signing key is public by design and deliberately sits above the auth
    // gate: a receipt is only independently verifiable if the verifier can fetch
    // the key without credentials.
    if (req.method === 'GET' && url.pathname === '/api/signing-key' && !signer.legacy) {
      return json(res, 200, {
        algorithm: signer.algorithm,
        keyId: signer.keyId,
        publicKey: signer.publicKeyPem,
        publicKeyBase64: signer.publicKeyBase64,
        ephemeralKey: signer.ephemeral,
        note: signer.ephemeral
          ? 'Ephemeral demo key. It is regenerated on restart, so receipts signed before a restart will not verify.'
          : 'Stable key. Receipts signed by this key verify offline with the public key alone.',
        verify: 'node scripts/verify-receipt.mjs <receipt.json> --url <origin>'
      });
    }
    if (url.pathname.startsWith('/api/') || url.pathname === '/mcp' || url.pathname === '/mcp/audit') {
      if (!authorized(req)) return json(res, 401, { error: 'authentication-required' });
      if (rateLimited(req)) return json(res, 429, { error: 'rate-limit-exceeded' });
    }
    if (req.method === 'GET' && url.pathname === '/api/bootstrap') { const scope = scopeForRequest(req); return json(res, 200, { capabilities: DEMO_CAPABILITIES.map(({ id, principal, label, tool, resource, scopes, expiresAt, status, reason, audience, tenantId, workspaceId, policyVersion }) => ({ id, principal, label, tool, resource, scopes, expiresAt, status, reason, audience, tenantId, workspaceId, policyVersion })), graph: graph(), receipts: await receiptStore.list(scope) }); }
    if (req.method === 'GET' && url.pathname === '/api/receipts') return json(res, 200, { receipts: await receiptStore.list(scopeForRequest(req)) });
    if (req.method === 'GET' && url.pathname === '/api/evidence') return json(res, 200, { schema: 'contextseal.synthetic-evidence-event.v1', syntheticOnly: true, events: syntheticEvidence });
    if (req.method === 'GET' && url.pathname === '/api/approvals') return json(res, 200, { approvals: approvalStore.list({ scope: scopeForRequest(req) }) });
    if (req.method === 'POST' && !req.headers['content-type']?.toLowerCase().startsWith('application/json')) return json(res, 415, { error: 'application-json-required' });
    if (req.method === 'POST' && url.pathname === '/api/authorize') {
      const request = validateAuthorizationRequest(await body(req));
      const headerScope = scopeForRequest(req);
      if (!demoMode && (request.tenantId !== headerScope.tenantId || request.workspaceId !== headerScope.workspaceId)) throw new Error('scope-binding-required');
      let result = authorize(request);
      if (result.allowed && request.nonce && !(await receiptStore.claimNonce({ principal: result.capability.principal, nonce: request.nonce, expiresAt: result.capability.expiresAt }))) result = authorize({ ...request, replayDetected: true });
      const entry = await receiptStore.appendEntry(({ sequence, previousReceipt }) => ({ receipt: makeReceipt(result, request, { sequence, previousReceipt }), execution: result.allowed ? 'would-forward-to-tool' : 'quarantined' }));
      const receipt = entry.receipt;
      return json(res, result.allowed ? 200 : 403, { allowed: result.allowed, reason: result.reason, code: result.code, inspection: result.inspection, receipt: receiptForResponse(receipt) });
    }
    const approvalMatch = url.pathname.match(/^\/api\/approvals\/([^/]+)\/(approve|deny)$/);
    if (req.method === 'POST' && url.pathname === '/api/approvals/request') {
      const request = validateApprovalRequest(await body(req));
      const headerScope = scopeForRequest(req);
      if (headerScope.tenantId && (request.tenantId !== headerScope.tenantId || request.workspaceId !== headerScope.workspaceId)) throw new Error('scope-binding-required');
      const result = authorize(request);
      if (!result.allowed) {
        const entry = await receiptStore.appendEntry(({ sequence, previousReceipt }) => ({ receipt: makeReceipt(result, request, { sequence, previousReceipt }), execution: 'quarantined' }));
        return json(res, 403, { allowed: false, reason: result.reason, code: result.code, inspection: result.inspection, receipt: receiptForResponse(entry.receipt) });
      }
      const approval = approvalStore.create({ request, policyResult: result });
      return json(res, 202, {
        allowed: false,
        status: approval.status,
        approvalId: approval.id,
        approval: { id: approval.id, status: approval.status, expiresAt: approval.expiresAt },
        expiresAt: approval.expiresAt,
        reason: 'Human approval is required before forwarding to the tool.',
        code: 'approval-required',
        inspection: result.inspection,
        policy: { allowed: true, reason: result.reason, code: 'policy-passed' }
      });
    }
    if (req.method === 'POST' && approvalMatch) {
      const approvalId = decodeURIComponent(approvalMatch[1]);
      const decision = approvalMatch[2] === 'approve' ? 'approve' : 'deny';
      validateApprovalCommand(await body(req), approvalId);
      const headerScope = scopeForRequest(req);
      const scope = headerScope.tenantId ? headerScope : undefined;
      const begun = approvalStore.begin(approvalId, decision, { scope });
      if (!begun) return json(res, 404, { error: 'approval-not-found' });
      if (begun.kind === 'already-resolved') return json(res, 409, { error: 'approval-not-pending', status: begun.record.status, approvalId });
      if (begun.kind === 'expired') {
        const expired = begun.record;
        const result = { allowed: false, code: 'approval-expired', reason: 'Human approval expired before resolution.', capability: { principal: expired.request.principal, audience: expired.request.audience, tenantId: expired.request.tenantId, workspaceId: expired.request.workspaceId } };
        const entry = await receiptStore.appendEntry(({ sequence, previousReceipt }) => ({ receipt: makeReceipt(result, expired.request, { sequence, previousReceipt, approvalId, approvalDecision: 'expired' }), execution: 'quarantined' }));
        approvalStore.completeDenial(approvalId, { receiptId: entry.receipt.id });
        return json(res, 410, { allowed: false, status: 'expired', approvalId, reason: result.reason, code: result.code, execution: 'quarantined', receipt: receiptForResponse(entry.receipt) });
      }
      if (decision === 'deny') {
        const denied = begun.record;
        const result = { allowed: false, code: 'human-denied', reason: 'Human approval was denied.', capability: { principal: denied.request.principal, audience: denied.request.audience, tenantId: denied.request.tenantId, workspaceId: denied.request.workspaceId }, inspection: denied.policy.inspection };
        const entry = await receiptStore.appendEntry(({ sequence, previousReceipt }) => ({ receipt: makeReceipt(result, denied.request, { sequence, previousReceipt, approvalId, approvalDecision: 'deny' }), execution: 'quarantined' }));
        approvalStore.completeDenial(approvalId, { receiptId: entry.receipt.id });
        return json(res, 200, { allowed: false, status: 'denied', approvalId, reason: result.reason, code: result.code, execution: 'quarantined', receipt: receiptForResponse(entry.receipt) });
      }
      const approved = begun.record;
      let result = authorize(approved.request);
      if (result.allowed && !(await receiptStore.claimNonce({ principal: result.capability.principal, nonce: approved.request.nonce, expiresAt: result.capability.expiresAt }))) result = authorize({ ...approved.request, replayDetected: true });
      const entry = await receiptStore.appendEntry(({ sequence, previousReceipt }) => ({ receipt: makeReceipt(result, approved.request, { sequence, previousReceipt, approvalId, approvalDecision: 'approve' }), execution: result.allowed ? 'would-forward-to-tool' : 'quarantined' }));
      approvalStore.completeApproval(approvalId, { outcome: result.allowed ? 'allow' : 'deny', reasonCode: result.allowed ? 'policy-passed' : result.code, receiptId: entry.receipt.id });
      return json(res, result.allowed ? 200 : 403, { allowed: result.allowed, status: 'approved', approvalId, reason: result.allowed ? 'Human approval accepted and policy checks passed.' : result.reason, code: result.allowed ? 'approved' : result.code, execution: result.allowed ? 'would-forward-to-tool' : 'quarantined', inspection: result.inspection, receipt: receiptForResponse(entry.receipt) });
    }
    if (req.method === 'POST' && url.pathname === '/api/artifacts/export') { const request = validateArtifactRequest(await body(req)); const headerScope = scopeForRequest(req); if (!demoMode && (request.tenantId !== headerScope.tenantId || request.workspaceId !== headerScope.workspaceId)) throw new Error('scope-binding-required'); const entry = await receiptStore.findByReceiptId(request.receiptId, { tenantId: request.tenantId, workspaceId: request.workspaceId }); if (!entry) return json(res, 404, { error: 'receipt-not-found' }); if (entry.receipt.decision !== 'allow') return json(res, 409, { error: 'artifact-requires-allowed-receipt' }); const manifest = artifactManifest({ filename: request.filename, content: request.content, receipt: entry.receipt, signer }); return json(res, 200, { artifact: { filename: request.filename, content: request.content }, manifest }); }
    if (req.method === 'POST' && url.pathname === '/api/artifacts/verify') { const request = validateVerifyRequest(await body(req)); const result = request.approved ? verifyApprovedArtifact({ approved: request.approved, observed: { filename: request.filename, content: request.content, manifest: request.manifest }, publicKey: signer.publicKeyPem, secret: signingSecret }) : verifyArtifact({ ...request, publicKey: signer.publicKeyPem, secret: signingSecret }); return json(res, 200, result); }
    if (req.method === 'POST' && url.pathname === '/api/evidence/package') {
      if (!evidenceWrappingKey) return json(res, 503, { error: 'evidence-export-unconfigured', reason: 'Configure CONTEXTSEAL_EVIDENCE_WRAPPING_KEY before enabling encrypted evidence export.' });
      const request = validateEvidencePackageRequest(await body(req));
      const selected = request.eventIds?.length ? syntheticEvidence.filter((event) => request.eventIds.includes(event.id)) : syntheticEvidence;
      if (!selected.length || selected.length !== (request.eventIds?.length || selected.length)) throw new Error('evidence-event-not-found');
      const evidencePackage = createEvidencePackage({ events: selected, wrappingKey: evidenceWrappingKey, keyId: process.env.CONTEXTSEAL_EVIDENCE_KEY_ID || 'contextseal-evidence-key', retentionDeadline: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString() });
      return json(res, 200, { syntheticOnly: true, decryptLocally: true, package: evidencePackage });
    }
    if (req.method === 'POST' && url.pathname === '/auth/pen-console') {
      if (!penGatePassword) return json(res, 503, { error: 'authentication-unconfigured' });
      const request = await body(req);
      if (!request || typeof request.password !== 'string' || !constantTimeMatch(request.password, penGatePassword)) {
        return json(res, 401, { error: 'authentication-failed' });
      }
      const token = issuePenGateSession();
      res.writeHead(204, {
        ...securityHeaders(),
        'cache-control': 'no-store',
        'set-cookie': `${PEN_GATE_COOKIE}=${encodeURIComponent(token)}; Path=/pen-console; HttpOnly; SameSite=Lax${secureCookie(req) ? '; Secure' : ''}`
      });
      res.end();
      return;
    }
    if (url.pathname === '/mcp') {
      if (!mcpOriginAllowed(req)) return mcpJson(res, 403, { jsonrpc: '2.0', id: null, error: { code: -32001, message: 'MCP Origin is not allowed.' } });
      if (req.method !== 'POST') return mcpJson(res, 405, { jsonrpc: '2.0', id: null, error: { code: -32000, message: 'This stateless MCP endpoint accepts POST only.' } });
      const accept = req.headers.accept || '';
      if (accept !== '*/*' && (!accept.includes('application/json') || !accept.includes('text/event-stream'))) return mcpJson(res, 406, { jsonrpc: '2.0', id: null, error: { code: -32000, message: 'MCP clients must accept application/json and text/event-stream.' } });
      const protocolVersion = req.headers['mcp-protocol-version'];
      if (protocolVersion && protocolVersion !== MCP_PROTOCOL_VERSION) return mcpJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32602, message: 'Unsupported MCP protocol version.', data: { supported: [MCP_PROTOCOL_VERSION] } } });
      const message = await body(req);
      if (message.method !== 'initialize' && !protocolVersion) return mcpJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32602, message: 'MCP-Protocol-Version is required after initialization.', data: { supported: [MCP_PROTOCOL_VERSION] } } });
      const result = await mcpHandler(message, { scope: scopeForRequest(req) });
      if (result === null) {
        res.writeHead(202, { ...securityHeaders(), 'mcp-protocol-version': MCP_PROTOCOL_VERSION, 'cache-control': 'no-store' });
        res.end();
        return;
      }
      return mcpJson(res, 200, result);
    }
    if (req.method === 'POST' && url.pathname === '/mcp/audit') { const request = validateAuditRequest(await body(req)); return json(res, 200, { jsonrpc: '2.0', result: { service: 'context-seal', capabilities: DEMO_CAPABILITIES.length, receipts: (await receiptStore.list(scopeForRequest(req))).map(({ receipt }) => receipt), policy: 'deny-by-default', policyVersion: POLICY_VERSION }, id: request.id ?? 1 }); }
    const isPenGateAsset = url.pathname === '/pen-console/gate.css';
    if (isPenConsolePath(url.pathname) && penGatePassword && !isPenGatePage(url.pathname) && !isPenGateAsset && !penGateSessionValid(req)) {
      if (isHtmlRequest(req, url.pathname)) return redirectToPenGate(res, url.pathname);
      return json(res, 401, { error: 'authentication-required' });
    }
    if (req.method === 'GET') return staticFile(res, url.pathname);
    return json(res, 405, { error: 'method-not-allowed' });
  } catch (error) { const status = error.message === 'payload-too-large' || error.message === 'input-too-large' ? 413 : error.code === 'receipt-storage-unavailable' || error.message === 'receipt-ledger-integrity-failure' ? 503 : 400; return json(res, status, { error: status === 503 ? 'service-unavailable' : 'invalid-request', ...(isProduction ? {} : { detail: error.message }) }); }
});
server.requestTimeout = 15_000;
server.headersTimeout = 10_000;
server.listen(port, host, () => { const address = server.address(); console.log(`CanaryNorth listening on http://${host}:${typeof address === 'object' ? address.port : port}${requireAuth ? ' (auth required)' : ' (demo mode)'}`); });
process.on('SIGTERM', async () => { await receiptStore.close(); server.close(); });
