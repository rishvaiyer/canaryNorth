import crypto from 'node:crypto';
import { evaluateAdaptiveContext, evaluateAgentBoundary, evaluateAgenticSsrf, evaluateApprovalAge, evaluateApprovalCarousel, evaluateApprovalFreshness, evaluateAudienceMismatch, evaluateBlastRadius, evaluateBrowserOriginClaim, evaluateCausalBasis, evaluateCanaryEvent, evaluateCanaryRequest, evaluateCausalContinuity, evaluateClockSplit, evaluateConsensusProvenance, evaluateContextFanout, evaluateControlFlow, evaluateCorpusTaint, evaluateDelegationFreshness, evaluateDependencyDoppelganger, evaluateEvidenceMasquerade, evaluateEvidenceShadow, evaluateExecutionBoundary, evaluateExportDrift, evaluateFrontierGap, evaluateHiddenCaptureState, evaluateIntentNormalization, evaluateIntentTrajectory, evaluateKeystreamRetention, evaluateLifecycleHook, evaluateLongGame, evaluateMcpScopeCrosswire, evaluateMemoryContext, evaluateMemoryGraft, evaluateMemoryPermissionShadow, evaluateModelExposure, evaluateModelIdentityMirage, evaluateOutcomeIntegrity, evaluatePassportSmuggle, evaluatePlatformPassport, evaluatePolicyGravity, evaluatePromptwareRelay, evaluateProvenanceBoundary, evaluateQuarantineReentry, evaluateQuietPermission, evaluateRecoveryClaim, evaluateRecoveryTrapdoor, evaluateBackgroundListener, evaluateRedactionGap, evaluateReconstructionRisk, evaluateResourceClass, evaluateRetrievalRanking, evaluateRevocationLineage, evaluateRouteAmbiguity, evaluateObservationActionGap, evaluateSchedulerDrift, evaluateSchemaAuthority, evaluateScopeAccumulation, evaluateSecondLock, evaluateSecretFocus, evaluateSkillDescriptor, evaluateTenantMirror, evaluateTokenFurnace, evaluateToolInventory, evaluateToolPivot, evaluateTrajectoryFork, evaluateTrustDebt, evaluateWorkflowGraph, verifyToolAttestation } from './agentic-defense.mjs';

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

export function authorize({ capabilityId, action, resource, input = '', now = new Date(), principal, audience, tenantId, workspaceId, policyVersion = POLICY_VERSION, nonce, replayDetected = false, toolManifest, memoryContext, provenance, canaryContext, adaptiveContext, causalContext, trustDebtContext, delegationContext, causalBasisContext, revocationLineageContext, intentNormContext, resourceClassContext, recoveryClaimContext, skillDescriptorContext, memoryGraftContext, agentBoundaryContext, canaryEventContext, secondLockContext, frontierGapContext, controlFlowContext, approvalFreshnessContext, outcomeIntegrityContext, quarantineReentryContext, scopeAccumulationContext, workflowGraphContext, consensusProvenanceContext, approvalAgeContext, policyGravityContext, intentTrajectoryContext, clockSplitContext, tenantMirrorContext, evidenceMasqueradeContext, secretFocusContext, backgroundListenerContext, keystreamRetentionContext, hiddenCaptureStateContext, redactionGapContext, audienceMismatchContext, reconstructionRiskContext, exportDriftContext, toolPivotContext, memoryPermissionShadowContext, schemaAuthorityContext, mcpScopeCrosswireContext, lifecycleHookContext, agenticSsrfContext, contextFanoutContext, retrievalRankingContext, observationActionGapContext, promptwareRelayContext, trajectoryForkContext, passportSmuggleContext, browserOriginClaimContext, tokenFurnaceContext, routeAmbiguityContext, quietPermissionContext, schedulerDriftContext, evidenceShadowContext, modelIdentityMirageContext, platformPassportContext, executionBoundaryContext, corpusTaintContext, toolInventoryContext, modelExposureContext, approvalCarouselContext, blastRadiusContext, recoveryTrapdoorContext, longGameContext, dependencyDoppelgangerContext, demoControls = {} }) {
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
  if (skillDescriptorContext !== undefined) {
    const skill = evaluateSkillDescriptor(skillDescriptorContext);
    if (!skill.allowed) return deny(skill.reasonCode, 'Skill descriptor did not satisfy attestation requirements.', capability, { clean: false, signals: [skill.reasonCode], agenticDefense: skill });
  }
  if (memoryGraftContext !== undefined) {
    const graft = evaluateMemoryGraft(memoryGraftContext);
    if (!graft.allowed) return deny(graft.reasonCode, 'Memory graft check failed provenance or freshness requirements.', capability, { clean: false, signals: [graft.reasonCode], agenticDefense: graft });
  }
  if (agentBoundaryContext !== undefined) {
    const boundary = evaluateAgentBoundary(agentBoundaryContext);
    if (!boundary.allowed) return deny(boundary.reasonCode, 'Agent boundary violation detected at trust crossing.', capability, { clean: false, signals: [boundary.reasonCode], agenticDefense: boundary });
  }
  if (canaryEventContext !== undefined) {
    const canaryEvent = evaluateCanaryEvent(canaryEventContext);
    if (!canaryEvent.allowed) return deny(canaryEvent.reasonCode, 'Synthetic canary event was blocked and recorded.', capability, { clean: false, signals: [canaryEvent.reasonCode], agenticDefense: canaryEvent });
  }
  if (secondLockContext !== undefined) {
    const secondLock = evaluateSecondLock(secondLockContext);
    if (!secondLock.allowed) return deny(secondLock.reasonCode, 'Second authentication lock condition was not satisfied.', capability, { clean: false, signals: [secondLock.reasonCode], agenticDefense: secondLock });
  }
  if (frontierGapContext !== undefined) {
    const frontier = evaluateFrontierGap(frontierGapContext);
    if (!frontier.allowed) return deny(frontier.reasonCode, 'Frontier gap condition requires review before action.', capability, { clean: false, signals: [frontier.reasonCode], agenticDefense: frontier });
  }
  if (controlFlowContext !== undefined) {
    const controlFlow = evaluateControlFlow(controlFlowContext);
    if (!controlFlow.allowed) return deny(controlFlow.reasonCode, 'Control flow safety condition was violated.', capability, { clean: false, signals: [controlFlow.reasonCode], agenticDefense: controlFlow });
  }
  if (approvalFreshnessContext !== undefined) {
    const freshness = evaluateApprovalFreshness(approvalFreshnessContext);
    if (!freshness.allowed) return deny(freshness.reasonCode, 'Expired approval cannot be replayed.', capability, { clean: false, signals: [freshness.reasonCode], agenticDefense: freshness });
  }
  if (outcomeIntegrityContext !== undefined) {
    const outcome = evaluateOutcomeIntegrity(outcomeIntegrityContext);
    if (!outcome.allowed) return deny(outcome.reasonCode, 'Claimed outcome does not match the receipt observation.', capability, { clean: false, signals: [outcome.reasonCode], agenticDefense: outcome });
  }
  if (quarantineReentryContext !== undefined) {
    const quarantine = evaluateQuarantineReentry(quarantineReentryContext);
    if (!quarantine.allowed) return deny(quarantine.reasonCode, 'Quarantined item cannot re-enter trusted context.', capability, { clean: false, signals: [quarantine.reasonCode], agenticDefense: quarantine });
  }
  if (scopeAccumulationContext !== undefined) {
    const scope = evaluateScopeAccumulation(scopeAccumulationContext);
    if (!scope.allowed) return deny(scope.reasonCode, 'Cumulative scope expansion was flagged before sensitive action.', capability, { clean: false, signals: [scope.reasonCode], agenticDefense: scope });
  }
  if (workflowGraphContext !== undefined) {
    const graph = evaluateWorkflowGraph(workflowGraphContext);
    if (!graph.allowed) return deny(graph.reasonCode, 'Observed workflow graph does not match the approved plan.', capability, { clean: false, signals: [graph.reasonCode], agenticDefense: graph });
  }
  if (consensusProvenanceContext !== undefined) {
    const consensus = evaluateConsensusProvenance(consensusProvenanceContext);
    if (!consensus.allowed) return deny(consensus.reasonCode, 'Agent consensus shares a single untrusted provenance root.', capability, { clean: false, signals: [consensus.reasonCode], agenticDefense: consensus });
  }
  if (approvalAgeContext !== undefined) {
    const age = evaluateApprovalAge(approvalAgeContext);
    if (!age.allowed) return deny(age.reasonCode, 'Approval age exceeds the allowed freshness window.', capability, { clean: false, signals: [age.reasonCode], agenticDefense: age });
  }
  if (policyGravityContext !== undefined) {
    const gravity = evaluatePolicyGravity(policyGravityContext);
    if (!gravity.allowed) return deny(gravity.reasonCode, 'Action impact requires a higher authorization level.', capability, { clean: false, signals: [gravity.reasonCode], agenticDefense: gravity });
  }
  if (intentTrajectoryContext !== undefined) {
    const traj = evaluateIntentTrajectory(intentTrajectoryContext);
    if (!traj.allowed) return deny(traj.reasonCode, 'Accumulated intent trajectory triggered a step-up or block.', capability, { clean: false, signals: [traj.reasonCode], agenticDefense: traj });
  }
  if (clockSplitContext !== undefined) {
    const cs = evaluateClockSplit(clockSplitContext);
    if (!cs.allowed) return deny(cs.reasonCode, 'Conflicting clock signals may make an expired approval appear current.', capability, { clean: false, signals: [cs.reasonCode], agenticDefense: cs });
  }
  if (tenantMirrorContext !== undefined) {
    const tm = evaluateTenantMirror(tenantMirrorContext);
    if (!tm.allowed) return deny(tm.reasonCode, 'Resource label matches but tenant binding differs.', capability, { clean: false, signals: [tm.reasonCode], agenticDefense: tm });
  }
  if (evidenceMasqueradeContext !== undefined) {
    const em = evaluateEvidenceMasquerade(evidenceMasqueradeContext);
    if (!em.allowed) return deny(em.reasonCode, 'Claimed approval lacks authoritative provenance.', capability, { clean: false, signals: [em.reasonCode], agenticDefense: em });
  }
  if (secretFocusContext !== undefined) {
    const sf = evaluateSecretFocus(secretFocusContext);
    if (!sf.allowed) return deny(sf.reasonCode, 'Keyboard listener observed a secret field without consent.', capability, { clean: false, signals: [sf.reasonCode], agenticDefense: sf });
  }
  if (backgroundListenerContext !== undefined) {
    const bl = evaluateBackgroundListener(backgroundListenerContext);
    if (!bl.allowed) return deny(bl.reasonCode, 'Background input listener lacks owner approval.', capability, { clean: false, signals: [bl.reasonCode], agenticDefense: bl });
  }
  if (keystreamRetentionContext !== undefined) {
    const kr = evaluateKeystreamRetention(keystreamRetentionContext);
    if (!kr.allowed) return deny(kr.reasonCode, 'Durable keystroke retention lacks declared purpose.', capability, { clean: false, signals: [kr.reasonCode], agenticDefense: kr });
  }
  if (hiddenCaptureStateContext !== undefined) {
    const hcs = evaluateHiddenCaptureState(hiddenCaptureStateContext);
    if (!hcs.allowed) return deny(hcs.reasonCode, 'Hidden capture state is active.', capability, { clean: false, signals: [hcs.reasonCode], agenticDefense: hcs });
  }
  if (redactionGapContext !== undefined) {
    const rg = evaluateRedactionGap(redactionGapContext);
    if (!rg.allowed) return deny(rg.reasonCode, 'Sensitive field in report lacks a redaction marker.', capability, { clean: false, signals: [rg.reasonCode], agenticDefense: rg });
  }
  if (audienceMismatchContext !== undefined) {
    const am = evaluateAudienceMismatch(audienceMismatchContext);
    if (!am.allowed) return deny(am.reasonCode, 'Private evidence is bound to a public export audience.', capability, { clean: false, signals: [am.reasonCode], agenticDefense: am });
  }
  if (reconstructionRiskContext !== undefined) {
    const rr = evaluateReconstructionRisk(reconstructionRiskContext);
    if (!rr.allowed) return deny(rr.reasonCode, 'Linkable field count and identity risk require step-up.', capability, { clean: false, signals: [rr.reasonCode], agenticDefense: rr });
  }
  if (exportDriftContext !== undefined) {
    const ed = evaluateExportDrift(exportDriftContext);
    if (!ed.allowed) return deny(ed.reasonCode, 'Export does not preserve source redaction constraints.', capability, { clean: false, signals: [ed.reasonCode], agenticDefense: ed });
  }
  if (toolPivotContext !== undefined) {
    const tp = evaluateToolPivot(toolPivotContext);
    if (!tp.allowed) return deny(tp.reasonCode, 'A trusted tool result cannot authorize a second un-scoped tool.', capability, { clean: false, signals: [tp.reasonCode], agenticDefense: tp });
  }
  if (memoryPermissionShadowContext !== undefined) {
    const mp = evaluateMemoryPermissionShadow(memoryPermissionShadowContext);
    if (!mp.allowed) return deny(mp.reasonCode, 'Memory permission verification incomplete.', capability, { clean: false, signals: [mp.reasonCode], agenticDefense: mp });
  }
  if (schemaAuthorityContext !== undefined) {
    const sa = evaluateSchemaAuthority(schemaAuthorityContext);
    if (!sa.allowed) return deny(sa.reasonCode, 'Tool parameter controls destination without policy validation.', capability, { clean: false, signals: [sa.reasonCode], agenticDefense: sa });
  }
  if (mcpScopeCrosswireContext !== undefined) {
    const mcp = evaluateMcpScopeCrosswire(mcpScopeCrosswireContext);
    if (!mcp.allowed) return deny(mcp.reasonCode, 'Read-only MCP scope reached a mutating handler.', capability, { clean: false, signals: [mcp.reasonCode], agenticDefense: mcp });
  }
  if (lifecycleHookContext !== undefined) {
    const lh = evaluateLifecycleHook(lifecycleHookContext);
    if (!lh.allowed) return deny(lh.reasonCode, 'Unapproved lifecycle change affects future agent behavior.', capability, { clean: false, signals: [lh.reasonCode], agenticDefense: lh });
  }
  if (agenticSsrfContext !== undefined) {
    const ssrf = evaluateAgenticSsrf(agenticSsrfContext);
    if (!ssrf.allowed) return deny(ssrf.reasonCode, 'Destination class is not authorized for agent-side requests.', capability, { clean: false, signals: [ssrf.reasonCode], agenticDefense: ssrf });
  }
  if (contextFanoutContext !== undefined) {
    const cf = evaluateContextFanout(contextFanoutContext);
    if (!cf.allowed) return deny(cf.reasonCode, 'Context fan-out exceeds branch, retry, or agent budget.', capability, { clean: false, signals: [cf.reasonCode], agenticDefense: cf });
  }
  if (retrievalRankingContext !== undefined) {
    const rr = evaluateRetrievalRanking(retrievalRankingContext);
    if (!rr.allowed) return deny(rr.reasonCode, 'Top-ranked retrieval result has not been trust-verified.', capability, { clean: false, signals: [rr.reasonCode], agenticDefense: rr });
  }
  if (observationActionGapContext !== undefined) {
    const oag = evaluateObservationActionGap(observationActionGapContext);
    if (!oag.allowed) return deny(oag.reasonCode, 'Final action does not match the observed and reviewed evidence.', capability, { clean: false, signals: [oag.reasonCode], agenticDefense: oag });
  }
  if (promptwareRelayContext !== undefined) {
    const pr = evaluatePromptwareRelay(promptwareRelayContext);
    if (!pr.allowed) return deny(pr.reasonCode, 'External content crossed an application boundary without origin preservation.', capability, { clean: false, signals: [pr.reasonCode], agenticDefense: pr });
  }
  if (trajectoryForkContext !== undefined) {
    const tf = evaluateTrajectoryFork(trajectoryForkContext);
    if (!tf.allowed) return deny(tf.reasonCode, 'Observed action trajectory diverges from the approved path.', capability, { clean: false, signals: [tf.reasonCode], agenticDefense: tf });
  }
  if (passportSmuggleContext !== undefined) {
    const ps = evaluatePassportSmuggle(passportSmuggleContext);
    if (!ps.allowed) return deny(ps.reasonCode, 'Capability passport changed across an approval boundary.', capability, { clean: false, signals: [ps.reasonCode], agenticDefense: ps });
  }
  if (browserOriginClaimContext !== undefined) {
    const boc = evaluateBrowserOriginClaim(browserOriginClaimContext);
    if (!boc.allowed) return deny(boc.reasonCode, 'Origin claim is not sufficient authorization evidence.', capability, { clean: false, signals: [boc.reasonCode], agenticDefense: boc });
  }
  if (tokenFurnaceContext !== undefined) {
    const tok = evaluateTokenFurnace(tokenFurnaceContext);
    if (!tok.allowed) return deny(tok.reasonCode, 'Credential-shaped metadata requires redaction.', capability, { clean: false, signals: [tok.reasonCode], agenticDefense: tok });
  }
  if (routeAmbiguityContext !== undefined) {
    const ra = evaluateRouteAmbiguity(routeAmbiguityContext);
    if (!ra.allowed) return deny(ra.reasonCode, 'Route is ambiguous and cannot authorize forwarding.', capability, { clean: false, signals: [ra.reasonCode], agenticDefense: ra });
  }
  if (quietPermissionContext !== undefined) {
    const qp = evaluateQuietPermission(quietPermissionContext);
    if (!qp.allowed) return deny(qp.reasonCode, 'Composed permission scopes exceed impact threshold.', capability, { clean: false, signals: [qp.reasonCode], agenticDefense: qp });
  }
  if (schedulerDriftContext !== undefined) {
    const sd = evaluateSchedulerDrift(schedulerDriftContext);
    if (!sd.allowed) return deny(sd.reasonCode, 'Multiple freshness sources disagree about approval status.', capability, { clean: false, signals: [sd.reasonCode], agenticDefense: sd });
  }
  if (evidenceShadowContext !== undefined) {
    const es = evaluateEvidenceShadow(evidenceShadowContext);
    if (!es.allowed) return deny(es.reasonCode, 'Decision cites evidence with unverified provenance.', capability, { clean: false, signals: [es.reasonCode], agenticDefense: es });
  }
  if (modelIdentityMirageContext !== undefined) {
    const mim = evaluateModelIdentityMirage(modelIdentityMirageContext);
    if (!mim.allowed) return deny(mim.reasonCode, 'Runtime model identity does not match approved identity class.', capability, { clean: false, signals: [mim.reasonCode], agenticDefense: mim });
  }
  if (platformPassportContext !== undefined) {
    const pp = evaluatePlatformPassport(platformPassportContext);
    if (!pp.allowed) return deny(pp.reasonCode, 'Skill permission metadata disagrees across platforms.', capability, { clean: false, signals: [pp.reasonCode], agenticDefense: pp });
  }
  if (executionBoundaryContext !== undefined) {
    const eb = evaluateExecutionBoundary(executionBoundaryContext);
    if (!eb.allowed) return deny(eb.reasonCode, 'Execution was requested but boundary does not permit it.', capability, { clean: false, signals: [eb.reasonCode], agenticDefense: eb });
  }
  if (corpusTaintContext !== undefined) {
    const ct = evaluateCorpusTaint(corpusTaintContext);
    if (!ct.allowed) return deny(ct.reasonCode, 'Training corpus provenance changed outside the approved lineage.', capability, { clean: false, signals: [ct.reasonCode], agenticDefense: ct });
  }
  if (toolInventoryContext !== undefined) {
    const ti = evaluateToolInventory(toolInventoryContext);
    if (!ti.allowed) return deny(ti.reasonCode, 'Requested tool has no approved inventory record.', capability, { clean: false, signals: [ti.reasonCode], agenticDefense: ti });
  }
  if (modelExposureContext !== undefined) {
    const me = evaluateModelExposure(modelExposureContext);
    if (!me.allowed) return deny(me.reasonCode, 'Model data extraction was requested without an approved audience.', capability, { clean: false, signals: [me.reasonCode], agenticDefense: me });
  }
  if (approvalCarouselContext !== undefined) {
    const ac = evaluateApprovalCarousel(approvalCarouselContext);
    if (!ac.allowed) return deny(ac.reasonCode, 'Repeated approvals with a sensitive action require step-up.', capability, { clean: false, signals: [ac.reasonCode], agenticDefense: ac });
  }
  if (blastRadiusContext !== undefined) {
    const br = evaluateBlastRadius(blastRadiusContext);
    if (!br.allowed) return deny(br.reasonCode, 'Projected action count exceeds the workflow budget.', capability, { clean: false, signals: [br.reasonCode], agenticDefense: br });
  }
  if (recoveryTrapdoorContext !== undefined) {
    const rt = evaluateRecoveryTrapdoor(recoveryTrapdoorContext);
    if (!rt.allowed) return deny(rt.reasonCode, 'Recovery path is weaker than the session it would inherit.', capability, { clean: false, signals: [rt.reasonCode], agenticDefense: rt });
  }
  if (longGameContext !== undefined) {
    const lg = evaluateLongGame(longGameContext);
    if (!lg.allowed) return deny(lg.reasonCode, 'Multi-step chain has drifted into a sensitive action.', capability, { clean: false, signals: [lg.reasonCode], agenticDefense: lg });
  }
  if (dependencyDoppelgangerContext !== undefined) {
    const dd = evaluateDependencyDoppelganger(dependencyDoppelgangerContext);
    if (!dd.allowed) return deny(dd.reasonCode, 'Dependency identity changed after approval.', capability, { clean: false, signals: [dd.reasonCode], agenticDefense: dd });
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
