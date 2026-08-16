import test from 'node:test';
import assert from 'node:assert/strict';
import { authorize } from '../src/policy.mjs';
import { createApprovalStore } from '../src/approvals.mjs';
import { createMemoryReceiptStore } from '../src/storage.mjs';

const createdAt = Date.parse('2026-08-15T12:00:00.000Z');

function ticketRequest(nonce = 'nonce_approval_12345') {
  return {
    capabilityId: 'cap_ticket_update_91ae',
    action: 'tickets.update',
    resource: 'ticket://demo-482',
    input: { status: 'pending-customer', note: 'Synthetic approval test' },
    principal: 'support-agent',
    audience: 'contextseal',
    tenantId: 'tenant_demo',
    workspaceId: 'workspace_demo',
    policyVersion: 'contextseal-policy-v2',
    nonce
  };
}

function policyResult(request) {
  return authorize({ ...request, now: new Date(createdAt) });
}

function scope(request) {
  return { tenantId: request.tenantId, workspaceId: request.workspaceId };
}

test('request creates an opaque, short-lived pending approval without a receipt', () => {
  const request = ticketRequest();
  const store = createApprovalStore({ ttlMs: 60_000, now: () => createdAt });
  const record = store.create({ request, policyResult: policyResult(request) });
  assert.match(record.id, /^apr_[A-Za-z0-9_-]{20,}$/);
  assert.equal(record.status, 'pending');
  assert.equal(record.request.nonce, request.nonce);
  assert.equal(record.policy.allowed, true);
  assert.equal(record.receiptId, null);
  assert.equal(store.get(record.id, { scope: scope(request) }).status, 'pending');
});

test('approval completes only after the policy result is allowed', () => {
  const request = ticketRequest('nonce_approval_allowed');
  const store = createApprovalStore({ ttlMs: 60_000, now: () => createdAt });
  const record = store.create({ request, policyResult: policyResult(request) });
  const begun = store.begin(record.id, 'approve', { scope: scope(request), at: createdAt });
  assert.equal(begun.kind, 'approving');
  const completed = store.completeApproval(record.id, { outcome: 'allow', reasonCode: 'policy-passed', receiptId: 'rcpt_0001', at: createdAt + 1 });
  assert.equal(completed.status, 'approved');
  assert.equal(completed.outcome, 'allow');
  assert.equal(completed.receiptId, 'rcpt_0001');
});

test('denial resolves the approval and records no forwarding outcome', () => {
  const request = ticketRequest('nonce_approval_denied');
  const store = createApprovalStore({ ttlMs: 60_000, now: () => createdAt });
  const record = store.create({ request, policyResult: policyResult(request) });
  const denied = store.begin(record.id, 'deny', { scope: scope(request), at: createdAt });
  assert.equal(denied.kind, 'denied');
  const completed = store.completeDenial(record.id, { receiptId: 'rcpt_0001', at: createdAt + 1 });
  assert.equal(completed.status, 'denied');
  assert.equal(completed.outcome, 'deny');
  assert.equal(completed.reasonCode, 'human-denied');
});

test('expiry resolves an untouched approval as denied', () => {
  const request = ticketRequest('nonce_approval_expiry');
  const store = createApprovalStore({ ttlMs: 1_000, now: () => createdAt + 1_001 });
  const record = store.create({ request, policyResult: policyResult(request), createdAt });
  const expired = store.begin(record.id, 'approve', { scope: scope(request), at: createdAt + 1_001 });
  assert.equal(expired.kind, 'expired');
  assert.equal(expired.record.status, 'expired');
  assert.equal(expired.record.outcome, 'deny');
  assert.equal(expired.record.reasonCode, 'approval-expired');
});

test('scope mismatch cannot resolve a pending approval', () => {
  const request = ticketRequest('nonce_approval_scope');
  const store = createApprovalStore({ ttlMs: 60_000, now: () => createdAt });
  const record = store.create({ request, policyResult: policyResult(request) });
  assert.throws(
    () => store.begin(record.id, 'approve', { scope: { tenantId: 'tenant_other', workspaceId: 'workspace_other' }, at: createdAt }),
    /approval-scope-mismatch/
  );
  assert.equal(store.get(record.id, { scope: scope(request) }).status, 'pending');
});

test('nonce replay blocks the approved record at the final policy check', async () => {
  const request = ticketRequest('nonce_approval_replay');
  const store = createApprovalStore({ ttlMs: 60_000, now: () => createdAt });
  const record = store.create({ request, policyResult: policyResult(request) });
  const nonceStore = createMemoryReceiptStore();
  assert.equal(await nonceStore.claimNonce({ principal: request.principal, nonce: request.nonce, expiresAt: '2030-08-15T18:00:00.000Z' }), true);
  const begun = store.begin(record.id, 'approve', { scope: scope(request), at: createdAt });
  const finalResult = authorize({ ...request, now: new Date(createdAt), replayDetected: true });
  assert.equal(finalResult.code, 'replay-detected');
  const completed = store.completeApproval(record.id, { outcome: finalResult.allowed ? 'allow' : 'deny', reasonCode: finalResult.code, receiptId: 'rcpt_0001', at: createdAt + 1 });
  assert.equal(begun.kind, 'approving');
  assert.equal(completed.status, 'approved');
  assert.equal(completed.outcome, 'deny');
  assert.equal(completed.reasonCode, 'replay-detected');
});
