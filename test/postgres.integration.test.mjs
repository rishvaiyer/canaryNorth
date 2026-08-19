import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createReceiptStore } from '../src/storage.mjs';

const databaseUrl = process.env.TEST_DATABASE_URL;

test('PostgreSQL persists chained receipts and one-time nonces across store instances', { skip: !databaseUrl }, async () => {
  const runId = crypto.randomBytes(6).toString('hex');
  const tenantId = `tenant_ci_${runId}`;
  const workspaceId = 'workspace_ci';
  const entryBuilder = ({ sequence, previousReceipt }) => {
    const suffix = String(sequence).padStart(4, '0');
    const receipt = {
      id: `rcpt_${suffix}`,
      receiptHash: `integration-hash-${runId}-${suffix}`,
      signature: `integration-signature-${suffix}`,
      tenantId,
      workspaceId,
      timestamp: new Date('2026-08-19T16:00:00.000Z').toISOString(),
      previousReceipt
    };
    return { receipt, execution: 'quarantined', syntheticOnly: true };
  };
  const first = await createReceiptStore({ databaseUrl });
  await first.initialize();
  const one = await first.appendEntry(entryBuilder);
  const two = await first.appendEntry(entryBuilder);
  assert.equal(two.receipt.previousReceipt, one.receipt.receiptHash);
  const nonce = `ci_nonce_${runId}_123456`;
  assert.equal(await first.claimNonce({ principal: 'ci-agent', nonce, expiresAt: '2030-01-01T00:00:00.000Z' }), true);
  assert.equal(await first.claimNonce({ principal: 'ci-agent', nonce, expiresAt: '2030-01-01T00:00:00.000Z' }), false);
  await first.close();

  const second = await createReceiptStore({ databaseUrl });
  await second.initialize();
  const entries = await second.list({ tenantId, workspaceId });
  assert.deepEqual(entries.map(({ receipt }) => receipt.id), [one.receipt.id, two.receipt.id]);
  await second.close();
});
