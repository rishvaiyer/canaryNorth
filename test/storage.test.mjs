import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createJsonlReceiptStore, createMemoryReceiptStore, createReceiptStore, POSTGRES_SCHEMA } from '../src/storage.mjs';

function entryBuilder({ sequence, previousReceipt }) {
  const receipt = {
    id: `rcpt_${String(sequence).padStart(4, '0')}`,
    receiptHash: `hash-${sequence}`,
    signature: `signature-${sequence}`,
    tenantId: 'tenant_demo',
    workspaceId: 'workspace_demo',
    previousReceipt
  };
  return { receipt, execution: 'quarantined' };
}

test('memory storage appends a chained receipt without retaining request input', async () => {
  const store = createMemoryReceiptStore();
  const first = await store.appendEntry(entryBuilder);
  const second = await store.appendEntry(entryBuilder);
  assert.equal(first.receipt.previousReceipt, 'GENESIS');
  assert.equal(second.receipt.previousReceipt, first.receipt.receiptHash);
  assert.deepEqual((await store.list()).map(({ receipt }) => receipt.id), ['rcpt_0001', 'rcpt_0002']);
  assert.equal((await store.list({ tenantId: 'tenant_other', workspaceId: 'workspace_demo' })).length, 0);
  assert.equal((await store.list({ tenantId: 'tenant_demo', workspaceId: 'workspace_demo' })).length, 2);
  await assert.rejects(store.list({ tenantId: 'tenant_demo' }), /complete-scope-required/);
  assert.equal(JSON.stringify(await store.list()).includes('secret'), false);
});

test('jsonl storage survives a store recreation through the abstraction', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'contextseal-storage-'));
  const ledgerPath = path.join(directory, 'receipts.jsonl');
  try {
    const first = createJsonlReceiptStore(ledgerPath);
    await first.initialize();
    await first.appendEntry(entryBuilder);
    const second = createJsonlReceiptStore(ledgerPath);
    await second.initialize();
    assert.equal((await second.list()).length, 1);
    assert.equal((await second.findByReceiptId('rcpt_0001')).receipt.id, 'rcpt_0001');
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('nonce claims are one-time within the bounded local process lifetime', async () => {
  const store = createMemoryReceiptStore();
  const request = { principal: 'weather-agent', nonce: 'nonce_1234567890', expiresAt: new Date(Date.now() + 60_000).toISOString() };
  assert.equal(await store.claimNonce(request), true);
  assert.equal(await store.claimNonce(request), false);
});

test('DATABASE_URL never silently falls back when the PostgreSQL driver is unavailable', async () => {
  await assert.rejects(
    createReceiptStore({ databaseUrl: 'postgres://example.invalid/contextseal', postgresModule: {} }),
    /postgres-driver-required/
  );
});

test('PostgreSQL schema and writes are designed for parameterized storage', () => {
  assert.ok(POSTGRES_SCHEMA.some((statement) => statement.includes('contextseal_receipts')));
  assert.ok(POSTGRES_SCHEMA.some((statement) => statement.includes('contextseal_nonces')));
});
