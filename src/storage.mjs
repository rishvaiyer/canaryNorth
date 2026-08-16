import fs from 'node:fs';
import path from 'node:path';

const RECEIPT_ID_PATTERN = /^rcpt_[0-9]+$/;
const NONCE_PATTERN = /^[A-Za-z0-9._~-]{16,128}$/;

// ReceiptStore is the persistence boundary. A future low-risk tool adapter
// should receive only an allowed, scope-bound decision and opaque references,
// then return a redacted result for the caller. It must not bypass this store
// or place provider credentials in model context.

// The PostgreSQL adapter intentionally owns schema initialization. Deployments
// should still run migrations under an operational change process, but a fresh
// demo database can initialize itself without a separate migration tool.
export const POSTGRES_SCHEMA = Object.freeze([
  `CREATE SEQUENCE IF NOT EXISTS contextseal_receipt_sequence`,
  `CREATE TABLE IF NOT EXISTS contextseal_receipts (
    sequence_no BIGINT PRIMARY KEY,
    id TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    receipt JSONB NOT NULL,
    entry JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,
  `CREATE INDEX IF NOT EXISTS contextseal_receipts_created_at_idx ON contextseal_receipts (created_at)`,
  `ALTER TABLE contextseal_receipts ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'unscoped'`,
  `ALTER TABLE contextseal_receipts ADD COLUMN IF NOT EXISTS workspace_id TEXT NOT NULL DEFAULT 'unscoped'`,
  `CREATE TABLE IF NOT EXISTS contextseal_nonces (
    principal TEXT NOT NULL,
    nonce TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (principal, nonce)
  )`,
  `CREATE INDEX IF NOT EXISTS contextseal_nonces_expires_at_idx ON contextseal_nonces (expires_at)`
]);

function clone(value) {
  return structuredClone(value);
}

function storageError(message, cause) {
  const error = new Error(message, cause ? { cause } : undefined);
  error.code = 'receipt-storage-unavailable';
  return error;
}

function validateEntry(entry) {
  if (!entry || typeof entry !== 'object' || !entry.receipt || typeof entry.receipt !== 'object') {
    throw storageError('receipt-entry-required');
  }
  if (!RECEIPT_ID_PATTERN.test(entry.receipt.id || '') || typeof entry.receipt.receiptHash !== 'string' || !entry.receipt.signature) {
    throw storageError('receipt-ledger-integrity-failure');
  }
}

function validateNonce(nonce) {
  return typeof nonce === 'string' && NONCE_PATTERN.test(nonce);
}

function matchesScope(entry, scope = {}) {
  return (!scope.tenantId || entry.receipt.tenantId === scope.tenantId) && (!scope.workspaceId || entry.receipt.workspaceId === scope.workspaceId);
}

function validateScope(scope = {}) {
  if ((scope.tenantId && !scope.workspaceId) || (!scope.tenantId && scope.workspaceId)) throw storageError('complete-scope-required');
  return scope;
}

function createNonceTracker() {
  const seen = new Map();
  return {
    claim(principal, nonce, expiresAt) {
      if (!validateNonce(nonce)) return false;
      const now = Date.now();
      for (const [key, expiry] of seen) if (expiry <= now) seen.delete(key);
      const key = `${principal}:${nonce}`;
      if (seen.has(key)) return false;
      const expiry = Math.max(now + 1, new Date(expiresAt || now + 300_000).getTime());
      seen.set(key, expiry);
      return true;
    }
  };
}

export function createMemoryReceiptStore({ initialEntries = [] } = {}) {
  const entries = initialEntries.map((entry) => {
    validateEntry(entry);
    return clone(entry);
  });
  let sequence = entries.reduce((max, entry) => Math.max(max, Number(entry.receipt.id.slice(5)) || 0), 0);
  const nonceTracker = createNonceTracker();
  return {
    mode: 'memory',
    async initialize() {},
    async list(scope) { return clone(entries.filter((entry) => matchesScope(entry, validateScope(scope)))); },
    async findByReceiptId(id, scope) { return clone(entries.find(({ receipt }) => receipt.id === id && matchesScope({ receipt }, validateScope(scope))) || null); },
    async appendEntry(buildEntry) {
      const entry = buildEntry({ sequence: ++sequence, previousReceipt: entries.at(-1)?.receipt.receiptHash || 'GENESIS' });
      validateEntry(entry);
      entries.push(clone(entry));
      return clone(entry);
    },
    async claimNonce({ principal, nonce, expiresAt }) { return nonceTracker.claim(principal, nonce, expiresAt); },
    async close() {}
  };
}

export function createJsonlReceiptStore(ledgerPath) {
  if (!ledgerPath || typeof ledgerPath !== 'string') throw storageError('receipt-ledger-path-required');
  let entries = [];
  let sequence = 0;
  const nonceTracker = createNonceTracker();

  return {
    mode: 'jsonl',
    async initialize() {
      try {
        fs.mkdirSync(path.dirname(ledgerPath), { recursive: true });
        if (!fs.existsSync(ledgerPath)) return;
        const lines = fs.readFileSync(ledgerPath, 'utf8').split('\n').filter(Boolean);
        entries = lines.map((line) => {
          const entry = JSON.parse(line);
          validateEntry(entry);
          return entry;
        });
        sequence = entries.reduce((max, entry) => Math.max(max, Number(entry.receipt.id.slice(5)) || 0), 0);
      } catch (error) {
        if (error.code === 'receipt-storage-unavailable') throw error;
        throw storageError('receipt-ledger-integrity-failure', error);
      }
    },
    async list(scope) { return clone(entries.filter((entry) => matchesScope(entry, validateScope(scope)))); },
    async findByReceiptId(id, scope) { return clone(entries.find(({ receipt }) => receipt.id === id && matchesScope({ receipt }, validateScope(scope))) || null); },
    async appendEntry(buildEntry) {
      const entry = buildEntry({ sequence: sequence + 1, previousReceipt: entries.at(-1)?.receipt.receiptHash || 'GENESIS' });
      validateEntry(entry);
      try {
        fs.mkdirSync(path.dirname(ledgerPath), { recursive: true });
        const fd = fs.openSync(ledgerPath, 'a');
        try {
          fs.writeSync(fd, `${JSON.stringify(entry)}\n`);
          fs.fsyncSync(fd);
        } finally {
          fs.closeSync(fd);
        }
        sequence += 1;
        entries.push(clone(entry));
        return clone(entry);
      } catch (error) {
        throw storageError('receipt-ledger-write-failed', error);
      }
    },
    async claimNonce({ principal, nonce, expiresAt }) { return nonceTracker.claim(principal, nonce, expiresAt); },
    async close() {}
  };
}

function resolvePool(pgModule) {
  const Pool = pgModule?.Pool || pgModule?.default?.Pool;
  if (typeof Pool !== 'function') {
    // Install the `pg` package in the application environment before setting
    // DATABASE_URL. It is intentionally not bundled here because this demo
    // currently has no external runtime dependencies.
    throw storageError('postgres-driver-required: install pg before using DATABASE_URL');
  }
  return Pool;
}

export function createPostgresReceiptStore({ databaseUrl, pgModule }) {
  if (!databaseUrl) throw storageError('database-url-required');
  const Pool = resolvePool(pgModule);
  const pool = new Pool({ connectionString: databaseUrl });
  let initialized = false;

  return {
    mode: 'postgres',
    async initialize() {
      try {
        for (const statement of POSTGRES_SCHEMA) await pool.query(statement);
        initialized = true;
      } catch (error) {
        throw storageError('postgres-initialize-failed', error);
      }
    },
    async list(scope = {}) {
      if (!initialized) throw storageError('receipt-store-not-initialized');
      validateScope(scope);
      try {
        const query = scope.tenantId && scope.workspaceId
          ? ['SELECT entry FROM contextseal_receipts WHERE tenant_id = $1 AND workspace_id = $2 ORDER BY sequence_no ASC', [scope.tenantId, scope.workspaceId]]
          : ['SELECT entry FROM contextseal_receipts ORDER BY sequence_no ASC', []];
        const result = await pool.query(query[0], query[1]);
        return result.rows.map((row) => clone(row.entry));
      } catch (error) {
        throw storageError('postgres-read-failed', error);
      }
    },
    async findByReceiptId(id, scope = {}) {
      if (!initialized) throw storageError('receipt-store-not-initialized');
      validateScope(scope);
      try {
        const query = scope.tenantId && scope.workspaceId
          ? ['SELECT entry FROM contextseal_receipts WHERE id = $1 AND tenant_id = $2 AND workspace_id = $3', [id, scope.tenantId, scope.workspaceId]]
          : ['SELECT entry FROM contextseal_receipts WHERE id = $1', [id]];
        const result = await pool.query(query[0], query[1]);
        return result.rows[0] ? clone(result.rows[0].entry) : null;
      } catch (error) {
        throw storageError('postgres-read-failed', error);
      }
    },
    async appendEntry(buildEntry) {
      if (!initialized) throw storageError('receipt-store-not-initialized');
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query("SELECT pg_advisory_xact_lock(hashtext('contextseal:receipt-chain'))");
        const priorResult = await client.query('SELECT receipt->>\'receiptHash\' AS "receiptHash" FROM contextseal_receipts ORDER BY sequence_no DESC LIMIT 1');
        const sequenceResult = await client.query("SELECT nextval('contextseal_receipt_sequence') AS sequence");
        const sequence = Number(sequenceResult.rows[0].sequence);
        const entry = buildEntry({ sequence, previousReceipt: priorResult.rows[0]?.receiptHash || 'GENESIS' });
        validateEntry(entry);
        await client.query(
          'INSERT INTO contextseal_receipts (sequence_no, id, tenant_id, workspace_id, receipt, entry, created_at) VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7)',
          [sequence, entry.receipt.id, entry.receipt.tenantId, entry.receipt.workspaceId, JSON.stringify(entry.receipt), JSON.stringify(entry), entry.receipt.timestamp]
        );
        await client.query('COMMIT');
        return clone(entry);
      } catch (error) {
        try { await client.query('ROLLBACK'); } catch {}
        if (error.code === 'receipt-storage-unavailable') throw error;
        throw storageError('postgres-write-failed', error);
      } finally {
        client.release();
      }
    },
    async claimNonce({ principal, nonce, expiresAt }) {
      if (!initialized) throw storageError('receipt-store-not-initialized');
      if (!validateNonce(nonce)) return false;
      try {
        await pool.query('DELETE FROM contextseal_nonces WHERE expires_at <= NOW()');
        const result = await pool.query(
          'INSERT INTO contextseal_nonces (principal, nonce, expires_at) VALUES ($1, $2, $3) ON CONFLICT (principal, nonce) DO NOTHING RETURNING nonce',
          [principal, nonce, expiresAt]
        );
        return result.rowCount === 1;
      } catch (error) {
        throw storageError('postgres-nonce-write-failed', error);
      }
    },
    async close() { await pool.end(); }
  };
}

export async function createReceiptStore({ databaseUrl, ledgerPath, postgresModule } = {}) {
  if (databaseUrl) {
    let pgModule = postgresModule;
    if (!pgModule) {
      try {
        pgModule = await import('pg');
      } catch (error) {
        throw storageError('postgres-driver-required: install pg before using DATABASE_URL', error);
      }
    }
    return createPostgresReceiptStore({ databaseUrl, pgModule });
  }
  if (ledgerPath) return createJsonlReceiptStore(ledgerPath);
  return createMemoryReceiptStore();
}
