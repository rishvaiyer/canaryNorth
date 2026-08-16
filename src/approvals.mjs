import crypto from 'node:crypto';

export const DEFAULT_APPROVAL_TTL_MS = 5 * 60 * 1000;

function clone(value) {
  return structuredClone(value);
}

function approvalError(message) {
  return new Error(message);
}

function opaqueApprovalId() {
  return `apr_${crypto.randomBytes(18).toString('base64url')}`;
}

function scopeMatches(request, scope = {}) {
  return (!scope.tenantId || request.tenantId === scope.tenantId) &&
    (!scope.workspaceId || request.workspaceId === scope.workspaceId);
}

function validateScope(scope = {}) {
  if ((scope.tenantId && !scope.workspaceId) || (!scope.tenantId && scope.workspaceId)) {
    throw approvalError('complete-scope-required');
  }
  return scope;
}

function validateTtl(ttlMs) {
  if (!Number.isFinite(ttlMs) || ttlMs < 1_000 || ttlMs > 15 * 60 * 1000) {
    throw approvalError('invalid-approval-ttl');
  }
  return Math.floor(ttlMs);
}

export function createApprovalStore({
  ttlMs = DEFAULT_APPROVAL_TTL_MS,
  now = () => Date.now(),
  idFactory = opaqueApprovalId
} = {}) {
  const lifetime = validateTtl(ttlMs);
  const pending = new Map();

  function getRecord(id) {
    if (typeof id !== 'string' || id.length < 8 || id.length > 128) throw approvalError('invalid-approval-id');
    return pending.get(id) || null;
  }

  function snapshot(record) {
    return clone(record);
  }

  function expireIfNeeded(record, at) {
    if (record.status === 'pending' && at >= Date.parse(record.expiresAt)) {
      record.status = 'expired';
      record.decision = 'expired';
      record.resolvedAt = new Date(at).toISOString();
      record.outcome = 'deny';
      record.reasonCode = 'approval-expired';
      return true;
    }
    return false;
  }

  return {
    mode: 'memory',
    ttlMs: lifetime,

    create({ request, policyResult, createdAt = now() }) {
      if (!request || typeof request !== 'object' || !policyResult || typeof policyResult !== 'object') {
        throw approvalError('approval-record-required');
      }
      const id = idFactory();
      if (typeof id !== 'string' || id.length < 8 || pending.has(id)) throw approvalError('invalid-approval-id');
      const record = {
        id,
        status: 'pending',
        requestedAt: new Date(createdAt).toISOString(),
        expiresAt: new Date(createdAt + lifetime).toISOString(),
        request: clone(request),
        policy: {
          allowed: Boolean(policyResult.allowed),
          reason: policyResult.reason || null,
          code: policyResult.code || (policyResult.allowed ? 'policy-passed' : 'policy-denied'),
          inspection: clone(policyResult.inspection || null)
        },
        decision: null,
        outcome: null,
        reasonCode: null,
        resolvedAt: null,
        receiptId: null
      };
      pending.set(id, record);
      return snapshot(record);
    },

    get(id, { scope } = {}) {
      const record = getRecord(id);
      if (!record) return null;
      validateScope(scope);
      if (!scopeMatches(record.request, scope)) throw approvalError('approval-scope-mismatch');
      expireIfNeeded(record, now());
      return snapshot(record);
    },

    list({ scope } = {}) {
      validateScope(scope);
      const at = now();
      return [...pending.values()]
        .filter((record) => scopeMatches(record.request, scope))
        .map((record) => {
          expireIfNeeded(record, at);
          return snapshot(record);
        });
    },

    begin(id, decision, { scope, at = now() } = {}) {
      if (!['approve', 'deny'].includes(decision)) throw approvalError('invalid-approval-decision');
      const record = getRecord(id);
      if (!record) return null;
      validateScope(scope);
      if (!scopeMatches(record.request, scope)) throw approvalError('approval-scope-mismatch');
      if (record.status !== 'pending') return { kind: 'already-resolved', record: snapshot(record) };
      if (expireIfNeeded(record, at)) return { kind: 'expired', record: snapshot(record) };
      record.decision = decision;
      record.status = decision === 'approve' ? 'approving' : 'denied';
      record.resolvedAt = decision === 'deny' ? new Date(at).toISOString() : null;
      record.outcome = decision === 'deny' ? 'deny' : null;
      record.reasonCode = decision === 'deny' ? 'human-denied' : null;
      return { kind: decision === 'approve' ? 'approving' : 'denied', record: snapshot(record) };
    },

    completeApproval(id, { outcome, reasonCode, receiptId, at = now() } = {}) {
      const record = getRecord(id);
      if (!record || record.status !== 'approving') return null;
      record.status = 'approved';
      record.resolvedAt = new Date(at).toISOString();
      record.outcome = outcome === 'allow' ? 'allow' : 'deny';
      record.reasonCode = reasonCode || (record.outcome === 'allow' ? 'policy-passed' : 'policy-denied');
      record.receiptId = receiptId || null;
      return snapshot(record);
    },

    completeDenial(id, { receiptId, at = now() } = {}) {
      const record = getRecord(id);
      if (!record || record.status !== 'denied') return null;
      record.resolvedAt = new Date(at).toISOString();
      record.receiptId = receiptId || null;
      return snapshot(record);
    }
  };
}
