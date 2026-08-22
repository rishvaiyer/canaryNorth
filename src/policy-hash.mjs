import crypto from 'node:crypto';
import { canonicalize } from './signing.mjs';
import { DEMO_CAPABILITIES, POLICY_VERSION } from './policy.mjs';

// A real hash over the real policy surface.
//
// Why this exists: the Benji7Lives fixture reported policyBeforeHash and
// policyAfterHash as the same string constant, so the equality it asserted was
// true by construction and could never have failed. These two functions make
// the before and after values two separate computations over live module state.
//
// The snapshot deliberately excludes `label` and `reason`, which are display
// copy. It includes everything that decides an authorization outcome.

export function policySnapshot() {
  return {
    policyVersion: POLICY_VERSION,
    capabilities: DEMO_CAPABILITIES.map(({ id, principal, tool, resource, scopes, audience, tenantId, workspaceId, policyVersion, expiresAt, status }) => ({
      id, principal, tool, resource, scopes: [...scopes], audience, tenantId, workspaceId, policyVersion, expiresAt, status
    }))
  };
}

export function policyHash(snapshot = policySnapshot()) {
  return crypto.createHash('sha256').update(canonicalize(snapshot)).digest('hex');
}
