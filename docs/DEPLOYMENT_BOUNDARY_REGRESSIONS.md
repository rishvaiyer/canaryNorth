# CanaryNorth deployment boundary regressions

This repository includes an adversarial, local-only deployment harness for the
configuration assumptions that sit around the policy engine. It starts isolated
CanaryNorth child processes on random loopback ports and proves that unsafe
production configurations fail closed before the service begins listening.

## Covered invariants

| Boundary | Regression proof |
| --- | --- |
| Signing | Production refuses to boot without required signing material. |
| Authentication | Production refuses to boot without a sufficiently long bearer token. |
| Persistence | Non-demo production refuses to boot without PostgreSQL or an append-only JSONL ledger. |
| Demo separation | Explicit demo mode reports `synthetic-demo`, in-memory storage, and synthetic evidence. |
| Key stability | An ephemeral Ed25519 demo key is disclosed as ephemeral; configured production reports a stable key. |
| API authentication | Protected APIs reject an unauthenticated request. |
| Scope binding | Production rejects missing or mismatched tenant and workspace scope. |
| Identity binding | Production rejects authorization requests missing principal, audience, policy version, or nonce. |
| Replay resistance | A second use of the same nonce is denied and recorded. |
| Receipt persistence | Allow and replay-deny decisions are appended to the configured ledger. |

## Run locally

```bash
npm ci
node --test test/deployment-boundaries.test.mjs
```

The dedicated GitHub Actions workflow runs the same suite for pull requests and
`main`. The ordinary `npm test` command also discovers the regression file.

## Safety and claim boundary

- Every request, credential value, capability, tenant, and artifact is synthetic.
- Child servers bind only to a random loopback port.
- The suite does not contact an external target or tool.
- `would-forward-to-tool` remains a simulated outcome, not proof of execution.
- The harness checks configuration and HTTP contracts. It is not a penetration
  test, exploit demonstration, production certification, identity-provider test,
  managed-database recovery test, or independent security review.
