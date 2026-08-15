# ContextSeal — AI Action Receipts

Every AI-generated file should carry its own provenance—privately.

ContextSeal is a trust-metadata layer for AI-generated work. Its policy proxy keeps raw credentials out of model context while producing signed, hash-chained receipts that explain which tools ran, what was approved, and what remains unverified. The current demo shows decision-level receipts; the product direction extends those receipts to artifact hashes and private embedded or sidecar provenance.

## Why it is useful

- **Opaque capabilities:** `cap_*` references are safe to put in model context; the provider key never is.
- **Structural policy:** action and resource allowlists, expiry, and deny-by-default enforcement happen in the proxy.
- **Content firewall:** prompt-injection and credential-shaped payloads are quarantined before forwarding.
- **Evidence:** every allow/deny decision produces a tamper-evident action receipt with a previous-receipt link.
- **Private provenance:** receipts expose process and evidence—not secrets, private identities, or unnecessary personal data.
- **MCP audit:** `POST /mcp/audit` supports a read-only `contextseal.audit` method.

The sample data is synthetic. The demo does not call an external tool or connect to a secret vault. It does not yet attach receipts to generated files; artifact binding is the next product layer.

## Run

```bash
npm test
npm run lint
npm start
open http://localhost:4178
```

Set `RECEIPT_SIGNING_KEY` in a real deployment. The development fallback is intentionally public and must not be used for production evidence.

Production mode (`NODE_ENV=production`) fails closed unless `RECEIPT_SIGNING_KEY` and `CONTEXTSEAL_AUTH_TOKEN` are set to values at least 32 characters long. Authenticated requests use `Authorization: Bearer <CONTEXTSEAL_AUTH_TOKEN>`. `CONTEXTSEAL_DEMO_MODE=1` is an explicit exception for this public synthetic demo only; it must never be used for real workloads or real receipts. Local development remains an explicitly unauthenticated synthetic demo unless `CONTEXTSEAL_REQUIRE_AUTH=1` is set.

The hosted synthetic demo is [context-seal-production.up.railway.app](https://context-seal-production.up.railway.app/). It contains no external tool connection, real capability store, identity provider, or user data. A real deployment must disable demo mode and add identity-bound authorization before exposing receipt APIs.

## API

- `GET /health` — liveness.
- `GET /api/bootstrap` — redacted capabilities, graph and receipts.
- `POST /api/authorize` — evaluate `{ capabilityId, action, resource, input }`.
- `GET /api/receipts` — current in-memory ledger.
- `POST /mcp/audit` — read-only JSON-RPC audit (`{ "method": "contextseal.audit", "id": 1 }`).

## Limits

This is a focused reference implementation: its ledger is in-memory, capability storage is fixture-backed, signatures use an HMAC secret, and the DLP/injection detectors are intentionally small. Production artifact provenance additionally needs canonical artifact hashing, format-safe embedding or private sidecars, durable storage, key rotation/HSM, identity binding, replay protection, policy versioning, a real secret manager, and a full content-security test corpus.
