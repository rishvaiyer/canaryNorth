# ContextSeal

ContextSeal is a secretless MCP policy-proxy demo for agents that need to call tools without receiving raw credentials. The model gets an opaque capability reference; the proxy resolves server-side policy, checks scope and expiry, screens untrusted content, and emits a signed, hash-chained receipt for every decision.

## Why it is useful

- **Opaque capabilities:** `cap_*` references are safe to put in model context; the provider key never is.
- **Structural policy:** action and resource allowlists, expiry, and deny-by-default enforcement happen in the proxy.
- **Content firewall:** prompt-injection and credential-shaped payloads are quarantined before forwarding.
- **Evidence:** every allow/deny decision produces a tamper-evident receipt with a previous-receipt link.
- **MCP audit:** `POST /mcp/audit` supports a read-only `contextseal.audit` method.

The sample data is synthetic. The demo does not call an external tool or connect to a secret vault.

## Run

```bash
npm test
npm run lint
npm start
open http://localhost:4178
```

Set `RECEIPT_SIGNING_KEY` in a real deployment. The development fallback is intentionally public and must not be used for production evidence.

## API

- `GET /health` — liveness.
- `GET /api/bootstrap` — redacted capabilities, graph and receipts.
- `POST /api/authorize` — evaluate `{ capabilityId, action, resource, input }`.
- `GET /api/receipts` — current in-memory ledger.
- `POST /mcp/audit` — read-only JSON-RPC audit (`{ "method": "contextseal.audit", "id": 1 }`).

## Limits

This is a focused reference implementation: its ledger is in-memory, capability storage is fixture-backed, signatures use an HMAC secret, and the DLP/injection detectors are intentionally small. Production use needs durable storage, key rotation/HSM, identity binding, replay protection, policy versioning, a real secret manager, and a full content-security test corpus.
