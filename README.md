# CanaryNorth: AI Action Receipts

Every AI-generated file should carry its own provenance, privately.

CanaryNorth is the new product name for this project, formerly ContextSeal. It is a trust and policy layer for AI-generated work. Its proxy keeps raw credentials out of model context while producing signed, hash-chained receipts that explain which actions were approved, which were blocked, and what remains unverified. The current demo is synthetic and shows decision-level receipts plus a portable artifact sidecar.

Compatibility note: repository paths, package names, API routes, schemas, database tables, headers, and `CONTEXTSEAL_*` environment variables remain unchanged so existing integrations do not break during the visual rebrand.

## Why it is useful

- **Opaque capabilities:** `cap_*` references are safe to put in model context; the provider key never is.
- **Structural policy:** action and resource allowlists, expiry, and deny-by-default enforcement happen in the proxy.
- **Content firewall:** prompt-injection, hidden direction-changing characters, tool-shaped metadata, memory-poisoning cues, broad export intent, unsafe output formats, and credential-shaped payloads are quarantined before forwarding.
- **Agentic trust gates:** optional typed metadata checks can verify tool attestation, revalidate memory scope and freshness, preserve delegated provenance, trip synthetic canaries, and stop adaptive context drift before an action is forwarded.
- **Evidence:** every allow/deny decision produces a tamper-evident action receipt with a previous-receipt link.
- **Private provenance:** receipts expose process and evidence, not secrets, private identities, or unnecessary personal data.
- **MCP audit:** `POST /mcp/audit` supports a read-only `contextseal.audit` method.
- **Workspace boundaries:** production requests can bind to a tenant and workspace, with explicit principal, audience, nonce, and policy-version checks.
- **Durable storage:** memory, append-only JSONL, and PostgreSQL receipt stores use the same storage interface.
- **Human approval:** the synthetic `tickets.update` flow creates a short-lived approval, supports approve or deny, re-checks policy and nonce state, and records the decision in a signed receipt.
- **Safe evidence ledger:** synthetic prompt-injection, DLP, replay, approval, malware-scan, and steganography-signal events use a versioned, redaction-aware schema. Malware and steganography rows are explicitly labeled as not-run or example-only.
- **Local evidence encryption:** the evidence package format uses envelope encryption with AES-256-GCM, a random data key, a wrapped customer key, retention metadata, tamper checks, and a separate integrity signature. Decryption is designed to happen locally with an operator-managed key.
- **ML direction:** the planned risk layer learns redacted workflow behavior in shadow mode and recommends review or quarantine. It cannot override deterministic deny rules and is not shipped as a trained detector yet.
- **Teaching graph:** the visual map supports guided scenarios, event timelines, node inspectors, keyboard navigation, touch dragging, and reset/recenter controls.

The sample data is synthetic. The demo does not call an external tool or connect to a secret vault. After running the safe path, use **[bind artifact]** to download `weather-brief.md` plus a `.receipt.json` sidecar containing the artifact hash, receipt hash, and signed manifest. This proves a policy decision and file integrity. It does not prove that the content is correct, safe, original, or human-approved.

For a plain-language walkthrough, use the **Explain like I'm five** link in the demo or open [public/learn.html](public/learn.html). For the interview-style story, open `/pen-entry.html` and then `/threat-lab.html`; those pages are a synthetic visualization only. The concise owner-facing iteration record is [docs/ITERATION_LOG.md](docs/ITERATION_LOG.md). The future-facing research is in [docs/RESEARCH_AI_SECURITY_2026.md](docs/RESEARCH_AI_SECURITY_2026.md), [docs/RESEARCH_FILE_THREATS_2026.md](docs/RESEARCH_FILE_THREATS_2026.md), [docs/PRODUCT_OPPORTUNITIES_2026.md](docs/PRODUCT_OPPORTUNITIES_2026.md), and [docs/ML_RISK_LAYER_ROADMAP.md](docs/ML_RISK_LAYER_ROADMAP.md).

## Run

```bash
npm test
npm run lint
npm start
open http://localhost:4178
```

Set `RECEIPT_SIGNING_KEY` in a real deployment. The development fallback is intentionally public and must not be used for production evidence. PostgreSQL deployments require the `pg` dependency already declared in `package.json`. Set `CONTEXTSEAL_EVIDENCE_WRAPPING_KEY` to a base64 or 64-character hex encoded 32-byte key before enabling encrypted evidence export. Keep that key in a KMS or secret manager and do not expose it to the browser.

Production mode (`NODE_ENV=production`) fails closed unless `RECEIPT_SIGNING_KEY` and `CONTEXTSEAL_AUTH_TOKEN` are set to values at least 32 characters long. Authenticated requests use `Authorization: Bearer <CONTEXTSEAL_AUTH_TOKEN>`. Outside demo mode, requests must also provide the existing technical headers `X-ContextSeal-Tenant`, `X-ContextSeal-Workspace`, principal, audience, policy version, and a one-time nonce. `CONTEXTSEAL_DEMO_MODE=1` is an explicit exception for this public synthetic demo only; it must never be used for real workloads or real receipts. Local development remains an explicitly unauthenticated synthetic demo unless `CONTEXTSEAL_REQUIRE_AUTH=1` is set.

Outside demo mode, configure either `DATABASE_URL` for PostgreSQL or `RECEIPT_LEDGER_PATH` for an append-only JSONL ledger. The PostgreSQL adapter initializes `contextseal_receipts` and `contextseal_nonces`, uses parameterized queries, and serializes receipt-chain writes. Mount JSONL storage on durable, access-controlled storage; an ephemeral container filesystem is not an audit store.

### Railway with PostgreSQL

The intended small-business deployment shape is one CanaryNorth service plus one Railway PostgreSQL service:

```bash
railway add --database postgres --json
railway variable set CONTEXTSEAL_DEMO_MODE=1 --service context-seal
railway up
```

Connect the database service's `DATABASE_URL` to the app service using Railway's variable reference UI or CLI. Keep demo mode enabled only for synthetic demonstrations. For real small-business workloads, disable demo mode, configure identity-bound authentication, and use a separate environment for testing.

The hosted synthetic demo is [context-seal-production.up.railway.app](https://context-seal-production.up.railway.app/). It contains no external tool connection, real capability store, identity provider, or user data. A real deployment must disable demo mode, add identity-bound authorization, configure durable ledger storage, and complete an independent security review before exposing receipt APIs.

## API

- `GET /health` - liveness and active storage mode.
- `GET /api/bootstrap` - redacted capabilities, graph, and scoped receipts.
- `POST /api/authorize` - evaluate a scoped request and append a receipt.
- `GET /api/receipts` - read receipts within the request scope.
- `GET /api/evidence` - read the synthetic, redaction-aware human ledger.
- `POST /api/evidence/package` - create an encrypted synthetic evidence package when an operator-managed wrapping key is configured. The service never returns that key.
- `POST /mcp/audit` - read-only JSON-RPC audit (`{ "method": "contextseal.audit", "id": 1 }`).
- `POST /api/artifacts/export` - bind an allowed receipt to a synthetic artifact and return the artifact plus signed receipt sidecar.
- `POST /api/artifacts/verify` - verify the artifact hash, manifest hash, and server signature.

## Limits

This is a focused reference implementation. Capabilities, approvals, and evidence events are fixture-backed, the public deployment remains synthetic, signatures use an HMAC secret, and the DLP/injection detectors are intentionally small deterministic signals, not a general classifier. The evidence module is an encrypted package format, not a malware scanner, steganography detector, or production retention service. The ML risk layer is a roadmap, not a trained security model. The PostgreSQL path is a durable persistence foundation, not a complete enterprise security platform. A small-business release still needs a real identity provider, durable approval and evidence persistence, tenant administration, policy management, secret-manager integration, structured logging, monitoring, backup/restore procedures, key rotation, independent security review, and a broader content-security test corpus.

## Small-business product direction

The most credible product is a narrow AI action gateway for one to three workflows, such as customer-support ticket updates, document exports, or scheduled reporting. The customer would get:

1. One protected workspace.
2. A few allowlisted actions and resources.
3. Human approval for higher-risk actions.
4. Durable receipts that answer who requested what, what policy decided, and what evidence exists.
5. A simple dashboard instead of a full security operations center.

That is a practical path toward enterprise-grade controls for small businesses without claiming to be a universal AI firewall.
