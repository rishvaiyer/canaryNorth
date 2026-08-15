# ContextSeal handoff

## Outcome

Public-ready synthetic security demo showing how an AI agent can request tool actions without receiving raw provider credentials. The project is isolated in the `context-seal` repository.

## Demo path

1. Open `/` and show that the model sees `cap_weather_read_7f3d`, while the conceptual provider key is never serialized.
2. Click **Run safe forecast**. Policy passes and a signed receipt appears.
3. Click **Quarantine injection**. The same capability is denied because untrusted text attempts to override instructions.
4. Click **Block secret-shaped input**. DLP stops a synthetic credential pattern before the tool path.
5. Use **Read-only MCP audit** to explain `POST /mcp/audit`, full receipt signatures, and the previous-receipt hash chain.

## Verification

- `npm test`: 12 passing policy and graph tests.
- `npm run lint`: syntax checks for server, policy, and browser JavaScript.
- `GET /health`, `GET /api/bootstrap`, `POST /api/authorize`, and `POST /mcp/audit`: smoke-tested locally on August 15, 2026.

## Deployment

Deploy with `railway up --new --name context-seal` from this directory after GitHub is connected. Set `RECEIPT_SIGNING_KEY` to a strong Railway sealed variable. Never commit that value. The service listens on Railway's `PORT` and requires no database for the synthetic demo.

## Known limitations

The ledger and fixture capabilities reset on restart. The vault and tool adapter are simulated. The detectors are intentionally narrow. There is no authentication, identity binding, replay protection, key rotation, policy versioning, or independent receipt-verification endpoint. The README and `THREAT_MODEL.md` describe the production hardening path.
