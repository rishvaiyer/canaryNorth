# CanaryNorth handoff

## Outcome

Standalone synthetic secretless MCP policy proxy demo with a production-shaped storage and authorization boundary. New code is isolated at `Documents/New project/context-seal`; no portfolio, CanonCue, or Thirdwurld files are changed.

## Demo path

1. Open `/` and point out that the model sees `cap_weather_read_7f3d`, while the provider key is never serialized.
2. Click **Run safe forecast**: policy passes and a signed receipt appears.
3. Click **Quarantine injection**: the same capability is denied because untrusted text tries to override instructions.
4. Click **Block secret-shaped input**: DLP blocks a credential-shaped value before forwarding.
5. Use **Read-only MCP audit** to explain `POST /mcp/audit` and the hash chain.
6. Click **Explain like I'm five** or open `/learn.html` for the beginner walkthrough.
7. Use the graph scenario controls, timeline, node inspector, keyboard navigation, and reset/recenter controls to explain the flow.
8. In **Review a synthetic ticket update**, request approval, then approve or deny it. The result is a synthetic approval record and receipt; no ticket system is called.
9. In the evidence ledger, point out that malware and steganography entries are visibly marked as not-run or example-only. The encrypted package module is local-decryption-ready, but the browser does not receive a key.

## Verification

- `npm test` - 44 tests.
- `npm run lint` - Node syntax checks for server, policy, and client.
- `GET /health`, `GET /api/bootstrap`, and `POST /mcp/audit` smoke-tested locally before handoff.
- `GET /api/evidence` and the encrypted evidence package module verified locally. Encrypted export stays disabled unless `CONTEXTSEAL_EVIDENCE_WRAPPING_KEY` is configured.
- Public deployment `f89812c8-2a22-4cf0-86ca-377a32fc9275` is `SUCCESS`; `/health`, `/pen-entry.html`, `/threat-lab.html`, `/learn.html`, and `/api/evidence` return 200. Public encrypted evidence export returns 503 until a wrapping key is intentionally configured.
- `git diff --check` passed.

## Deployment

The existing Railway project is `context-seal`, with service `context-seal` and public domain `context-seal-production.up.railway.app`. Add a PostgreSQL service, connect its `DATABASE_URL` to the app, keep `CONTEXTSEAL_DEMO_MODE=1` for synthetic demos, and deploy with `railway up`. Set `RECEIPT_SIGNING_KEY` and `CONTEXTSEAL_AUTH_TOKEN` as sealed variables. Never commit either value. The service listens on Railway's `PORT`.

## Known limitations

The public demo still uses synthetic fixture capabilities and does not call external tools. The approval and evidence ledgers are product-shaped simulations, not complete durable case management. The evidence module encrypts packages but does not scan malware or steganography. The ML risk layer is planned shadow-mode work, not a live detector. The PostgreSQL receipt adapter is ready, but a real small-business product still needs identity-provider integration, tenant administration, durable approvals and evidence, a secret manager, durable operational backups, replay testing, and an independent security review. See `THREAT_MODEL.md`, `SECURITY.md`, and `docs/ITERATION_LOG.md` for boundaries and evolution notes.
