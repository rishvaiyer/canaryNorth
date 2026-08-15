# ContextSeal handoff

## Outcome

Standalone public-ready secretless MCP policy proxy demo. New code is isolated at `Documents/New project/context-seal`; no portfolio, CanonCue, or Thirdwurld files are changed.

## Demo path

1. Open `/` and point out that the model sees `cap_weather_read_7f3d`, while the provider key is never serialized.
2. Click **Run safe forecast**: policy passes and a signed receipt appears.
3. Click **Quarantine injection**: the same capability is denied because untrusted text tries to override instructions.
4. Click **Block secret-shaped input**: DLP blocks a credential-shaped value before forwarding.
5. Use **Read-only MCP audit** to explain `POST /mcp/audit` and the hash chain.

## Verification

- `npm test` — seven policy tests.
- `npm run lint` — Node syntax checks for server, policy and client.
- `GET /health`, `GET /api/bootstrap`, and `POST /mcp/audit` smoke-tested locally before handoff.

## Deployment

Deploy with `railway up --new --name context-seal` from this directory after GitHub is connected. Set `RECEIPT_SIGNING_KEY` to a Railway sealed variable. Never commit that value. The service listens on Railway's `PORT` and has no database or paid resource requirement.

## Known limitations

The ledger and fixture capabilities reset on restart; the vault/tool adapter is simulated; detectors are intentionally narrow; and there is no authentication layer. The README and `THREAT_MODEL.md` describe the production hardening path.
