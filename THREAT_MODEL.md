# ContextSeal threat model

## Trust boundaries

1. **Agent/model context:** untrusted and may contain hostile instructions. It receives opaque capability identifiers only.
2. **ContextSeal proxy:** trusted policy enforcement boundary. It validates request shape, capability, action, resource, expiry and content before forwarding.
3. **Tool/provider boundary:** not implemented in this synthetic demo. A production adapter must resolve credentials only inside this boundary.
4. **Receipt ledger:** evidence boundary. This demo is in-memory; production needs an append-only durable store.

## Threats and controls

| Threat | Control | Residual risk |
|---|---|---|
| Prompt injection attempts to override policy | injection quarantine before forwarding | Pattern detector is not a full classifier |
| Credential exfiltration in tool input | DLP block for common secret shapes | Custom formats require broader detectors |
| Over-broad delegated authority | exact action/resource allowlist and expiry | Fixture capabilities are not identity-bound |
| Replay or silent receipt mutation | receipt hash chain + HMAC signature | In-memory ledger resets on restart |
| Unknown capability reference | deny-by-default lookup | No external identity provider in demo |
| Large malicious payload | 100 KB request cap | Rate limiting is deployment responsibility |

## Production hardening checklist

- Bind capabilities to workload identity and audience; never accept bearer capabilities from arbitrary callers.
- Store signing keys in KMS/HSM, rotate them, and include key IDs in receipts.
- Use a durable append-only ledger with monotonic sequence/transaction IDs.
- Add nonce/replay protection, rate limits, schema validation, and tenant isolation.
- Make policy versions and approval provenance explicit in every receipt.
- Keep secret manager responses in a non-model process and scrub logs/traces.
- Treat DLP as layered detection plus human review, not a guarantee.
