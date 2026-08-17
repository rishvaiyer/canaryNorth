# CanaryNorth threat model

> Public preview note: The current private fixture map contains 115 active fixture-to-CanaryNorth evaluator checks, each with a passing direct or authorization-path test. The four `dormant-rehearsal-variants` remain disabled by default and outside that count. This is metadata-policy evidence, not a claim of scanner coverage, live target detection, production safety, or universal protection.

## Trust boundaries

1. **Agent/model context:** untrusted and may contain hostile instructions. It receives opaque capability identifiers only.
2. **CanaryNorth proxy:** trusted policy enforcement boundary. It validates request shape, capability, action, resource, expiry and content before forwarding.
3. **Tool/provider boundary:** not implemented in this synthetic demo. A production adapter must resolve credentials only inside this boundary.
4. **Receipt and evidence ledger:** evidence boundary. Receipts use the configured durable store, while the human evidence view and approval state are synthetic in this demo. Encrypted export requires an operator-managed wrapping key.

## Threats and controls

| Threat | Control | Residual risk |
|---|---|---|
| Prompt injection attempts to override policy | injection quarantine before forwarding | Pattern detector is not a full classifier |
| Hidden or direction-changing content | Unicode control-character signal and quarantine | Benign documents may require human review; this is not image steganography detection |
| Tool shadowing or fake tool metadata | Tool-shaped metadata signal plus deny-before-forwarding | The optional descriptor check is structural metadata consistency only; independent cryptographic signature and registry verification are not connected |
| Memory poisoning | Durable-memory mutation cue is quarantined | No production memory service is connected |
| Broad export or exfiltration intent | Protected-data export signal and deny-before-forwarding | Custom data classes require broader DLP coverage |
| Unsafe active-content output format | HTML/script and executable-format signal | Output sanitization is still required at every renderer |
| Credential exfiltration in tool input | DLP block for common secret shapes | Custom formats require broader detectors |
| Over-broad delegated authority | exact action/resource allowlist and expiry | Fixture capabilities are not identity-bound |
| Replay or silent receipt mutation | receipt hash chain + HMAC signature | In-memory ledger resets on restart |
| Unknown capability reference | deny-by-default lookup | No external identity provider in demo |
| Large malicious payload | 100 KB request cap | Rate limiting is deployment responsibility |
| Sensitive evidence leakage | Redaction-aware event schema, safe summaries, hashes, and no raw payload in the normal ledger | Redaction is defense in depth, not proof that every secret format is known |
| Evidence package tampering or key misuse | AES-256-GCM envelope encryption, manifest and content hashes, local decrypt, separate integrity signature | Key custody, rotation, recovery, and deletion are not implemented as a managed service |
| Steganographic or malware content | Canonical event types and explicit `signal` or `not-run` labels | No live steganography or malware scanner is connected |
| Model drift or unusual agent behavior | Planned redacted-feature baseline and shadow-mode risk scoring | No trained model or labeled production corpus is shipped |
| Forged delegation or provenance metadata | Optional provenance recipient, delegation, and source-trust checks | Current checks are metadata-only predicates, not cryptographic proof of signer, delegation expiry, or replay resistance |

## Production hardening checklist

- Bind capabilities to workload identity and audience; never accept bearer capabilities from arbitrary callers. The demo now protects API routes with an operator token when auth is enabled, but this is not a substitute for workload identity.
- Store signing keys in KMS/HSM, rotate them, and include key IDs in receipts.
- Use a durable append-only ledger with monotonic sequence/transaction IDs.
- Add nonce/replay protection and tenant isolation. The demo now has basic rate limiting, request validation, and server-side time enforcement; these remain deployment-grade requirements for production.
- Make policy versions and approval provenance explicit in every receipt.
- Keep secret manager responses in a non-model process and scrub logs/traces.
- Treat DLP as layered detection plus human review, not a guarantee.
- Add a quarantine-only file analysis service for malware and steganography signals, with scanner version, bounded extraction, no execution, and redacted findings.
- Build the ML risk layer as an advisory detector with per-workflow baselines, abstention, human labels, replay evaluation, and rollbackable thresholds.
