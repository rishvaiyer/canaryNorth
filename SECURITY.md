# Security policy

ContextSeal is currently a synthetic demo and is not approved for real credentials, personal data, or production tool execution.

## Reporting

Do not open a public issue for a suspected vulnerability. Report privately to the repository owner with reproduction steps, affected commit, impact, and whether any real data was involved.

## Production gate

Before real deployment, disable `CONTEXTSEAL_DEMO_MODE`, configure strong sealed signing and authentication keys, connect an identity-bound authentication layer, bind every request to a tenant and workspace, and use durable PostgreSQL or access-controlled JSONL storage. Complete threat modeling, dependency/release review, retention decisions, backup/restore testing, monitoring, incident response planning, and an independent security review.

The intended first commercial scope is a small-business AI action gateway with one to three low-risk workflows. It must not be presented as a universal prompt-injection blocker or as proof that generated content is correct.

## Evidence and detection boundaries

- The human ledger stores safe summaries, categories, hashes, retention metadata, and receipt references. Raw prompts, secrets, and malware payloads do not belong in the normal report.
- `src/evidence.mjs` provides a versioned envelope-encryption package format using AES-256-GCM, local decryption, redaction checks, retention metadata, and separate integrity signing. It is not a malware scanner, steganography detector, or key-management service.
- Steganography is a possible signal with false positives, not proof of maliciousness. Malware scanning belongs in an isolated quarantine pipeline with resource limits, scanner versioning, and safe result summaries.
- The planned ML layer may recommend review based on redacted behavior features. It must not override deny-by-default policy, scope, nonce, or human approval requirements. It must be evaluated in shadow mode against a versioned corpus before enforcement.
- Customer-controlled wrapping keys, key rotation, deletion, retention enforcement, and recovery procedures are required before real evidence is processed.
