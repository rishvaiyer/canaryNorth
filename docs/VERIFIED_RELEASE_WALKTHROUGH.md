# CanaryNorth verified release walkthrough

This slice answers one question: did a policy or code change alter the decisions CanaryNorth is expected to make?

## Run the gate

```bash
npm run release:verify
```

The command replays a fixed, synthetic suite through the current policy. It includes one approved control and several expected denials for action drift, resource drift, expiry, instruction conflict, secret-shaped input, nonce replay, and stale approval.

The release passes only when every observed outcome matches its reviewed baseline and the suite contains both allow and deny controls. A changed version is recorded. A changed outcome blocks the gate.

## Save independently verifiable evidence

```bash
CONTEXTSEAL_SIGNING_KEY='<32-byte seed or PEM>' \
CONTEXTSEAL_RELEASE_ID='<commit or release id>' \
CONTEXTSEAL_RELEASE_EVIDENCE_OUTPUT='./output/release-evidence.json' \
npm run release:verify
```

With a stable Ed25519 key, the evidence names the key, records the exact replay-suite digest, compares baseline and candidate versions, lists each redacted result, and carries a signature that can be checked with the corresponding public key. The signature also covers whether the key is stable or ephemeral, so that posture cannot be relabeled later. Without a configured key, the local command uses an ephemeral key and labels it honestly. That proves integrity within the run, not durable signer identity.

Verify a saved record with the matching public key:

```bash
node scripts/verify-receipt.mjs ./output/release-evidence.json --key ./public-key.pem
```

## CI behavior

GitHub Actions runs the replay gate after the normal test suite. It also starts an isolated PostgreSQL service and verifies that chained synthetic receipts and nonce claims survive a new store instance.

## Boundaries

- Synthetic fixtures only.
- No real credential, customer record, tool execution, scanner, or external target.
- A passing replay suite proves the reviewed cases did not regress. It does not prove production security.
- Production deployment still needs stable key management, identity integration, backups, monitoring, migration review, and independent security review.
