# Security policy

ContextSeal is a synthetic demo and is not approved for real credentials, personal data, or production tool execution.

## Reporting

Do not open a public issue for a suspected vulnerability. Report privately to the repository owner with reproduction steps, affected commit, impact, and whether any real data was involved.

## Production gate

Before real deployment, disable `CONTEXTSEAL_DEMO_MODE`, configure a strong signing key, an identity-bound authentication layer, and a durable access-controlled `RECEIPT_LEDGER_PATH`. Complete threat modeling, dependency/release review, retention decisions, and an independent security review.
