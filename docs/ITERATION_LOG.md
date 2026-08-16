# CanaryNorth iteration log

Status: evidence-ledger iteration complete. This log records what changed, what was verified, and what still needs a production gate.

## 1. Original project state

- **Goal:** Establish the starting point for the CanaryNorth demo.
- **Pseudocode:** `agent -> opaque capability -> policy proxy -> synthetic tool; receipt -> hash chain`
- **Plain-English summary:** The project began as a local, synthetic secretless MCP policy-proxy demo. It used fixture capabilities, an in-memory receipt ledger, HMAC-signed receipts, narrow injection and DLP detectors, and no real tool or credential connection.
- **Verification:** Repository tests cover policy decisions, receipt hashing/signing, artifact binding, and graph behavior. The checked-in docs explicitly identify synthetic-only scope and restart-reset behavior.
- **Remaining boundary:** No production authorization, identity binding, durable audit store, external tool adapter, or broad detector corpus is proven.

## 2. Requested security and persistence upgrade

- **Goal:** Make the trust boundary harder to misuse and make receipt history durable.
- **Pseudocode:** `validate request -> authenticate when enabled -> enforce scope/time/content -> sign + chain receipt -> append durably`
- **Plain-English summary:** The service now has a storage interface with memory, append-only JSONL, and PostgreSQL implementations. Requests can bind principal, audience, tenant, workspace, policy version, and nonce. Production mode requires authentication, scope fields, and durable storage.
- **Verification:** 26 tests pass. The PostgreSQL adapter uses parameterized queries, initializes receipt and nonce tables, claims nonces, and serializes receipt-chain writes. The Railway deployment reports `storage: postgres` and the public safe and blocked flows work.
- **Remaining boundary:** Identity is still explicit bearer-token plus scope data, not a JWT or identity-provider integration. Key rotation, backup/restore, retention, and independent security review remain required.

## 3. Graph upgrade

- **Goal:** Turn the architecture map into an inspectable teaching surface.
- **Pseudocode:** `render nodes + labeled edges -> select/drag/nudge node -> show explanation -> run safe/injection/DLP path -> reset`
- **Plain-English summary:** The graph now has movable nodes, keyboard positioning, node inspectors, labeled relationships, reset behavior, and guided paths that distinguish an allowed would-forward route from denied requests that stop at the proxy.
- **Verification:** `npm test`, `npm run lint`, and browser checks pass. The graph supports guided scenarios, an event timeline, node inspectors, labeled edges, hover/focus states, keyboard navigation, touch dragging, reset, and recenter controls.
- **Remaining boundary:** The graph is a truthful synthetic guide. It does not represent a live external tool execution.

## 4. Beginner explainer and approval boundary

- **Goal:** Explain the security model without requiring MCP or cryptography background.
- **Pseudocode:** `show reference -> check request -> human approves higher-risk work -> allow or stop -> record receipt`
- **Plain-English summary:** `public/learn.html` now uses a locked-door story and explains the approval layer in five pieces. The main demo links to it as **Explain like I'm five**.
- **Verification:** The page is self-contained with inline SVG/CSS illustrations, responsive light and dark color schemes, accessible labels, no external assets, and local and public HTTP smoke tests returning 200. The synthetic approval request, approve, deny, expiry, scope, and replay paths are covered by tests.
- **Remaining boundary:** The approval store is in memory and the workflow never calls a real ticket system. The current demo is not proof of perfect security, correct output, or production identity.

## 5. Synthetic approval layer

- **Goal:** Make higher-risk actions stop for a human decision before the proxy would forward them.
- **Pseudocode:** `request tickets.update -> policy passes -> create short-lived approval -> human approve or deny -> re-check nonce/policy -> signed receipt`
- **Plain-English summary:** The demo now has a real approval state machine for one synthetic ticket update. It expires pending decisions, binds them to scope, re-checks policy, and records approve, deny, expiry, or replay outcomes.
- **Verification:** Approval unit tests pass, the local HTTP smoke test returned request 202 and approve 200 with `would-forward-to-tool`, and no external ticket system was called.
- **Remaining boundary:** Approvals are memory-only. A full product needs durable approval records, authenticated approver identity, separation of duties, audit retention, and a real low-risk adapter.

## 6. Railway and PostgreSQL hosting plan

- **Goal:** Move from a synthetic hosted demo toward a durable, controlled deployment path.
- **Pseudocode:** `Railway service + private PostgreSQL -> migrations -> transactionally append receipts -> health/readiness checks -> restart/restore test`
- **Plain-English summary:** Railway now hosts the service with a PostgreSQL service connected through `DATABASE_URL`. Demo mode remains enabled, so the public data stays synthetic while receipts are durable.
- **Verification:** The PostgreSQL service was created, the app variable was wired, deployment `7a85ceea-238d-4236-bdd4-5aaef5267fbc` reached `SUCCESS`, `/health` reports `storage: postgres`, `/learn.html` returns 200, and public safe, prompt-injection, and approval flows return 200, 403, and 202 then 200 respectively.
- **Remaining boundary:** No real customer data, credentials, external tools, or production identity system are connected. Backup/restore, least-privilege database roles, monitoring, and an independent security review remain future gates.

## 7. Documentation update

- **Goal:** Keep the owner-facing record aligned with implementation and proof.
- **Pseudocode:** `inspect source + tests + docs -> record each stage -> label verified work -> state next boundary`
- **Plain-English summary:** The owner explainer and this log now explain the architecture, approval boundary, owner walkthrough, and current verification limits without expanding the shipped-feature claim.
- **Verification:** The app iteration uses 44 passing tests, lint, `git diff --check`, local HTTP smoke, and public Railway smoke. The public demo exposes the approval panel, beginner link, Project Pentesting entry page, Threat Lab, and evidence route.
- **Remaining boundary:** Update this log only when a change is actually implemented and verified; do not convert plans into shipped-feature claims.

## Small-business direction

- **Pseudocode:** `one workspace -> a few allowlisted actions -> human approval for risk -> durable receipt -> simple dashboard`
- **Plain-English summary:** The credible next product is a narrow AI action gateway for one to three small-business workflows, not a universal AI firewall.
- **Proof gate:** Add identity-provider integration, one low-risk real adapter, tenant administration, approval workflows, backup and restore, monitoring, and an independent review before using real customer data.

## 8. Human evidence ledger and local encryption

- **Goal:** Give a human a useful security report without repeating sensitive payloads, and provide a future path for local decryption.
- **Pseudocode:** `safe event -> redact secret-looking fields -> hash -> human ledger; optional package -> random data key -> wrapped customer key -> local decrypt`
- **Plain-English summary:** The evidence schema covers prompt injection, DLP, policy, approval, replay, malware-scan, steganography-signal, and tool events. The report uses summaries, categories, severity, hashes, retention metadata, and references. The package module encrypts synthetic evidence with AES-256-GCM and keeps integrity signing separate from confidentiality.
- **Verification:** Evidence tests cover redaction, tampering, wrong keys, retention, package size, and integrity signatures. `GET /api/evidence` exposes only synthetic events. Encrypted package export is disabled until an operator-managed 32-byte wrapping key is configured.
- **Remaining boundary:** No malware scanner, steganography detector, production key service, durable evidence store, or browser-side decryption is shipped.

## 9. 2026 research and ML direction

- **Goal:** Find a defensible future wedge instead of overclaiming a universal AI firewall.
- **Pseudocode:** `redacted behavior features -> per-workflow baseline -> shadow score -> human label -> replay evaluation -> review recommendation`
- **Plain-English summary:** Current research points to agent identity, authorization, memory poisoning, prompt injection, and continuous monitoring as high-value control areas. The strongest product wedge is a workflow-bound action firewall with human-readable evidence. The ML layer should learn unusual action chains and drift, while deterministic policy stays in control.
- **Sources:** See `docs/RESEARCH_AI_SECURITY_2026.md`, `docs/RESEARCH_FILE_THREATS_2026.md`, and `docs/PRODUCT_OPPORTUNITIES_2026.md`.
- **Remaining boundary:** No trained model is shipped. The next gate is a redacted feature schema, seeded threat corpus, shadow-mode baseline, calibration report, and rollback plan.

## 10. Project Pentesting and PenTel private rehearsal

- **Goal:** Demonstrate real defensive testing against a fake company without publishing the private attack corpus.
- **Pseudocode:** `private PenTel target -> private red-team case -> CanaryNorth decision -> allowed path only -> fake target receipt -> redacted report`
- **Plain-English summary:** A separate local Git repository contains a harmless PenTel Supply target, a private runner, a research-linked catalog of 11 detection families, a redacted report helper, and interview notes. The public page uses a pen-writing entrance and Threat Lab animation to explain the result. The hidden-ink Easter egg is decorative only.
- **Verification:** Private catalog tests pass 3/3. The isolated PenTel rehearsal passes 10/10. A clean synthetic action reaches the fake target only after an allow decision. Prompt injection, DLP, replay, unknown capability, and ungated direct actions do not reach it. Public Railway deployment `f89812c8-2a22-4cf0-86ca-377a32fc9275` is successful and the new pages/routes smoke-test successfully.
- **Remaining boundary:** The private catalog is a defensive regression set, not a universal detector. Malware and steganography remain review-only signals in the shipped demo. No real target, credential, external tool, or live scanner is connected.
## 2026-08-16, research-backed control-plane gates

- **Plain-English summary:** The private PenTel lab now records each synthetic rehearsal as a redacted observation in a whiteboard ledger. It can stay in memory for a quick demo, write an AES-256-GCM encrypted local file when a key is supplied, or use an explicitly configured PostgreSQL adapter. No raw prompt, payload, credential, personal data, or real target result is stored.
- **Defense change:** CanaryNorth now accepts only bounded typed metadata for tool attestation, memory activation, provenance delegation, synthetic canaries, and adaptive drift. The policy binds memory scope and delegated provenance to the capability, then preserves the existing content firewall and signed receipt path.
- **Verification:** CanaryNorth `npm test` passes 57 tests. The private PenTel suite passes 88 report tests and 40/40 rehearsal scenes. Local HTTP smoke verified tool-attestation drift and synthetic canary requests return 403 without forwarding.
- **Claim boundary:** These are research-backed synthetic controls, not proof of universal agent security. Malware remains `unknown`/`not-run`; steganography remains `heuristic-review`; the shadow score is not trained ML and cannot enforce policy.
