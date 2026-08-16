# ContextSeal Research and Build Brief, 2026

Date: 2026-08-16

Status: implementation brief. This document separates verified current-source findings, product inference, and work that still needs testing.

## Executive decision

ContextSeal should become an evidence-backed AI action firewall for small teams:

`untrusted content or file -> quarantine -> safe file identity -> detectors -> deterministic policy -> human approval when needed -> tool boundary -> signed evidence`

The product should not promise one perfect detector. Its advantage is the joined control loop:

1. Constrain what an agent can do.
2. Inspect what the agent is about to use.
3. Stop or hold suspicious work.
4. Explain the decision to a human.
5. Preserve a redacted, tamper-evident record.
6. Learn workflow behavior in shadow mode without letting ML override hard policy.

## What current research says

### Agent identity and authorization are becoming first-class

NIST's 2026 work on AI agent security and identity emphasizes that agents need explicit identity, authorization, auditability, non-repudiation, and controls for prompt injection and delegated authority. ContextSeal already has the beginnings of this boundary through opaque capabilities, principal, audience, tenant, workspace, policy version, nonce, and receipts.

Sources: [NIST AI agent security RFI](https://www.nist.gov/news-events/news/2026/01/caisi-issues-request-information-about-securing-ai-agent-systems), [NIST identity and authorization concept paper](https://www.nist.gov/news-events/news/2026/02/new-concept-paper-identity-and-authority-software-agents), [NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative).

### Prompt injection is a data-boundary failure, not only a bad phrase

The practical threat is that instructions can arrive through user text, documents, webpages, images, tool output, memory, metadata, or another agent. A keyword block catches only a narrow slice. Detection must preserve source labels, normalize content, inspect structured fields, and constrain action authority outside the model.

Sources: [OWASP Prompt Injection](https://owasp.org/www-community/attacks/PromptInjection), [UCSD common prompt-injection taxonomy](https://cseweb.ucsd.edu/~efernandes/teaching/res/common-pi-tricks.html), [2026 component model for prompt injection](https://arxiv.org/abs/2608.07808).

### Memory is part of the attack surface

OWASP's 2026 memory guidance treats persistent agent memory as a place where attackers can plant instructions, preferences, or false facts that later appear trusted. ContextSeal should treat memory writes as a separate capability with provenance, review, versioning, and rollback.

Source: [OWASP, Memory Is a Feature. It Is Also an Attack Surface](https://genai.owasp.org/2026/05/13/memory-is-a-feature-it-is-also-an-attack-surface/).

### Security needs continuous monitoring and update

NIST's 2026 work frames AI security as a monitor-and-update problem rather than a one-time certification. ContextSeal's receipt chain and planned behavior baseline fit this direction, but the baseline must remain advisory until it is measured against a labeled corpus.

Sources: [NIST continuous monitor-and-update model](https://www.nist.gov/news-events/news/2026/06/nist-mathematical-proof-supports-transition-continuous-monitor-and-update), [NIST large-scale agent red teaming](https://www.nist.gov/blogs/caisi-research-blog/insights-ai-agent-security-large-scale-red-teaming-competition).

### Human approval, telemetry, and sandbox boundaries are practical controls

OpenAI's current agent safety guidance emphasizes boundaries, approvals, telemetry, risk-based action governance, and sandbox separation. These are useful design references even when ContextSeal uses a different model or provider.

Sources: [Running Codex safely](https://openai.com/index/running-codex-safely/), [AI agent link safety](https://openai.com/index/ai-agent-link-safety/), [Agents SDK evolution](https://openai.com/index/the-next-evolution-of-the-agents-sdk/).

## What Pliny's ST3GG adds

The referenced project is [elder-plinius/ST3GG](https://github.com/elder-plinius/st3gg), pinned locally at commit `35f8b2b8529a74091c97ce622ee0cbf1ae3bd260` in the private PenTel repo.

Its claimed blue-team surface includes file-type identification, Unicode and whitespace analysis, metadata forensics, PNG and image analysis, archive and document analysis, network-packet analysis, and a large example/test library. Its code exposes a subprocess CLI and a registry of analysis functions. These are useful capabilities to evaluate locally, not claims ContextSeal should repeat without reproducing tests.

### License boundary

ST3GG is AGPL-3.0. Private local modification and execution are a different situation from distributing it or running a modified network service for users. Before any public or commercial integration, preserve notices, review the source and dependency obligations, and get legal advice about whether to keep it isolated as a subprocess, use an alternative license, or replace portions with independently implemented detectors.

Source: [ST3GG LICENSE](https://github.com/elder-plinius/ST3GG/blob/main/LICENSE), [AGPL-3.0 text](https://www.gnu.org/licenses/agpl-3.0.html).

### What ST3GG can and cannot prove

It can produce scanner findings and technical indicators. It cannot, by itself, prove that a file is malicious, that a hidden payload is intended to harm a system, or that a clean result means no hidden content exists. Its upstream claims about breadth and test counts need independent verification on our pinned commit and our own corpus.

## Detection coverage we should build

| Surface | First detector layer | Human result | Current status |
| --- | --- | --- | --- |
| Direct prompt injection | normalized instruction-conflict and policy-override signals | blocked | shipped narrow detector |
| Indirect document or webpage injection | source labels, hidden-text inspection, instruction-shaped content | quarantine or review | private catalog, not shipped scanner |
| Unicode and invisible text | normalization, zero-width, bidi, confusable, variation-selector, whitespace checks | review with exact code-point evidence | ST3GG adapter in progress |
| Image and PNG steganography | file identity, chunk inspection, bit-plane and statistical indicators | suspicious signal, never automatic guilt | ST3GG adapter in progress |
| Metadata and trailing data | EXIF, XMP, unknown chunks, post-EOF bytes, archive extras | quarantine for bounded analysis | ST3GG adapter in progress |
| Polyglot or mismatched files | magic bytes versus extension and parser disagreement | quarantine | planned |
| Archives and documents | bounded listing, decompression limits, macro or active-content indicators | quarantine and separate malware scan | planned |
| Malware | AV or sandbox result from an isolated service | blocked or review based on verdict | not connected |
| Memory poisoning | provenance and approval for durable writes | hold for human review | planned |
| Tool shadowing | signed tool identity, schema, origin, and capability binding | deny | planned |
| Behavior anomaly | per-workflow baseline and sequence drift | review recommendation | roadmap |

## Architecture to build toward

### Quarantine worker

The worker receives a file reference and immutable metadata, not a model instruction. It enforces file size, decompression depth, CPU time, memory, and recursion limits. It never executes the file. It writes only safe metadata and scanner results to the evidence ledger.

### Scanner adapter

The adapter runs a pinned local scanner subprocess with:

- explicit command allowlist
- timeout and memory boundary
- no network access
- input path outside the web root
- scanner commit and dependency version
- normalized finding schema
- no raw payload in normal logs
- separate raw evidence vault only when explicitly enabled

### Finding schema

```text
finding_id
file_hash
scanner
scanner_version
detector
category
severity
confidence
status: clean | signal | suspicious | error | not-run
safe_summary
evidence_hash
redaction_status
created_at
```

`signal` means a detector observed an indicator. `suspicious` means several indicators or a calibrated rule crossed a threshold. Neither means malicious without corroborating policy, sandbox, or human evidence.

### Decision policy

- Hard policy deny always wins.
- Malware or active-content quarantine prevents forwarding.
- Steganography signals trigger bounded inspection or review, not automatic blame.
- A clean scanner result does not override scope, approval, replay, or identity failures.
- ML can recommend review, never silently authorize.

## Corpus and evaluation plan

Build the private corpus in four groups:

1. Clean controls: ordinary PNG, JPEG, PDF, text, JSON, ZIP, and office-like fixtures with benign metadata.
2. Known synthetic positives: ST3GG-generated examples and upstream examples, pinned with hashes.
3. Adversarial transformations: re-encoding, resize, metadata stripping, Unicode normalization, archive nesting, and filename changes.
4. Realistic false positives: watermarked images, accessibility text, emoji, multilingual text, signed documents, QR codes, tracking pixels, compressed assets, and generated art.

Every case gets a manifest with content hash, source, expected category, expected status, scanner version, and why the label is trusted. Do not use real customer data.

Metrics:

- true-positive rate by modality and detector family
- false-positive rate by clean control family
- abstention rate
- scan timeout and resource-failure rate
- evidence completeness
- percentage of findings with reproducible hashes
- time to human decision
- regression delta between scanner versions

Do not report one grand accuracy number. A detector that is excellent on PNG LSB and blind to document metadata needs a split scorecard.

## ML layer after deterministic coverage

The first model should be a transparent risk scorer over redacted features:

- detector categories and counts
- file type and parser disagreement
- tool and action sequence
- destination class
- request burst and retry pattern
- approval and denial history
- memory-write provenance
- scanner version and confidence

Run it in shadow mode. Compare recommendations with human labels and seeded incidents. Add workflow-specific thresholds, an abstain state, drift alerts, and rollback. Do not train on raw customer prompts by default.

## Phased build sequence

### Phase 0, private foundation

- Pin ST3GG commit and record AGPL notice.
- Build scanner adapter with timeout, limits, normalized findings, and redacted output.
- Create a small clean and positive corpus with hashes.
- Run only against the fake PenTel target and local files.

Exit gate: adapter tests pass and no raw payload appears in normal reports.

### Phase 1, evidence-backed Threat Lab

- Show file identity, scanner version, detector, safe summary, confidence, and evidence hash.
- Show “not run” and “scanner error” explicitly.
- Link each finding to the attack-chain graph and receipt.

Exit gate: a human can explain every row without opening raw content.

### Phase 2, isolated malware pipeline

- Add a real malware scanner or sandbox behind a separate service boundary.
- Use a harmless vendor test fixture and a vetted benign corpus.
- Enforce quarantine, no execution in the ContextSeal process, and scanner-version tracking.

Exit gate: independent review of isolation, retention, and false-positive handling.

### Phase 3, shadow ML

- Build per-workflow baselines.
- Replay the corpus and historical redacted events.
- Calibrate review recommendations and drift alerts.

Exit gate: measured improvement without an unacceptable human review burden.

### Phase 4, narrow pilot

- One real low-risk adapter.
- Authenticated identity and approver separation.
- Durable approvals and evidence.
- Backup, restore, monitoring, incident response, key rotation, and independent review.

Exit gate: a design partner completes a real workflow without needing the full enterprise platform.

## Product positioning

Do not position this as “we detect every malicious file.” Position it as:

> ContextSeal gives AI actions a security boundary, a human-readable decision, and evidence you can inspect later. It can add specialized scanners without giving any scanner unchecked authority.

The distinctive feature is the chain from suspicious input to constrained action to explainable receipt. The scanner is a component. The product is the control loop.

## Interview-ready story

“I built a private fake company called PenTel Supply and placed ContextSeal in front of its synthetic AI actions. The red-team harness runs a research-backed set of inert cases, including direct and indirect injection, role confusion, Unicode and hidden content, tool metadata, memory poisoning, replay, and exfiltration intent. Clean actions reach the fake target only after policy approval. Blocked actions do not. The report stores a redacted reason, scanner metadata, and evidence hash. I am adding ST3GG locally for steganalysis, but I keep its AGPL dependency private and I separate scanner signals from proof of malware.”

## Honest current state

- ContextSeal public demo: synthetic, deployed, no live malware or steganography scanner.
- Private PenTel repo: local fake target, red-team harness, 11-family prompt-injection catalog, redacted reporting.
- ST3GG: pinned private dependency, integration and corpus work in progress.
- Next proof: scanner adapter tests, clean and positive corpus, normalized evidence events, then a local Threat Lab replay.

