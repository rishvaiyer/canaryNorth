# ML Risk Layer Roadmap

Status: design direction, not a shipped ML detector.

## Design thesis

CanaryNorth should learn whether an AI workflow is behaving unusually, while deterministic policy remains the final security gate. The ML layer recommends observe, review, or quarantine. It must not silently authorize a request that policy denied.

## Highest-impact first slice

1. Capture redacted event features from the existing receipt and evidence paths.
2. Build per-workflow baselines for tool, action, resource class, destination class, time, request rate, policy result, approval result, and file-risk category.
3. Run the scorer in shadow mode beside the current policy engine.
4. Compare alerts against seeded attack scenarios and human labels.
5. Calibrate thresholds by workflow, measure false positives, and only then connect medium-risk results to approval.

## Useful outputs

- `normal`: the request resembles the workflow baseline.
- `review`: behavior is unusual or several weak signals combine.
- `quarantine`: a hard policy rule or a high-confidence threat signal already stopped the request.
- `abstain`: the model lacks enough evidence. Send to review, never allow because of uncertainty.

## Features worth learning

- Tool and action sequence, including new or rare transitions.
- Resource and destination classes, not raw private values.
- Request bursts, retry loops, and denied-request patterns.
- Approval frequency, approver separation, and approval-to-action timing.
- Detector categories such as prompt-injection signal, DLP signal, malware result, or steganography signal.
- Agent, workflow, tenant, and policy-version changes.

## Distinctive features

### Behavior fingerprint

Show the normal workflow shape and highlight what changed. A support agent suddenly exporting many customer records should be visibly different from its baseline.

### Attack-chain graph

Link suspicious input, evidence item, policy decision, approval, tool request, and outcome. Every graph node must resolve to a receipt, evidence hash, or detector result. The graph is an investigation surface, not decoration.

### Replay lab

Replay redacted historical and seeded attack events against a proposed policy or model version. Report what would have been stopped, reviewed, or released, including false positives.

### Drift guard

Alert after a model, prompt, tool, or policy update changes workflow behavior. Include the before-and-after baseline and the first affected receipt.

## Safety boundaries

- Do not train on raw customer prompts by default.
- Use redacted features, encrypted evidence, tenant isolation, retention limits, and customer-controlled deletion.
- Do not use anomaly alone as proof of maliciousness.
- Do not let a model override deny-by-default policy, scope, nonce, or approval rules.
- Keep steganography and malware findings as detector signals until backed by real scanners, test corpora, and reviewable evidence.
- Version the model, feature schema, threshold, and training window in every risk event.

## Success metrics

- Detection recall on a versioned, seeded threat corpus.
- False-positive rate per workflow, not only one global average.
- Percentage of alerts with a human-readable evidence chain.
- Time from alert to understandable decision.
- Regression rate after policy, prompt, tool, or model changes.
- Percentage of raw sensitive content avoided by the training path.

## Pushback and kill gates

Do not build a custom foundation model first. If a transparent baseline does not improve seeded attack detection without creating an unacceptable review burden, stop and improve the deterministic detectors, evidence quality, or workflow scope before adding model complexity.

