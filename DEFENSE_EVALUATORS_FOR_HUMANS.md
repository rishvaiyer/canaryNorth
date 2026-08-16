# CanaryNorth Defense Evaluators, Like I Am 5

These are three small deterministic policy checks. They look at safe metadata around an action. They do not inspect malware, execute files, or use a machine-learning model.

## Causal Cut

Imagine a road from a person's approved request to a tool action.

- `trustedPathEdges` counts trusted bridges on the road.
- `requiredTrustedEdges` says how many bridges are needed.
- `untrustedGapCount` counts broken or untrusted parts.
- `actionIntentMatch` says whether the action still matches the approved intent.

If the road is incomplete, CanaryNorth blocks before forwarding. A trusted-looking final tool is not enough by itself.

## Trust Debt

Imagine small warning stickers piling up on a task.

- `unresolvedSignals` counts the open warnings.
- `debtScore` is the synthetic risk total from 0 to 1.
- `debtBudget` is how much unresolved risk the action may tolerate.
- `sensitiveAction` says whether the requested action matters enough to require a stop.

If a sensitive action is over budget, CanaryNorth returns `trust-debt-exceeded` and requires review. This is a deterministic budget check, not a trained risk model.

## Delegation Expiry

Imagine one helper giving another helper a permission slip.

- `delegatorTrusted` says the giver was trusted.
- `receiverTrusted` says the receiver is trusted.
- `delegated` says the permission was actually delegated.
- `audienceMatches` says it was meant for this receiver.
- `delegationExpiresAt` says when the slip stops working.

All of those must be true, and the current server time must be before expiry. A trusted helper with an expired slip is still blocked.

## What the result means

- `allowed: true` means this metadata policy passed. It does not mean a real-world action is automatically safe.
- `allowed: false` means the authorization path stops before the tool-forwarding boundary.
- `rawContent: withheld` means the evaluator does not return the original content.
- `reviewRequired: true` means a human or stronger control should decide what happens next.

## Where the code lives

- `src/agentic-defense.mjs`: the three evaluator functions.
- `src/policy.mjs`: the authorization path that calls them.
- `server.mjs`: request-shape validation for their metadata.
- `test/agentic-defense.test.mjs`: direct evaluator tests.
- `test/policy.test.mjs`: end-to-end authorization checks.

## Honest boundary

These checks prove that CanaryNorth can enforce three typed metadata boundaries in this reference implementation. They do not prove universal AI protection, malware detection, steganography detection, identity-provider security, or production readiness.
