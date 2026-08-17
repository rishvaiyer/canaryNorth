# CanaryNorth defense work, like I am 5

CanaryNorth is the defensive control layer. It looks at safe metadata around an AI-requested action and asks whether the request still has enough trusted context to move forward.

Imagine a school crossing guard. The guard does not need to read every private page in a backpack. The guard checks the permission slip, who is carrying it, whether it is still valid, and whether the requested trip matches what was approved.

## What is now connected

The active private fixture catalog has 115 connected CanaryNorth evaluator pairings. Every active pairing is marked implemented and has a passing direct or authorization-path test in the matched CanaryNorth and PenTel checkouts. One fixture can have more than one independent check, so the map contains 115 checks across 114 unique scenario IDs.

The `dormant-rehearsal-variants` family is intentionally excluded from that active count. It contains four lower-priority, opt-in synthetic variants and stays disabled by default.

This is a metadata-policy result. The fixtures and evaluator requests are synthetic, redacted, local, and target-free. The passing tests do not prove scanner coverage, malware or steganography detection, live target detection, production deployment behavior, trained-ML coverage, or universal AI protection.

## What the current work is trying to answer

- **Is the path still trustworthy?** The request should have a continuous, explainable route from approved intent to proposed action.
- **Have warnings piled up?** Several unresolved signals may require a pause or human review before a sensitive action.
- **Is delegated permission still valid?** A helper may need a fresh, correctly addressed permission slip at the moment of action.
- **Does the evidence still match?** The record should explain the decision without exposing raw hostile content or private data.

These are deterministic metadata policies, not a machine-learning model. They do not inspect malware, execute files, or prove universal AI protection. The active pairing count is published because it is now verified, while private fixture payloads and operational details remain protected.

## What a result means

- `allowed: true` means the checked metadata passed this policy. It does not mean a real-world action is automatically safe.
- `allowed: false` means this authorization path stops before tool forwarding.
- `rawContent: withheld` means the original content is not returned to the evaluator.
- `reviewRequired: true` means a human or stronger control should decide what happens next.

## Where the work lives

The implementation, request validation, pairing map, and tests are kept in the repository so the behavior can be reviewed. The public preview describes the boundary and the verified active pairing count without exposing private fixture payloads.

## Honest boundary

This reference implementation demonstrates typed metadata boundaries and redacted decision records. It does not prove malware detection, steganography detection, identity-provider security, enterprise readiness, or universal protection.
