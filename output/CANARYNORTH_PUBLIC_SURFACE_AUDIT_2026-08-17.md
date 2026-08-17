# CanaryNorth public-surface audit

Date: 2026-08-17

## Decision

Public-facing copy now says that CanaryNorth defense coverage is still being iterated. It no longer publishes the current defense count, the exact connected-pairing count, or the internal pairing names in the visible CanaryNorth/PenTel console surfaces.

## Checked

- CanaryNorth README and public threat-model documentation.
- Public PenTel console pages: mission board, case console, coverage, guide, walkthrough, and gate destination list.
- Public PenTel console scripts that render catalog counts, pairing status, coverage labels, and dashboard metrics.
- Public owner-download labels for the private lab documents.
- The private PenTel checkout, including the `unevil-malware` page and current lab documents, to confirm it remains separate from the public CanaryNorth copy.

## Changed

- Replaced visible coverage counts with `CanaryNorth defense coverage is still being iterated.`
- Replaced the public pairing inventory with a high-level CanaryNorth/PenTel ownership explanation.
- Replaced dashboard metric counts with system, lab, evidence, and iteration status.
- Replaced public coverage labels that implied a finished inventory with `current iteration`, `synthetic fixture`, and `under review` language.
- Reworked the public ELI5 defense note so it explains the control shape without publishing a finished inventory.
- Marked downloadable lab documents as private owner copies in the gated console.

## Boundary

This audit changes public-facing copy and display behavior only. The private PenTel lab keeps its detailed learning material. The public source tree still contains implementation code and synthetic scenario data, so a public repository should not be treated as a secrecy boundary for internal control names. Keep detailed defense notes and private lab documents behind the owner gate or in the private repository.

## Honest status

This is a copy and exposure audit. It does not change, expand, or prove CanaryNorth defensive capability. It does not claim malware detection, steganography detection, trained ML, or universal AI protection.

## Verification

- `npm test`: 76/76 passed.
- `node --check`: passed for `server.mjs` and every `public/pen-console/*.mjs` module.
- Targeted copy scan: no exact defense-count or pairing-inventory phrases remain in the public markdown and HTML/JS surfaces checked.
- Focused `git diff --check`: passed for the tracked files changed by this audit.
- No push, deployment, email, or external target activity occurred.
