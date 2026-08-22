#!/usr/bin/env python3
import re, pathlib

root = pathlib.Path.cwd()
KEEP = {
    'verifyToolAttestation', 'evaluateMemoryContext', 'evaluateProvenanceBoundary',
    'evaluateCanaryRequest', 'evaluateDelegationFreshness', 'evaluateApprovalFreshness',
}

# ---- agentic-defense.mjs: cut whole functions between export boundaries ----
p = root / 'src/agentic-defense.mjs'
text = p.read_text()
chunks = re.split(r'(?=^export function )', text, flags=re.M)
out = [chunks[0]]
for chunk in chunks[1:]:
    name = re.match(r'export function (\w+)\(', chunk)
    if name and name.group(1) in KEEP:
        out.append(chunk)
p.write_text(''.join(out).rstrip() + '\n')
print('defense functions kept:', len(out) - 1)
