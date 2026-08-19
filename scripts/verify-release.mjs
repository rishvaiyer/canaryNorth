#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { authorize, POLICY_VERSION } from '../src/policy.mjs';
import { createReleaseEvidence, verifyReleaseEvidence } from '../src/release-evidence.mjs';
import { createSigner } from '../src/signing.mjs';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const suitePath = process.env.CONTEXTSEAL_RELEASE_SUITE || path.join(root, 'fixtures', 'release-replays.v1.json');
const outputPath = process.env.CONTEXTSEAL_RELEASE_EVIDENCE_OUTPUT || null;
const packageValue = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const suite = JSON.parse(fs.readFileSync(suitePath, 'utf8'));
const signer = createSigner({
  enabled: true,
  privateKey: process.env.CONTEXTSEAL_SIGNING_KEY,
  allowEphemeral: !process.env.CONTEXTSEAL_SIGNING_KEY
});
const candidate = {
  releaseId: process.env.CONTEXTSEAL_RELEASE_ID || process.env.GITHUB_SHA || 'local-working-tree',
  versions: {
    application: packageValue.version,
    policy: POLICY_VERSION,
    replaySuite: '1'
  }
};
const evidence = createReleaseEvidence({ suite, candidate, evaluate: authorize, signer });
const verification = verifyReleaseEvidence(evidence, signer.publicKeyPem);

if (outputPath) {
  fs.mkdirSync(path.dirname(path.resolve(outputPath)), { recursive: true });
  fs.writeFileSync(path.resolve(outputPath), `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
  fs.chmodSync(path.resolve(outputPath), 0o600);
}

console.log(`CanaryNorth release gate: ${evidence.gate.passed ? 'PASS' : 'BLOCK'}`);
console.log(`Replay results: ${evidence.summary.passed}/${evidence.summary.total}, regressions: ${evidence.summary.regressions}`);
console.log(`Evidence verification: ${verification.valid ? 'PASS' : 'FAIL'}, signer: ${evidence.signing.ephemeralKey ? 'ephemeral local key' : evidence.signing.keyId}`);
if (outputPath) console.log(`Evidence file: ${path.resolve(outputPath)}`);

if (!verification.valid) process.exitCode = 1;
