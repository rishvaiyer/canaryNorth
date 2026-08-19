import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { authorize, POLICY_VERSION } from '../src/policy.mjs';
import { createReleaseEvidence, verifyReleaseEvidence } from '../src/release-evidence.mjs';
import { createSigner } from '../src/signing.mjs';

const suite = JSON.parse(fs.readFileSync(new URL('../fixtures/release-replays.v1.json', import.meta.url), 'utf8'));
const signer = createSigner({ enabled: true, allowEphemeral: true });
const candidate = { releaseId: 'test-candidate', versions: { application: '0.1.0', policy: POLICY_VERSION, replaySuite: '1' } };

test('release evidence replays allow and deny controls with zero regressions', () => {
  const evidence = createReleaseEvidence({ suite, candidate, evaluate: authorize, signer });
  assert.equal(evidence.gate.passed, true);
  assert.equal(evidence.summary.regressions, 0);
  assert.ok(evidence.summary.allowed > 0);
  assert.ok(evidence.summary.denied > 0);
  assert.equal(evidence.syntheticOnly, true);
  assert.equal(JSON.stringify(evidence).includes('synthetic_fixture_only'), false);
  assert.equal(verifyReleaseEvidence(evidence, signer.publicKeyPem).valid, true);
});

test('a changed policy outcome blocks the release gate', () => {
  const regressed = (request) => request.action === 'tickets.update'
    ? { allowed: true, reason: 'Regressed evaluator.' }
    : authorize(request);
  const evidence = createReleaseEvidence({ suite, candidate, evaluate: regressed, signer });
  assert.equal(evidence.gate.passed, false);
  assert.equal(evidence.summary.regressions, 1);
  assert.equal(verifyReleaseEvidence(evidence, signer.publicKeyPem).valid, false);
  assert.equal(verifyReleaseEvidence(evidence, signer.publicKeyPem).reason, 'verified-regression-evidence');
});

test('tampering with signed release evidence fails verification', () => {
  const evidence = createReleaseEvidence({ suite, candidate, evaluate: authorize, signer });
  const tampered = structuredClone(evidence);
  tampered.summary.regressions = 0;
  tampered.results[0].actual.allowed = false;
  const verification = verifyReleaseEvidence(tampered, signer.publicKeyPem);
  assert.equal(verification.valid, false);
  assert.equal(verification.checks.evidenceHash, false);
  assert.equal(verification.checks.signature, false);
});

test('signer posture cannot be relabeled after evidence is issued', () => {
  const evidence = createReleaseEvidence({ suite, candidate, evaluate: authorize, signer });
  const relabeled = structuredClone(evidence);
  relabeled.signing.ephemeralKey = false;
  const verification = verifyReleaseEvidence(relabeled, signer.publicKeyPem);
  assert.equal(verification.valid, false);
  assert.equal(verification.checks.evidenceHash, true);
  assert.equal(verification.checks.signature, false);
});

test('version comparison makes candidate changes explicit without inventing a regression', () => {
  const changed = { ...candidate, versions: { ...candidate.versions, policy: 'contextseal-policy-v3' } };
  const evidence = createReleaseEvidence({ suite, candidate: changed, evaluate: authorize, signer });
  assert.deepEqual(evidence.versionComparison.find(({ name }) => name === 'policy'), {
    name: 'policy',
    baseline: 'contextseal-policy-v2',
    candidate: 'contextseal-policy-v3',
    changed: true
  });
  assert.equal(evidence.gate.passed, true);
});
