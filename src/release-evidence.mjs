import crypto from 'node:crypto';
import { canonicalize, SIGNATURE_ALGORITHM, verifySignature } from './signing.mjs';

const SUITE_SCHEMA = 'contextseal.release-replay-suite.v1';
const EVIDENCE_SCHEMA = 'contextseal.release-evidence.v1';

function digest(value) {
  return crypto.createHash('sha256').update(canonicalize(value), 'utf8').digest('hex');
}

function assertRecord(value, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${name}-required`);
}

function validateSuite(suite) {
  assertRecord(suite, 'suite');
  if (suite.schema !== SUITE_SCHEMA) throw new Error('unsupported-release-suite');
  if (typeof suite.id !== 'string' || !suite.id || suite.id.length > 128) throw new Error('invalid-suite-id');
  if (!Number.isFinite(Date.parse(suite.evaluationTime))) throw new Error('invalid-evaluation-time');
  assertRecord(suite.baseline, 'baseline');
  assertRecord(suite.baseline.versions, 'baseline-versions');
  if (!Array.isArray(suite.cases) || suite.cases.length < 2 || suite.cases.length > 500) throw new Error('invalid-release-cases');
  const ids = new Set();
  for (const replayCase of suite.cases) {
    assertRecord(replayCase, 'release-case');
    if (typeof replayCase.id !== 'string' || !replayCase.id || replayCase.id.length > 128 || ids.has(replayCase.id)) throw new Error('invalid-release-case-id');
    ids.add(replayCase.id);
    assertRecord(replayCase.request, 'release-case-request');
    assertRecord(replayCase.expected, 'release-case-expected');
    if (typeof replayCase.expected.allowed !== 'boolean' || typeof replayCase.expected.code !== 'string') throw new Error('invalid-release-case-expected');
  }
}

function compareVersions(baseline = {}, candidate = {}) {
  const names = [...new Set([...Object.keys(baseline), ...Object.keys(candidate)])].sort();
  return names.map((name) => ({
    name,
    baseline: baseline[name] ?? null,
    candidate: candidate[name] ?? null,
    changed: canonicalize(baseline[name] ?? null) !== canonicalize(candidate[name] ?? null)
  }));
}

function resultFor(replayCase, evaluationTime, evaluate) {
  const result = evaluate({ ...structuredClone(replayCase.request), now: new Date(evaluationTime) });
  const actual = { allowed: Boolean(result.allowed), code: result.allowed ? 'policy-passed' : String(result.code || 'unspecified-denial') };
  const passed = actual.allowed === replayCase.expected.allowed && actual.code === replayCase.expected.code;
  return {
    caseId: replayCase.id,
    description: replayCase.description || replayCase.id,
    expected: structuredClone(replayCase.expected),
    actual,
    passed
  };
}

function unsignedPayload(evidence) {
  const { evidenceHash, signing, ...payload } = evidence;
  return payload;
}

export function createReleaseEvidence({ suite, candidate, evaluate, signer }) {
  validateSuite(suite);
  assertRecord(candidate, 'candidate');
  assertRecord(candidate.versions, 'candidate-versions');
  if (typeof evaluate !== 'function') throw new Error('release-evaluator-required');
  if (!signer || signer.algorithm !== SIGNATURE_ALGORITHM || typeof signer.sign !== 'function') throw new Error('ed25519-release-signer-required');

  const results = suite.cases.map((replayCase) => resultFor(replayCase, suite.evaluationTime, evaluate));
  const regressions = results.filter((result) => !result.passed);
  const allowed = results.filter((result) => result.actual.allowed).length;
  const denied = results.length - allowed;
  const gatePassed = regressions.length === 0 && allowed > 0 && denied > 0;
  const payload = {
    schema: EVIDENCE_SCHEMA,
    syntheticOnly: true,
    suiteId: suite.id,
    suiteHash: `sha256:${digest(suite)}`,
    evaluatedAt: new Date(suite.evaluationTime).toISOString(),
    baselineRelease: suite.baseline.releaseId || 'unspecified-baseline',
    candidateRelease: candidate.releaseId || 'working-tree',
    versionComparison: compareVersions(suite.baseline.versions, candidate.versions),
    summary: {
      total: results.length,
      passed: results.length - regressions.length,
      regressions: regressions.length,
      allowed,
      denied
    },
    results,
    gate: {
      passed: gatePassed,
      reason: gatePassed ? 'zero-regressions-with-allow-and-deny-controls' : 'release-regression-or-incomplete-control-set'
    },
    limitations: [
      'synthetic deterministic replay only',
      'does not prove production security',
      'does not execute tools or contact external targets'
    ]
  };
  const evidenceHash = `sha256:${digest(payload)}`;
  const signing = {
    algorithm: signer.algorithm,
    keyId: signer.keyId,
    ephemeralKey: signer.ephemeral
  };
  const signedPayload = { ...payload, evidenceHash, signing };
  return {
    ...signedPayload,
    signing: {
      ...signing,
      signature: signer.sign(signedPayload)
    }
  };
}

export function verifyReleaseEvidence(evidence, publicKey) {
  if (!evidence || evidence.schema !== EVIDENCE_SCHEMA || !evidence.signing) return { valid: false, reason: 'unsupported-release-evidence' };
  const payload = unsignedPayload(evidence);
  const expectedHash = `sha256:${digest(payload)}`;
  const validHash = expectedHash === evidence.evidenceHash;
  const signing = {
    algorithm: evidence.signing.algorithm,
    keyId: evidence.signing.keyId,
    ephemeralKey: evidence.signing.ephemeralKey
  };
  const signedPayload = { ...payload, evidenceHash: evidence.evidenceHash, signing };
  const validSignature = evidence.signing.algorithm === SIGNATURE_ALGORITHM && verifySignature({
    payload: signedPayload,
    signature: evidence.signing.signature,
    publicKey
  });
  return {
    valid: validHash && validSignature && evidence.gate?.passed === true,
    reason: validHash && validSignature ? (evidence.gate?.passed ? 'verified-release-evidence' : 'verified-regression-evidence') : 'release-evidence-integrity-failure',
    checks: { evidenceHash: validHash, signature: validSignature, releaseGate: evidence.gate?.passed === true }
  };
}

export { EVIDENCE_SCHEMA, SUITE_SCHEMA };
