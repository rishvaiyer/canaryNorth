import assert from 'node:assert/strict';
import test from 'node:test';

import { evaluateScannerFinding } from '../src/agentic-defense.mjs';
import { findingSummary, fromTrivySummary, fromTruffleHogSummary, normalizeScannerFinding, SCANNER_FINDING_SCHEMA } from '../src/scanner-findings.mjs';
import { authorize } from '../src/policy.mjs';

const location = { repositoryLabel: 'synthetic-repository', pathClass: 'history', line: 0, revisionDigest: 'sha256:synthetic-revision' };
const candidate = { source: 'trufflehog', findingClass: 'credential-candidate', verificationState: 'candidate', rawValueStored: false, detectorVersionPinned: true, provenancePreserved: true };
const weather = { capabilityId: 'cap_weather_read_7f3d', action: 'weather.get_forecast', resource: 'weather://nyc', now: new Date('2026-08-15T12:00:00Z') };

test('scanner adapters accept redacted Trivy and TruffleHog summaries only', () => {
  const trivy = fromTrivySummary({ findingId: 'finding-trivy-1', detectorVersion: 'synthetic-trivy-v1', type: 'misconfiguration', severity: 'high', ...location });
  const trufflehog = fromTruffleHogSummary({ findingId: 'finding-trufflehog-1', detectorVersion: 'synthetic-trufflehog-v1', ...location, secretFingerprint: 'hmac-sha256:0123456789abcdef0123456789abcdef' });
  assert.equal(trivy.schema, SCANNER_FINDING_SCHEMA);
  assert.equal(trivy.findingClass, 'iac-misconfiguration');
  assert.equal(trufflehog.findingClass, 'credential-candidate');
  assert.equal(trufflehog.evidence, '[redacted]');
  assert.equal('rawValue' in trufflehog, false);
});

test('scanner normalizer rejects raw fields and unclassified locations', () => {
  assert.throws(() => normalizeScannerFinding({ findingId: 'bad', source: 'trivy', detectorVersion: 'v1', findingClass: 'credential-candidate', severity: 'high', location, verificationState: 'candidate', rawValueStored: false, rawValue: 'not-accepted' }), { code: 'raw-scanner-value-forbidden' });
  assert.throws(() => normalizeScannerFinding({ findingId: 'bad-location', source: 'trivy', detectorVersion: 'v1', findingClass: 'credential-candidate', severity: 'high', location: { ...location, path: 'never-stored' }, verificationState: 'candidate', rawValueStored: false }), { code: 'scanner-location-field-forbidden' });
});

test('finding summaries preserve the review evidence without a raw value', () => {
  const finding = normalizeScannerFinding({ findingId: 'finding-safe', source: 'pattern-worker', detectorVersion: 'rules-v1', findingClass: 'weak-framework-secret', severity: 'medium', location: { ...location, pathClass: 'config' }, verificationState: 'candidate', rawValueStored: false });
  const summary = findingSummary(finding);
  assert.equal(summary.evidence, '[redacted]');
  assert.equal(summary.rawValueStored, false);
  assert.equal(JSON.stringify(summary).includes('never-stored'), false);
});

test('candidate findings require review and validation cannot skip human scope checks', () => {
  assert.equal(evaluateScannerFinding(candidate).reasonCode, 'secret-finding-review-required');
  assert.equal(evaluateScannerFinding({ ...candidate, rawValueStored: true }).reasonCode, 'raw-secret-retention-denied');
  assert.equal(evaluateScannerFinding({ ...candidate, activeValidationRequested: true }).reasonCode, 'validation-human-approval-required');
  assert.equal(evaluateScannerFinding({ ...candidate, activeValidationRequested: true, humanApproved: true, ownedTarget: false }).reasonCode, 'validation-owned-target-required');
  assert.equal(evaluateScannerFinding({ ...candidate, activeValidationRequested: true, humanApproved: true, ownedTarget: true, validatorAllowlisted: true, rateWithinBudget: true }).allowed, true);
});

test('CanaryNorth blocks a candidate finding before the tool boundary', () => {
  assert.equal(authorize({ ...weather, scannerFindingContext: candidate }).code, 'secret-finding-review-required');
  assert.equal(authorize({ ...weather, scannerFindingContext: { ...candidate, rawValueStored: true } }).code, 'raw-secret-retention-denied');
  assert.equal(authorize({ ...weather, scannerFindingContext: { ...candidate, activeValidationRequested: true, humanApproved: true, ownedTarget: true, validatorAllowlisted: true, rateWithinBudget: true } }).allowed, true);
});
