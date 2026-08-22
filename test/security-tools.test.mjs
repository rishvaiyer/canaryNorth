import assert from 'node:assert/strict';
import test from 'node:test';

import { buildPassiveScanCommand, redactScannerOutput } from '../src/passive-scanner.mjs';
import { authorizeSecurityTool, listSecurityTools } from '../src/security-tools.mjs';

test('tool registry accounts for every supplied security project', () => {
  assert.deepEqual(listSecurityTools().map(({ id }) => id), ['trivy', 'trufflehog', 'badsecrets', 'crapsecrets', 'secrets-patterns-db', 'nuclei', 'keyhacks', 'keyfinder', 'sign-saboteur']);
});

test('only Trivy and TruffleHog receive passive local commands', () => {
  assert.match(buildPassiveScanCommand('trivy', '/safe/root').args.join(' '), /--offline/);
  assert.match(buildPassiveScanCommand('trufflehog', '/safe/root').args.join(' '), /--no-verification/);
  assert.throws(() => buildPassiveScanCommand('nuclei', '/safe/root'), /security-tool-active-mode-required/);
});

test('active tools require a human-approved owned target and bounded validator', () => {
  assert.equal(authorizeSecurityTool({ toolId: 'nuclei', mode: 'owned-active' }).reasonCode, 'security-tool-human-approval-required');
  assert.equal(authorizeSecurityTool({ toolId: 'nuclei', mode: 'owned-active', humanApproved: true, ownedTarget: false }).reasonCode, 'security-tool-owned-target-required');
  assert.equal(authorizeSecurityTool({ toolId: 'nuclei', mode: 'owned-active', humanApproved: true, ownedTarget: true, validatorAllowlisted: true, rateWithinBudget: true }).allowed, true);
});

test('scanner output is reduced to redacted counts before leaving the adapter', () => {
  assert.deepEqual(redactScannerOutput('trivy', JSON.stringify({ Results: [{ Secrets: [{ ignored: true }], Misconfigurations: [{ ignored: true }] }] })), { source: 'trivy', executionStatus: 'completed', findingCount: 2, rawOutputStored: false, evidence: '[redacted]' });
  assert.deepEqual(redactScannerOutput('trufflehog', '{"ignored":true}\n{"ignored":true}\n'), { source: 'trufflehog', executionStatus: 'completed', findingCount: 2, rawOutputStored: false, evidence: '[redacted]' });
});
