import test from 'node:test';
import assert from 'node:assert/strict';
import { artifactManifest, artifactHash, verifyApprovedArtifact, verifyArtifact } from '../src/artifacts.mjs';

const secret = 'demo-signing-secret';
const receipt = { id: 'rcpt_0001', receiptHash: 'a'.repeat(64), decision: 'allow', principal: 'weather-agent' };
const content = '# Synthetic forecast\n';

test('binds a receipt to the exact artifact bytes', () => {
  const manifest = artifactManifest({ filename: 'brief.md', content, receipt, secret });
  assert.equal(manifest.artifactHash, `sha256:${artifactHash(content)}`);
  assert.equal(verifyArtifact({ filename: 'brief.md', content, manifest, secret }).valid, true);
});

test('detects artifact tampering', () => {
  const manifest = artifactManifest({ filename: 'brief.md', content, receipt, secret });
  const result = verifyArtifact({ filename: 'brief.md', content: `${content}changed`, manifest, secret });
  assert.equal(result.valid, false);
  assert.equal(result.checks.artifactHash, false);
});

test('rejects an observed artifact that drifts from the approved artifact', () => {
  const approved = { filename: 'brief.md', content, manifest: artifactManifest({ filename: 'brief.md', content, receipt, secret }) };
  const changedContent = `${content}changed`;
  const observed = { filename: 'brief.md', content: changedContent, manifest: artifactManifest({ filename: 'brief.md', content: changedContent, receipt, secret }) };
  const result = verifyApprovedArtifact({ approved, observed, secret });
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'approved-artifact-drift');
  assert.equal(result.checks.exactArtifact, false);
});

test('accepts the exact approved artifact and receipt binding', () => {
  const packageValue = { filename: 'brief.md', content, manifest: artifactManifest({ filename: 'brief.md', content, receipt, secret }) };
  const result = verifyApprovedArtifact({ approved: packageValue, observed: packageValue, secret });
  assert.equal(result.valid, true);
  assert.equal(result.checks.approvedDecision, true);
});
