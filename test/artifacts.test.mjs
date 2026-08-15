import test from 'node:test';
import assert from 'node:assert/strict';
import { artifactManifest, artifactHash, verifyArtifact } from '../src/artifacts.mjs';

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
