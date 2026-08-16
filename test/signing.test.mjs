import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { canonicalize, createLegacySigner, createSigner, ed25519Enabled, verifyLegacyHmac, verifySignature } from '../src/signing.mjs';
import { artifactManifest, verifyArtifact } from '../src/artifacts.mjs';

const receipt = { id: 'rcpt_0001', receiptHash: 'a'.repeat(64), decision: 'allow', principal: 'weather-agent' };
const content = '# Synthetic forecast\n';

test('a signature verifies with the public key alone, with no signing material', () => {
  const signer = createSigner({ enabled: true, allowEphemeral: true });
  const payload = { decision: 'allow', receiptId: 'rcpt_0001' };
  const signature = signer.sign(payload);
  // Only the public key is passed here. This is the property HMAC could not offer.
  assert.equal(verifySignature({ payload, signature, publicKey: signer.publicKeyPem }), true);
  assert.equal(verifySignature({ payload, signature, publicKey: signer.publicKeyBase64 }), true);
});

test('a different key cannot verify, so signatures are attributable', () => {
  const signer = createSigner({ enabled: true, allowEphemeral: true });
  const other = createSigner({ enabled: true, allowEphemeral: true });
  const payload = { decision: 'allow' };
  const signature = signer.sign(payload);
  assert.equal(verifySignature({ payload, signature, publicKey: other.publicKeyPem }), false);
  assert.notEqual(signer.keyId, other.keyId);
});

test('altering any signed field fails verification', () => {
  const signer = createSigner({ enabled: true, allowEphemeral: true });
  const payload = { decision: 'deny', reasonCode: 'prompt-injection' };
  const signature = signer.sign(payload);
  assert.equal(verifySignature({ payload: { ...payload, decision: 'allow' }, signature, publicKey: signer.publicKeyPem }), false);
});

test('canonical form is key-order independent, so harmless reordering does not break a receipt', () => {
  const signer = createSigner({ enabled: true, allowEphemeral: true });
  const a = { decision: 'allow', id: 'rcpt_1', nested: { x: 1, y: 2 } };
  const b = { nested: { y: 2, x: 1 }, id: 'rcpt_1', decision: 'allow' };
  assert.equal(canonicalize(a), canonicalize(b));
  assert.equal(verifySignature({ payload: b, signature: signer.sign(a), publicKey: signer.publicKeyPem }), true);
});

test('a 32-byte seed produces a stable key across restarts', () => {
  const seed = crypto.randomBytes(32).toString('hex');
  const first = createSigner({ enabled: true, privateKey: seed });
  const second = createSigner({ enabled: true, privateKey: seed });
  assert.equal(first.keyId, second.keyId);
  assert.equal(first.ephemeral, false);
  // A receipt signed before a restart still verifies after one.
  const payload = { decision: 'allow' };
  assert.equal(verifySignature({ payload, signature: first.sign(payload), publicKey: second.publicKeyPem }), true);
});

test('a missing key is refused unless an ephemeral key is explicitly allowed', () => {
  assert.throws(() => createSigner({ enabled: true }), /CONTEXTSEAL_SIGNING_KEY is required/);
  assert.equal(createSigner({ enabled: true, allowEphemeral: true }).ephemeral, true);
});

test('artifact manifests record their algorithm and key id', () => {
  const signer = createSigner({ enabled: true, allowEphemeral: true });
  const manifest = artifactManifest({ filename: 'brief.md', content, receipt, signer });
  assert.equal(manifest.signatureAlgorithm, 'ed25519');
  assert.equal(manifest.keyId, signer.keyId);
  assert.equal(verifyArtifact({ filename: 'brief.md', content, manifest, publicKey: signer.publicKeyPem }).valid, true);
});

test('legacy HMAC manifests still verify when the old secret is supplied', () => {
  const secret = 'legacy-demo-signing-secret';
  const base = {
    schema: 'contextseal.artifact-receipt.v1',
    filename: 'brief.md',
    contentType: 'text/markdown',
    bytes: Buffer.byteLength(content, 'utf8'),
    artifactHash: `sha256:${crypto.createHash('sha256').update(content, 'utf8').digest('hex')}`,
    receiptId: receipt.id,
    receiptHash: receipt.receiptHash,
    decision: receipt.decision,
    generatedBy: receipt.principal,
    verification: 'policy-decision-only'
  };
  const manifestHash = crypto.createHash('sha256').update(JSON.stringify(base)).digest('hex');
  const legacy = {
    ...base,
    manifestHash,
    signatureAlgorithm: 'hmac-sha256',
    signature: crypto.createHmac('sha256', secret).update(JSON.stringify({ ...base, manifestHash })).digest('hex')
  };
  const result = verifyArtifact({ filename: 'brief.md', content, manifest: legacy, secret });
  assert.equal(result.valid, true);
  assert.equal(result.signatureAlgorithm, 'hmac-sha256');
  // And the point of the migration: the public key is useless against it.
  assert.equal(verifyArtifact({ filename: 'brief.md', content, manifest: legacy, publicKey: createSigner({ enabled: true, allowEphemeral: true }).publicKeyPem }).valid, false);
});

test('legacy HMAC verification rejects a wrong secret', () => {
  assert.equal(verifyLegacyHmac({ payload: { a: 1 }, signature: 'deadbeef', secret: 'wrong' }), false);
});

test('signature truncation is gated on the Ed25519 toggle, never unconditional', async () => {
  // The authorize and approval responses shorten the signature to 14 characters
  // for display. That is fine while signatures are HMACs nobody can verify, but
  // once the public key is published a truncated signature makes the response
  // unverifiable, which defeats the point. So the truncation must live behind
  // the `signer.legacy` check, not on the response path unconditionally.
  const source = await readFile(new URL('../server.mjs', import.meta.url), 'utf8');
  assert.match(source, /if \(!signer\.legacy\) return receipt;/,
    'truncation is no longer gated on the toggle');
  assert.equal(/receipt\.signature\.slice\(0, 14\)/.test(source.replace(/[\s\S]*?function receiptForResponse[\s\S]*?\n}/, '')), false,
    'a signature is truncated outside receiptForResponse');
});

test('Ed25519 is off by default, so the shipped behavior is unchanged', () => {
  assert.equal(ed25519Enabled({}), false);
  assert.equal(ed25519Enabled({ CONTEXTSEAL_ED25519: '1' }), true);
  const signer = createSigner({ legacySecret: 'context-seal-dev-signing-key' });
  assert.equal(signer.legacy, true);
  assert.equal(signer.algorithm, 'hmac-sha256');
  assert.equal(signer.keyId, null);
});

test('with the toggle off, signatures are byte-identical to the pre-Ed25519 implementation', () => {
  const secret = 'context-seal-dev-signing-key';
  const receiptPayload = { id: 'rcpt_0001', decision: 'allow', receiptHash: 'a'.repeat(64) };
  // This is verbatim the old signReceipt() body.
  const original = crypto.createHmac('sha256', secret).update(JSON.stringify(receiptPayload)).digest('hex');
  assert.equal(createSigner({ legacySecret: secret }).sign(receiptPayload), original);
  assert.equal(createLegacySigner(secret).sign(receiptPayload), original);
});

test('with the toggle off, manifests carry no signatureAlgorithm or keyId', () => {
  const manifest = artifactManifest({ filename: 'brief.md', content, receipt, secret: 'demo-signing-secret' });
  assert.equal('signatureAlgorithm' in manifest, false);
  assert.equal('keyId' in manifest, false);
  assert.equal(verifyArtifact({ filename: 'brief.md', content, manifest, secret: 'demo-signing-secret' }).valid, true);
});
