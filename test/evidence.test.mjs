import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  EVENT_TYPES,
  MAX_PACKAGE_BYTES,
  createEvidenceEvent,
  createEvidencePackage,
  decryptEvidencePackageLocally,
  redactSensitiveFields,
  signEvidencePackageIntegrity,
  verifyEvidencePackageIntegrity
} from '../src/evidence.mjs';

const wrappingKey = crypto.randomBytes(32);
const wrongKey = crypto.randomBytes(32);

function event(overrides = {}) {
  return {
    type: 'policy',
    summary: 'Synthetic policy decision recorded for a demo request.',
    severity: 'medium',
    metadata: { requestId: 'req_demo_001' },
    ...overrides
  };
}

function makePackage(overrides = {}) {
  return createEvidencePackage({
    events: [event()],
    wrappingKey,
    keyId: 'customer-demo-key-2026-08',
    createdAt: '2026-08-15T12:00:00.000Z',
    retentionDeadline: '2026-09-15T12:00:00.000Z',
    ...overrides
  });
}

test('publishes the canonical synthetic event types', () => {
  assert.deepEqual(EVENT_TYPES, ['prompt-injection', 'dlp', 'policy', 'approval', 'replay', 'malware-scan', 'steganography-signal', 'tool']);
  const record = createEvidenceEvent(event({ type: 'malware-scan', severity: 'high' }));
  assert.equal(record.schema, 'contextseal.synthetic-evidence-event.v1');
  assert.match(record.evidenceHash, /^sha256:[0-9a-f]{64}$/);
  assert.equal(record.retentionDeadline, null);
});

test('round trips through local envelope encryption and preserves retention metadata', () => {
  const evidencePackage = makePackage({ events: [event({ type: 'prompt-injection' }), event({ type: 'tool', severity: 'low' })] });
  const restored = decryptEvidencePackageLocally(evidencePackage, wrappingKey);
  assert.equal(restored.localOnly, true);
  assert.equal(restored.syntheticOnly, true);
  assert.equal(restored.manifest.keyId, 'customer-demo-key-2026-08');
  assert.equal(restored.manifest.retentionDeadline, '2026-09-15T12:00:00.000Z');
  assert.equal(restored.manifest.eventCount, 2);
  assert.deepEqual(restored.events.map(({ type }) => type), ['prompt-injection', 'tool']);
  assert.match(restored.manifest.wrappedKey, /^[A-Za-z0-9+/]+=*$/);
  assert.match(restored.manifest.nonce, /^[A-Za-z0-9+/]+=*$/);
  assert.match(restored.manifest.contentAuthTag, /^[A-Za-z0-9+/]+=*$/);
});

test('accepts canonical event records as package inputs', () => {
  const canonicalEvent = createEvidenceEvent(event({ type: 'approval' }));
  const evidencePackage = makePackage({ events: [canonicalEvent] });
  assert.equal(decryptEvidencePackageLocally(evidencePackage, wrappingKey).events[0].type, 'approval');
});

test('detects ciphertext tampering before returning plaintext', () => {
  const evidencePackage = makePackage();
  const tampered = { ...evidencePackage, ciphertext: `${evidencePackage.ciphertext.slice(0, -2)}AA` };
  assert.throws(() => decryptEvidencePackageLocally(tampered, wrappingKey), { code: 'content-decryption-failed' });
});

test('detects manifest tampering', () => {
  const evidencePackage = makePackage();
  const tampered = { ...evidencePackage, manifest: { ...evidencePackage.manifest, retentionDeadline: '2026-10-15T12:00:00.000Z' } };
  assert.throws(() => decryptEvidencePackageLocally(tampered, wrappingKey), { code: 'manifest-tampered' });
});

test('rejects a wrong customer wrapping key', () => {
  assert.throws(() => decryptEvidencePackageLocally(makePackage(), wrongKey), { code: 'key-unwrapping-failed' });
});

test('redacts secret-looking fields only when explicitly requested', () => {
  assert.throws(() => createEvidenceEvent(event({ details: { apiKey: 'sk_demo_123456789012345' } })), { code: 'secret-looking-field' });
  const record = createEvidenceEvent(event({ details: { apiKey: 'sk_demo_123456789012345', nested: { password: 'not-retained' } } }), { redact: true });
  assert.deepEqual(record.details, { apiKey: '[REDACTED]', nested: { password: '[REDACTED]' } });
  assert.equal(record.redaction.applied, true);
  assert.equal(record.redaction.count, 2);
  const summaryRecord = createEvidenceEvent(event({ summary: 'Bearer abcdefghijklmnop' }), { redact: true });
  assert.equal(summaryRecord.summary, '[REDACTED]');
  assert.deepEqual(summaryRecord.redaction.fields, [{ path: '$.summary', reason: 'secret-looking-summary' }]);
  assert.deepEqual(redactSensitiveFields({ token: 'raw', keep: 'synthetic' }).value, { token: '[REDACTED]', keep: 'synthetic' });
});

test('does not treat the package as a malware scanner', () => {
  const evidencePackage = makePackage({ events: [event({ type: 'malware-scan', summary: 'Synthetic scan signal recorded, no scanning performed.' })] });
  assert.equal(evidencePackage.manifest.malwareScanner, false);
  assert.equal(evidencePackage.manifest.syntheticOnly, true);
});

test('keeps integrity signatures separate from encryption', () => {
  const evidencePackage = makePackage();
  const signatureKey = crypto.randomBytes(32);
  const signature = signEvidencePackageIntegrity(evidencePackage, signatureKey);
  assert.equal(signature.purpose, 'integrity-only');
  assert.equal(verifyEvidencePackageIntegrity(evidencePackage, signature, signatureKey), true);
  assert.equal(verifyEvidencePackageIntegrity({ ...evidencePackage, ciphertext: `${evidencePackage.ciphertext}A` }, signature, signatureKey), false);
  assert.equal(evidencePackage.manifest.integritySignature, null);
});

test('rejects secret-looking summaries, unknown event types, and invalid retention', () => {
  assert.throws(() => createEvidenceEvent(event({ summary: 'Authorization: Bearer abcdefghijklmnop' })), { code: 'secret-looking-summary' });
  assert.throws(() => createEvidenceEvent(event({ type: 'unknown' })), { code: 'invalid-event-type' });
  assert.throws(() => makePackage({ retentionDeadline: '2026-08-15T11:59:59.000Z' }), { code: 'retention-deadline-invalid' });
});

test('rejects oversized event and package payloads by default', () => {
  assert.throws(() => createEvidenceEvent(event({ details: { large: 'x'.repeat(40_000) } })), { code: 'event-too-large' });
  const oversizedEvents = Array.from({ length: 256 }, (_, index) => event({ id: `evt_${index}`, summary: `Synthetic event ${index} ${'x'.repeat(900)}` }));
  assert.ok(MAX_PACKAGE_BYTES > 0);
  assert.throws(() => createEvidencePackage({ events: oversizedEvents, wrappingKey, keyId: 'demo-key', createdAt: '2026-08-15T12:00:00.000Z', retentionDeadline: '2026-09-15T12:00:00.000Z' }), { code: 'package-too-large' });
});

test('rejects invalid keys and malformed packages', () => {
  assert.throws(() => makePackage({ wrappingKey: Buffer.alloc(31) }), { code: 'invalid-wrappingKey' });
  assert.throws(() => decryptEvidencePackageLocally({}, wrappingKey), { code: 'manifest-required' });
  assert.throws(() => decryptEvidencePackageLocally({ ...makePackage(), ciphertext: '' }, wrappingKey), { code: 'invalid-ciphertext' });
});
