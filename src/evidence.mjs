import crypto from 'node:crypto';

/**
 * Synthetic/demo evidence only. This module records security decisions and
 * signals. It is not a malware scanner, DLP engine, or production evidence
 * retention service.
 */
export const EVIDENCE_SCHEMA = 'contextseal.synthetic-evidence.v1';
export const EVIDENCE_EVENT_SCHEMA = 'contextseal.synthetic-evidence-event.v1';
export const EVIDENCE_PACKAGE_VERSION = 1;
export const EVIDENCE_PURPOSE = 'synthetic-demo-evidence';
export const MAX_EVENT_BYTES = 32 * 1024;
export const MAX_PACKAGE_BYTES = 256 * 1024;

export const EVENT_TYPES = Object.freeze([
  'prompt-injection',
  'dlp',
  'policy',
  'approval',
  'replay',
  'malware-scan',
  'steganography-signal',
  'tool'
]);

export const SEVERITIES = Object.freeze(['info', 'low', 'medium', 'high', 'critical']);
const REDACTED = '[REDACTED]';
const ALLOWED_EVENT_FIELDS = new Set(['id', 'type', 'summary', 'details', 'metadata', 'severity', 'occurredAt', 'retentionDeadline', 'redactions']);
const SECRET_KEY_NAMES = new Set([
  'password', 'passwd', 'secret', 'token', 'apikey', 'accesstoken', 'refreshtoken',
  'authorization', 'cookie', 'privatekey', 'credential', 'passphrase', 'seed',
  'clientsecret', 'bearertoken', 'signingkey', 'wrappedkey'
]);
const SECRET_VALUE_PATTERNS = [
  /-----BEGIN\s+(?:RSA|EC|OPENSSH)?\s*PRIVATE KEY-----/i,
  /\b(?:sk|rk|pk)_[A-Za-z0-9_-]{12,}\b/i,
  /\bbearer\s+[A-Za-z0-9._~-]{16,}\b/i,
  /\b(?:password|client[_-]?secret|access[_-]?token|api[_-]?key)\s*[:=]\s*[^\s,}]+/i,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/
];

function fail(code, message) {
  const error = new TypeError(message);
  error.code = code;
  throw error;
}

function assertPlainObject(value, code = 'object-required') {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    fail(code, 'Expected a plain object.');
  }
}

function assertAllowedFields(value, allowed, code = 'unknown-field') {
  for (const key of Object.keys(value)) if (!allowed.has(key)) fail(code, `Unknown field: ${key}.`);
}

function normalizeText(value, field, maxLength = 2_000) {
  if (typeof value !== 'string' || value.trim().length === 0 || value.length > maxLength) fail(`invalid-${field}`, `Invalid ${field}.`);
  return value.trim().replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, ' ');
}

function isoDate(value, field) {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value)) || new Date(value).toISOString() !== value) fail(`invalid-${field}`, `Invalid ${field}; use an ISO-8601 timestamp.`);
  return value;
}

function isSecretKey(key) {
  const normalized = key.replace(/[^a-z0-9]/gi, '').toLowerCase();
  return SECRET_KEY_NAMES.has(normalized);
}

function containsSecretLookingText(value) {
  return typeof value === 'string' && SECRET_VALUE_PATTERNS.some((pattern) => pattern.test(value));
}

function jsonSafe(value, path = '$', { redact = false, redactions = [] } = {}, seen = new WeakSet()) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    if (containsSecretLookingText(value)) {
      if (redact) {
        redactions.push({ path, reason: 'secret-looking-value' });
        return REDACTED;
      }
      fail('secret-looking-value', `Secret-looking value at ${path} is not accepted.`);
    }
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('non-finite-number', `Non-finite number at ${path}.`);
    return value;
  }
  if (typeof value !== 'object') fail('non-json-value', `Non-JSON value at ${path}.`);
  if (seen.has(value)) fail('cyclic-payload', `Cyclic payload at ${path}.`);
  seen.add(value);
  let result;
  if (Array.isArray(value)) {
    result = value.map((item, index) => jsonSafe(item, `${path}[${index}]`, { redact, redactions }, seen));
  } else {
    result = {};
    for (const [key, item] of Object.entries(value)) {
      const childPath = `${path}.${key}`;
      if (isSecretKey(key)) {
        if (redact) {
          redactions.push({ path: childPath, reason: 'secret-looking-field' });
          result[key] = REDACTED;
          continue;
        }
        fail('secret-looking-field', `Secret-looking field at ${childPath} is not accepted.`);
      }
      result[key] = jsonSafe(item, childPath, { redact, redactions }, seen);
    }
  }
  seen.delete(value);
  return result;
}

function sortForCanonicalJson(value) {
  if (Array.isArray(value)) return value.map(sortForCanonicalJson);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortForCanonicalJson(value[key])]));
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(sortForCanonicalJson(value));
}

function sha256(value) {
  return `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;
}

function bytes(value) {
  return Buffer.from(value, 'base64');
}

function base64(value) {
  return Buffer.from(value).toString('base64');
}

function keyBytes(value, field = 'wrappingKey') {
  if (value instanceof crypto.KeyObject) {
    if (value.type !== 'secret') fail(`invalid-${field}`, `${field} must be a 256-bit secret key.`);
    const exported = value.export();
    if (!Buffer.isBuffer(exported) || exported.length !== 32) fail(`invalid-${field}`, `${field} must be a 256-bit secret key.`);
    return exported;
  }
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) fail(`invalid-${field}`, `${field} must be a 32-byte Buffer or secret KeyObject.`);
  const buffer = Buffer.from(value);
  if (buffer.length !== 32) fail(`invalid-${field}`, `${field} must be exactly 32 bytes.`);
  return buffer;
}

function validateRetention(retentionDeadline, createdAt) {
  const deadline = isoDate(retentionDeadline, 'retentionDeadline');
  if (Date.parse(deadline) <= Date.parse(createdAt)) fail('retention-deadline-invalid', 'Retention deadline must be after package creation.');
  return deadline;
}

function normalizeRedactions(redactions) {
  if (redactions === undefined) return [];
  if (!Array.isArray(redactions) || redactions.length > 64) fail('invalid-redactions', 'Redactions must be an array of at most 64 field paths.');
  return redactions.map((entry) => {
    if (typeof entry === 'string') return { path: normalizeText(entry, 'redaction-path', 256), reason: 'caller-supplied-redaction' };
    assertPlainObject(entry, 'invalid-redaction');
    if (typeof entry.path !== 'string') fail('invalid-redaction', 'Each redaction must have a path.');
    return { path: normalizeText(entry.path, 'redaction-path', 256), reason: normalizeText(entry.reason || 'caller-supplied-redaction', 'redaction-reason', 160) };
  });
}

function severityForEvents(events) {
  return events.reduce((highest, event) => Math.max(highest, SEVERITIES.indexOf(event.severity)), 0);
}

export function redactSensitiveFields(value) {
  const redactions = [];
  const safeValue = jsonSafe(value, '$', { redact: true, redactions });
  return { value: safeValue, redactions };
}

export function createEvidenceEvent(input, { redact = false, now = new Date().toISOString() } = {}) {
  assertPlainObject(input, 'event-object-required');
  assertAllowedFields(input, ALLOWED_EVENT_FIELDS);
  if (!EVENT_TYPES.includes(input.type)) fail('invalid-event-type', 'Event type is not in the canonical synthetic event schema.');
  const occurredAt = input.occurredAt === undefined ? isoDate(now, 'now') : isoDate(input.occurredAt, 'occurredAt');
  const summary = normalizeText(input.summary, 'summary');
  const redactions = normalizeRedactions(input.redactions);
  if (containsSecretLookingText(summary)) {
    if (!redact) fail('secret-looking-summary', 'Secret-looking summary is not accepted.');
    redactions.push({ path: '$.summary', reason: 'secret-looking-summary' });
  }
  if (redactions.length > 64) fail('invalid-redactions', 'Redactions must be an array of at most 64 field paths.');
  const details = input.details === undefined ? {} : jsonSafe(input.details, '$.details', { redact, redactions });
  const metadata = input.metadata === undefined ? {} : jsonSafe(input.metadata, '$.metadata', { redact, redactions });
  const safeSummary = containsSecretLookingText(summary) && redact ? REDACTED : summary;
  const event = {
    schema: EVIDENCE_EVENT_SCHEMA,
    id: input.id === undefined ? `evt_${crypto.randomUUID()}` : normalizeText(input.id, 'id', 128),
    type: input.type,
    occurredAt,
    severity: input.severity === undefined ? 'info' : input.severity,
    summary: safeSummary,
    details,
    metadata,
    redaction: {
      applied: redactions.length > 0,
      count: redactions.length,
      fields: redactions,
      strategy: redactions.length > 0 ? 'explicit-or-secret-looking-values-replaced' : 'none'
    },
    retentionDeadline: input.retentionDeadline === undefined ? null : isoDate(input.retentionDeadline, 'retentionDeadline')
  };
  if (!SEVERITIES.includes(event.severity)) fail('invalid-severity', 'Severity is not in the canonical severity set.');
  const serialized = canonicalJson(event);
  if (Buffer.byteLength(serialized, 'utf8') > MAX_EVENT_BYTES) fail('event-too-large', `Evidence event exceeds ${MAX_EVENT_BYTES} bytes.`);
  return { ...event, evidenceHash: sha256(serialized) };
}

function packageAad(manifest) {
  const { contentAuthTag: _ignored, ...authenticatedManifest } = manifest;
  return Buffer.from(canonicalJson(authenticatedManifest), 'utf8');
}

function manifestHashInput(manifest) {
  const { manifestHash: _ignored, contentAuthTag: _authTag, ...hashableManifest } = manifest;
  return hashableManifest;
}

function wrapDataKey(dataKey, wrappingKey, { keyId, schema, version, purpose }) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', wrappingKey, nonce);
  cipher.setAAD(Buffer.from(canonicalJson({ keyId, schema, version, purpose }), 'utf8'));
  const wrapped = Buffer.concat([cipher.update(dataKey), cipher.final()]);
  return { wrappedKey: base64(wrapped), keyWrapNonce: base64(nonce), keyWrapAuthTag: base64(cipher.getAuthTag()) };
}

function unwrapDataKey(manifest, wrappingKey) {
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', wrappingKey, bytes(manifest.keyWrapNonce));
    decipher.setAAD(Buffer.from(canonicalJson({ keyId: manifest.keyId, schema: manifest.schema, version: manifest.version, purpose: manifest.purpose }), 'utf8'));
    decipher.setAuthTag(bytes(manifest.keyWrapAuthTag));
    return Buffer.concat([decipher.update(bytes(manifest.wrappedKey)), decipher.final()]);
  } catch {
    fail('key-unwrapping-failed', 'The package key could not be unwrapped with the supplied customer key.');
  }
}

function validateManifest(manifest) {
  assertPlainObject(manifest, 'manifest-required');
  if (manifest.schema !== EVIDENCE_SCHEMA || manifest.version !== EVIDENCE_PACKAGE_VERSION || manifest.purpose !== EVIDENCE_PURPOSE) fail('unsupported-manifest', 'Unsupported evidence package manifest.');
  for (const field of ['keyId', 'wrappedKey', 'keyWrapNonce', 'keyWrapAuthTag', 'nonce', 'contentAuthTag', 'evidenceHash', 'createdAt', 'retentionDeadline', 'manifestHash']) {
    if (typeof manifest[field] !== 'string' || manifest[field].length === 0) fail('invalid-manifest', `Manifest field ${field} is required.`);
  }
  if (manifest.contentAlgorithm !== 'aes-256-gcm' || manifest.keyWrapAlgorithm !== 'aes-256-gcm') fail('unsupported-encryption', 'Unsupported evidence encryption algorithm.');
  isoDate(manifest.createdAt, 'createdAt');
  validateRetention(manifest.retentionDeadline, manifest.createdAt);
  for (const field of ['wrappedKey', 'keyWrapNonce', 'keyWrapAuthTag', 'nonce', 'contentAuthTag']) {
    const decoded = bytes(manifest[field]);
    if (decoded.length === 0) fail('invalid-manifest', `Manifest field ${field} is not valid base64.`);
  }
  if (!Number.isInteger(manifest.eventCount) || manifest.eventCount < 1) fail('invalid-manifest', 'Manifest eventCount is invalid.');
}

export function createEvidencePackage({ events, wrappingKey, keyId, retentionDeadline, createdAt = new Date().toISOString() } = {}) {
  if (!Array.isArray(events) || events.length < 1 || events.length > 256) fail('invalid-events', 'A package requires between 1 and 256 events.');
  const safeCreatedAt = isoDate(createdAt, 'createdAt');
  const safeDeadline = validateRetention(retentionDeadline, safeCreatedAt);
  const safeKeyId = normalizeText(keyId, 'keyId', 128);
  if (containsSecretLookingText(safeKeyId) || isSecretKey(safeKeyId)) fail('secret-looking-key-id', 'Key id must identify a key without containing key material.');
  const key = keyBytes(wrappingKey);
  const safeEvents = events.map((event) => {
    const eventInput = event?.schema === EVIDENCE_EVENT_SCHEMA
      ? {
          id: event.id,
          type: event.type,
          summary: event.summary,
          details: event.details,
          metadata: event.metadata,
          severity: event.severity,
          occurredAt: event.occurredAt,
          retentionDeadline: event.retentionDeadline || undefined,
          redactions: event.redaction?.fields
        }
      : event;
    const safeEvent = createEvidenceEvent(eventInput);
    if (safeEvent.retentionDeadline) validateRetention(safeEvent.retentionDeadline, safeCreatedAt);
    return { ...safeEvent, retentionDeadline: safeEvent.retentionDeadline || safeDeadline };
  });
  const plaintext = Buffer.from(canonicalJson({ schema: EVIDENCE_SCHEMA, version: EVIDENCE_PACKAGE_VERSION, purpose: EVIDENCE_PURPOSE, events: safeEvents }), 'utf8');
  if (plaintext.length > MAX_PACKAGE_BYTES) fail('package-too-large', `Evidence package exceeds ${MAX_PACKAGE_BYTES} bytes.`);
  const evidenceHash = sha256(plaintext);
  const dataKey = crypto.randomBytes(32);
  const wrapped = wrapDataKey(dataKey, key, { keyId: safeKeyId, schema: EVIDENCE_SCHEMA, version: EVIDENCE_PACKAGE_VERSION, purpose: EVIDENCE_PURPOSE });
  const nonce = crypto.randomBytes(12);
  const manifest = {
    schema: EVIDENCE_SCHEMA,
    version: EVIDENCE_PACKAGE_VERSION,
    purpose: EVIDENCE_PURPOSE,
    syntheticOnly: true,
    malwareScanner: false,
    contentAlgorithm: 'aes-256-gcm',
    keyWrapAlgorithm: 'aes-256-gcm',
    keyId: safeKeyId,
    ...wrapped,
    nonce: base64(nonce),
    evidenceHash,
    createdAt: safeCreatedAt,
    retentionDeadline: safeDeadline,
    eventCount: safeEvents.length,
    severity: SEVERITIES[severityForEvents(safeEvents)],
    integritySignature: null
  };
  manifest.manifestHash = sha256(canonicalJson(manifestHashInput(manifest)));
  const cipher = crypto.createCipheriv('aes-256-gcm', dataKey, nonce);
  cipher.setAAD(packageAad(manifest));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  manifest.contentAuthTag = base64(cipher.getAuthTag());
  return Object.freeze({ manifest: Object.freeze(manifest), ciphertext: base64(ciphertext) });
}

export function decryptEvidencePackageLocally(evidencePackage, wrappingKey) {
  assertPlainObject(evidencePackage, 'package-required');
  validateManifest(evidencePackage.manifest);
  if (typeof evidencePackage.ciphertext !== 'string' || bytes(evidencePackage.ciphertext).length === 0) fail('invalid-ciphertext', 'Encrypted evidence ciphertext is required.');
  const key = keyBytes(wrappingKey);
  const manifest = evidencePackage.manifest;
  const expectedManifestHash = sha256(canonicalJson(manifestHashInput(manifest)));
  if (expectedManifestHash !== manifest.manifestHash) fail('manifest-tampered', 'Evidence manifest integrity check failed.');
  const dataKey = unwrapDataKey(manifest, key);
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', dataKey, bytes(manifest.nonce));
    decipher.setAAD(packageAad(manifest));
    decipher.setAuthTag(bytes(manifest.contentAuthTag));
    const plaintext = Buffer.concat([decipher.update(bytes(evidencePackage.ciphertext)), decipher.final()]);
    if (plaintext.length > MAX_PACKAGE_BYTES) fail('package-too-large', 'Decrypted evidence package is too large.');
    const actualHash = sha256(plaintext);
    if (actualHash !== manifest.evidenceHash) fail('evidence-hash-mismatch', 'Evidence hash does not match decrypted bytes.');
    const decoded = JSON.parse(plaintext.toString('utf8'));
    if (decoded.schema !== EVIDENCE_SCHEMA || decoded.version !== EVIDENCE_PACKAGE_VERSION || !Array.isArray(decoded.events)) fail('invalid-plaintext', 'Decrypted evidence payload is invalid.');
    if (decoded.events.length !== manifest.eventCount) fail('event-count-mismatch', 'Decrypted event count does not match the manifest.');
    return { syntheticOnly: true, localOnly: true, manifest, events: decoded.events, evidenceHash: actualHash };
  } catch (error) {
    if (error?.code) throw error;
    fail('content-decryption-failed', 'Evidence ciphertext authentication failed.');
  }
}

export const decryptEvidencePackage = decryptEvidencePackageLocally;
export const createSyntheticEvidenceEvent = createEvidenceEvent;
export const createSyntheticEvidencePackage = createEvidencePackage;

function signatureInput(evidencePackage) {
  assertPlainObject(evidencePackage, 'package-required');
  validateManifest(evidencePackage.manifest);
  if (typeof evidencePackage.ciphertext !== 'string') fail('invalid-ciphertext', 'Encrypted evidence ciphertext is required.');
  return canonicalJson({ manifest: evidencePackage.manifest, ciphertext: evidencePackage.ciphertext });
}

/** Integrity authenticity is separate from confidentiality encryption. */
export function signEvidencePackageIntegrity(evidencePackage, signingKey) {
  const key = keyBytes(signingKey, 'signingKey');
  return { algorithm: 'hmac-sha256', purpose: 'integrity-only', signature: crypto.createHmac('sha256', key).update(signatureInput(evidencePackage)).digest('hex') };
}

export function verifyEvidencePackageIntegrity(evidencePackage, integritySignature, signingKey) {
  if (!integritySignature || integritySignature.algorithm !== 'hmac-sha256' || integritySignature.purpose !== 'integrity-only' || typeof integritySignature.signature !== 'string') return false;
  const expected = signEvidencePackageIntegrity(evidencePackage, signingKey).signature;
  const actual = Buffer.from(integritySignature.signature, 'hex');
  const wanted = Buffer.from(expected, 'hex');
  return actual.length === wanted.length && crypto.timingSafeEqual(actual, wanted);
}
