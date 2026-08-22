// ELI5: a scanner says "I found something that might be a key." It does not
// say "you may use it." CanaryNorth receives only a covered-up clue, never the
// key itself, then asks a person before any next step.

export const SCANNER_FINDING_SCHEMA = 'canarynorth.scanner-finding.v1';
export const SCANNER_SOURCES = Object.freeze(['trivy', 'trufflehog', 'pattern-worker', 'badsecrets', 'crapsecrets', 'manual']);
export const FINDING_CLASSES = Object.freeze(['credential-candidate', 'weak-framework-secret', 'dependency-vulnerability', 'iac-misconfiguration', 'license-risk', 'token-integrity']);
export const VERIFICATION_STATES = Object.freeze(['candidate', 'false-positive', 'approved-for-validation', 'validated', 'revoked', 'unknown']);

const SEVERITIES = new Set(['low', 'medium', 'high', 'critical', 'unknown']);
const PATH_CLASSES = new Set(['source', 'history', 'config', 'iac', 'dependency', 'container', 'browser', 'token']);
const FINGERPRINT = /^hmac-sha256:[a-f0-9]{16,128}$/;

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function string(value, field, max = 128) {
  if (typeof value !== 'string' || value.length < 1 || value.length > max) fail(`invalid-${field}`);
  return value;
}

function enumValue(value, values, field) {
  if (!values.includes(value)) fail(`invalid-${field}`);
  return value;
}

function ensureNoRawFields(input) {
  const forbidden = ['rawValue', 'secret', 'credential', 'token', 'match', 'payload', 'content'];
  if (forbidden.some((field) => Object.prototype.hasOwnProperty.call(input, field))) fail('raw-scanner-value-forbidden');
}

export function normalizeScannerFinding(input) {
  if (!input || Array.isArray(input) || typeof input !== 'object') fail('scanner-finding-object-required');
  ensureNoRawFields(input);
  if (input.rawValueStored !== false) fail('raw-scanner-value-forbidden');
  const location = input.location;
  if (!location || Array.isArray(location) || typeof location !== 'object') fail('scanner-location-required');
  if (Object.keys(location).some((field) => !['repositoryLabel', 'pathClass', 'line', 'revisionDigest'].includes(field))) fail('scanner-location-field-forbidden');
  const normalized = {
    schema: SCANNER_FINDING_SCHEMA,
    findingId: string(input.findingId, 'finding-id'),
    source: enumValue(input.source, SCANNER_SOURCES, 'scanner-source'),
    detectorVersion: string(input.detectorVersion, 'detector-version'),
    findingClass: enumValue(input.findingClass, FINDING_CLASSES, 'finding-class'),
    severity: SEVERITIES.has(input.severity) ? input.severity : fail('invalid-finding-severity'),
    location: {
      repositoryLabel: string(location.repositoryLabel, 'repository-label'),
      pathClass: PATH_CLASSES.has(location.pathClass) ? location.pathClass : fail('invalid-path-class'),
      line: Number.isInteger(location.line) && location.line >= 0 ? location.line : fail('invalid-finding-line'),
      revisionDigest: string(location.revisionDigest, 'revision-digest')
    },
    verificationState: enumValue(input.verificationState, VERIFICATION_STATES, 'verification-state'),
    rawValueStored: false,
    evidence: '[redacted]'
  };
  if (input.secretFingerprint !== undefined) {
    if (typeof input.secretFingerprint !== 'string' || !FINGERPRINT.test(input.secretFingerprint)) fail('invalid-secret-fingerprint');
    normalized.secretFingerprint = input.secretFingerprint;
  }
  return Object.freeze(normalized);
}

export function fromTrivySummary({ findingId, detectorVersion, type, severity = 'unknown', repositoryLabel, pathClass, line = 0, revisionDigest, verificationState = 'candidate', secretFingerprint } = {}) {
  const findingClass = ({ secret: 'credential-candidate', vulnerability: 'dependency-vulnerability', misconfiguration: 'iac-misconfiguration', license: 'license-risk' })[String(type || '').toLowerCase()];
  if (!findingClass) fail('unsupported-trivy-finding-type');
  return normalizeScannerFinding({ findingId, source: 'trivy', detectorVersion, findingClass, severity: String(severity).toLowerCase(), location: { repositoryLabel, pathClass, line, revisionDigest }, verificationState, rawValueStored: false, ...(secretFingerprint ? { secretFingerprint } : {}) });
}

export function fromTruffleHogSummary({ findingId, detectorVersion, repositoryLabel, pathClass, line = 0, revisionDigest, verificationState = 'candidate', secretFingerprint } = {}) {
  return normalizeScannerFinding({ findingId, source: 'trufflehog', detectorVersion, findingClass: 'credential-candidate', severity: 'high', location: { repositoryLabel, pathClass, line, revisionDigest }, verificationState, rawValueStored: false, ...(secretFingerprint ? { secretFingerprint } : {}) });
}

export function findingSummary(finding) {
  const normalized = normalizeScannerFinding(finding);
  return Object.freeze({
    schema: normalized.schema,
    findingId: normalized.findingId,
    source: normalized.source,
    detectorVersion: normalized.detectorVersion,
    findingClass: normalized.findingClass,
    severity: normalized.severity,
    location: normalized.location,
    verificationState: normalized.verificationState,
    rawValueStored: false,
    evidence: '[redacted]'
  });
}
