import crypto from 'node:crypto';
import { LEGACY_SIGNATURE_ALGORITHM, SIGNATURE_ALGORITHM, verifyLegacyHmac, verifySignature } from './signing.mjs';

export function artifactHash(content) {
  return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

function manifestBase({ filename, content, receipt }) {
  return {
    schema: 'contextseal.artifact-receipt.v1',
    filename,
    contentType: 'text/markdown',
    bytes: Buffer.byteLength(content, 'utf8'),
    artifactHash: `sha256:${artifactHash(content)}`,
    receiptId: receipt.id || receipt.receiptId,
    receiptHash: receipt.receiptHash,
    decision: receipt.decision,
    generatedBy: receipt.principal || receipt.generatedBy,
    verification: 'policy-decision-only'
  };
}

export function artifactManifest({ filename, content, receipt, signer }) {
  const base = manifestBase({ filename, content, receipt });
  const manifestHash = crypto.createHash('sha256').update(JSON.stringify(base)).digest('hex');
  const signed = { ...base, manifestHash };
  return {
    ...signed,
    signatureAlgorithm: signer.algorithm,
    keyId: signer.keyId,
    signature: signer.sign(signed)
  };
}

/**
 * Verify an artifact package.
 *
 * `publicKey` alone is enough for anything signed with Ed25519, which is the
 * point: a third party can check a receipt without holding signing material.
 * `secret` is consulted only for legacy HMAC manifests issued before the
 * Ed25519 change.
 */
export function verifyArtifact({ filename, content, manifest, publicKey, secret }) {
  if (!manifest || manifest.schema !== 'contextseal.artifact-receipt.v1') return { valid: false, reason: 'unsupported-manifest' };
  const base = manifestBase({ filename, content, receipt: manifest });
  const expectedManifestHash = crypto.createHash('sha256').update(JSON.stringify(base)).digest('hex');
  const validHash = base.artifactHash === manifest.artifactHash;
  const validManifest = expectedManifestHash === manifest.manifestHash;

  const signedPayload = { ...base, manifestHash: manifest.manifestHash };
  const algorithm = manifest.signatureAlgorithm || LEGACY_SIGNATURE_ALGORITHM;
  let validSignature = false;
  if (algorithm === SIGNATURE_ALGORITHM) {
    validSignature = verifySignature({ payload: signedPayload, signature: manifest.signature, publicKey });
  } else if (algorithm === LEGACY_SIGNATURE_ALGORITHM) {
    validSignature = verifyLegacyHmac({ payload: signedPayload, signature: manifest.signature, secret });
  }

  return {
    valid: validHash && validManifest && validSignature,
    signatureAlgorithm: algorithm,
    checks: { artifactHash: validHash, manifestHash: validManifest, signature: validSignature }
  };
}

export function verifyApprovedArtifact({ approved, observed, publicKey, secret }) {
  if (!approved || !observed) return { valid: false, reason: 'approved-and-observed-packages-required' };
  const approvedIntegrity = verifyArtifact({ ...approved, publicKey, secret });
  const observedIntegrity = verifyArtifact({ ...observed, publicKey, secret });
  const exactArtifact = approved.manifest?.artifactHash === observed.manifest?.artifactHash && approved.filename === observed.filename;
  const sameReceipt = approved.manifest?.receiptId === observed.manifest?.receiptId && approved.manifest?.receiptHash === observed.manifest?.receiptHash;
  const approvedDecision = approved.manifest?.decision === 'allow';
  const valid = approvedIntegrity.valid && observedIntegrity.valid && exactArtifact && sameReceipt && approvedDecision;
  return {
    valid,
    reason: valid ? 'approved-artifact-matches-observed' : 'approved-artifact-drift',
    checks: { approvedIntegrity: approvedIntegrity.valid, observedIntegrity: observedIntegrity.valid, exactArtifact, sameReceipt, approvedDecision }
  };
}
