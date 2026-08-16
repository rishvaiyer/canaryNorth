import crypto from 'node:crypto';

export function artifactHash(content) {
  return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

export function artifactManifest({ filename, content, receipt, secret }) {
  const base = {
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
  const manifestHash = crypto.createHash('sha256').update(JSON.stringify(base)).digest('hex');
  return { ...base, manifestHash, signature: crypto.createHmac('sha256', secret).update(JSON.stringify({ ...base, manifestHash })).digest('hex') };
}

export function verifyArtifact({ filename, content, manifest, secret }) {
  if (!manifest || manifest.schema !== 'contextseal.artifact-receipt.v1') return { valid: false, reason: 'unsupported-manifest' };
  const expected = artifactManifest({ filename, content, receipt: manifest, secret });
  const validHash = expected.artifactHash === manifest.artifactHash;
  const validManifest = expected.manifestHash === manifest.manifestHash;
  const validSignature = expected.signature === manifest.signature;
  return { valid: validHash && validManifest && validSignature, checks: { artifactHash: validHash, manifestHash: validManifest, signature: validSignature } };
}

export function verifyApprovedArtifact({ approved, observed, secret }) {
  if (!approved || !observed) return { valid: false, reason: 'approved-and-observed-packages-required' };
  const approvedIntegrity = verifyArtifact({ ...approved, secret });
  const observedIntegrity = verifyArtifact({ ...observed, secret });
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
