#!/usr/bin/env node
// Third-party receipt verifier.
//
// Verifies a CanaryNorth receipt or artifact manifest using ONLY the published
// public key. It never needs, and never accepts, signing material. That is the
// property Ed25519 buys over the previous HMAC scheme: you can check that a
// receipt is authentic without being able to forge one.
//
// Usage:
//   node scripts/verify-receipt.mjs receipt.json --url https://context-seal-production.up.railway.app
//   node scripts/verify-receipt.mjs receipt.json --key ./public-key.pem
//   curl -s $ORIGIN/api/receipts | jq '.receipts[0].receipt' > r.json && node scripts/verify-receipt.mjs r.json --url $ORIGIN
//
// Exit code 0 means verified, 1 means it did not verify.

import fs from 'node:fs';
import { canonicalize, verifySignature } from '../src/signing.mjs';
import { verifyReleaseEvidence } from '../src/release-evidence.mjs';

const args = process.argv.slice(2);
const file = args.find((a) => !a.startsWith('--'));
const flag = (name) => {
  const i = args.indexOf(`--${name}`);
  return i === -1 ? null : args[i + 1];
};

if (!file) {
  console.error('usage: node scripts/verify-receipt.mjs <receipt.json> [--url <origin> | --key <public-key.pem>]');
  process.exit(2);
}

const document = JSON.parse(fs.readFileSync(file, 'utf8'));
// Accept a bare receipt, a store entry, or an artifact package.
const subject = document.receipt || document.manifest || document;

let publicKey = null;
const keyPath = flag('key');
const origin = flag('url');
if (keyPath) {
  publicKey = fs.readFileSync(keyPath, 'utf8');
} else if (origin) {
  const response = await fetch(`${origin.replace(/\/$/, '')}/api/signing-key`);
  if (!response.ok) {
    console.error(`could not fetch signing key: HTTP ${response.status}`);
    process.exit(2);
  }
  const key = await response.json();
  publicKey = key.publicKey;
  if (key.ephemeralKey) {
    console.warn('warning: the server reports an ephemeral demo key, so older receipts will not verify');
  }
} else {
  console.error('supply --url <origin> to fetch the published key, or --key <public-key.pem>');
  process.exit(2);
}

if (subject.schema === 'contextseal.release-evidence.v1') {
  const verification = verifyReleaseEvidence(subject, publicKey);
  console.log(`subject      ${subject.candidateRelease || '(unnamed release)'}`);
  console.log(`algorithm    ${subject.signing?.algorithm || '(absent)'}`);
  console.log(`key id       ${subject.signing?.keyId || '(absent)'}`);
  console.log(`release gate ${subject.gate?.passed ? 'PASS' : 'BLOCK'}`);
  console.log(`signature    ${verification.checks?.signature ? 'VERIFIED' : 'FAILED'}`);
  console.log(`evidence     ${verification.valid ? 'VERIFIED' : 'FAILED'}`);
  process.exit(verification.valid ? 0 : 1);
}

const { signature, signatureAlgorithm, keyId, ...payload } = subject;

if (signatureAlgorithm && signatureAlgorithm !== 'ed25519') {
  console.error(`signature algorithm ${signatureAlgorithm} cannot be verified with a public key alone.`);
  console.error('Receipts issued before the Ed25519 change used a shared secret and are not independently verifiable.');
  process.exit(1);
}

const ok = verifySignature({ payload, signature, publicKey });

console.log(`subject      ${subject.id || subject.receiptId || subject.filename || '(unnamed)'}`);
console.log(`algorithm    ${signatureAlgorithm || '(absent)'}`);
console.log(`key id       ${keyId || '(absent)'}`);
console.log(`canonical    ${canonicalize(payload).slice(0, 72)}...`);
console.log(`signature    ${ok ? 'VERIFIED' : 'FAILED'}`);

if (!ok) {
  console.error('\nThis receipt did not verify. Either it was altered after signing, or it was');
  console.error('signed by a different key than the one published at /api/signing-key.');
}

process.exit(ok ? 0 : 1);
