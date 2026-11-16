import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  canonicalizePolicyPayload,
  type NodeEnrollmentChallenge,
  type NodeLeasePayload,
} from "@aindigo/shared";

import {
  signNodeLease,
  verifyNodeEnrollmentProof,
} from "./node-enrollment.js";

import type {
  ControlPlaneSigningKey,
} from "./control-plane-signing-key.js";

function generateEd25519Pair() {
  return crypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
    },
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
  });
}

function fingerprint(publicKeyPem: string): string {
  return crypto
    .createHash("sha256")
    .update(publicKeyPem.trim(), "utf8")
    .digest("hex")
    .slice(0, 16);
}

function createChallenge(
  publicKeyPem: string,
  nowMs = Date.now()
): NodeEnrollmentChallenge {
  const fp = fingerprint(publicKeyPem);

  return {
    schemaVersion: "1.0",
    challengeId: crypto.randomUUID(),
    nodeId: `node_${fp}`,
    nodePublicKeyFingerprint: fp,
    clientNonce: crypto.randomBytes(32).toString("hex"),
    serverNonce: crypto.randomBytes(32).toString("hex"),
    issuedAt: new Date(nowMs).toISOString(),
    expiresAt: new Date(nowMs + 60_000).toISOString(),
  };
}

function createLease(
  keyId: string,
  nowMs = Date.now()
): NodeLeasePayload {
  const pair = generateEd25519Pair();
  const fp = fingerprint(pair.publicKey);

  return {
    schemaVersion: "1.0",
    leaseId: crypto.randomUUID(),
    keyId,
    tenantId: "tenant-enrollment-test",
    nodeId: `node_${fp}`,
    nodePublicKeyFingerprint: fp,
    issuedAt: new Date(nowMs).toISOString(),
    expiresAt: new Date(nowMs + 86_400_000).toISOString(),
    offlineMaxSeconds: 172800,
  };
}

test("verifies a valid Data Plane enrollment proof", () => {
  const pair = generateEd25519Pair();
  const now = Date.now();
  const challenge = createChallenge(pair.publicKey, now);

  const canonicalJson = canonicalizePolicyPayload(challenge);

  const signature = crypto.sign(
    null,
    Buffer.from(canonicalJson, "utf8"),
    crypto.createPrivateKey(pair.privateKey)
  ).toString("base64");

  assert.equal(
    verifyNodeEnrollmentProof(
      challenge,
      pair.publicKey,
      signature,
      now
    ),
    true
  );
});

test("rejects a modified enrollment challenge", () => {
  const pair = generateEd25519Pair();
  const now = Date.now();
  const challenge = createChallenge(pair.publicKey, now);

  const signature = crypto.sign(
    null,
    Buffer.from(canonicalizePolicyPayload(challenge), "utf8"),
    crypto.createPrivateKey(pair.privateKey)
  ).toString("base64");

  const modified = {
    ...challenge,
    serverNonce: crypto.randomBytes(32).toString("hex"),
  };

  assert.equal(
    verifyNodeEnrollmentProof(
      modified,
      pair.publicKey,
      signature,
      now
    ),
    false
  );
});

test("rejects an enrollment proof signed by another node", () => {
  const originalPair = generateEd25519Pair();
  const otherPair = generateEd25519Pair();
  const now = Date.now();

  const challenge = createChallenge(originalPair.publicKey, now);

  const signature = crypto.sign(
    null,
    Buffer.from(canonicalizePolicyPayload(challenge), "utf8"),
    crypto.createPrivateKey(otherPair.privateKey)
  ).toString("base64");

  assert.equal(
    verifyNodeEnrollmentProof(
      challenge,
      originalPair.publicKey,
      signature,
      now
    ),
    false
  );
});

test("rejects an expired enrollment challenge", () => {
  const pair = generateEd25519Pair();
  const now = Date.now();
  const challenge = createChallenge(pair.publicKey, now - 120_000);

  const signature = crypto.sign(
    null,
    Buffer.from(canonicalizePolicyPayload(challenge), "utf8"),
    crypto.createPrivateKey(pair.privateKey)
  ).toString("base64");

  assert.equal(
    verifyNodeEnrollmentProof(
      challenge,
      pair.publicKey,
      signature,
      now
    ),
    false
  );
});

test("rejects a challenge issued too far in the future", () => {
  const pair = generateEd25519Pair();
  const now = Date.now();
  const challenge = createChallenge(pair.publicKey, now + 120_000);

  const signature = crypto.sign(
    null,
    Buffer.from(canonicalizePolicyPayload(challenge), "utf8"),
    crypto.createPrivateKey(pair.privateKey)
  ).toString("base64");

  assert.equal(
    verifyNodeEnrollmentProof(
      challenge,
      pair.publicKey,
      signature,
      now
    ),
    false
  );
});

test("rejects malformed enrollment signatures", () => {
  const pair = generateEd25519Pair();
  const challenge = createChallenge(pair.publicKey);

  assert.equal(
    verifyNodeEnrollmentProof(
      challenge,
      pair.publicKey,
      "invalid-signature",
      Date.now()
    ),
    false
  );
});

test("signs a valid node-specific offline lease", () => {
  const pair = generateEd25519Pair();
  const keyId = "cp-enrollment-test-key";
  const now = Date.now();

  const signingKey: ControlPlaneSigningKey = {
    keyId,
    privateKeyPem: pair.privateKey,
    publicKeyPem: pair.publicKey,
  };

  const payload = createLease(keyId, now);
  const signedLease = signNodeLease(payload, signingKey, now);

  assert.equal(signedLease.payload.keyId, keyId);
  assert.equal(signedLease.payload.tenantId, payload.tenantId);

  const valid = crypto.verify(
    null,
    Buffer.from(
      canonicalizePolicyPayload(signedLease.payload),
      "utf8"
    ),
    crypto.createPublicKey(pair.publicKey),
    Buffer.from(signedLease.signature, "base64")
  );

  assert.equal(valid, true);
});

test("rejects a lease with a mismatched signing key ID", () => {
  const pair = generateEd25519Pair();

  const signingKey: ControlPlaneSigningKey = {
    keyId: "expected-key",
    privateKeyPem: pair.privateKey,
    publicKeyPem: pair.publicKey,
  };

  const payload = createLease("different-key");

  assert.throws(
    () => signNodeLease(payload, signingKey),
    /Signing key ID mismatch/
  );
});

test("rejects an expired lease", () => {
  const pair = generateEd25519Pair();
  const keyId = "cp-expired-test-key";
  const now = Date.now();

  const signingKey: ControlPlaneSigningKey = {
    keyId,
    privateKeyPem: pair.privateKey,
    publicKeyPem: pair.publicKey,
  };

  const payload = {
    ...createLease(keyId, now - 120_000),
    expiresAt: new Date(now - 1_000).toISOString(),
  };

  assert.throws(
    () => signNodeLease(payload, signingKey, now),
    /Lease is not currently valid/
  );
});

test("rejects a mismatched Control Plane signing keypair", () => {
  const pair = generateEd25519Pair();
  const otherPair = generateEd25519Pair();
  const keyId = "cp-mismatch-test-key";

  const signingKey: ControlPlaneSigningKey = {
    keyId,
    privateKeyPem: pair.privateKey,
    publicKeyPem: otherPair.publicKey,
  };

  const payload = createLease(keyId);

  assert.throws(
    () => signNodeLease(payload, signingKey),
    /Signing keypair mismatch/
  );
});

test("rejects an offline lease exceeding the schema maximum", () => {
  const pair = generateEd25519Pair();
  const keyId = "cp-offline-limit-test-key";

  const signingKey: ControlPlaneSigningKey = {
    keyId,
    privateKeyPem: pair.privateKey,
    publicKeyPem: pair.publicKey,
  };

  const payload = {
    ...createLease(keyId),
    expiresAt: new Date(Date.now() + 259_200_000).toISOString(),
  };

  assert.throws(
    () => signNodeLease(payload, signingKey),
    /Invalid lease payload/
  );
});
