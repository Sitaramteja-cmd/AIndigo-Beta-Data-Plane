import crypto from "node:crypto";

import {
  canonicalizePolicyPayload,
  Ed25519SignatureSchema,
  NodeEnrollmentChallengeSchema,
  NodeLeasePayloadSchema,
  PublicKeyPemSchema,
  SignedNodeLeaseSchema,
  type NodeEnrollmentChallenge,
  type NodeLeasePayload,
  type SignedNodeLease,
} from "@aindigo/shared";

import type {
  ControlPlaneSigningKey,
} from "./control-plane-signing-key.js";

const MAX_CLOCK_SKEW_MS = 60_000;

function getEd25519PublicKey(publicKeyPem: string): crypto.KeyObject {
  const publicKey = crypto.createPublicKey(publicKeyPem);

  if (
    publicKey.type !== "public" ||
    publicKey.asymmetricKeyType !== "ed25519"
  ) {
    throw new Error("NODE_ENROLLMENT_ERROR: Public key must be Ed25519");
  }

  return publicKey;
}

function getNodeFingerprint(publicKeyPem: string): string {
  return crypto
    .createHash("sha256")
    .update(publicKeyPem.trim(), "utf8")
    .digest("hex")
    .slice(0, 16);
}

/**
 * Verifies a Data Plane proof against the exact challenge retrieved
 * from Control Plane storage.
 *
 * This function verifies cryptographic authenticity only.
 * Challenge consumption and replay prevention belong to the
 * persistent enrollment service and its database transaction.
 */
export function verifyNodeEnrollmentProof(
  challengeInput: unknown,
  nodePublicKeyPemInput: unknown,
  signatureInput: unknown,
  nowMs: number = Date.now()
): boolean {
  try {
    if (!Number.isSafeInteger(nowMs) || nowMs < 0) {
      return false;
    }

    const challenge: NodeEnrollmentChallenge =
      NodeEnrollmentChallengeSchema.parse(challengeInput);

    const nodePublicKeyPem =
      PublicKeyPemSchema.parse(nodePublicKeyPemInput);

    const signature =
      Ed25519SignatureSchema.parse(signatureInput);

    const issuedAt = Date.parse(challenge.issuedAt);
    const expiresAt = Date.parse(challenge.expiresAt);

    if (
      !Number.isFinite(issuedAt) ||
      !Number.isFinite(expiresAt) ||
      issuedAt > nowMs + MAX_CLOCK_SKEW_MS ||
      expiresAt <= nowMs
    ) {
      return false;
    }

    const fingerprint = getNodeFingerprint(nodePublicKeyPem);

    if (
      challenge.nodePublicKeyFingerprint !== fingerprint ||
      challenge.nodeId !== `node_${fingerprint}`
    ) {
      return false;
    }

    const publicKey = getEd25519PublicKey(nodePublicKeyPem);
    const canonicalJson = canonicalizePolicyPayload(challenge);
    const signatureBytes = Buffer.from(signature, "base64");

    if (signatureBytes.toString("base64") !== signature) {
      return false;
    }

    return crypto.verify(
      null,
      Buffer.from(canonicalJson, "utf8"),
      publicKey,
      signatureBytes
    );
  } catch {
    return false;
  }
}

/**
 * Signs a node-specific offline lease using the configured
 * Control Plane Ed25519 signing identity.
 *
 * The lease payload is canonicalized and copied before signing.
 */
export function signNodeLease(
  payloadInput: unknown,
  signingKey: ControlPlaneSigningKey,
  nowMs: number = Date.now()
): SignedNodeLease {
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) {
    throw new Error("NODE_LEASE_ERROR: Invalid signing time");
  }

  if (
    !signingKey ||
    typeof signingKey.keyId !== "string" ||
    !signingKey.keyId.trim() ||
    typeof signingKey.privateKeyPem !== "string" ||
    !signingKey.privateKeyPem.trim() ||
    typeof signingKey.publicKeyPem !== "string" ||
    !signingKey.publicKeyPem.trim()
  ) {
    throw new Error("NODE_LEASE_ERROR: Invalid signing key configuration");
  }

  let payload: NodeLeasePayload;

  try {
    payload = NodeLeasePayloadSchema.parse(payloadInput);
  } catch {
    throw new Error("NODE_LEASE_ERROR: Invalid lease payload");
  }

  if (payload.keyId !== signingKey.keyId) {
    throw new Error("NODE_LEASE_ERROR: Signing key ID mismatch");
  }

  const issuedAt = Date.parse(payload.issuedAt);
  const expiresAt = Date.parse(payload.expiresAt);

  if (
    !Number.isFinite(issuedAt) ||
    !Number.isFinite(expiresAt) ||
    issuedAt > nowMs + MAX_CLOCK_SKEW_MS ||
    expiresAt <= nowMs
  ) {
    throw new Error("NODE_LEASE_ERROR: Lease is not currently valid");
  }

  let privateKey: crypto.KeyObject;
  let publicKey: crypto.KeyObject;

  try {
    privateKey = crypto.createPrivateKey(signingKey.privateKeyPem);
    publicKey = getEd25519PublicKey(signingKey.publicKeyPem);
  } catch {
    throw new Error("NODE_LEASE_ERROR: Invalid signing key PEM");
  }

  if (
    privateKey.type !== "private" ||
    privateKey.asymmetricKeyType !== "ed25519"
  ) {
    throw new Error("NODE_LEASE_ERROR: Private key must be Ed25519");
  }

  const derivedPublicKey = crypto.createPublicKey(privateKey);

  const derivedDer = derivedPublicKey.export({
    type: "spki",
    format: "der",
  });

  const configuredDer = publicKey.export({
    type: "spki",
    format: "der",
  });

  if (!derivedDer.equals(configuredDer)) {
    throw new Error("NODE_LEASE_ERROR: Signing keypair mismatch");
  }

  const canonicalJson = canonicalizePolicyPayload(payload);
  const signedPayload = JSON.parse(canonicalJson) as NodeLeasePayload;

  const signatureBytes = crypto.sign(
    null,
    Buffer.from(canonicalJson, "utf8"),
    privateKey
  );

  if (signatureBytes.length !== 64) {
    throw new Error("NODE_LEASE_ERROR: Invalid Ed25519 signature length");
  }

  return SignedNodeLeaseSchema.parse({
    payload: signedPayload,
    signature: signatureBytes.toString("base64"),
  });
}
