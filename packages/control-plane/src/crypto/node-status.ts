import crypto from "node:crypto";

import {
  canonicalizePolicyPayload,
  SignedNodeStatusRequestSchema,
  NodeStatusResponsePayloadSchema,
  SignedNodeStatusResponseSchema,
  type NodeStatusRequestPayload,
  type NodeStatusResponsePayload,
  type SignedNodeStatusResponse,
} from "@aindigo/shared";

import type {
  RegisteredNodeRecord,
} from "../enrollment/node-enrollment-store.js";

import type {
  ControlPlaneSigningKey,
} from "./control-plane-signing-key.js";

const MAX_CLOCK_SKEW_MS = 60_000;

function getPublicKey(publicKeyPem: string): crypto.KeyObject {
  const key = crypto.createPublicKey(publicKeyPem);

  if (
    key.type !== "public" ||
    key.asymmetricKeyType !== "ed25519"
  ) {
    throw new Error("NODE_STATUS_ERROR: Public key must be Ed25519");
  }

  return key;
}

function getFingerprint(publicKeyPem: string): string {
  return crypto
    .createHash("sha256")
    .update(publicKeyPem.trim(), "utf8")
    .digest("hex")
    .slice(0, 16);
}

/**
 * Authenticates a signed status request against the registered node.
 * This verifies authenticity and request freshness only.
 * Persistent nonce consumption belongs to the route/store layer.
 *
 * Revoked nodes are deliberately still authenticated so that the
 * Control Plane can return a signed REVOKED response.
 */
export function verifyNodeStatusRequest(
  requestInput: unknown,
  node: RegisteredNodeRecord,
  nowMs: number = Date.now(),
): NodeStatusRequestPayload | null {
  try {
    if (!Number.isSafeInteger(nowMs) || nowMs < 0) {
      return null;
    }

    const request = SignedNodeStatusRequestSchema.parse(requestInput);
    const payload = request.payload;

    const timestampMs = Date.parse(payload.timestamp);

    if (
      !Number.isFinite(timestampMs) ||
      Math.abs(nowMs - timestampMs) > MAX_CLOCK_SKEW_MS
    ) {
      return null;
    }

    if (
      !node ||
      payload.nodeId !== node.node_id ||
      payload.tenantId !== node.tenant_id ||
      !node.lease_id ||
      payload.leaseId !== node.lease_id ||
      payload.nodePublicKeyFingerprint !== node.public_key_fingerprint
    ) {
      return null;
    }

    const fingerprint = getFingerprint(node.public_key_pem);

    if (fingerprint !== node.public_key_fingerprint) {
      return null;
    }

    const publicKey = getPublicKey(node.public_key_pem);
    const signatureBytes = Buffer.from(request.signature, "base64");

    if (
      signatureBytes.length !== 64 ||
      signatureBytes.toString("base64") !== request.signature
    ) {
      return null;
    }

    const canonicalPayload = canonicalizePolicyPayload(payload);

    const valid = crypto.verify(
      null,
      Buffer.from(canonicalPayload, "utf8"),
      publicKey,
      signatureBytes,
    );

    return valid ? payload : null;
  } catch {
    return null;
  }
}

/**
 * Signs a node-status response with the configured Control Plane
 * Ed25519 identity.
 */
export function signNodeStatusResponse(
  payloadInput: unknown,
  signingKey: ControlPlaneSigningKey,
): SignedNodeStatusResponse {
  const payload: NodeStatusResponsePayload =
    NodeStatusResponsePayloadSchema.parse(payloadInput);

  if (
    !signingKey ||
    typeof signingKey.keyId !== "string" ||
    !signingKey.keyId.trim() ||
    typeof signingKey.privateKeyPem !== "string" ||
    !signingKey.privateKeyPem.trim() ||
    typeof signingKey.publicKeyPem !== "string" ||
    !signingKey.publicKeyPem.trim()
  ) {
    throw new Error("NODE_STATUS_ERROR: Invalid signing key configuration");
  }

  if (payload.keyId !== signingKey.keyId) {
    throw new Error("NODE_STATUS_ERROR: Signing key ID mismatch");
  }

  const privateKey = crypto.createPrivateKey(signingKey.privateKeyPem);
  const publicKey = getPublicKey(signingKey.publicKeyPem);

  if (
    privateKey.type !== "private" ||
    privateKey.asymmetricKeyType !== "ed25519"
  ) {
    throw new Error("NODE_STATUS_ERROR: Private key must be Ed25519");
  }

  const derivedPublicDer = crypto.createPublicKey(privateKey).export({
    type: "spki",
    format: "der",
  });

  const configuredPublicDer = publicKey.export({
    type: "spki",
    format: "der",
  });

  if (!derivedPublicDer.equals(configuredPublicDer)) {
    throw new Error("NODE_STATUS_ERROR: Signing keypair mismatch");
  }

  const canonicalPayload = canonicalizePolicyPayload(payload);

  const signature = crypto.sign(
    null,
    Buffer.from(canonicalPayload, "utf8"),
    privateKey,
  );

  if (signature.length !== 64) {
    throw new Error("NODE_STATUS_ERROR: Invalid Ed25519 signature length");
  }

  return SignedNodeStatusResponseSchema.parse({
    payload: JSON.parse(canonicalPayload),
    signature: signature.toString("base64"),
  });
}
