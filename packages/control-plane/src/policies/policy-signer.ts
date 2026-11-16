import crypto from "node:crypto";
import { Buffer } from "node:buffer";

import {
  canonicalizePolicyPayload,
  type PolicyBundlePayload,
  type PolicyBundleEnvelope,
} from "@aindigo/shared";

export interface PolicySigningKey {
  keyId: string;
  privateKeyPem: string;
}

/**
 * Signs a policy bundle using the Control Plane's Ed25519 private key.
 *
 * The signature covers canonical JSON UTF-8 bytes directly.
 * The private key must never be distributed to the Data Plane.
 */
export function signPolicyBundle(
  payload: PolicyBundlePayload,
  signingKey: PolicySigningKey
): PolicyBundleEnvelope {
  if (
    !signingKey ||
    typeof signingKey.keyId !== "string" ||
    !signingKey.keyId.trim() ||
    typeof signingKey.privateKeyPem !== "string" ||
    !signingKey.privateKeyPem.trim()
  ) {
    throw new Error(
      "POLICY_SIGNING_ERROR: Invalid signing key configuration"
    );
  }

  // 1. Canonicalize before accessing payload properties (protects against getter side-effects).
  const canonicalJson = canonicalizePolicyPayload(payload);

  // 2. Work with an independent snapshot of the signed content.
  const signedPayload = JSON.parse(
    canonicalJson
  ) as PolicyBundlePayload;

  if (
    typeof signedPayload.keyId !== "string" ||
    !signedPayload.keyId.trim()
  ) {
    throw new Error(
      "POLICY_SIGNING_ERROR: Missing policy keyId"
    );
  }

  if (signedPayload.keyId !== signingKey.keyId) {
    throw new Error(
      "POLICY_SIGNING_ERROR: Signing key ID mismatch"
    );
  }

  let privateKey: crypto.KeyObject;

  try {
    privateKey = crypto.createPrivateKey(
      signingKey.privateKeyPem
    );
  } catch {
    throw new Error(
      "POLICY_SIGNING_ERROR: Invalid private key PEM"
    );
  }

  if (
    privateKey.type !== "private" ||
    privateKey.asymmetricKeyType !== "ed25519"
  ) {
    throw new Error(
      "POLICY_SIGNING_ERROR: Private key must be Ed25519"
    );
  }

  // 3. Sign the exact canonical UTF-8 bytes directly.
  const signatureBytes = crypto.sign(
    null,
    Buffer.from(canonicalJson, "utf8"),
    privateKey
  );

  if (signatureBytes.length !== 64) {
    throw new Error(
      "POLICY_SIGNING_ERROR: Invalid Ed25519 signature length"
    );
  }

  return {
    payload: signedPayload,
    signature: signatureBytes.toString("base64"),
  };
}