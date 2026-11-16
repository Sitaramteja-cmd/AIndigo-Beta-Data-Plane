import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import {
  canonicalizePolicyPayload,
  NodeEnrollmentChallengeSchema,
  SignedNodeLeaseSchema,
  type NodeEnrollmentChallenge,
  type SignedNodeLease,
} from "@aindigo/shared";

export interface UnsignedReceiptPayload {
  receipt_id: string;
  timestamp: string;
  node_id: string;
  department: string;
  model_requested: string;
  model_routed: string;
  prompt_tokens: number;
  completion_tokens: number;
  cost_usd: number;
  dlp_categories: string[];
  cache_hit: boolean;
  prev_hash: string;
  schema_version: string;
}

export interface SignedReceipt extends UnsignedReceiptPayload {
  receipt_hash: string;
  ed25519_signature: string;
  node_pubkey_fingerprint: string;
}

export interface NodeIdentity {
  nodeId: string;
  publicKeyPem: string;
  privateKeyPem: string;
  publicKeyFingerprint: string;
}

const DEFAULT_KEYS_DIR = path.resolve(process.cwd(), ".keys");
const PRIVATE_KEY_FILENAME = "node_ed25519_private.pem";
const PUBLIC_KEY_FILENAME = "node_ed25519_public.pem";

function securityError(message: string): Error {
  return new Error(`NODE_IDENTITY_SECURITY_ERROR: ${message}`);
}

function getFingerprint(publicKeyPem: string): string {
  return crypto
    .createHash("sha256")
    .update(publicKeyPem.trim())
    .digest("hex")
    .slice(0, 16);
}

function validateKeyPair(
  privateKeyPem: string,
  publicKeyPem: string
): string {
  let privateKey: crypto.KeyObject;
  let publicKey: crypto.KeyObject;

  try {
    privateKey = crypto.createPrivateKey(privateKeyPem);
    publicKey = crypto.createPublicKey(publicKeyPem);
  } catch {
    throw securityError("Unable to parse node identity PEM files.");
  }

  if (
    privateKey.type !== "private" ||
    privateKey.asymmetricKeyType !== "ed25519"
  ) {
    throw securityError("Node private key must be Ed25519.");
  }

  if (
    publicKey.type !== "public" ||
    publicKey.asymmetricKeyType !== "ed25519"
  ) {
    throw securityError("Node public key must be Ed25519.");
  }

  const derivedPublicKey = crypto.createPublicKey(privateKey);

  const derivedDer = derivedPublicKey.export({
    type: "spki",
    format: "der",
  });

  const suppliedDer = publicKey.export({
    type: "spki",
    format: "der",
  });

  if (!crypto.timingSafeEqual(
    Buffer.from(derivedDer),
    Buffer.from(suppliedDer)
  )) {
    throw securityError("Node private and public keys do not match.");
  }

  return getFingerprint(publicKeyPem);
}

/**
 * Loads and validates the existing Ed25519 identity.
 * Generates a keypair only when neither identity file exists.
 * Never replaces an incomplete or invalid existing identity.
 */
export function getOrCreateNodeIdentity(
  keysDir: string = DEFAULT_KEYS_DIR
): NodeIdentity {
  const privPath = path.join(keysDir, PRIVATE_KEY_FILENAME);
  const pubPath = path.join(keysDir, PUBLIC_KEY_FILENAME);



  const privateExists = fs.existsSync(privPath);
  const publicExists = fs.existsSync(pubPath);

  if (privateExists !== publicExists) {
    throw securityError(
      "Incomplete node identity: only one key file exists. Restore the original keypair; automatic regeneration is prohibited."
    );
  }

  let privateKeyPem: string;
  let publicKeyPem: string;

  if (privateExists && publicExists) {
    try {
      privateKeyPem = fs.readFileSync(privPath, "utf8");
      publicKeyPem = fs.readFileSync(pubPath, "utf8");
    } catch {
      throw securityError("Unable to read existing node identity files.");
    }
  } else {
    // Only create the directory when provisioning a brand-new identity.
    // Existing keypairs can therefore be loaded from read-only mounts.
    fs.mkdirSync(keysDir, { recursive: true });

    const { publicKey, privateKey } = crypto.generateKeyPairSync(
      "ed25519",
      {
        publicKeyEncoding: {
          type: "spki",
          format: "pem",
        },
        privateKeyEncoding: {
          type: "pkcs8",
          format: "pem",
        },
      }
    );

    try {
      fs.writeFileSync(privPath, privateKey, {
        encoding: "utf8",
        mode: 0o600,
        flag: "wx",
      });

      fs.writeFileSync(pubPath, publicKey, {
        encoding: "utf8",
        mode: 0o644,
        flag: "wx",
      });
    } catch {
      throw securityError(
        "Unable to persist a new node identity safely. Inspect the key directory before retrying."
      );
    }

    privateKeyPem = privateKey;
    publicKeyPem = publicKey;
  }

  const fingerprint = validateKeyPair(
    privateKeyPem,
    publicKeyPem
  );

  return {
    nodeId: `node_${fingerprint}`,
    publicKeyPem,
    privateKeyPem,
    publicKeyFingerprint: fingerprint,
  };
}

/**
* Signs a Control Plane enrollment challenge with the existing node identity.
 *
 * The signature covers the complete canonical challenge JSON directly.
 * This is separate from receipt signing, which retains its existing hash-based
 * signature semantics.
 */
export function signNodeEnrollmentChallenge(
  challenge: NodeEnrollmentChallenge,
  identity: NodeIdentity
): string {
  let validatedChallenge: NodeEnrollmentChallenge;

  try {
    validatedChallenge = NodeEnrollmentChallengeSchema.parse(challenge);
  } catch {
    throw securityError("Invalid node enrollment challenge.");
  }

  const fingerprint = validateKeyPair(
    identity.privateKeyPem,
    identity.publicKeyPem
  );

  if (
    identity.publicKeyFingerprint !== fingerprint ||
    identity.nodeId !== `node_${fingerprint}` ||
    validatedChallenge.nodeId !== identity.nodeId ||
    validatedChallenge.nodePublicKeyFingerprint !== fingerprint
  ) {
    throw securityError(
      "Enrollment challenge does not match the existing node identity."
    );
  }

  let canonicalJson: string;

  try {
    canonicalJson = canonicalizePolicyPayload(validatedChallenge);
  } catch {
    throw securityError("Unable to canonicalize enrollment challenge.");
  }

  const privateKey = crypto.createPrivateKey(identity.privateKeyPem);

  const signature = crypto.sign(
    null,
    Buffer.from(canonicalJson, "utf8"),
    privateKey
  );

  if (signature.length !== 64) {
    throw securityError("Unexpected Ed25519 enrollment signature length.");
  }

  return signature.toString("base64");
}
/**
 * Produces deterministic canonical JSON.
 * Field ordering and numeric normalization are preserved for compatibility.
 */
export function canonicalizePayload(
  payload: UnsignedReceiptPayload
): string {
  const ordered: Record<string, unknown> = {
    cache_hit: Boolean(payload.cache_hit),
    completion_tokens: Number(payload.completion_tokens),
    cost_usd: Number(Number(payload.cost_usd).toFixed(6)),
    department: String(payload.department),
    dlp_categories: [...payload.dlp_categories].sort(),
    model_requested: String(payload.model_requested),
    model_routed: String(payload.model_routed),
    node_id: String(payload.node_id),
    prev_hash: String(payload.prev_hash),
    prompt_tokens: Number(payload.prompt_tokens),
    receipt_id: String(payload.receipt_id),
    schema_version: String(payload.schema_version),
    timestamp: String(payload.timestamp),
  };

  return JSON.stringify(ordered);
}

/**
 * Computes the SHA-256 chain hash and signs it with the node's Ed25519 key.
 */
export function signReceiptEd25519(
  payload: UnsignedReceiptPayload,
  identity: NodeIdentity
): SignedReceipt {
  const fingerprint = validateKeyPair(
    identity.privateKeyPem,
    identity.publicKeyPem
  );

  if (
    identity.publicKeyFingerprint !== fingerprint ||
    identity.nodeId !== `node_${fingerprint}` ||
    payload.node_id !== identity.nodeId
  ) {
    throw securityError(
      "Receipt node identity does not match the signing keypair."
    );
  }

  const canonicalJson = canonicalizePayload(payload);

  const receiptHash = crypto
    .createHash("sha256")
    .update(canonicalJson)
    .digest("hex");

  const privateKeyObj = crypto.createPrivateKey(
    identity.privateKeyPem
  );

  const signatureBuffer = crypto.sign(
    null,
    Buffer.from(receiptHash, "utf8"),
    privateKeyObj
  );

  if (signatureBuffer.length !== 64) {
    throw securityError("Unexpected Ed25519 signature length.");
  }

  return {
    ...payload,
    receipt_hash: receiptHash,
    ed25519_signature: signatureBuffer.toString("base64"),
    node_pubkey_fingerprint: fingerprint,
  };
}

/**
 * Verifies a receipt using the trusted node public key.
 */
export function verifyReceiptEd25519(
  receipt: SignedReceipt,
  publicKeyPem: string
): { valid: boolean; reason?: string } {
  try {
    if (
      !receipt ||
      typeof receipt !== "object" ||
      typeof receipt.receipt_id !== "string" ||
      typeof receipt.node_id !== "string" ||
      typeof receipt.receipt_hash !== "string" ||
      typeof receipt.ed25519_signature !== "string" ||
      typeof receipt.node_pubkey_fingerprint !== "string"
    ) {
      return {
        valid: false,
        reason: "Invalid receipt structure.",
      };
    }

    const publicKeyObj = crypto.createPublicKey(publicKeyPem);

    if (publicKeyObj.asymmetricKeyType !== "ed25519") {
      return {
        valid: false,
        reason: "Trusted public key must be Ed25519.",
      };
    }

    const fingerprint = getFingerprint(publicKeyPem);

    if (receipt.node_pubkey_fingerprint !== fingerprint) {
      return {
        valid: false,
        reason: "Receipt public-key fingerprint mismatch.",
      };
    }

    if (receipt.node_id !== `node_${fingerprint}`) {
      return {
        valid: false,
        reason: "Receipt node identity does not match trusted public key.",
      };
    }

    if (!/^[a-f0-9]{64}$/.test(receipt.receipt_hash)) {
      return {
        valid: false,
        reason: "Invalid receipt hash encoding.",
      };
    }

    const signatureBytes = Buffer.from(
      receipt.ed25519_signature,
      "base64"
    );

    if (
      signatureBytes.length !== 64 ||
      signatureBytes.toString("base64") !== receipt.ed25519_signature
    ) {
      return {
        valid: false,
        reason: "Invalid Ed25519 signature encoding.",
      };
    }

    const expectedCanonical = canonicalizePayload(receipt);

    const recomputedHash = crypto
      .createHash("sha256")
      .update(expectedCanonical)
      .digest("hex");

    if (recomputedHash !== receipt.receipt_hash) {
      return {
        valid: false,
        reason: `Hash mismatch on ${receipt.receipt_id}.`,
      };
    }

    const sigValid = crypto.verify(
      null,
      Buffer.from(receipt.receipt_hash, "utf8"),
      publicKeyObj,
      signatureBytes
    );

    if (!sigValid) {
      return {
        valid: false,
        reason: `Ed25519 signature verification failed on ${receipt.receipt_id}.`,
      };
    }

    return { valid: true };
  } catch {
    return {
      valid: false,
      reason: "Receipt verification failed due to invalid cryptographic input.",
    };
  }
}



/**
 * Verifies a Control Plane-signed node lease.
 *
 * Trust is established using the independently configured Control Plane
 * public key, never a public key supplied by the lease itself.
 */
export function verifyNodeLease(
  leaseInput: unknown,
  controlPlanePublicKeyPem: string,
  identity: NodeIdentity,
  expectedTenantId: string,
  nowMs: number = Date.now(),
  expectedKeyId?: string
): SignedNodeLease {
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) {
    throw securityError("Invalid node lease verification time.");
  }

  if (
    typeof controlPlanePublicKeyPem !== "string" ||
    !controlPlanePublicKeyPem.trim()
  ) {
    throw securityError("Pinned Control Plane public key is required.");
  }

  if (
    typeof expectedTenantId !== "string" ||
    !expectedTenantId.trim()
  ) {
    throw securityError("Expected tenant identity is required.");
  }

  let lease: SignedNodeLease;

  try {
    lease = SignedNodeLeaseSchema.parse(leaseInput);
  } catch {
    throw securityError("Invalid signed node lease structure.");
  }

  const fingerprint = validateKeyPair(
    identity.privateKeyPem,
    identity.publicKeyPem
  );

  if (
    identity.nodeId !== `node_${fingerprint}` ||
    identity.publicKeyFingerprint !== fingerprint
  ) {
    throw securityError("Local node identity metadata is inconsistent.");
  }

  const payload = lease.payload;

  if (
    payload.nodeId !== identity.nodeId ||
    payload.nodePublicKeyFingerprint !== fingerprint
  ) {
    throw securityError("Node lease does not match this Data Plane identity.");
  }

  if (payload.tenantId !== expectedTenantId) {
    throw securityError("Node lease tenant binding mismatch.");
  }

  if (
    expectedKeyId !== undefined &&
    payload.keyId !== expectedKeyId
  ) {
    throw securityError("Node lease signing key ID mismatch.");
  }

  const issuedAt = Date.parse(payload.issuedAt);
  const expiresAt = Date.parse(payload.expiresAt);

  if (
    !Number.isFinite(issuedAt) ||
    !Number.isFinite(expiresAt) ||
    issuedAt > nowMs + 60_000 ||
    expiresAt <= nowMs
  ) {
    throw securityError("Node lease is expired or not yet valid.");
  }

  const lifetimeSeconds = (expiresAt - issuedAt) / 1000;

  if (
    lifetimeSeconds <= 0 ||
    lifetimeSeconds > payload.offlineMaxSeconds ||
    payload.offlineMaxSeconds > 172800
  ) {
    throw securityError("Node lease exceeds its permitted offline lifetime.");
  }

  let publicKey: crypto.KeyObject;

  try {
    publicKey = crypto.createPublicKey(controlPlanePublicKeyPem);
  } catch {
    throw securityError("Invalid pinned Control Plane public key.");
  }

  if (
    publicKey.type !== "public" ||
    publicKey.asymmetricKeyType !== "ed25519"
  ) {
    throw securityError("Pinned Control Plane key must be Ed25519.");
  }

  let canonicalJson: string;

  try {
    canonicalJson = canonicalizePolicyPayload(payload);
  } catch {
    throw securityError("Unable to canonicalize node lease.");
  }

  const signatureBytes = Buffer.from(lease.signature, "base64");

  if (
    signatureBytes.length !== 64 ||
    signatureBytes.toString("base64") !== lease.signature
  ) {
    throw securityError("Invalid node lease signature encoding.");
  }

  const valid = crypto.verify(
    null,
    Buffer.from(canonicalJson, "utf8"),
    publicKey,
    signatureBytes
  );

  if (!valid) {
    throw securityError("Node lease signature verification failed.");
  }

  return lease;
}
