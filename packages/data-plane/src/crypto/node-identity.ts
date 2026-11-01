import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

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
const PRIV_KEY_FILE = path.join(DEFAULT_KEYS_DIR, "node_ed25519_private.pem");
const PUB_KEY_FILE = path.join(DEFAULT_KEYS_DIR, "node_ed25519_public.pem");

/**
 * Loads existing Ed25519 keypair from .keys/ or generates a new one on first boot.
 * The private key never leaves the local Data Plane node.
 */
export function getOrCreateNodeIdentity(keysDir: string = DEFAULT_KEYS_DIR): NodeIdentity {
  const privPath = path.join(keysDir, "node_ed25519_private.pem");
  const pubPath = path.join(keysDir, "node_ed25519_public.pem");

  if (!fs.existsSync(keysDir)) {
    fs.mkdirSync(keysDir, { recursive: true });
  }

  let privateKeyPem: string;
  let publicKeyPem: string;

  if (fs.existsSync(privPath) && fs.existsSync(pubPath)) {
    privateKeyPem = fs.readFileSync(privPath, "utf8");
    publicKeyPem = fs.readFileSync(pubPath, "utf8");
  } else {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    fs.writeFileSync(privPath, privateKey, { encoding: "utf8", mode: 0o600 });
    fs.writeFileSync(pubPath, publicKey, { encoding: "utf8", mode: 0o644 });
    privateKeyPem = privateKey;
    publicKeyPem = publicKey;
  }

  const fingerprint = crypto
    .createHash("sha256")
    .update(publicKeyPem.trim())
    .digest("hex")
    .slice(0, 16);

  return {
    nodeId: `node_${fingerprint}`,
    publicKeyPem,
    privateKeyPem,
    publicKeyFingerprint: fingerprint,
  };
}

/**
 * Produces a deterministic canonical JSON string with sorted keys
 * so hashes match across all platforms and runtimes.
 */
export function canonicalizePayload(payload: UnsignedReceiptPayload): string {
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
 * Computes SHA-256 chain hash and signs it with the Data Plane's Ed25519 private key.
 */
export function signReceiptEd25519(
  payload: UnsignedReceiptPayload,
  identity: NodeIdentity
): SignedReceipt {
  const canonicalJson = canonicalizePayload(payload);
  const receiptHash = crypto.createHash("sha256").update(canonicalJson).digest("hex");

  const privateKeyObj = crypto.createPrivateKey(identity.privateKeyPem);
  const signatureBuffer = crypto.sign(null, Buffer.from(receiptHash, "utf8"), privateKeyObj);

  return {
    ...payload,
    receipt_hash: receiptHash,
    ed25519_signature: signatureBuffer.toString("base64"),
    node_pubkey_fingerprint: identity.publicKeyFingerprint,
  };
}

/**
 * Verifies a single receipt's SHA-256 hash and Ed25519 signature using ONLY the public key.
 */
export function verifyReceiptEd25519(
  receipt: SignedReceipt,
  publicKeyPem: string
): { valid: boolean; reason?: string } {
  try {
    const expectedCanonical = canonicalizePayload(receipt);
    const recomputedHash = crypto.createHash("sha256").update(expectedCanonical).digest("hex");

    if (recomputedHash !== receipt.receipt_hash) {
      return {
        valid: false,
        reason: `Hash mismatch on ${receipt.receipt_id}: expected ${recomputedHash}, got ${receipt.receipt_hash}`,
      };
    }

    const publicKeyObj = crypto.createPublicKey(publicKeyPem);
    const sigValid = crypto.verify(
      null,
      Buffer.from(receipt.receipt_hash, "utf8"),
      publicKeyObj,
      Buffer.from(receipt.ed25519_signature, "base64")
    );

    if (!sigValid) {
      return {
        valid: false,
        reason: `Ed25519 signature verification failed on ${receipt.receipt_id}`,
      };
    }

    return { valid: true };
  } catch (err: any) {
    return { valid: false, reason: err.message };
  }
}
