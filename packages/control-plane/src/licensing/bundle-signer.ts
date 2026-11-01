import crypto from "node:crypto";

export interface PolicyBundle {
  schema_version: string;
  org_id: string;
  plan: "community" | "pro" | "enterprise";
  policy_mode: "mask" | "block" | "warn" | "log_only";
  max_nodes: number;
  monthly_token_quota: number;
  custom_regexes: Array<{ id: string; pattern: string }>;
  cache_enabled: boolean;
  issued_at: string;
  expires_at: string;
}

export interface SignedPolicyBundle {
  bundle: PolicyBundle;
  signature: string; // Ed25519 signature by Control Plane
}

/**
 * Signs a policy bundle using the Control Plane's Ed25519 private key.
 */
export function signPolicyBundle(
  bundle: PolicyBundle,
  controlPlanePrivateKeyPem: string
): SignedPolicyBundle {
  const canonical = JSON.stringify(bundle, Object.keys(bundle).sort());
  const hash = crypto.createHash("sha256").update(canonical).digest("hex");
  const privKey = crypto.createPrivateKey(controlPlanePrivateKeyPem);
  const signature = crypto.sign(null, Buffer.from(hash, "utf8"), privKey);

  return {
    bundle,
    signature: signature.toString("base64"),
  };
}

/**
 * Verifies a signed policy bundle on the Data Plane using only the Control Plane public key.
 */
export function verifyPolicyBundle(
  signedBundle: SignedPolicyBundle,
  controlPlanePublicKeyPem: string
): { valid: boolean; reason?: string } {
  try {
    const canonical = JSON.stringify(signedBundle.bundle, Object.keys(signedBundle.bundle).sort());
    const recomputedHash = crypto.createHash("sha256").update(canonical).digest("hex");

    const pubKey = crypto.createPublicKey(controlPlanePublicKeyPem);
    const isValid = crypto.verify(
      null,
      Buffer.from(recomputedHash, "utf8"),
      pubKey,
      Buffer.from(signedBundle.signature, "base64")
    );

    if (!isValid) {
      return { valid: false, reason: "Policy bundle signature verification failed." };
    }

    // Check expiration
    if (new Date(signedBundle.bundle.expires_at).getTime() < Date.now()) {
      return { valid: false, reason: "Policy bundle has expired." };
    }

    return { valid: true };
  } catch (err: any) {
    return { valid: false, reason: err.message };
  }
}
