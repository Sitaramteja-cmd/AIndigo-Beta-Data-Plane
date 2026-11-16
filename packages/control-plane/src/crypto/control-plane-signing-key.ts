import crypto from "node:crypto";
import fs from "node:fs";

export interface ControlPlaneSigningKeyConfig {
  keyId: string;
  privateKeyPath: string;
  publicKeyPath: string;
}

export interface ControlPlaneSigningKey {
  readonly keyId: string;
  readonly privateKeyPem: string;
  readonly publicKeyPem: string;
}

function validateNonEmptyString(
  value: unknown,
  field: string
): asserts value is string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(
      `CONTROL_PLANE_SIGNING_KEY_ERROR: ${field} is required`
    );
  }
}

function readKeyFile(filePath: string, field: string): string {
  let contents: string;

  try {
    contents = fs.readFileSync(filePath, "utf8");
  } catch {
    throw new Error(
      `CONTROL_PLANE_SIGNING_KEY_ERROR: Cannot read ${field}`
    );
  }

  if (!contents.trim()) {
    throw new Error(
      `CONTROL_PLANE_SIGNING_KEY_ERROR: ${field} is empty`
    );
  }

  return contents;
}

function assertEd25519KeyPair(
  privateKeyPem: string,
  publicKeyPem: string
): void {
  let privateKey: crypto.KeyObject;
  let publicKey: crypto.KeyObject;

  try {
    privateKey = crypto.createPrivateKey(privateKeyPem);
  } catch {
    throw new Error(
      "CONTROL_PLANE_SIGNING_KEY_ERROR: Invalid private key PEM"
    );
  }

  try {
    publicKey = crypto.createPublicKey(publicKeyPem);
  } catch {
    throw new Error(
      "CONTROL_PLANE_SIGNING_KEY_ERROR: Invalid public key PEM"
    );
  }

  if (
    privateKey.type !== "private" ||
    privateKey.asymmetricKeyType !== "ed25519"
  ) {
    throw new Error(
      "CONTROL_PLANE_SIGNING_KEY_ERROR: Private key must be Ed25519"
    );
  }

  if (
    publicKey.type !== "public" ||
    publicKey.asymmetricKeyType !== "ed25519"
  ) {
    throw new Error(
      "CONTROL_PLANE_SIGNING_KEY_ERROR: Public key must be Ed25519"
    );
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
    throw new Error(
      "CONTROL_PLANE_SIGNING_KEY_ERROR: Private/public keypair mismatch"
    );
  }
}

export function loadControlPlaneSigningKey(
  config: ControlPlaneSigningKeyConfig
): ControlPlaneSigningKey {
  if (!config || typeof config !== "object") {
    throw new Error(
      "CONTROL_PLANE_SIGNING_KEY_ERROR: Configuration is required"
    );
  }

  validateNonEmptyString(config.keyId, "CONTROL_PLANE_SIGNING_KEY_ID");
  validateNonEmptyString(
    config.privateKeyPath,
    "CONTROL_PLANE_SIGNING_PRIVATE_KEY_PATH"
  );
  validateNonEmptyString(
    config.publicKeyPath,
    "CONTROL_PLANE_SIGNING_PUBLIC_KEY_PATH"
  );

  const privateKeyPem = readKeyFile(
    config.privateKeyPath,
    "private signing key"
  );

  const publicKeyPem = readKeyFile(
    config.publicKeyPath,
    "public signing key"
  );

  assertEd25519KeyPair(privateKeyPem, publicKeyPem);

  return Object.freeze({
    keyId: config.keyId.trim(),
    privateKeyPem,
    publicKeyPem,
  });
}
