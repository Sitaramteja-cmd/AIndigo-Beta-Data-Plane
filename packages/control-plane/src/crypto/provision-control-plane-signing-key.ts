import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import {
  loadControlPlaneSigningKey,
} from "./control-plane-signing-key.js";

function main(): void {
  const privateArgument = process.argv[2];
  const publicArgument = process.argv[3];

  if (!privateArgument || !publicArgument) {
    throw new Error(
      "Usage: provision-control-plane-signing-key.ts <private-key-path> <public-key-path>"
    );
  }

  const privateKeyPath = path.resolve(privateArgument);
  const publicKeyPath = path.resolve(publicArgument);

  if (privateKeyPath === publicKeyPath) {
    throw new Error("Private and public key paths must be different");
  }

  if (
    fs.existsSync(privateKeyPath) ||
    fs.existsSync(publicKeyPath)
  ) {
    throw new Error(
      "Refusing to overwrite an existing signing-key file"
    );
  }

  fs.mkdirSync(path.dirname(privateKeyPath), {
    recursive: true,
  });

  fs.mkdirSync(path.dirname(publicKeyPath), {
    recursive: true,
  });

  const pair = crypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
    },
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
  });

  let privateCreated = false;
  let publicCreated = false;

  try {
    fs.writeFileSync(privateKeyPath, pair.privateKey, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    privateCreated = true;

    fs.writeFileSync(publicKeyPath, pair.publicKey, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o644,
    });
    publicCreated = true;

    const publicKey = crypto.createPublicKey(pair.publicKey);
    const publicDer = publicKey.export({
      type: "spki",
      format: "der",
    });

    const fingerprint = crypto
      .createHash("sha256")
      .update(publicDer)
      .digest("hex");

    const keyId = `cp-ed25519-${fingerprint.slice(0, 16)}`;

    const loaded = loadControlPlaneSigningKey({
      keyId,
      privateKeyPath,
      publicKeyPath,
    });

    if (
      loaded.privateKeyPem !== pair.privateKey ||
      loaded.publicKeyPem !== pair.publicKey
    ) {
      throw new Error("Generated signing-key validation failed");
    }

    console.log("Control Plane Ed25519 signing identity provisioned.");
    console.log(`Key ID: ${loaded.keyId}`);
    console.log(`Public-key SHA256 fingerprint: ${fingerprint}`);
    console.log(`Private key: ${privateKeyPath}`);
    console.log(`Public key: ${publicKeyPath}`);
    console.log("Keypair validation: PASSED");
    console.log("Private key material was not printed.");

    if (process.platform === "win32") {
      console.log(
        "IMPORTANT: Apply and verify Windows ACL restrictions on the private key."
      );
    }
  } catch (error) {
    // Remove only files created by this invocation.
    if (publicCreated) {
      fs.unlinkSync(publicKeyPath);
    }

    if (privateCreated) {
      fs.unlinkSync(privateKeyPath);
    }

    throw error;
  }
}

try {
  main();
} catch (error) {
  const message =
    error instanceof Error ? error.message : "Unknown provisioning error";

  console.error(`CONTROL_PLANE_KEY_PROVISIONING_ERROR: ${message}`);
  process.exitCode = 1;
}
