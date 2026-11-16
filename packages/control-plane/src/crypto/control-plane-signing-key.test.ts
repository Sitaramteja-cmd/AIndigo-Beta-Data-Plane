import test, { afterEach } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  loadControlPlaneSigningKey,
} from "./control-plane-signing-key.js";

const temporaryDirectories: string[] = [];

function createTemporaryDirectory(): string {
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), "aindigo-cp-signing-test-")
  );

  temporaryDirectories.push(directory);
  return directory;
}

function generateEd25519KeyPair() {
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

function writeKeyPair(
  directory: string,
  privateKeyPem: string,
  publicKeyPem: string
) {
  const privateKeyPath = path.join(directory, "private.pem");
  const publicKeyPath = path.join(directory, "public.pem");

  fs.writeFileSync(privateKeyPath, privateKeyPem, {
    encoding: "utf8",
    mode: 0o600,
  });

  fs.writeFileSync(publicKeyPath, publicKeyPem, {
    encoding: "utf8",
    mode: 0o644,
  });

  return {
    keyId: "cp-signing-test-2026",
    privateKeyPath,
    publicKeyPath,
  };
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    fs.rmSync(directory, {
      recursive: true,
      force: true,
    });
  }
});

test("loads a valid Ed25519 signing keypair", () => {
  const directory = createTemporaryDirectory();
  const pair = generateEd25519KeyPair();

  const config = writeKeyPair(
    directory,
    pair.privateKey,
    pair.publicKey
  );

  const result = loadControlPlaneSigningKey(config);

  assert.equal(result.keyId, config.keyId);
  assert.equal(result.privateKeyPem, pair.privateKey);
  assert.equal(result.publicKeyPem, pair.publicKey);
  assert.equal(Object.isFrozen(result), true);
});

test("rejects missing configuration", () => {
  assert.throws(
    () => loadControlPlaneSigningKey(undefined as never),
    /Configuration is required/
  );
});

test("rejects an empty key ID", () => {
  const directory = createTemporaryDirectory();
  const pair = generateEd25519KeyPair();

  const config = writeKeyPair(
    directory,
    pair.privateKey,
    pair.publicKey
  );

  assert.throws(
    () => loadControlPlaneSigningKey({
      ...config,
      keyId: "   ",
    }),
    /CONTROL_PLANE_SIGNING_KEY_ID is required/
  );
});

test("rejects a missing private key file", () => {
  const directory = createTemporaryDirectory();
  const pair = generateEd25519KeyPair();

  const config = writeKeyPair(
    directory,
    pair.privateKey,
    pair.publicKey
  );

  fs.unlinkSync(config.privateKeyPath);

  assert.throws(
    () => loadControlPlaneSigningKey(config),
    /Cannot read private signing key/
  );
});

test("rejects a missing public key file", () => {
  const directory = createTemporaryDirectory();
  const pair = generateEd25519KeyPair();

  const config = writeKeyPair(
    directory,
    pair.privateKey,
    pair.publicKey
  );

  fs.unlinkSync(config.publicKeyPath);

  assert.throws(
    () => loadControlPlaneSigningKey(config),
    /Cannot read public signing key/
  );
});

test("rejects an empty private key file", () => {
  const directory = createTemporaryDirectory();
  const pair = generateEd25519KeyPair();

  const config = writeKeyPair(
    directory,
    pair.privateKey,
    pair.publicKey
  );

  fs.writeFileSync(config.privateKeyPath, "");

  assert.throws(
    () => loadControlPlaneSigningKey(config),
    /private signing key is empty/
  );
});

test("rejects invalid private key PEM", () => {
  const directory = createTemporaryDirectory();
  const pair = generateEd25519KeyPair();

  const config = writeKeyPair(
    directory,
    "invalid-private-key",
    pair.publicKey
  );

  assert.throws(
    () => loadControlPlaneSigningKey(config),
    /Invalid private key PEM/
  );
});

test("rejects invalid public key PEM", () => {
  const directory = createTemporaryDirectory();
  const pair = generateEd25519KeyPair();

  const config = writeKeyPair(
    directory,
    pair.privateKey,
    "invalid-public-key"
  );

  assert.throws(
    () => loadControlPlaneSigningKey(config),
    /Invalid public key PEM/
  );
});

test("rejects RSA private keys", () => {
  const directory = createTemporaryDirectory();

  const rsa = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
    },
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
  });

  const config = writeKeyPair(
    directory,
    rsa.privateKey,
    rsa.publicKey
  );

  assert.throws(
    () => loadControlPlaneSigningKey(config),
    /Private key must be Ed25519/
  );
});

test("rejects an Ed25519 private key paired with another public key", () => {
  const directory = createTemporaryDirectory();

  const firstPair = generateEd25519KeyPair();
  const secondPair = generateEd25519KeyPair();

  const config = writeKeyPair(
    directory,
    firstPair.privateKey,
    secondPair.publicKey
  );

  assert.throws(
    () => loadControlPlaneSigningKey(config),
    /Private\/public keypair mismatch/
  );
});
