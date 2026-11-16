import test, { afterEach } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  loadControlPlaneSigningKeyFromEnvironment,
} from "./control-plane-signing-config.js";

const temporaryDirectories: string[] = [];

function createKeyPairFiles() {
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), "aindigo-cp-config-test-")
  );

  temporaryDirectories.push(directory);

  const pair = crypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });

  const privateKeyPath = path.join(directory, "private.pem");
  const publicKeyPath = path.join(directory, "public.pem");

  fs.writeFileSync(privateKeyPath, pair.privateKey, {
    encoding: "utf8",
    mode: 0o600,
  });

  fs.writeFileSync(publicKeyPath, pair.publicKey, {
    encoding: "utf8",
    mode: 0o644,
  });

  return { privateKeyPath, publicKeyPath };
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("allows development startup when signing configuration is absent", () => {
  assert.equal(
    loadControlPlaneSigningKeyFromEnvironment({
      NODE_ENV: "development",
    }),
    null
  );
});

test("rejects production startup when signing configuration is absent", () => {
  assert.throws(
    () => loadControlPlaneSigningKeyFromEnvironment({
      NODE_ENV: "production",
    }),
    /Production requires a configured signing identity/
  );
});

test("rejects partially configured signing environment", () => {
  assert.throws(
    () => loadControlPlaneSigningKeyFromEnvironment({
      NODE_ENV: "development",
      CONTROL_PLANE_SIGNING_KEY_ID: "test-key",
    }),
    /All three signing-key environment variables are required/
  );
});

test("loads a valid signing identity in development", () => {
  const files = createKeyPairFiles();

  const result = loadControlPlaneSigningKeyFromEnvironment({
    NODE_ENV: "development",
    CONTROL_PLANE_SIGNING_KEY_ID: "development-test-key",
    CONTROL_PLANE_SIGNING_PRIVATE_KEY_PATH: files.privateKeyPath,
    CONTROL_PLANE_SIGNING_PUBLIC_KEY_PATH: files.publicKeyPath,
  });

  assert.ok(result);
  assert.equal(result.keyId, "development-test-key");
});

test("loads a valid signing identity in production", () => {
  const files = createKeyPairFiles();

  const result = loadControlPlaneSigningKeyFromEnvironment({
    NODE_ENV: "production",
    CONTROL_PLANE_SIGNING_KEY_ID: "production-test-key",
    CONTROL_PLANE_SIGNING_PRIVATE_KEY_PATH: files.privateKeyPath,
    CONTROL_PLANE_SIGNING_PUBLIC_KEY_PATH: files.publicKeyPath,
  });

  assert.ok(result);
  assert.equal(result.keyId, "production-test-key");
});

test("rejects invalid key files in production", () => {
  assert.throws(
    () => loadControlPlaneSigningKeyFromEnvironment({
      NODE_ENV: "production",
      CONTROL_PLANE_SIGNING_KEY_ID: "invalid-test-key",
      CONTROL_PLANE_SIGNING_PRIVATE_KEY_PATH: "missing-private.pem",
      CONTROL_PLANE_SIGNING_PUBLIC_KEY_PATH: "missing-public.pem",
    }),
    /Cannot read private signing key/
  );
});
