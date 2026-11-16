import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { signPolicyBundle, type PolicySigningKey } from "./policy-signer.js";
import { canonicalizePolicyPayload, type PolicyBundlePayload } from "@aindigo/shared";

test("Control Plane Policy Signer Comprehensive Suite", async (t) => {
  const { publicKey: pubKeyObj, privateKey: privKeyPem } = crypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  });

  const keyId = "key-cp-2026-01";
  const signingKey: PolicySigningKey = {
    keyId,
    privateKeyPem: privKeyPem,
  };

  const now = Date.now();
  const samplePayload: PolicyBundlePayload = {
    schemaVersion: "1.0",
    bundleId: "bundle-sign-01",
    keyId,
    orgId: "org-enterprise-01",
    edgeNodeId: "edge-node-42",
    version: 1,
    issuedAt: now,
    expiresAt: now + 86400000,
    entitlements: {
      licenseId: "lic-001",
      licenseVersion: 1,
      tier: "ENTERPRISE",
      maxRequestsPerMinute: 2000,
      allowedModels: ["gpt-4o", "claude-3-5-sonnet"],
    },
    routing: {
      allowedUpstreams: [
        { provider: "openai", endpoint: "https://api.openai.com", enabled: true },
      ],
      fallback: { enabled: true, strategy: "SAME_PROVIDER" },
    },
    security: {
      egressAllowlist: ["api.openai.com"],
      enforceHttps: true,
    },
    featureFlags: { advancedAudit: true },
    dlp: {
      enabled: true,
      checksumValidators: [{ validatorId: "luhn", enabled: true }],
      redactionRules: [{ category: "API_KEY", action: "BLOCK", enabled: true }],
    },
  };

  await t.test("1. Successfully signs a valid policy payload", () => {
    const envelope = signPolicyBundle(samplePayload, signingKey);
    assert.equal(envelope.payload.bundleId, samplePayload.bundleId);
    assert.equal(typeof envelope.signature, "string");
    assert.equal(Buffer.from(envelope.signature, "base64").length, 64);
  });

  await t.test("2. Verifies the signature using the corresponding public key", () => {
    const envelope = signPolicyBundle(samplePayload, signingKey);
    const canonicalJson = canonicalizePolicyPayload(envelope.payload);
    const pubKey = crypto.createPublicKey(pubKeyObj);

    const isValid = crypto.verify(
      null,
      Buffer.from(canonicalJson, "utf8"),
      pubKey,
      Buffer.from(envelope.signature, "base64")
    );
    assert.equal(isValid, true);
  });

  await t.test("3. Returns an independent signed payload snapshot", () => {
    const originalPayload = structuredClone(samplePayload);

    const envelope = signPolicyBundle(
      originalPayload,
      signingKey
    );

    originalPayload.version = 999;

    assert.equal(envelope.payload.version, 1);
  });

  await t.test("4. Rejects a mismatched keyId", () => {
    const mismatchedPayload = { ...samplePayload, keyId: "wrong-key-id" };
    assert.throws(
      () => signPolicyBundle(mismatchedPayload, signingKey),
      /Signing key ID mismatch/
    );
  });

  await t.test("5. Rejects an invalid private-key PEM", () => {
    const invalidKey: PolicySigningKey = {
      keyId,
      privateKeyPem: "-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----",
    };
    assert.throws(
      () => signPolicyBundle(samplePayload, invalidKey),
      /Invalid private key PEM/
    );
  });

  await t.test("6. Detects payload tampering", () => {
    const envelope = signPolicyBundle(samplePayload, signingKey);
    const tamperedPayload = { ...envelope.payload, version: 999 };
    const canonicalJson = canonicalizePolicyPayload(tamperedPayload);
    const pubKey = crypto.createPublicKey(pubKeyObj);

    const isValid = crypto.verify(
      null,
      Buffer.from(canonicalJson, "utf8"),
      pubKey,
      Buffer.from(envelope.signature, "base64")
    );
    assert.equal(isValid, false);
  });

  await t.test("7. Rejects verification with the wrong public key", () => {
    const envelope = signPolicyBundle(samplePayload, signingKey);
    const canonicalJson = canonicalizePolicyPayload(envelope.payload);

    const { publicKey: wrongPubKeyPem } = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { format: "pem", type: "spki" },
    });
    const wrongPubKey = crypto.createPublicKey(wrongPubKeyPem);

    const isValid = crypto.verify(
      null,
      Buffer.from(canonicalJson, "utf8"),
      wrongPubKey,
      Buffer.from(envelope.signature, "base64")
    );
    assert.equal(isValid, false);
  });

  await t.test("8. Rejects non-Ed25519 (RSA) private keys", () => {
    const { privateKey: rsaPrivKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { format: "pem", type: "pkcs8" },
    });

    const rsaSigningKey: PolicySigningKey = {
      keyId,
      privateKeyPem: rsaPrivKey,
    };

    assert.throws(
      () => signPolicyBundle(samplePayload, rsaSigningKey),
      /Private key must be Ed25519/
    );
  });

  await t.test("9. Rejects circular policy payloads during canonicalization", () => {
    const circularPayload = {
      ...samplePayload,
    } as Record<string, unknown>;

    circularPayload.self = circularPayload;

    assert.throws(
      () => signPolicyBundle(
        circularPayload as unknown as PolicyBundlePayload,
        signingKey
      ),
      /Circular reference detected/
    );
  });
});
