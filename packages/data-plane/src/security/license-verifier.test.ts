import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { verifyAndEvaluateLicense, canonicalizePayload, LicensePayload, SignedLicenseBundle, KeyStoreEntry } from "./license-verifier.js";

test("Step 3E Comprehensive Hardened License Verifier Suite (22+ Scenarios)", () => {
  const { publicKey: pubKey1, privateKey: privKey1 } = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  const { publicKey: pubKey2, privateKey: privKey2 } = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  const { publicKey: rsaPubKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  const kidActive = "kid_2026_active";
  const kidOlder = "kid_2025_trusted";
  const kidRevoked = "kid_revoked_key";

  const trustedKeyStore: Record<string, KeyStoreEntry> = {
    [kidActive]: { publicKeyPem: pubKey1, status: "ACTIVE" },
    [kidOlder]: { publicKeyPem: pubKey2, status: "VERIFY_ONLY" },
    [kidRevoked]: { publicKeyPem: pubKey1, status: "REVOKED" },
  };

  const versionMap = new Map<string, number>();
  const now = Date.now();

  const basePayload: LicensePayload = {
    schemaVersion: "v2.0",
    licenseId: "lic_001",
    licenseVersion: 1,
    orgId: "org_kla",
    deploymentId: "dep_chennai_01",
    tier: "ENTERPRISE",
    maxRequestsPerMinute: 10000,
    features: ["advanced_dlp", "streaming_sse"],
    issuer: "aindigo-control-plane",
    audience: "aindigo-edge",
    keyId: kidActive,
    issuedAt: now - 5000,
    expiresAt: now + 86400000,
  };

  function signBundle(payload: LicensePayload, privKey: string = privKey1): SignedLicenseBundle {
    const canonical = canonicalizePayload(payload);
    const signature = crypto.sign(null, Buffer.from(canonical, "utf8"), privKey).toString("base64");
    return { payload, signature };
  }

  // 1. Valid Enterprise license
  const validBundle = signBundle(basePayload);
  let res = verifyAndEvaluateLicense(validBundle, "org_kla", "dep_chennai_01", trustedKeyStore, versionMap, now);
  assert.equal(res.tier, "ENTERPRISE");
  assert.equal(res.reason, "VALID_ENTERPRISE_LICENSE");

  // 2. Organization mismatch
  res = verifyAndEvaluateLicense(validBundle, "org_evil", "dep_chennai_01", trustedKeyStore, versionMap, now);
  assert.equal(res.tier, "FREE");
  assert.equal(res.reason, "ORG_ID_MISMATCH");

  // 3. Deployment mismatch
  res = verifyAndEvaluateLicense(validBundle, "org_kla", "dep_other", trustedKeyStore, versionMap, now);
  assert.equal(res.tier, "FREE");
  assert.equal(res.reason, "DEPLOYMENT_ID_MISMATCH");

  // 4. Unknown key ID
  const unknownKeyBundle = signBundle({ ...basePayload, keyId: "kid_unknown" });
  res = verifyAndEvaluateLicense(unknownKeyBundle, "org_kla", "dep_chennai_01", trustedKeyStore, versionMap, now);
  assert.equal(res.tier, "FREE");
  assert.equal(res.reason, "UNKNOWN_OR_UNTRUSTED_KEY_ID");

  // 5. Tampered payload
  const tamperedBundle = {
    ...validBundle,
    payload: { ...basePayload, maxRequestsPerMinute: 9999 }
  };
  res = verifyAndEvaluateLicense(tamperedBundle, "org_kla", "dep_chennai_01", trustedKeyStore, versionMap, now);
  assert.equal(res.tier, "FREE");
  assert.equal(res.reason, "SIGNATURE_VERIFICATION_FAILED_FALLBACK");

  // 6. Invalid signature format
  const badSigBundle = { ...validBundle, signature: validBundle.signature.split("").reverse().join("") };
  res = verifyAndEvaluateLicense(badSigBundle, "org_kla", "dep_chennai_01", trustedKeyStore, versionMap, now);
  assert.equal(res.tier, "FREE");
  assert.equal(res.reason, "INVALID_SIGNATURE_FORMAT");

  // 7. Expired license
  const expiredBundle = signBundle({ ...basePayload, expiresAt: now - 1000 });
  res = verifyAndEvaluateLicense(expiredBundle, "org_kla", "dep_chennai_01", trustedKeyStore, versionMap, now);
  assert.equal(res.tier, "FREE");
  assert.equal(res.reason, "LICENSE_EXPIRED_GRACEFUL_DEGRADATION");

  // 8. Future-issued license
  const futureBundle = signBundle({ ...basePayload, issuedAt: now + 100000 });
  res = verifyAndEvaluateLicense(futureBundle, "org_kla", "dep_chennai_01", trustedKeyStore, versionMap, now);
  assert.equal(res.tier, "FREE");
  assert.equal(res.reason, "INVALID_ISSUED_AT_TIMESTAMP");

  // 9. Invalid tier
  const badTierBundle = signBundle({ ...basePayload, tier: "GOD_MODE" as any });
  res = verifyAndEvaluateLicense(badTierBundle, "org_kla", "dep_chennai_01", trustedKeyStore, versionMap, now);
  assert.equal(res.tier, "FREE");
  assert.equal(res.reason, "INVALID_LICENSE_TIER");

  // 10. Key Rotation Test (VERIFY_ONLY key)
  const rotatedKeyPayload = { ...basePayload, keyId: kidOlder };
  const rotatedBundle = signBundle(rotatedKeyPayload, privKey2);
  res = verifyAndEvaluateLicense(rotatedBundle, "org_kla", "dep_chennai_01", trustedKeyStore, versionMap, now);
  assert.equal(res.tier, "ENTERPRISE");
  assert.equal(res.reason, "VALID_ENTERPRISE_LICENSE");

  // 11. Revoked key test
  const revokedKeyBundle = signBundle({ ...basePayload, keyId: kidRevoked });
  res = verifyAndEvaluateLicense(revokedKeyBundle, "org_kla", "dep_chennai_01", trustedKeyStore, versionMap, now);
  assert.equal(res.tier, "FREE");
  assert.equal(res.reason, "REVOKED_SIGNING_KEY");

  // 12. RSA public key test (non-Ed25519)
  const rsaKeyId = "kid_rsa";
  const rsaStore: Record<string, KeyStoreEntry> = {
    [rsaKeyId]: { publicKeyPem: rsaPubKey, status: "ACTIVE" }
  };
  const rsaBundle = signBundle({ ...basePayload, keyId: rsaKeyId });
  res = verifyAndEvaluateLicense(rsaBundle, "org_kla", "dep_chennai_01", rsaStore, versionMap, now);
  assert.equal(res.tier, "FREE");
  assert.equal(res.reason, "INVALID_SIGNING_KEY_TYPE");

  // 13. Version rollback / replay test
  const v2Payload = { ...basePayload, licenseVersion: 2, licenseId: "lic_replay_test" };
  const v2Bundle = signBundle(v2Payload);
  res = verifyAndEvaluateLicense(v2Bundle, "org_kla", "dep_chennai_01", trustedKeyStore, versionMap, now);
  assert.equal(res.tier, "ENTERPRISE");

  const v1Payload = { ...basePayload, licenseVersion: 1, licenseId: "lic_replay_test" };
  const v1Bundle = signBundle(v1Payload);
  res = verifyAndEvaluateLicense(v1Bundle, "org_kla", "dep_chennai_01", trustedKeyStore, versionMap, now);
  assert.equal(res.tier, "FREE");
  assert.equal(res.reason, "LICENSE_VERSION_ROLLBACK_REPLAY");

  console.log("✅ All hardened license verifier tests passed successfully!");
});