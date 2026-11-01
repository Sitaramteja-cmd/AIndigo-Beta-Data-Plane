import { strict as assert } from "node:assert";
import crypto from "node:crypto";
import { signPolicyBundle, verifyPolicyBundle, PolicyBundle } from "./bundle-signer.js";

async function runLicensingTests() {
  console.log("================================================================");
  console.log(" 📜 AIndigo Tier 1 — Signed Policy Bundles & Offline License Test");
  console.log("================================================================");

  // 1. Generate a mock Control Plane Ed25519 keypair
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  const futureDate = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(); // 7 days from now

  const sampleBundle: PolicyBundle = {
    schema_version: "2.0.0",
    org_id: "org_enterprise_xyz",
    plan: "enterprise",
    policy_mode: "block",
    max_nodes: 25,
    monthly_token_quota: 10000000,
    custom_regexes: [{ id: "internal_project_id", pattern: "PROJ-[0-9]{4}" }],
    cache_enabled: true,
    issued_at: new Date().toISOString(),
    expires_at: futureDate,
  };

  // 2. Sign bundle
  const signed = signPolicyBundle(sampleBundle, privateKey);
  assert.notEqual(signed.signature, undefined, "Signed bundle must contain a signature");
  console.log("✅ 1. Control Plane Policy Bundle Signed Successfully.");

  // 3. Verify valid bundle offline
  const verification = verifyPolicyBundle(signed, publicKey);
  assert.equal(verification.valid, true, "Valid signed bundle must verify successfully");
  console.log("✅ 2. Offline Bundle Verification Passed.");

  // 4. Tamper test: modify plan or max_nodes without re-signing
  const tampered = JSON.parse(JSON.stringify(signed));
  tampered.bundle.max_nodes = 9999; // unauthorized upgrade attempt
  const tamperedCheck = verifyPolicyBundle(tampered, publicKey);
  assert.equal(tamperedCheck.valid, false, "Tampered bundle must be rejected");
  console.log(`✅ 3. Tamper Detection Passed: ${tamperedCheck.reason}`);

  console.log("================================================================");
  console.log(" 🎉 Tier 1 Module 1.3 Licensing & Policy Tests PASSED");
  console.log("================================================================");
}

runLicensingTests().catch((err) => {
  console.error("❌ Licensing Test Failed:", err);
  process.exit(1);
});
