import { strict as assert } from "node:assert";
import { hashPassword, verifyPassword } from "./password.js";

async function runAuthTests() {
  console.log("================================================================");
  console.log(" 🔐 AIndigo Tier 1 — Production Auth (Argon2id) Security Test");
  console.log("================================================================");

  const testPassword = "EnterpriseSecurePassword!2026";
  const wrongPassword = "WrongPassword999!";

  // 1. Hash password
  const hashed = await hashPassword(testPassword);
  assert.notEqual(hashed, testPassword, "Hash must not equal plaintext");
  assert.equal(hashed.includes("argon2id"), true, "Must use argon2id algorithm identifier");
  console.log("✅ 1. Argon2id Hash Generation Verified.");

  // 2. Verify correct password
  const isValid = await verifyPassword(hashed, testPassword);
  assert.equal(isValid, true, "Correct password must verify successfully");
  console.log("✅ 2. Correct Password Verification Passed.");

  // 3. Reject incorrect password
  const isInvalid = await verifyPassword(hashed, wrongPassword);
  assert.equal(isInvalid, false, "Incorrect password must be rejected");
  console.log("✅ 3. Incorrect Password Rejection Passed.");

  // 4. Verify unique salts (hashing the same password twice yields different hashes)
  const hashedSecond = await hashPassword(testPassword);
  assert.notEqual(hashed, hashedSecond, "Identical passwords must produce unique salts/hashes");
  console.log("✅ 4. Unique Salt Generation Verified.");

  console.log("================================================================");
  console.log(" 🎉 Tier 1 Module 1.2 Auth Security Tests PASSED");
  console.log("================================================================");
}

runAuthTests().catch((err) => {
  console.error("❌ Auth Test Failed:", err);
  process.exit(1);
});
