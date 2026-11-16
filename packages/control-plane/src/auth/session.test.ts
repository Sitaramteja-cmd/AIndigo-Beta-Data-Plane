import { strict as assert } from "node:assert";

import {
  SESSION_TTL_MS,
  createSessionToken,
  hashSessionToken,
  verifySessionToken,
  getSessionExpiry,
} from "./session.js";

function runSessionTests() {
  console.log("==================================================");
  console.log(" AIndigo — Browser Session Security Tests");
  console.log("==================================================");

  // 1. Token generation
  const token = createSessionToken();

  assert.match(
    token,
    /^aindigo_sess_[a-f0-9]{64}$/,
    "Session token must have the expected secure format",
  );

  console.log("PASS 1: Cryptographically random session token generated.");

  // 2. Uniqueness
  const secondToken = createSessionToken();

  assert.notEqual(
    token,
    secondToken,
    "Independent sessions must receive different tokens",
  );

  console.log("PASS 2: Session tokens are unique.");

  // 3. Token hashing
  const tokenHash = hashSessionToken(token);

  assert.match(
    tokenHash,
    /^[a-f0-9]{64}$/,
    "Stored token fingerprint must be a SHA-256 hex digest",
  );

  assert.notEqual(
    tokenHash,
    token,
    "Raw session token must not be stored as its fingerprint",
  );

  console.log("PASS 3: Session token fingerprint generated.");

  // 4. Correct token verification
  assert.equal(
    verifySessionToken(token, tokenHash),
    true,
    "Correct token must verify",
  );

  console.log("PASS 4: Correct session token accepted.");

  // 5. Incorrect token rejection
  assert.equal(
    verifySessionToken(secondToken, tokenHash),
    false,
    "Different token must be rejected",
  );

  console.log("PASS 5: Incorrect session token rejected.");

  // 6. Malformed fingerprint rejection
  assert.equal(
    verifySessionToken(token, "invalid"),
    false,
    "Malformed fingerprint must be rejected",
  );

  console.log("PASS 6: Malformed fingerprint rejected.");

  // 7. Session expiry
  const createdAt = new Date("2026-11-03T00:00:00.000Z");
  const expiresAt = getSessionExpiry(createdAt);

  assert.equal(
    expiresAt.getTime() - createdAt.getTime(),
    SESSION_TTL_MS,
    "Session must expire after the configured lifetime",
  );

  assert.equal(
    SESSION_TTL_MS,
    24 * 60 * 60 * 1000,
    "Initial session lifetime must be 24 hours",
  );

  console.log("PASS 7: Session expiry is exactly 24 hours.");

  // 8. Invalid creation date
  assert.throws(
    () => getSessionExpiry(new Date("invalid")),
    /valid session creation date/i,
  );

  console.log("PASS 8: Invalid session creation date rejected.");

  console.log("==================================================");
  console.log(" ALL SESSION SECURITY TESTS PASSED");
  console.log("==================================================");
}

try {
  runSessionTests();
} catch (error) {
  console.error("SESSION TEST FAILURE:", error);
  process.exitCode = 1;
}
