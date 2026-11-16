import { strict as assert } from "node:assert";
import { DatabaseSync } from "node:sqlite";

import {
  initializeSessionStore,
  createUserSession,
  resolveUserSession,
  revokeUserSession,
} from "./session-store.js";

import { hashSessionToken } from "./session.js";

function runSessionStoreTests() {
  console.log("AIndigo - Persistent Session Store Tests");

  const db = new DatabaseSync(":memory:");

  try {
    db.exec(`
      PRAGMA foreign_keys = ON;

      CREATE TABLE tenants (
        password_hash TEXT,
        cluster_sync_token TEXT,
        tenant_id TEXT PRIMARY KEY,
        org_name TEXT,
        email TEXT,
        subscription_tier TEXT,
        monthly_request_limit INTEGER
      );

      INSERT INTO tenants (
  tenant_id,
  org_name,
  email,
  subscription_tier,
  monthly_request_limit,
  password_hash,
  cluster_sync_token
) VALUES (
  'tenant_test_1',
  'Test Company',
  'test@example.com',
  'COMMUNITY',
  10000,
  'test-password-hash',
  'test-sync-secret'
);
    `);

    initializeSessionStore(db);
    initializeSessionStore(db);
    console.log("PASS 1: Repeatable schema initialization.");

    const now = 1793664000000;
    const created = createUserSession(db, "tenant_test_1", now);

    assert.match(created.sessionId, /^[0-9a-f-]{36}$/i);
    assert.match(created.token, /^aindigo_sess_[a-f0-9]{64}$/);
    assert.equal(created.expiresAt - now, 86400000);
    console.log("PASS 2: Tenant-bound session created.");

    const stored = db.prepare(`
      SELECT token_hash FROM user_sessions WHERE session_id = ?
    `).get(created.sessionId) as { token_hash: string };

    assert.equal(stored.token_hash, hashSessionToken(created.token));
    assert.notEqual(stored.token_hash, created.token);
    console.log("PASS 3: Only token fingerprint stored.");

    const tenant = resolveUserSession(db, created.token, now + 1000);

    assert.ok(tenant);
    assert.equal(tenant.tenant_id, "tenant_test_1");
    assert.equal(tenant.email, "test@example.com");
    assert.equal(Object.hasOwn(tenant, "token_hash"), false);
assert.equal(Object.hasOwn(tenant, "password_hash"), false);
assert.equal(Object.hasOwn(tenant, "cluster_sync_token"), false);
    console.log("PASS 4: Valid session resolves safely.");

    assert.equal(
      resolveUserSession(
        db,
        "aindigo_sess_" + "0".repeat(64),
        now + 1000,
      ),
      null,
    );
    console.log("PASS 5: Incorrect token rejected.");

    assert.equal(
      resolveUserSession(db, created.token, created.expiresAt),
      null,
    );
    console.log("PASS 6: Expired session rejected.");

    assert.equal(revokeUserSession(db, created.token, now + 2000), true);
    assert.equal(resolveUserSession(db, created.token, now + 3000), null);
    console.log("PASS 7: Revoked session rejected.");

    assert.equal(revokeUserSession(db, created.token, now + 4000), false);
    console.log("PASS 8: Repeated revocation handled.");

    assert.throws(
      () => createUserSession(db, "unknown_tenant", now),
      /unknown tenant/i,
    );
    console.log("PASS 9: Unknown tenant rejected.");

    console.log("ALL SESSION STORE TESTS PASSED");
  } finally {
    db.close();
  }
}

try {
  runSessionStoreTests();
} catch (error) {
  console.error("SESSION STORE TEST FAILURE:", error);
  process.exitCode = 1;
}
