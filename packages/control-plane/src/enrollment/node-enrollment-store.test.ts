import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { DatabaseSync } from "node:sqlite";

import {
  initializeNodeEnrollmentStore,
  createEnrollmentCode,
  revokeEnrollmentCode,
  createEnrollmentChallenge,
  completeNodeEnrollment,
  resolveEnrollmentCodeTenant,
  resolveEnrollmentChallengeTenant,
  getRegisteredNode,
  revokeRegisteredNode,
} from "./node-enrollment-store.js";

import {
  canonicalizePolicyPayload,
} from "@aindigo/shared";

function createDatabase(): DatabaseSync {
  const db = new DatabaseSync(":memory:");

  db.exec(`
    PRAGMA foreign_keys = ON;

    CREATE TABLE tenants (
      tenant_id TEXT PRIMARY KEY,
      org_name TEXT,
      email TEXT UNIQUE
    );

    CREATE TABLE synced_receipts (
      receipt_id TEXT PRIMARY KEY,
      tenant_id TEXT
    );

    INSERT INTO tenants (tenant_id, org_name, email)
    VALUES
      ('tenant_alpha', 'Alpha Corp', 'alpha@example.com'),
      ('tenant_beta', 'Beta Corp', 'beta@example.com');

    INSERT INTO synced_receipts (receipt_id, tenant_id)
    VALUES ('receipt_existing', 'tenant_alpha');
  `);

  return db;
}

function insertEnrollmentCode(
  db: DatabaseSync,
  codeHash: string,
  tenantId: string
): void {
  db.prepare(`
    INSERT INTO node_enrollment_codes (
      code_hash,
      tenant_id,
      label,
      created_at,
      expires_at
    ) VALUES (?, ?, ?, ?, ?)
  `).run(codeHash, tenantId, "Test node", 1000, 2000);
}

function insertChallenge(
  db: DatabaseSync,
  values: {
    challengeId: string;
    codeHash: string;
    tenantId: string;
    nodeId: string;
  }
): void {
  db.prepare(`
    INSERT INTO node_enrollment_challenges (
      challenge_id,
      code_hash,
      tenant_id,
      node_id,
      public_key_pem,
      public_key_fingerprint,
      client_nonce,
      server_nonce,
      issued_at,
      expires_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    values.challengeId,
    values.codeHash,
    values.tenantId,
    values.nodeId,
    "test-public-key",
    "a".repeat(16),
    "b".repeat(64),
    "c".repeat(64),
    1000,
    1500
  );
}

test("initializes the schema repeatedly without errors", () => {
  const db = createDatabase();

  try {
    initializeNodeEnrollmentStore(db);
    initializeNodeEnrollmentStore(db);

    const tables = db.prepare(`
      SELECT name
      FROM sqlite_master
      WHERE type = 'table'
      ORDER BY name
    `).all() as Array<{ name: string }>;

    const names = tables.map((table) => table.name);

    assert.ok(names.includes("node_enrollment_codes"));
    assert.ok(names.includes("node_enrollment_challenges"));
    assert.ok(names.includes("registered_nodes"));
  } finally {
    db.close();
  }
});

test("creates all seven enrollment indexes", () => {
  const db = createDatabase();

  try {
    initializeNodeEnrollmentStore(db);

    const indexes = db.prepare(`
      SELECT name
      FROM sqlite_master
      WHERE type = 'index'
        AND name LIKE 'idx_%'
      ORDER BY name
    `).all() as Array<{ name: string }>;

    assert.equal(indexes.length, 7);
  } finally {
    db.close();
  }
});

test("preserves existing tenant and telemetry data", () => {
  const db = createDatabase();

  try {
    initializeNodeEnrollmentStore(db);

    const tenantCount = db.prepare(`
      SELECT COUNT(*) AS count FROM tenants
    `).get() as { count: number };

    const receipt = db.prepare(`
      SELECT receipt_id, tenant_id
      FROM synced_receipts
      WHERE receipt_id = ?
    `).get("receipt_existing") as {
      receipt_id: string;
      tenant_id: string;
    };

    assert.equal(tenantCount.count, 2);
    assert.equal(receipt.receipt_id, "receipt_existing");
    assert.equal(receipt.tenant_id, "tenant_alpha");
  } finally {
    db.close();
  }
});

test("rejects enrollment codes for unknown tenants", () => {
  const db = createDatabase();

  try {
    initializeNodeEnrollmentStore(db);

    assert.throws(
      () => insertEnrollmentCode(db, "1".repeat(64), "tenant_missing"),
      /FOREIGN KEY constraint failed/
    );
  } finally {
    db.close();
  }
});

test("rejects a challenge bound to another tenant's enrollment code", () => {
  const db = createDatabase();

  try {
    initializeNodeEnrollmentStore(db);
    insertEnrollmentCode(db, "2".repeat(64), "tenant_alpha");

    assert.throws(
      () => insertChallenge(db, {
        challengeId: "challenge-cross-tenant",
        codeHash: "2".repeat(64),
        tenantId: "tenant_beta",
        nodeId: "node_aaaaaaaaaaaaaaaa"
      }),
      /FOREIGN KEY constraint failed/
    );
  } finally {
    db.close();
  }
});

test("allows a challenge bound to the correct tenant and code", () => {
  const db = createDatabase();

  try {
    initializeNodeEnrollmentStore(db);
    insertEnrollmentCode(db, "3".repeat(64), "tenant_alpha");

    insertChallenge(db, {
      challengeId: "challenge-valid",
      codeHash: "3".repeat(64),
      tenantId: "tenant_alpha",
      nodeId: "node_aaaaaaaaaaaaaaaa"
    });

    const result = db.prepare(`
      SELECT tenant_id
      FROM node_enrollment_challenges
      WHERE challenge_id = ?
    `).get("challenge-valid") as { tenant_id: string };

    assert.equal(result.tenant_id, "tenant_alpha");
  } finally {
    db.close();
  }
});

test("rejects duplicate enrollment code hashes", () => {
  const db = createDatabase();

  try {
    initializeNodeEnrollmentStore(db);
    insertEnrollmentCode(db, "4".repeat(64), "tenant_alpha");

    assert.throws(
      () => insertEnrollmentCode(db, "4".repeat(64), "tenant_alpha"),
      /UNIQUE constraint failed/
    );
  } finally {
    db.close();
  }
});

test("rejects duplicate node IDs across tenants", () => {
  const db = createDatabase();

  try {
    initializeNodeEnrollmentStore(db);

    const insertNode = db.prepare(`
      INSERT INTO registered_nodes (
        node_id,
        tenant_id,
        public_key_pem,
        public_key_fingerprint,
        label,
        enrolled_at
      ) VALUES (?, ?, ?, ?, ?, ?)
    `);

    insertNode.run(
      "node_aaaaaaaaaaaaaaaa",
      "tenant_alpha",
      "public-key-alpha",
      "a".repeat(16),
      "Alpha node",
      1000
    );

    assert.throws(
      () => insertNode.run(
        "node_aaaaaaaaaaaaaaaa",
        "tenant_beta",
        "public-key-beta",
        "b".repeat(16),
        "Beta node",
        1000
      ),
      /UNIQUE constraint failed/
    );
  } finally {
    db.close();
  }
});

test("rejects invalid node status values", () => {
  const db = createDatabase();

  try {
    initializeNodeEnrollmentStore(db);

    assert.throws(
      () => db.prepare(`
        INSERT INTO registered_nodes (
          node_id,
          tenant_id,
          public_key_pem,
          public_key_fingerprint,
          label,
          status,
          enrolled_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(
        "node_bbbbbbbbbbbbbbbb",
        "tenant_alpha",
        "public-key",
        "b".repeat(16),
        "Invalid status node",
        "PENDING",
        1000
      ),
      /CHECK constraint failed/
    );
  } finally {
    db.close();
  }
});

test("rejects malformed public-key fingerprints", () => {
  const db = createDatabase();

  try {
    initializeNodeEnrollmentStore(db);

    assert.throws(
      () => db.prepare(`
        INSERT INTO registered_nodes (
          node_id,
          tenant_id,
          public_key_pem,
          public_key_fingerprint,
          label,
          enrolled_at
        ) VALUES (?, ?, ?, ?, ?, ?)
      `).run(
        "node_cccccccccccccccc",
        "tenant_alpha",
        "public-key",
        "invalid",
        "Malformed fingerprint",
        1000
      ),
      /CHECK constraint failed/
    );
  } finally {
    db.close();
  }
});


function createTestNodeIdentity(): {
  nodeId: string;
  publicKeyPem: string;
} {
  const { publicKey } = crypto.generateKeyPairSync("ed25519");

  const publicKeyPem = publicKey.export({
    type: "spki",
    format: "pem",
  }).toString();

  const fingerprint = crypto
    .createHash("sha256")
    .update(publicKeyPem.trim(), "utf8")
    .digest("hex")
    .slice(0, 16);

  return {
    nodeId: `node_${fingerprint}`,
    publicKeyPem,
  };
}

function countRows(db: DatabaseSync, table: string): number {
  const result = db.prepare(
    `SELECT COUNT(*) AS count FROM ${table}`
  ).get() as { count: number };

  return result.count;
}

test("creates a 43-character enrollment code and stores only its hash", () => {
  const db = createDatabase();

  try {
    initializeNodeEnrollmentStore(db);

    const result = createEnrollmentCode(
      db,
      "tenant_alpha",
      { label: "Production Node" },
      1000
    );

    assert.equal(result.enrollmentCode.length, 43);
    assert.match(result.enrollmentCode, /^[A-Za-z0-9_-]+$/);
    assert.equal(
      result.expiresAt,
      new Date(1000 + 15 * 60 * 1000).toISOString()
    );

    const expectedHash = crypto
      .createHash("sha256")
      .update(result.enrollmentCode, "utf8")
      .digest("hex");

    const stored = db.prepare(`
      SELECT code_hash, label
      FROM node_enrollment_codes
      WHERE tenant_id = ?
    `).get("tenant_alpha") as {
      code_hash: string;
      label: string;
    };

    assert.equal(stored.code_hash, expectedHash);
    assert.notEqual(stored.code_hash, result.enrollmentCode);
    assert.equal(stored.label, "Production Node");
  } finally {
    db.close();
  }
});

test("revokes an enrollment code only for its owning tenant", () => {
  const db = createDatabase();

  try {
    initializeNodeEnrollmentStore(db);

    const result = createEnrollmentCode(
      db,
      "tenant_alpha",
      { label: "Revocation Test" },
      1000
    );

    assert.equal(
      revokeEnrollmentCode(db, "tenant_beta", result.enrollmentCode, 2000),
      false
    );

    assert.equal(
      revokeEnrollmentCode(db, "tenant_alpha", result.enrollmentCode, 2000),
      true
    );

    assert.equal(
      revokeEnrollmentCode(db, "tenant_alpha", result.enrollmentCode, 3000),
      false
    );
  } finally {
    db.close();
  }
});

test("rejects challenge creation using an expired enrollment code", () => {
  const db = createDatabase();

  try {
    initializeNodeEnrollmentStore(db);

    const code = createEnrollmentCode(
      db,
      "tenant_alpha",
      { label: "Expired Code Test" },
      1000
    );

    const identity = createTestNodeIdentity();

    assert.throws(
      () => createEnrollmentChallenge(
        db,
        "tenant_alpha",
        {
          enrollmentCode: code.enrollmentCode,
          nodeId: identity.nodeId,
          nodePublicKeyPem: identity.publicKeyPem,
          clientNonce: "a".repeat(64),
        },
        1000 + 15 * 60 * 1000
      ),
      /invalid or expired/
    );

    assert.equal(countRows(db, "node_enrollment_challenges"), 0);
  } finally {
    db.close();
  }
});

test("rejects challenge creation using a revoked enrollment code", () => {
  const db = createDatabase();

  try {
    initializeNodeEnrollmentStore(db);

    const code = createEnrollmentCode(
      db,
      "tenant_alpha",
      { label: "Revoked Code Test" },
      1000
    );

    const identity = createTestNodeIdentity();

    assert.equal(
      revokeEnrollmentCode(db, "tenant_alpha", code.enrollmentCode, 1500),
      true
    );

    assert.throws(
      () => createEnrollmentChallenge(
        db,
        "tenant_alpha",
        {
          enrollmentCode: code.enrollmentCode,
          nodeId: identity.nodeId,
          nodePublicKeyPem: identity.publicKeyPem,
          clientNonce: "b".repeat(64),
        },
        2000
      ),
      /invalid or expired/
    );

    assert.equal(countRows(db, "node_enrollment_challenges"), 0);
  } finally {
    db.close();
  }
});

test("creates a challenge bound to the correct node identity and tenant", () => {
  const db = createDatabase();

  try {
    initializeNodeEnrollmentStore(db);

    const code = createEnrollmentCode(
      db,
      "tenant_alpha",
      { label: "Challenge Test" },
      1000
    );

    const identity = createTestNodeIdentity();
    const nowMs = 2000;

    const challenge = createEnrollmentChallenge(
      db,
      "tenant_alpha",
      {
        enrollmentCode: code.enrollmentCode,
        nodeId: identity.nodeId,
        nodePublicKeyPem: identity.publicKeyPem,
        clientNonce: "c".repeat(64),
      },
      nowMs
    );

    const fingerprint = crypto
      .createHash("sha256")
      .update(identity.publicKeyPem.trim(), "utf8")
      .digest("hex")
      .slice(0, 16);

    assert.equal(challenge.nodeId, identity.nodeId);
    assert.equal(challenge.nodePublicKeyFingerprint, fingerprint);
    assert.equal(challenge.clientNonce, "c".repeat(64));
    assert.equal(
      challenge.issuedAt,
      new Date(nowMs).toISOString()
    );
    assert.equal(
      challenge.expiresAt,
      new Date(nowMs + 2 * 60 * 1000).toISOString()
    );

    const stored = db.prepare(`
      SELECT tenant_id, node_id, public_key_fingerprint
      FROM node_enrollment_challenges
      WHERE challenge_id = ?
    `).get(challenge.challengeId) as {
      tenant_id: string;
      node_id: string;
      public_key_fingerprint: string;
    };

    assert.equal(stored.tenant_id, "tenant_alpha");
    assert.equal(stored.node_id, identity.nodeId);
    assert.equal(stored.public_key_fingerprint, fingerprint);
  } finally {
    db.close();
  }
});

test("rejects a node ID that does not match its public key", () => {
  const db = createDatabase();

  try {
    initializeNodeEnrollmentStore(db);

    const code = createEnrollmentCode(
      db,
      "tenant_alpha",
      { label: "Identity Mismatch Test" },
      1000
    );

    const identity = createTestNodeIdentity();

    assert.throws(
      () => createEnrollmentChallenge(
        db,
        "tenant_alpha",
        {
          enrollmentCode: code.enrollmentCode,
          nodeId: "node_aaaaaaaaaaaaaaaa",
          nodePublicKeyPem: identity.publicKeyPem,
          clientNonce: "d".repeat(64),
        },
        2000
      ),
      /fingerprint mismatch/
    );

    assert.equal(countRows(db, "node_enrollment_challenges"), 0);
  } finally {
    db.close();
  }
});

test("rejects challenge creation for an already registered node", () => {
  const db = createDatabase();

  try {
    initializeNodeEnrollmentStore(db);

    const code = createEnrollmentCode(
      db,
      "tenant_alpha",
      { label: "Already Registered Test" },
      1000
    );

    const identity = createTestNodeIdentity();

    db.prepare(`
      INSERT INTO registered_nodes (
        node_id,
        tenant_id,
        public_key_pem,
        public_key_fingerprint,
        label,
        enrolled_at
      ) VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      identity.nodeId,
      "tenant_alpha",
      identity.publicKeyPem,
      identity.nodeId.slice(5),
      "Existing Node",
      1500
    );

    assert.throws(
      () => createEnrollmentChallenge(
        db,
        "tenant_alpha",
        {
          enrollmentCode: code.enrollmentCode,
          nodeId: identity.nodeId,
          nodePublicKeyPem: identity.publicKeyPem,
          clientNonce: "e".repeat(64),
        },
        2000
      ),
      /already registered/
    );

    assert.equal(countRows(db, "node_enrollment_challenges"), 0);
  } finally {
    db.close();
  }
});

test("does not create a challenge when an enrollment code belongs to another tenant", () => {
  const db = createDatabase();

  try {
    initializeNodeEnrollmentStore(db);

    const code = createEnrollmentCode(
      db,
      "tenant_alpha",
      { label: "Tenant Isolation Test" },
      1000
    );

    const identity = createTestNodeIdentity();

    assert.throws(
      () => createEnrollmentChallenge(
        db,
        "tenant_beta",
        {
          enrollmentCode: code.enrollmentCode,
          nodeId: identity.nodeId,
          nodePublicKeyPem: identity.publicKeyPem,
          clientNonce: "f".repeat(64),
        },
        2000
      ),
      /invalid or expired/
    );

    assert.equal(countRows(db, "node_enrollment_challenges"), 0);
  } finally {
    db.close();
  }
});


function createSignedEnrollmentScenario(
  db: DatabaseSync,
  nowMs: number = 2000
): {
  nodeId: string;
  privateKeyPem: string;
  challengeId: string;
  proof: {
    challengeId: string;
    nodeId: string;
    signature: string;
  };
  signingKey: {
    keyId: string;
    privateKeyPem: string;
    publicKeyPem: string;
  };
  enrollmentCode: string;
} {
  const { publicKey, privateKey } =
    crypto.generateKeyPairSync("ed25519");

  const publicKeyPem = publicKey.export({
    type: "spki",
    format: "pem",
  }).toString();

  const privateKeyPem = privateKey.export({
    type: "pkcs8",
    format: "pem",
  }).toString();

  // Generate a separate Ed25519 keypair for Control Plane lease signing.
  const cpKeys = crypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
    },
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
  });

  // Test-only signing identity used to sign node enrollment leases.
  const signingKey = {
    keyId: "cp-enrollment-test-2026",
    privateKeyPem: cpKeys.privateKey,
    publicKeyPem: cpKeys.publicKey,
  };

  const fingerprint = crypto
    .createHash("sha256")
    .update(publicKeyPem.trim(), "utf8")
    .digest("hex")
    .slice(0, 16);

  const nodeId = `node_${fingerprint}`;

  const code = createEnrollmentCode(
    db,
    "tenant_alpha",
    { label: "Atomic Registration Test" },
    1000
  );

  const challenge = createEnrollmentChallenge(
    db,
    "tenant_alpha",
    {
      enrollmentCode: code.enrollmentCode,
      nodeId,
      nodePublicKeyPem: publicKeyPem,
      clientNonce: "a".repeat(64),
    },
    nowMs
  );

  const canonicalJson = canonicalizePolicyPayload(challenge);

  const signature = crypto.sign(
    null,
    Buffer.from(canonicalJson, "utf8"),
    privateKey
  ).toString("base64");

  return {
    nodeId,
    privateKeyPem,
    signingKey,
    challengeId: challenge.challengeId,
    enrollmentCode: code.enrollmentCode,
    proof: {
      challengeId: challenge.challengeId,
      nodeId,
      signature,
    },
  };
}

test("completes enrollment using a valid Ed25519 proof", () => {
  const db = createDatabase();

  try {
    initializeNodeEnrollmentStore(db);

    const scenario = createSignedEnrollmentScenario(db);

    const result = completeNodeEnrollment(
  db,
  "tenant_alpha",
  scenario.proof,
  scenario.signingKey,
  3000
);

    assert.equal(result.nodeId, scenario.nodeId);
    assert.equal(result.tenantId, "tenant_alpha");
    assert.equal(result.label, "Atomic Registration Test");

        // Verify the signed lease returned by enrollment.
    assert.equal(result.signedLease.payload.tenantId, "tenant_alpha");
    assert.equal(result.signedLease.payload.nodeId, scenario.nodeId);
    assert.equal(
      result.signedLease.payload.keyId,
      scenario.signingKey.keyId
    );
    assert.equal(
      result.signedLease.payload.offlineMaxSeconds,
      172800
    );

    // Verify the lease signature using the Control Plane public key.
    const leaseSignatureValid = crypto.verify(
      null,
      Buffer.from(
        canonicalizePolicyPayload(result.signedLease.payload),
        "utf8"
      ),
      crypto.createPublicKey(scenario.signingKey.publicKeyPem),
      Buffer.from(result.signedLease.signature, "base64")
    );

    assert.equal(leaseSignatureValid, true);

        const node = db.prepare(`
      SELECT
        node_id,
        tenant_id,
        status,
        lease_id,
        lease_expires_at
      FROM registered_nodes
      WHERE node_id = ?
    `).get(scenario.nodeId) as {
      node_id: string;
      tenant_id: string;
      status: string;
      lease_id: string;
      lease_expires_at: number;
    };

    assert.equal(node.node_id, scenario.nodeId);
    assert.equal(node.tenant_id, "tenant_alpha");
    assert.equal(node.status, "ACTIVE");

  // Verify the issued lease was persisted against the registered node.
    assert.equal(
      node.lease_id,
      result.signedLease.payload.leaseId
    );

    assert.equal(
      node.lease_expires_at,
      Date.parse(result.signedLease.payload.expiresAt)
    );

    const code = db.prepare(`
      SELECT consumed_at
      FROM node_enrollment_codes
      WHERE tenant_id = ?
    `).get("tenant_alpha") as { consumed_at: number };

   const challenge = db.prepare(`
      SELECT consumed_at
      FROM node_enrollment_challenges
      WHERE challenge_id = ?
    `).get(scenario.challengeId) as { consumed_at: number };

    assert.equal(code.consumed_at, 3000);
    assert.equal(challenge.consumed_at, 3000);
  } finally {
    db.close();
  }
});

test("rejects replay of an already completed enrollment proof", () => {
  const db = createDatabase();

  try {
    initializeNodeEnrollmentStore(db);

    const scenario = createSignedEnrollmentScenario(db);

    completeNodeEnrollment(
  db,
  "tenant_alpha",
  scenario.proof,
  scenario.signingKey,
  3000
);

  assert.throws(
    () => completeNodeEnrollment(
      db,
      "tenant_alpha",
      scenario.proof,
      scenario.signingKey,
      4000
    ),
    /invalid, expired, or already consumed/
  );

    assert.equal(countRows(db, "registered_nodes"), 1);
  } finally {
    db.close();
  }
});

test("rejects an invalid Ed25519 proof without consuming enrollment state", () => {
  const db = createDatabase();

  try {
    initializeNodeEnrollmentStore(db);

    const scenario = createSignedEnrollmentScenario(db);

    const wrongKeyPair = crypto.generateKeyPairSync("ed25519");

    const challengeRow = db.prepare(`
      SELECT
        challenge_id,
        node_id,
        public_key_fingerprint,
        client_nonce,
        server_nonce,
        issued_at,
        expires_at
      FROM node_enrollment_challenges
      WHERE challenge_id = ?
    `).get(scenario.challengeId) as {
      challenge_id: string;
      node_id: string;
      public_key_fingerprint: string;
      client_nonce: string;
      server_nonce: string;
      issued_at: number;
      expires_at: number;
    };

    const challenge = {
      schemaVersion: "1.0" as const,
      challengeId: challengeRow.challenge_id,
      nodeId: challengeRow.node_id,
      nodePublicKeyFingerprint: challengeRow.public_key_fingerprint,
      clientNonce: challengeRow.client_nonce,
      serverNonce: challengeRow.server_nonce,
      issuedAt: new Date(challengeRow.issued_at).toISOString(),
      expiresAt: new Date(challengeRow.expires_at).toISOString(),
    };

    const wrongSignature = crypto.sign(
      null,
      Buffer.from(canonicalizePolicyPayload(challenge), "utf8"),
      wrongKeyPair.privateKey
    ).toString("base64");

    assert.throws(
      () => completeNodeEnrollment(
  db,
  "tenant_alpha",
  {
    ...scenario.proof,
    signature: wrongSignature,
  },
  scenario.signingKey,
  3000
),
      /proof-of-possession verification failed/
    );

    assert.equal(countRows(db, "registered_nodes"), 0);

    const code = db.prepare(`
      SELECT consumed_at
      FROM node_enrollment_codes
      WHERE tenant_id = ?
    `).get("tenant_alpha") as { consumed_at: number | null };

    const storedChallenge = db.prepare(`
      SELECT consumed_at
      FROM node_enrollment_challenges
      WHERE challenge_id = ?
    `).get(scenario.challengeId) as { consumed_at: number | null };

    assert.equal(code.consumed_at, null);
    assert.equal(storedChallenge.consumed_at, null);
  } finally {
    db.close();
  }
});


test("rejects proof submission from a different tenant", () => {
  const db = createDatabase();

  try {
    initializeNodeEnrollmentStore(db);

    const scenario = createSignedEnrollmentScenario(db);

    assert.throws(
      () => completeNodeEnrollment(
        db,
        "tenant_beta",
        scenario.proof,
        scenario.signingKey,
        3000
      ),
      /invalid, expired, or already consumed/
    );

    assert.equal(countRows(db, "registered_nodes"), 0);
  } finally {
    db.close();
  }
});


test("rejects proof submission after challenge expiry", () => {
  const db = createDatabase();

  try {
    initializeNodeEnrollmentStore(db);

    const scenario = createSignedEnrollmentScenario(db, 2000);

    assert.throws(
      () => completeNodeEnrollment(
  db,
  "tenant_alpha",
  scenario.proof,
  scenario.signingKey,
  122000
),
      /invalid, expired, or already consumed/
    );

    assert.equal(countRows(db, "registered_nodes"), 0);
  } finally {
    db.close();
  }
});

test("rolls back code and challenge consumption if node insertion fails", () => {
  const db = createDatabase();

  try {
    initializeNodeEnrollmentStore(db);

    const scenario = createSignedEnrollmentScenario(db);

    const fingerprint = scenario.nodeId.slice(5);

    db.prepare(`
      INSERT INTO registered_nodes (
        node_id,
        tenant_id,
        public_key_pem,
        public_key_fingerprint,
        label,
        enrolled_at
      ) VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      scenario.nodeId,
      "tenant_alpha",
      "existing-public-key",
      fingerprint,
      "Existing Registration",
      1500
    );


    assert.throws(
      () => completeNodeEnrollment(
        db,
        "tenant_alpha",
        scenario.proof,
        scenario.signingKey,
        3000
      ),
      /UNIQUE constraint failed/
    );

    const code = db.prepare(`
      SELECT consumed_at
      FROM node_enrollment_codes
      WHERE tenant_id = ?
    `).get("tenant_alpha") as { consumed_at: number | null };

    const challenge = db.prepare(`
      SELECT consumed_at
      FROM node_enrollment_challenges
      WHERE challenge_id = ?
    `).get(scenario.challengeId) as { consumed_at: number | null };

    assert.equal(code.consumed_at, null);
    assert.equal(challenge.consumed_at, null);
    assert.equal(countRows(db, "registered_nodes"), 1);
  } finally {
    db.close();
  }
});

test("rejects invalid Control Plane signing keys without consuming enrollment state", () => {
  const db = createDatabase();

  try {
    initializeNodeEnrollmentStore(db);

    const scenario = createSignedEnrollmentScenario(db);

    // Generate a different, valid Ed25519 keypair.
    const wrongCpKeyPair = crypto.generateKeyPairSync("ed25519");

    const wrongPublicKeyPem = wrongCpKeyPair.publicKey.export({
      type: "spki",
      format: "pem",
    }).toString();

    // Keep the original private key but configure the wrong public key.
    const invalidSigningKey = {
      ...scenario.signingKey,
      publicKeyPem: wrongPublicKeyPem,
    };

    assert.throws(
      () => completeNodeEnrollment(
        db,
        "tenant_alpha",
        scenario.proof,
        invalidSigningKey,
        3000
      ),
      /Signing keypair mismatch/
    );

    // No node should be registered.
    assert.equal(countRows(db, "registered_nodes"), 0);

    // Enrollment code must remain unconsumed.
    const code = db.prepare(`
      SELECT consumed_at
      FROM node_enrollment_codes
      WHERE tenant_id = ?
    `).get("tenant_alpha") as { consumed_at: number | null };

    // Challenge must remain unconsumed.
    const challenge = db.prepare(`
      SELECT consumed_at
      FROM node_enrollment_challenges
      WHERE challenge_id = ?
    `).get(scenario.challengeId) as { consumed_at: number | null };

    assert.equal(code.consumed_at, null);
    assert.equal(challenge.consumed_at, null);
  } finally {
    db.close();
  }
});


test("resolves the tenant from an active enrollment code", () => {
  const db = createDatabase();

  try {
    initializeNodeEnrollmentStore(db);

    const result = createEnrollmentCode(
      db,
      "tenant_alpha",
      { label: "Production node" },
      1000
    );

    assert.equal(
      resolveEnrollmentCodeTenant(db, result.enrollmentCode, 1001),
      "tenant_alpha"
    );
  } finally {
    db.close();
  }
});

test("does not resolve revoked, consumed, or expired enrollment codes", () => {
  const db = createDatabase();

  try {
    initializeNodeEnrollmentStore(db);

    const revoked = createEnrollmentCode(
      db, "tenant_alpha", { label: "Revoked node" }, 1000
    );

    assert.equal(
      revokeEnrollmentCode(db, "tenant_alpha", revoked.enrollmentCode, 1001),
      true
    );

    assert.equal(
      resolveEnrollmentCodeTenant(db, revoked.enrollmentCode, 1002),
      null
    );

    const consumed = createEnrollmentCode(
      db, "tenant_alpha", { label: "Consumed node" }, 2000
    );

    db.prepare(`
      UPDATE node_enrollment_codes
      SET consumed_at = ?
      WHERE tenant_id = ?
    `).run(2001, "tenant_alpha");

    assert.equal(
      resolveEnrollmentCodeTenant(db, consumed.enrollmentCode, 2002),
      null
    );

    const expired = createEnrollmentCode(
      db, "tenant_beta", { label: "Expired node" }, 3000
    );

    assert.equal(
      resolveEnrollmentCodeTenant(
        db,
        expired.enrollmentCode,
        3000 + 15 * 60 * 1000
      ),
      null
    );
  } finally {
    db.close();
  }
});

test("resolves the tenant from an active enrollment challenge", () => {
  const db = createDatabase();

  try {
    initializeNodeEnrollmentStore(db);

    const enrollment = createEnrollmentCode(
      db,
      "tenant_alpha",
      { label: "Production node" },
      1000
    );

    const keys = crypto.generateKeyPairSync("ed25519", {
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });

    const fingerprint = crypto
      .createHash("sha256")
      .update(keys.publicKey.trim(), "utf8")
      .digest("hex")
      .slice(0, 16);

    const challenge = createEnrollmentChallenge(
      db,
      "tenant_alpha",
      {
        enrollmentCode: enrollment.enrollmentCode,
        nodeId: `node_${fingerprint}`,
        nodePublicKeyPem: keys.publicKey,
        clientNonce: "a".repeat(64),
      },
      1001
    );

    assert.equal(
      resolveEnrollmentChallengeTenant(
        db,
        challenge.challengeId,
        1002
      ),
      "tenant_alpha"
    );

    assert.equal(
      resolveEnrollmentChallengeTenant(
        db,
        "00000000-0000-0000-0000-000000000000",
        1002
      ),
      null
    );
  } finally {
    db.close();
  }
});

test("does not resolve a consumed or expired enrollment challenge", () => {
  const db = createDatabase();

  try {
    initializeNodeEnrollmentStore(db);

    const enrollment = createEnrollmentCode(
      db,
      "tenant_beta",
      { label: "Test node" },
      1000
    );

    const keys = crypto.generateKeyPairSync("ed25519", {
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });

    const fingerprint = crypto
      .createHash("sha256")
      .update(keys.publicKey.trim(), "utf8")
      .digest("hex")
      .slice(0, 16);

    const challenge = createEnrollmentChallenge(
      db,
      "tenant_beta",
      {
        enrollmentCode: enrollment.enrollmentCode,
        nodeId: `node_${fingerprint}`,
        nodePublicKeyPem: keys.publicKey,
        clientNonce: "b".repeat(64),
      },
      1001
    );

    db.prepare(`
      UPDATE node_enrollment_challenges
      SET consumed_at = ?
      WHERE challenge_id = ?
    `).run(1002, challenge.challengeId);

    assert.equal(
      resolveEnrollmentChallengeTenant(
        db,
        challenge.challengeId,
        1003
      ),
      null
    );

    const expiredEnrollment = createEnrollmentCode(
      db,
      "tenant_beta",
      { label: "Expired challenge node" },
      2000
    );

    const expiredKeys = crypto.generateKeyPairSync("ed25519", {
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });

    const expiredFingerprint = crypto
      .createHash("sha256")
      .update(expiredKeys.publicKey.trim(), "utf8")
      .digest("hex")
      .slice(0, 16);

    const expiredChallenge = createEnrollmentChallenge(
      db,
      "tenant_beta",
      {
        enrollmentCode: expiredEnrollment.enrollmentCode,
        nodeId: `node_${expiredFingerprint}`,
        nodePublicKeyPem: expiredKeys.publicKey,
        clientNonce: "c".repeat(64),
      },
      2001
    );

    assert.equal(
      resolveEnrollmentChallengeTenant(
        db,
        expiredChallenge.challengeId,
        2001 + 2 * 60 * 1000
      ),
      null
    );
  } finally {
    db.close();
  }
});



test("retrieves registered nodes only within their tenant", () => {
  const db = createDatabase();

  try {
    initializeNodeEnrollmentStore(db);

    db.prepare(`
      INSERT INTO registered_nodes (
        node_id, tenant_id, public_key_pem, public_key_fingerprint,
        label, status, enrolled_at
      ) VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?)
    `).run(
      "node_alpha",
      "tenant_alpha",
      "test-public-key-alpha",
      "a".repeat(16),
      "Alpha node",
      1000
    );

    const node = getRegisteredNode(db, "tenant_alpha", "node_alpha");

    assert.ok(node);
    assert.equal(node.node_id, "node_alpha");
    assert.equal(node.tenant_id, "tenant_alpha");
    assert.equal(node.status, "ACTIVE");
    assert.equal(node.public_key_pem, "test-public-key-alpha");

    assert.equal(getRegisteredNode(db, "tenant_beta", "node_alpha"), null);
    assert.equal(getRegisteredNode(db, "tenant_alpha", "missing_node"), null);
  } finally {
    db.close();
  }
});

test("revokes only the matching active node within its tenant", () => {
  const db = createDatabase();

  try {
    initializeNodeEnrollmentStore(db);

    const insertNode = db.prepare(`
      INSERT INTO registered_nodes (
        node_id, tenant_id, public_key_pem, public_key_fingerprint,
        label, status, enrolled_at
      ) VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?)
    `);

    insertNode.run("node_alpha", "tenant_alpha", "test-public-key-alpha",
      "a".repeat(16), "Alpha node", 1000);

    insertNode.run("node_beta", "tenant_beta", "test-public-key-beta",
      "b".repeat(16), "Beta node", 1000);

    assert.equal(revokeRegisteredNode(db, "tenant_alpha", "node_alpha", 5000), true);

    const revoked = getRegisteredNode(db, "tenant_alpha", "node_alpha");
    const untouched = getRegisteredNode(db, "tenant_beta", "node_beta");

    assert.equal(revoked?.status, "REVOKED");
    assert.equal(revoked?.revoked_at, 5000);
    assert.equal(untouched?.status, "ACTIVE");
    assert.equal(untouched?.revoked_at, null);

    assert.equal(revokeRegisteredNode(db, "tenant_alpha", "node_alpha", 6000), false);
    assert.equal(revokeRegisteredNode(db, "tenant_beta", "node_alpha", 7000), false);
  } finally {
    db.close();
  }
});

test("rejects invalid node revocation timestamps", () => {
  const db = createDatabase();

  try {
    initializeNodeEnrollmentStore(db);

    assert.throws(
      () => revokeRegisteredNode(db, "tenant_alpha", "node_alpha", -1),
      /Invalid node revocation context/
    );
  } finally {
    db.close();
  }
});
