import crypto from "node:crypto";
import type { DatabaseSync } from "node:sqlite";

import {
  verifyNodeEnrollmentProof,
  signNodeLease,
} from "../crypto/node-enrollment.js";

import type {
  ControlPlaneSigningKey,
} from "../crypto/control-plane-signing-key.js";

import {
  EnrollmentCodeCreateRequestSchema,
  EnrollmentCodeSchema,
  NodeEnrollmentChallengeRequestSchema,
  NodeEnrollmentChallengeSchema,
  NodeEnrollmentProofRequestSchema,
  PublicKeyPemSchema,
  type NodeEnrollmentChallenge,
} from "@aindigo/shared";

/**
 * Initializes the persistent Node Enrollment schema.
 *
 * This migration is additive and repeatable:
 * - Existing tenant/session/telemetry tables are not modified.
 * - Enrollment codes are stored as hashes, never plaintext.
 * - Challenges are bound to a tenant, code, and node identity.
 * - Node identities are globally unique.
 *
 * The caller controls the database transaction boundary.
 */
export function initializeNodeEnrollmentStore(db: DatabaseSync): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS node_enrollment_codes (
      code_hash TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      label TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      consumed_at INTEGER,
      revoked_at INTEGER,

      FOREIGN KEY (tenant_id)
        REFERENCES tenants(tenant_id)
        ON DELETE CASCADE,

      CHECK (length(code_hash) = 64),
      CHECK (expires_at > created_at),
      UNIQUE (code_hash, tenant_id)
    );

    CREATE INDEX IF NOT EXISTS idx_node_enrollment_codes_tenant
      ON node_enrollment_codes(tenant_id, created_at DESC);

    CREATE INDEX IF NOT EXISTS idx_node_enrollment_codes_expiry
      ON node_enrollment_codes(expires_at);

    CREATE TABLE IF NOT EXISTS node_enrollment_challenges (
      challenge_id TEXT PRIMARY KEY,
      code_hash TEXT NOT NULL,
      tenant_id TEXT NOT NULL,
      node_id TEXT NOT NULL,
      public_key_pem TEXT NOT NULL,
      public_key_fingerprint TEXT NOT NULL,
      client_nonce TEXT NOT NULL,
      server_nonce TEXT NOT NULL,
      issued_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      consumed_at INTEGER,

      FOREIGN KEY (code_hash, tenant_id)
        REFERENCES node_enrollment_codes(code_hash, tenant_id)
        ON DELETE CASCADE,

      FOREIGN KEY (tenant_id)
        REFERENCES tenants(tenant_id)
        ON DELETE CASCADE,

      CHECK (length(public_key_fingerprint) = 16),
      CHECK (length(client_nonce) = 64),
      CHECK (length(server_nonce) = 64),
      CHECK (expires_at > issued_at)
    );

    CREATE INDEX IF NOT EXISTS idx_node_enrollment_challenges_code
      ON node_enrollment_challenges(code_hash, issued_at DESC);

    CREATE INDEX IF NOT EXISTS idx_node_enrollment_challenges_tenant
      ON node_enrollment_challenges(tenant_id, node_id);

    CREATE TABLE IF NOT EXISTS registered_nodes (
      node_id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      public_key_pem TEXT NOT NULL,
      public_key_fingerprint TEXT NOT NULL,
      label TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'ACTIVE',
      enrolled_at INTEGER NOT NULL,
      last_seen_at INTEGER,
      lease_id TEXT,
      lease_expires_at INTEGER,
      revoked_at INTEGER,

      FOREIGN KEY (tenant_id)
        REFERENCES tenants(tenant_id)
        ON DELETE CASCADE,

      CHECK (length(public_key_fingerprint) = 16),
      CHECK (status IN ('ACTIVE', 'REVOKED'))
    );

    CREATE INDEX IF NOT EXISTS idx_registered_nodes_tenant
      ON registered_nodes(tenant_id, enrolled_at DESC);

    CREATE INDEX IF NOT EXISTS idx_registered_nodes_status
      ON registered_nodes(status);

    CREATE TABLE IF NOT EXISTS node_status_nonces (
      node_id TEXT NOT NULL,
      nonce_hash TEXT NOT NULL,
      received_at INTEGER NOT NULL,
      PRIMARY KEY (node_id, nonce_hash),
      FOREIGN KEY (node_id)
        REFERENCES registered_nodes(node_id)
        ON DELETE CASCADE,
      CHECK (length(nonce_hash) = 64),
      CHECK (received_at > 0)
    );

    CREATE INDEX IF NOT EXISTS idx_node_status_nonces_received
      ON node_status_nonces(received_at);
  `);
}



const ENROLLMENT_CODE_TTL_MS = 15 * 60 * 1000;
const ENROLLMENT_CHALLENGE_TTL_MS = 2 * 60 * 1000;

function hashEnrollmentCode(code: string): string {
  return crypto.createHash("sha256").update(code, "utf8").digest("hex");
}
/**
 * Resolves the tenant owning an active enrollment code.
 * The plaintext code is never persisted or logged.
 */
export function resolveEnrollmentCodeTenant(
  db: DatabaseSync,
  enrollmentCodeInput: unknown,
  nowMs: number = Date.now()
): string | null {
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) {
    throw new Error("NODE_ENROLLMENT_ERROR: Invalid resolution time");
  }

  const enrollmentCode = EnrollmentCodeSchema.parse(enrollmentCodeInput);
  const codeHash = hashEnrollmentCode(enrollmentCode);

  const row = db.prepare(`
    SELECT tenant_id
    FROM node_enrollment_codes
    WHERE code_hash = ?
      AND consumed_at IS NULL
      AND revoked_at IS NULL
      AND expires_at > ?
    LIMIT 1
  `).get(codeHash, nowMs) as { tenant_id: string } | undefined;

  return row?.tenant_id ?? null;
}

/**
 * Resolves the tenant owning an active challenge whose enrollment
 * code is also still valid, unused, and not revoked.
 */
export function resolveEnrollmentChallengeTenant(
  db: DatabaseSync,
  challengeIdInput: unknown,
  nowMs: number = Date.now()
): string | null {
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) {
    throw new Error("NODE_ENROLLMENT_ERROR: Invalid resolution time");
  }

  if (
    typeof challengeIdInput !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
      challengeIdInput
    )
  ) {
    return null;
  }

  const row = db.prepare(`
    SELECT c.tenant_id
    FROM node_enrollment_challenges c
    INNER JOIN node_enrollment_codes e
      ON e.code_hash = c.code_hash
     AND e.tenant_id = c.tenant_id
    WHERE c.challenge_id = ?
      AND c.consumed_at IS NULL
      AND c.expires_at > ?
      AND e.consumed_at IS NULL
      AND e.revoked_at IS NULL
      AND e.expires_at > ?
    LIMIT 1
  `).get(challengeIdInput, nowMs, nowMs) as
    | { tenant_id: string }
    | undefined;

  return row?.tenant_id ?? null;
}

function getEnrollmentPublicKeyFingerprint(publicKeyPem: string): string {
  const publicKey = crypto.createPublicKey(publicKeyPem);

  if (
    publicKey.type !== "public" ||
    publicKey.asymmetricKeyType !== "ed25519"
  ) {
    throw new Error("NODE_ENROLLMENT_ERROR: Expected an Ed25519 public key");
  }

  return crypto
    .createHash("sha256")
    .update(publicKeyPem.trim(), "utf8")
    .digest("hex")
    .slice(0, 16);
}

export function createEnrollmentCode(
  db: DatabaseSync,
  tenantId: string,
  requestInput: unknown,
  nowMs: number = Date.now()
): {
  enrollmentCode: string;
  expiresAt: string;
} {
  const request = EnrollmentCodeCreateRequestSchema.parse(requestInput);

  if (
    typeof tenantId !== "string" ||
    !tenantId.trim() ||
    !Number.isSafeInteger(nowMs) ||
    nowMs < 0
  ) {
    throw new Error("NODE_ENROLLMENT_ERROR: Invalid enrollment-code context");
  }

  const enrollmentCode = crypto.randomBytes(32).toString("base64url");
  const codeHash = hashEnrollmentCode(enrollmentCode);
  const expiresAtMs = nowMs + ENROLLMENT_CODE_TTL_MS;

  db.prepare(`
    INSERT INTO node_enrollment_codes (
      code_hash,
      tenant_id,
      label,
      created_at,
      expires_at
    ) VALUES (?, ?, ?, ?, ?)
  `).run(
    codeHash,
    tenantId,
    request.label,
    nowMs,
    expiresAtMs
  );

  return {
    enrollmentCode,
    expiresAt: new Date(expiresAtMs).toISOString(),
  };
}

export function revokeEnrollmentCode(
  db: DatabaseSync,
  tenantId: string,
  enrollmentCodeInput: unknown,
  nowMs: number = Date.now()
): boolean {
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) {
    throw new Error("NODE_ENROLLMENT_ERROR: Invalid revocation time");
  }

  const enrollmentCode = EnrollmentCodeSchema.parse(enrollmentCodeInput);
  const codeHash = hashEnrollmentCode(enrollmentCode);

  const result = db.prepare(`
    UPDATE node_enrollment_codes
    SET revoked_at = ?
    WHERE code_hash = ?
      AND tenant_id = ?
      AND consumed_at IS NULL
      AND revoked_at IS NULL
      AND expires_at > ?
  `).run(nowMs, codeHash, tenantId, nowMs);

  return result.changes === 1;
}

export function createEnrollmentChallenge(
  db: DatabaseSync,
  tenantId: string,
  requestInput: unknown,
  nowMs: number = Date.now()
): NodeEnrollmentChallenge {
  if (
    typeof tenantId !== "string" ||
    !tenantId.trim() ||
    !Number.isSafeInteger(nowMs) ||
    nowMs < 0
  ) {
    throw new Error("NODE_ENROLLMENT_ERROR: Invalid challenge context");
  }

  const request = NodeEnrollmentChallengeRequestSchema.parse(requestInput);
  const publicKeyPem = PublicKeyPemSchema.parse(request.nodePublicKeyPem);
  const fingerprint = getEnrollmentPublicKeyFingerprint(publicKeyPem);

  if (request.nodeId !== `node_${fingerprint}`) {
    throw new Error("NODE_ENROLLMENT_ERROR: Node identity fingerprint mismatch");
  }

  const codeHash = hashEnrollmentCode(request.enrollmentCode);
  const challengeId = crypto.randomUUID();
  const serverNonce = crypto.randomBytes(32).toString("hex");
  const expiresAtMs = nowMs + ENROLLMENT_CHALLENGE_TTL_MS;

  const challenge = NodeEnrollmentChallengeSchema.parse({
    schemaVersion: "1.0",
    challengeId,
    nodeId: request.nodeId,
    nodePublicKeyFingerprint: fingerprint,
    clientNonce: request.clientNonce,
    serverNonce,
    issuedAt: new Date(nowMs).toISOString(),
    expiresAt: new Date(expiresAtMs).toISOString(),
  });

  db.exec("BEGIN IMMEDIATE");

  try {
    const code = db.prepare(`
      SELECT code_hash
      FROM node_enrollment_codes
      WHERE code_hash = ?
        AND tenant_id = ?
        AND consumed_at IS NULL
        AND revoked_at IS NULL
        AND expires_at > ?
    `).get(codeHash, tenantId, nowMs);

    if (!code) {
      throw new Error("NODE_ENROLLMENT_ERROR: Enrollment code is invalid or expired");
    }

    const existingNode = db.prepare(`
      SELECT node_id
      FROM registered_nodes
      WHERE node_id = ?
    `).get(request.nodeId);

    if (existingNode) {
      throw new Error("NODE_ENROLLMENT_ERROR: Node is already registered");
    }

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
      challenge.challengeId,
      codeHash,
      tenantId,
      challenge.nodeId,
      publicKeyPem,
      fingerprint,
      challenge.clientNonce,
      challenge.serverNonce,
      nowMs,
      expiresAtMs
    );

    db.exec("COMMIT");
    return challenge;
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}


/**
 * Verifies a node's proof of possession and atomically consumes
 * the enrollment code and challenge while registering the node.
 *
 * The tenant ID must come from the authenticated Control Plane
 * session, never from the submitted proof body.
 */

const NODE_LEASE_LIFETIME_SECONDS = 172800;

export function completeNodeEnrollment(
  db: DatabaseSync,
  tenantId: string,
  proofInput: unknown,
  signingKey: ControlPlaneSigningKey,
  nowMs: number = Date.now()
): {
  nodeId: string;
  tenantId: string;
  publicKeyFingerprint: string;
  label: string;
  enrolledAt: string;
  signedLease: import("@aindigo/shared").SignedNodeLease;
} {
  if (
    typeof tenantId !== "string" ||
    !tenantId.trim() ||
    !Number.isSafeInteger(nowMs) ||
    nowMs < 0
  ) {
    throw new Error("NODE_ENROLLMENT_ERROR: Invalid enrollment context");
  }

  if (!signingKey) {
    throw new Error(
      "NODE_ENROLLMENT_ERROR: Control Plane signing key is required"
    );
  }

  const proof = NodeEnrollmentProofRequestSchema.parse(proofInput);

  db.exec("BEGIN IMMEDIATE");

  try {
    const row = db.prepare(`
      SELECT
        c.challenge_id,
        c.code_hash,
        c.tenant_id,
        c.node_id,
        c.public_key_pem,
        c.public_key_fingerprint,
        c.client_nonce,
        c.server_nonce,
        c.issued_at,
        c.expires_at,
        e.label
      FROM node_enrollment_challenges c
      INNER JOIN node_enrollment_codes e
        ON e.code_hash = c.code_hash
       AND e.tenant_id = c.tenant_id
      WHERE c.challenge_id = ?
        AND c.tenant_id = ?
        AND c.node_id = ?
        AND c.consumed_at IS NULL
        AND c.expires_at > ?
        AND e.consumed_at IS NULL
        AND e.revoked_at IS NULL
        AND e.expires_at > ?
    `).get(
      proof.challengeId,
      tenantId,
      proof.nodeId,
      nowMs,
      nowMs
    ) as {
      challenge_id: string;
      code_hash: string;
      tenant_id: string;
      node_id: string;
      public_key_pem: string;
      public_key_fingerprint: string;
      client_nonce: string;
      server_nonce: string;
      issued_at: number;
      expires_at: number;
      label: string;
    } | undefined;

    if (!row) {
      throw new Error(
        "NODE_ENROLLMENT_ERROR: Challenge or enrollment code is invalid, expired, or already consumed"
      );
    }

    const challenge = NodeEnrollmentChallengeSchema.parse({
      schemaVersion: "1.0",
      challengeId: row.challenge_id,
      nodeId: row.node_id,
      nodePublicKeyFingerprint: row.public_key_fingerprint,
      clientNonce: row.client_nonce,
      serverNonce: row.server_nonce,
      issuedAt: new Date(row.issued_at).toISOString(),
      expiresAt: new Date(row.expires_at).toISOString(),
    });

    const proofValid = verifyNodeEnrollmentProof(
      challenge,
      row.public_key_pem,
      proof.signature,
      nowMs
    );

    if (!proofValid) {
      throw new Error(
        "NODE_ENROLLMENT_ERROR: Node proof-of-possession verification failed"
      );
    }

    // Sign the lease before consuming enrollment state.
    // A signing failure must leave the code and challenge untouched.
    const leaseId = crypto.randomUUID();
    const issuedAt = new Date(nowMs).toISOString();
    const expiresAt = new Date(
      nowMs + NODE_LEASE_LIFETIME_SECONDS * 1000
    ).toISOString();

    const signedLease = signNodeLease(
      {
        schemaVersion: "1.0",
        leaseId,
        keyId: signingKey.keyId,
        tenantId: row.tenant_id,
        nodeId: row.node_id,
        nodePublicKeyFingerprint: row.public_key_fingerprint,
        issuedAt,
        expiresAt,
        offlineMaxSeconds: NODE_LEASE_LIFETIME_SECONDS,
      },
      signingKey,
      nowMs
    );

    const consumeCode = db.prepare(`
      UPDATE node_enrollment_codes
      SET consumed_at = ?
      WHERE code_hash = ?
        AND tenant_id = ?
        AND consumed_at IS NULL
        AND revoked_at IS NULL
        AND expires_at > ?
    `).run(nowMs, row.code_hash, tenantId, nowMs);

    if (consumeCode.changes !== 1) {
      throw new Error(
        "NODE_ENROLLMENT_ERROR: Enrollment code was already consumed"
      );
    }

    const consumeChallenge = db.prepare(`
      UPDATE node_enrollment_challenges
      SET consumed_at = ?
      WHERE challenge_id = ?
        AND tenant_id = ?
        AND consumed_at IS NULL
        AND expires_at > ?
    `).run(nowMs, row.challenge_id, tenantId, nowMs);

    if (consumeChallenge.changes !== 1) {
      throw new Error(
        "NODE_ENROLLMENT_ERROR: Challenge was already consumed"
      );
    }

    db.prepare(`
      INSERT INTO registered_nodes (
        node_id,
        tenant_id,
        public_key_pem,
        public_key_fingerprint,
        label,
        status,
        enrolled_at,
        lease_id,
        lease_expires_at
      ) VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?)
    `).run(
      row.node_id,
      row.tenant_id,
      row.public_key_pem,
      row.public_key_fingerprint,
      row.label,
      nowMs,
      leaseId,
      Date.parse(expiresAt)
    );

    db.exec("COMMIT");

    return {
      nodeId: row.node_id,
      tenantId: row.tenant_id,
      publicKeyFingerprint: row.public_key_fingerprint,
      label: row.label,
      enrolledAt: issuedAt,
      signedLease,
    };
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}



export interface RegisteredNodeRecord {
  node_id: string;
  tenant_id: string;
  public_key_pem: string;
  public_key_fingerprint: string;
  label: string;
  status: "ACTIVE" | "REVOKED";
  enrolled_at: number;
  last_seen_at: number | null;
  lease_id: string | null;
  lease_expires_at: number | null;
  revoked_at: number | null;
}

/**
 * Retrieves a registered node only within its owning tenant.
 * Returns null when the node does not belong to that tenant.
 */
export function getRegisteredNode(
  db: DatabaseSync,
  tenantId: string,
  nodeId: string
): RegisteredNodeRecord | null {
  if (
    typeof tenantId !== "string" ||
    !tenantId.trim() ||
    typeof nodeId !== "string" ||
    !nodeId.trim()
  ) {
    return null;
  }

  const row = db.prepare(`
    SELECT
      node_id,
      tenant_id,
      public_key_pem,
      public_key_fingerprint,
      label,
      status,
      enrolled_at,
      last_seen_at,
      lease_id,
      lease_expires_at,
      revoked_at
    FROM registered_nodes
    WHERE tenant_id = ?
      AND node_id = ?
    LIMIT 1
  `).get(tenantId, nodeId) as RegisteredNodeRecord | undefined;

  return row ?? null;
}

/**
 * Revokes an ACTIVE registered node within its owning tenant.
 * Returns true only when this call changes the node's status.
 */
export function revokeRegisteredNode(
  db: DatabaseSync,
  tenantId: string,
  nodeId: string,
  nowMs: number = Date.now()
): boolean {
  if (
    typeof tenantId !== "string" ||
    !tenantId.trim() ||
    typeof nodeId !== "string" ||
    !nodeId.trim() ||
    !Number.isSafeInteger(nowMs) ||
    nowMs < 0
  ) {
    throw new Error("NODE_ENROLLMENT_ERROR: Invalid node revocation context");
  }

  const result = db.prepare(`
    UPDATE registered_nodes
    SET
      status = 'REVOKED',
      revoked_at = ?
    WHERE tenant_id = ?
      AND node_id = ?
      AND status = 'ACTIVE'
  `).run(nowMs, tenantId, nodeId);

  return result.changes === 1;
}
/**
 * Atomically consumes a signed node-status request nonce.
 * Only a SHA-256 hash is persisted.
 * Expired replay records are pruned after the two-minute window.
 */
export function consumeNodeStatusNonce(
  db: DatabaseSync,
  nodeId: string,
  nonce: string,
  nowMs: number = Date.now()
): boolean {
  if (
    typeof nodeId !== "string" ||
    !nodeId.trim() ||
    typeof nonce !== "string" ||
    !/^[a-f0-9]{64}$/.test(nonce) ||
    !Number.isSafeInteger(nowMs) ||
    nowMs <= 0
  ) {
    throw new Error("NODE_STATUS_ERROR: Invalid nonce context");
  }

  const nonceHash = crypto
    .createHash("sha256")
    .update(nonce, "utf8")
    .digest("hex");

  db.prepare(`
    DELETE FROM node_status_nonces
    WHERE received_at < ?
  `).run(nowMs - 2 * 60 * 1000);

  const result = db.prepare(`
    INSERT OR IGNORE INTO node_status_nonces (
      node_id,
      nonce_hash,
      received_at
    ) VALUES (?, ?, ?)
  `).run(nodeId, nonceHash, nowMs);

  return result.changes === 1;
}

/**
 * Updates last_seen_at for an authenticated registered node.
 * Tenant and node identity must both match.
 */
export function updateRegisteredNodeLastSeen(
  db: DatabaseSync,
  tenantId: string,
  nodeId: string,
  nowMs: number = Date.now()
): boolean {
  if (
    typeof tenantId !== "string" ||
    !tenantId.trim() ||
    typeof nodeId !== "string" ||
    !nodeId.trim() ||
    !Number.isSafeInteger(nowMs) ||
    nowMs <= 0
  ) {
    throw new Error("NODE_STATUS_ERROR: Invalid node activity context");
  }

  const result = db.prepare(`
    UPDATE registered_nodes
    SET last_seen_at = ?
    WHERE tenant_id = ?
      AND node_id = ?
  `).run(nowMs, tenantId, nodeId);

  return result.changes === 1;
}