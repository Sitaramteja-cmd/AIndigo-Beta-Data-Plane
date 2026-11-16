
import type { DatabaseSync } from 'node:sqlite';

import {
  SignedNodeLeaseSchema,
  type SignedNodeLease,
} from '@aindigo/shared';

import { verifyNodeLease } from './node-identity.js';

type NodeIdentity = Parameters<typeof verifyNodeLease>[2];

export interface PersistedNodeLease {
  tenantId: string;
  nodeId: string;
  leaseId: string;
  keyId: string;
  signedLease: SignedNodeLease;
  issuedAtMs: number;
  expiresAtMs: number;
  acceptedAtMs: number;
  updatedAtMs: number;
}

export interface NodeLeaseClockState {
  lastObservedWallClockMs: number;
  lastLeaseIssuedAtMs: number;
  updatedAtMs: number;
}

export interface NodeLeaseStoreOptions {
  clockRollbackToleranceMs?: number;
}

const DEFAULT_CLOCK_ROLLBACK_TOLERANCE_MS = 5 * 60 * 1000;

function parseTimestamp(value: string, field: string): number {
  const timestamp = Date.parse(value);

  if (!Number.isFinite(timestamp)) {
    throw new Error(`Invalid node lease timestamp: ${field}`);
  }

  return timestamp;
}

function beginTransaction(db: DatabaseSync): void {
  db.exec('BEGIN IMMEDIATE');
}

function commitTransaction(db: DatabaseSync): void {
  db.exec('COMMIT');
}

function rollbackTransaction(db: DatabaseSync): void {
  try {
    db.exec('ROLLBACK');
  } catch {
    // Preserve the original failure.
  }
}

/**
 * Creates the local lease and clock checkpoint tables.
 * Safe to call repeatedly.
 */
export function initializeNodeLeaseStore(db: DatabaseSync): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS node_lease_state (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      tenant_id TEXT NOT NULL,
      node_id TEXT NOT NULL,
      lease_id TEXT NOT NULL UNIQUE,
      key_id TEXT NOT NULL,
      signed_lease_json TEXT NOT NULL,
      issued_at_ms INTEGER NOT NULL,
      expires_at_ms INTEGER NOT NULL,
      accepted_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      CHECK (issued_at_ms < expires_at_ms),
      CHECK (accepted_at_ms > 0),
      CHECK (updated_at_ms > 0)
    );

    CREATE TABLE IF NOT EXISTS node_lease_clock_state (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      last_observed_wall_clock_ms INTEGER NOT NULL DEFAULT 0,
      last_lease_issued_at_ms INTEGER NOT NULL DEFAULT 0,
      updated_at_ms INTEGER NOT NULL DEFAULT 0,
      CHECK (last_observed_wall_clock_ms >= 0),
      CHECK (last_lease_issued_at_ms >= 0),
      CHECK (updated_at_ms >= 0)
    );

    INSERT OR IGNORE INTO node_lease_clock_state (
      id,
      last_observed_wall_clock_ms,
      last_lease_issued_at_ms,
      updated_at_ms
    ) VALUES (1, 0, 0, 0);
  `);
}

/**
 * Retrieves the current persisted lease.
 * The signed JSON is schema-validated before returning.
 */
export function getPersistedNodeLease(
  db: DatabaseSync
): PersistedNodeLease | null {
  const row = db.prepare(`
    SELECT
      tenant_id,
      node_id,
      lease_id,
      key_id,
      signed_lease_json,
      issued_at_ms,
      expires_at_ms,
      accepted_at_ms,
      updated_at_ms
    FROM node_lease_state
    WHERE id = 1
  `).get() as Record<string, unknown> | undefined;

  if (!row) {
    return null;
  }

  let parsed: unknown;

  try {
    parsed = JSON.parse(String(row.signed_lease_json));
  } catch {
    throw new Error('Persisted node lease contains invalid JSON.');
  }

  const result = SignedNodeLeaseSchema.safeParse(parsed);

  if (!result.success) {
    throw new Error('Persisted node lease failed schema validation.');
  }

  return {
    tenantId: String(row.tenant_id),
    nodeId: String(row.node_id),
    leaseId: String(row.lease_id),
    keyId: String(row.key_id),
    signedLease: result.data,
    issuedAtMs: Number(row.issued_at_ms),
    expiresAtMs: Number(row.expires_at_ms),
    acceptedAtMs: Number(row.accepted_at_ms),
    updatedAtMs: Number(row.updated_at_ms),
  };
}

/**
 * Retrieves the monotonic clock checkpoint.
 */
export function getNodeLeaseClockState(
  db: DatabaseSync
): NodeLeaseClockState {
  const row = db.prepare(`
    SELECT
      last_observed_wall_clock_ms,
      last_lease_issued_at_ms,
      updated_at_ms
    FROM node_lease_clock_state
    WHERE id = 1
  `).get() as Record<string, unknown> | undefined;

  if (!row) {
    throw new Error('Node lease clock state is missing.');
  }

  return {
    lastObservedWallClockMs: Number(row.last_observed_wall_clock_ms),
    lastLeaseIssuedAtMs: Number(row.last_lease_issued_at_ms),
    updatedAtMs: Number(row.updated_at_ms),
  };
}

/**
 * Verifies a Control Plane-signed lease and persists it atomically.
 *
 * The existing cryptographic verifier is reused.
 * Unverified lease input is never written to the database.
 */
export function verifyAndPersistNodeLease(
  db: DatabaseSync,
  leaseInput: unknown,
  controlPlanePublicKeyPem: string,
  identity: NodeIdentity,
  expectedTenantId: string,
  nowMs: number = Date.now(),
  expectedKeyId?: string,
  options: NodeLeaseStoreOptions = {}
): PersistedNodeLease {
  if (!Number.isSafeInteger(nowMs) || nowMs <= 0) {
    throw new Error('Invalid node lease acceptance timestamp.');
  }

  const tolerance =
    options.clockRollbackToleranceMs ??
    DEFAULT_CLOCK_ROLLBACK_TOLERANCE_MS;

  if (!Number.isSafeInteger(tolerance) || tolerance < 0) {
    throw new Error('Invalid clock rollback tolerance.');
  }

  // Existing cryptographic and identity checks are authoritative.
  const verifiedLease = verifyNodeLease(
    leaseInput,
    controlPlanePublicKeyPem,
    identity,
    expectedTenantId,
    nowMs,
    expectedKeyId
  );

  const payload = verifiedLease.payload;

  const issuedAtMs = parseTimestamp(payload.issuedAt, 'issuedAt');
  const expiresAtMs = parseTimestamp(payload.expiresAt, 'expiresAt');

  const serializedLease = JSON.stringify(verifiedLease);

  beginTransaction(db);

  try {
    const existing = getPersistedNodeLease(db);
    const clock = getNodeLeaseClockState(db);

    if (
      clock.lastObservedWallClockMs > 0 &&
      nowMs + tolerance < clock.lastObservedWallClockMs
    ) {
      throw new Error('System clock rollback detected.');
    }

    if (existing) {
      if (
        existing.tenantId !== payload.tenantId ||
        existing.nodeId !== payload.nodeId
      ) {
        throw new Error(
          'Persisted node identity cannot be changed without explicit reprovisioning.'
        );
      }

      const existingJson = JSON.stringify(existing.signedLease);

      // Reaccepting the exact same lease is safe and idempotent.
      if (existing.leaseId === payload.leaseId) {
        if (existingJson !== serializedLease) {
          throw new Error(
            'The same lease ID was presented with different contents.'
          );
        }

        commitTransaction(db);
        return existing;
      }

      if (issuedAtMs <= existing.issuedAtMs) {
        throw new Error('An older or replayed node lease was rejected.');
      }
    }

    // Also protect against lease-row deletion while the clock
    // checkpoint remains intact.
    if (issuedAtMs <= clock.lastLeaseIssuedAtMs) {
      throw new Error('Node lease issuance rollback detected.');
    }

    db.prepare(`
      INSERT INTO node_lease_state (
        id,
        tenant_id,
        node_id,
        lease_id,
        key_id,
        signed_lease_json,
        issued_at_ms,
        expires_at_ms,
        accepted_at_ms,
        updated_at_ms
      ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        tenant_id = excluded.tenant_id,
        node_id = excluded.node_id,
        lease_id = excluded.lease_id,
        key_id = excluded.key_id,
        signed_lease_json = excluded.signed_lease_json,
        issued_at_ms = excluded.issued_at_ms,
        expires_at_ms = excluded.expires_at_ms,
        accepted_at_ms = excluded.accepted_at_ms,
        updated_at_ms = excluded.updated_at_ms
    `).run(
      payload.tenantId,
      payload.nodeId,
      payload.leaseId,
      payload.keyId,
      serializedLease,
      issuedAtMs,
      expiresAtMs,
      nowMs,
      nowMs
    );

    db.prepare(`
      UPDATE node_lease_clock_state
      SET
        last_observed_wall_clock_ms = MAX(
          last_observed_wall_clock_ms, ?
        ),
        last_lease_issued_at_ms = ?,
        updated_at_ms = ?
      WHERE id = 1
    `).run(nowMs, issuedAtMs, nowMs);

    commitTransaction(db);

    return {
      tenantId: payload.tenantId,
      nodeId: payload.nodeId,
      leaseId: payload.leaseId,
      keyId: payload.keyId,
      signedLease: verifiedLease,
      issuedAtMs,
      expiresAtMs,
      acceptedAtMs: nowMs,
      updatedAtMs: nowMs,
    };
  } catch (error) {
    rollbackTransaction(db);
    throw error;
  }
}

/**
 * Records a local clock observation.
 * Rejects rollback beyond the configured tolerance.
 */
export function recordNodeLeaseClockObservation(
  db: DatabaseSync,
  nowMs: number = Date.now(),
  options: NodeLeaseStoreOptions = {}
): NodeLeaseClockState {
  if (!Number.isSafeInteger(nowMs) || nowMs <= 0) {
    throw new Error('Invalid system clock observation.');
  }

  const tolerance =
    options.clockRollbackToleranceMs ??
    DEFAULT_CLOCK_ROLLBACK_TOLERANCE_MS;

  if (!Number.isSafeInteger(tolerance) || tolerance < 0) {
    throw new Error('Invalid clock rollback tolerance.');
  }

  beginTransaction(db);

  try {
    const current = getNodeLeaseClockState(db);

    if (
      current.lastObservedWallClockMs > 0 &&
      nowMs + tolerance < current.lastObservedWallClockMs
    ) {
      throw new Error('System clock rollback detected.');
    }

    const updatedAtMs = Math.max(nowMs, current.updatedAtMs);

    db.prepare(`
      UPDATE node_lease_clock_state
      SET
        last_observed_wall_clock_ms = MAX(
          last_observed_wall_clock_ms, ?
        ),
        updated_at_ms = ?
      WHERE id = 1
    `).run(nowMs, updatedAtMs);

    commitTransaction(db);

    return getNodeLeaseClockState(db);
  } catch (error) {
    rollbackTransaction(db);
    throw error;
  }
}
