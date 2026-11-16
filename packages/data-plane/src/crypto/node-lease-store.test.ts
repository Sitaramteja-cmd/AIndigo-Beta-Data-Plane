
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import {
  canonicalizePolicyPayload,
  type NodeLeasePayload,
  type SignedNodeLease,
} from '@aindigo/shared';

import { getOrCreateNodeIdentity } from './node-identity.js';

import {
  initializeNodeLeaseStore,
  getPersistedNodeLease,
  getNodeLeaseClockState,
  verifyAndPersistNodeLease,
  recordNodeLeaseClockObservation,
} from './node-lease-store.js';

type NodeIdentity = ReturnType<typeof getOrCreateNodeIdentity>;

const BASE_TIME = 1_800_000_000_000;

function createHarness() {
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), 'aindigo-lease-store-')
  );

  const db = new DatabaseSync(':memory:');

  const identity = getOrCreateNodeIdentity(directory);

  const controlPlaneKeys =
    crypto.generateKeyPairSync('ed25519');

  const controlPlanePublicKeyPem =
    controlPlaneKeys.publicKey.export({
      type: 'spki',
      format: 'pem',
    }).toString();

  const controlPlanePrivateKey = controlPlaneKeys.privateKey;

  const keyId = 'cp-lease-store-test-key';

  initializeNodeLeaseStore(db);

  function createLease(
    identityForLease: NodeIdentity = identity,
    issuedAtMs: number = BASE_TIME,
    overrides: Partial<NodeLeasePayload> = {}
  ): SignedNodeLease {
    const payload: NodeLeasePayload = {
      schemaVersion: '1.0',
      leaseId: crypto.randomUUID(),
      keyId,
      tenantId: 'tenant_alpha',
      nodeId: identityForLease.nodeId,
      nodePublicKeyFingerprint:
        identityForLease.publicKeyFingerprint,
      issuedAt: new Date(issuedAtMs).toISOString(),
      expiresAt: new Date(
        issuedAtMs + 86_400_000
      ).toISOString(),
      offlineMaxSeconds: 172800,
      ...overrides,
    };

    const signature = crypto.sign(
      null,
      Buffer.from(
        canonicalizePolicyPayload(payload),
        'utf8'
      ),
      controlPlanePrivateKey
    ).toString('base64');

    return { payload, signature };
  }

  function persist(
    lease: SignedNodeLease,
    nowMs: number,
    expectedTenantId = 'tenant_alpha',
    identityForVerification: NodeIdentity = identity
  ) {
    return verifyAndPersistNodeLease(
      db,
      lease,
      controlPlanePublicKeyPem,
      identityForVerification,
      expectedTenantId,
      nowMs,
      keyId
    );
  }

  function close() {
    db.close();
    fs.rmSync(directory, {
      recursive: true,
      force: true,
    });
  }

  return {
    db,
    identity,
    createLease,
    persist,
    close,
  };
}

test('initializes lease and clock tables', () => {
  const h = createHarness();

  try {
    const tables = h.db.prepare(`
      SELECT name
      FROM sqlite_master
      WHERE type = 'table'
        AND name IN (
          'node_lease_state',
          'node_lease_clock_state'
        )
      ORDER BY name
    `).all() as Array<{ name: string }>;

    assert.deepEqual(
      tables.map(row => row.name),
      ['node_lease_clock_state', 'node_lease_state']
    );

    const clock = getNodeLeaseClockState(h.db);

    assert.equal(clock.lastObservedWallClockMs, 0);
    assert.equal(clock.lastLeaseIssuedAtMs, 0);
  } finally {
    h.close();
  }
});

test('persists a valid signed lease', () => {
  const h = createHarness();

  try {
    const lease = h.createLease();

    const persisted = h.persist(lease, BASE_TIME);

    assert.equal(persisted.tenantId, 'tenant_alpha');
    assert.equal(persisted.nodeId, h.identity.nodeId);
    assert.equal(persisted.leaseId, lease.payload.leaseId);
    assert.equal(persisted.keyId, lease.payload.keyId);

    assert.deepEqual(
      persisted.signedLease,
      lease
    );
  } finally {
    h.close();
  }
});

test('retrieves the persisted lease after saving', () => {
  const h = createHarness();

  try {
    const lease = h.createLease();

    h.persist(lease, BASE_TIME);

    const retrieved = getPersistedNodeLease(h.db);

    assert.ok(retrieved);
    assert.equal(retrieved.leaseId, lease.payload.leaseId);
    assert.deepEqual(retrieved.signedLease, lease);
  } finally {
    h.close();
  }
});

test('accepts the exact same lease idempotently', () => {
  const h = createHarness();

  try {
    const lease = h.createLease();

    const first = h.persist(lease, BASE_TIME);
    const second = h.persist(lease, BASE_TIME + 1000);

    assert.equal(first.leaseId, second.leaseId);

    const retrieved = getPersistedNodeLease(h.db);

    assert.ok(retrieved);
    assert.equal(retrieved.leaseId, lease.payload.leaseId);
  } finally {
    h.close();
  }
});

test('rejects a lease with an invalid signature', () => {
  const h = createHarness();

  try {
    const lease = h.createLease();

    const tampered = {
      ...lease,
      signature: Buffer.alloc(64, 1).toString('base64'),
    };

    assert.throws(
      () => h.persist(tampered, BASE_TIME),
      /signature verification failed/
    );

    assert.equal(getPersistedNodeLease(h.db), null);
  } finally {
    h.close();
  }
});

test('rejects an older lease after a newer lease was persisted', () => {
  const h = createHarness();

  try {
    const newerLease = h.createLease(
      h.identity,
      BASE_TIME + 10_000
    );

    h.persist(newerLease, BASE_TIME + 10_000);

    const olderLease = h.createLease(
      h.identity,
      BASE_TIME
    );

    assert.throws(
      () => h.persist(olderLease, BASE_TIME + 11_000),
      /older or replayed/
    );

    const current = getPersistedNodeLease(h.db);

    assert.ok(current);
    assert.equal(current.leaseId, newerLease.payload.leaseId);
  } finally {
    h.close();
  }
});

test('rejects a lease belonging to a different tenant', () => {
  const h = createHarness();

  try {
    const originalLease = h.createLease();

    h.persist(originalLease, BASE_TIME);

    const differentTenantLease = h.createLease(
      h.identity,
      BASE_TIME + 10_000,
      { tenantId: 'tenant_beta' }
    );

    assert.throws(
      () => h.persist(
        differentTenantLease,
        BASE_TIME + 10_000,
        'tenant_beta'
      ),
      /identity cannot be changed/
    );

    const current = getPersistedNodeLease(h.db);

    assert.ok(current);
    assert.equal(current.tenantId, 'tenant_alpha');
  } finally {
    h.close();
  }
});

test('rejects a lease belonging to a different node', () => {
  const h = createHarness();

  const secondDirectory = fs.mkdtempSync(
    path.join(os.tmpdir(), 'aindigo-second-node-')
  );

  try {
    const originalLease = h.createLease();

    h.persist(originalLease, BASE_TIME);

    const secondIdentity =
      getOrCreateNodeIdentity(secondDirectory);

    const differentNodeLease = h.createLease(
      secondIdentity,
      BASE_TIME + 10_000
    );

    assert.throws(
      () => h.persist(
        differentNodeLease,
        BASE_TIME + 10_000,
        'tenant_alpha',
        secondIdentity
      ),
      /identity cannot be changed/
    );

    const current = getPersistedNodeLease(h.db);

    assert.ok(current);
    assert.equal(current.nodeId, h.identity.nodeId);
  } finally {
    h.close();

    fs.rmSync(secondDirectory, {
      recursive: true,
      force: true,
    });
  }
});

test('rejects modified contents using an existing lease ID', () => {
  const h = createHarness();

  try {
    const originalLease = h.createLease();

    h.persist(originalLease, BASE_TIME);

    const modifiedLease = h.createLease(
      h.identity,
      BASE_TIME,
      {
        leaseId: originalLease.payload.leaseId,
        offlineMaxSeconds: 86400,
      }
    );

    assert.throws(
      () => h.persist(modifiedLease, BASE_TIME + 1000),
      /same lease ID/
    );

    const current = getPersistedNodeLease(h.db);

    assert.ok(current);
    assert.deepEqual(current.signedLease, originalLease);
  } finally {
    h.close();
  }
});

test('detects excessive system clock rollback', () => {
  const h = createHarness();

  try {
    recordNodeLeaseClockObservation(
      h.db,
      BASE_TIME
    );

    assert.throws(
      () => recordNodeLeaseClockObservation(
        h.db,
        BASE_TIME - 6 * 60 * 1000
      ),
      /clock rollback detected/
    );

    const clock = getNodeLeaseClockState(h.db);

    assert.equal(
      clock.lastObservedWallClockMs,
      BASE_TIME
    );
  } finally {
    h.close();
  }
});

test('rejects a lease when the system clock has rolled back', () => {
  const h = createHarness();

  try {
    const originalLease = h.createLease();

    h.persist(originalLease, BASE_TIME);

    const rollbackTime = BASE_TIME - 6 * 60 * 1000;

    const leaseAfterRollback = h.createLease(
      h.identity,
      rollbackTime
    );

    assert.throws(
      () => h.persist(
        leaseAfterRollback,
        rollbackTime
      ),
      /clock rollback detected/
    );

    const current = getPersistedNodeLease(h.db);

    assert.ok(current);
    assert.equal(
      current.leaseId,
      originalLease.payload.leaseId
    );
  } finally {
    h.close();
  }
});

test('accepts a newer valid lease and advances the checkpoint', () => {
  const h = createHarness();

  try {
    const firstLease = h.createLease();

    h.persist(firstLease, BASE_TIME);

    const secondLease = h.createLease(
      h.identity,
      BASE_TIME + 10_000
    );

    h.persist(secondLease, BASE_TIME + 10_000);

    const current = getPersistedNodeLease(h.db);
    const clock = getNodeLeaseClockState(h.db);

    assert.ok(current);
    assert.equal(
      current.leaseId,
      secondLease.payload.leaseId
    );

    assert.equal(
      clock.lastLeaseIssuedAtMs,
      BASE_TIME + 10_000
    );

    assert.equal(
      clock.lastObservedWallClockMs,
      BASE_TIME + 10_000
    );
  } finally {
    h.close();
  }
});

test('rejects an old lease after its persisted lease row is deleted', () => {
  const h = createHarness();

  try {
    const firstLease = h.createLease();

    h.persist(firstLease, BASE_TIME);

    // Simulate deletion of only the lease row.
    // The monotonic clock checkpoint remains.
    h.db.prepare(
      'DELETE FROM node_lease_state WHERE id = 1'
    ).run();

    const replayedLease = h.createLease(
      h.identity,
      BASE_TIME
    );

    assert.throws(
      () => h.persist(
        replayedLease,
        BASE_TIME + 10_000
      ),
      /issuance rollback detected/
    );

    assert.equal(getPersistedNodeLease(h.db), null);

    const clock = getNodeLeaseClockState(h.db);

    assert.equal(
      clock.lastLeaseIssuedAtMs,
      BASE_TIME
    );
  } finally {
    h.close();
  }
});
