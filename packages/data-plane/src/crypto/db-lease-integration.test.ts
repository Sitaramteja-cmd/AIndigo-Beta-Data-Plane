import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  canonicalizePolicyPayload,
  type NodeLeasePayload,
  type SignedNodeLease,
} from '@aindigo/shared';

import { getOrCreateNodeIdentity } from './node-identity.js';

test('Data Plane database wrappers persist and retrieve signed node leases safely', async () => {
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), 'aindigo-db-lease-integration-')
  );

  const databasePath = path.join(directory, 'integration.sqlite');
  const keysDirectory = path.join(directory, 'node-keys');

  const previousDatabasePath = process.env.DATA_PLANE_DB_PATH;

  let databaseModule:
    | typeof import('../db.js')
    | undefined;

  try {
    // The database path must be set before importing db.ts because
    // db.ts opens its SQLite connection during module initialization.
    process.env.DATA_PLANE_DB_PATH = databasePath;

    const identity = getOrCreateNodeIdentity(keysDirectory);

    const controlPlaneKeys =
      crypto.generateKeyPairSync('ed25519');

    const controlPlanePublicKeyPem =
      controlPlaneKeys.publicKey.export({
        type: 'spki',
        format: 'pem',
      }).toString();

    const keyId = 'cp-db-integration-test-key';
    const nowMs = Date.now();

    function createLease(): SignedNodeLease {
      const payload: NodeLeasePayload = {
        schemaVersion: '1.0',
        leaseId: crypto.randomUUID(),
        keyId,
        tenantId: 'tenant_db_integration',
        nodeId: identity.nodeId,
        nodePublicKeyFingerprint:
          identity.publicKeyFingerprint,
        issuedAt: new Date(nowMs).toISOString(),
        expiresAt: new Date(
          nowMs + 86_400_000
        ).toISOString(),
        offlineMaxSeconds: 172800,
      };

      const signature = crypto.sign(
        null,
        Buffer.from(
          canonicalizePolicyPayload(payload),
          'utf8'
        ),
        controlPlaneKeys.privateKey
      ).toString('base64');

      return { payload, signature };
    }

    // Import only after setting the isolated database path.
    databaseModule = await import('../db.js');

    // 1. No lease should exist in this fresh database.
    assert.equal(
      databaseModule.getPersistedDataPlaneNodeLease(),
      null
    );

    // 2. Persist a valid Control Plane-signed lease.
    const lease = createLease();

    const persisted =
      databaseModule.verifyAndPersistDataPlaneNodeLease(
        lease,
        controlPlanePublicKeyPem,
        identity,
        'tenant_db_integration',
        nowMs,
        keyId
      );

    assert.equal(persisted.tenantId, 'tenant_db_integration');
    assert.equal(persisted.nodeId, identity.nodeId);
    assert.equal(persisted.leaseId, lease.payload.leaseId);
    assert.equal(persisted.keyId, keyId);
    assert.deepEqual(persisted.signedLease, lease);

    // 3. Retrieve the lease through the public database wrapper.
    const retrieved =
      databaseModule.getPersistedDataPlaneNodeLease();

    assert.ok(retrieved);
    assert.equal(retrieved.tenantId, 'tenant_db_integration');
    assert.equal(retrieved.nodeId, identity.nodeId);
    assert.deepEqual(retrieved.signedLease, lease);

    // 4. Record a clock observation.
    const observedTime = nowMs + 1_000;

    databaseModule.recordDataPlaneNodeLeaseClockObservation(
      observedTime
    );

    const clockState =
      databaseModule.getDataPlaneNodeLeaseClockState();

    assert.equal(
      clockState.lastObservedWallClockMs,
      observedTime
    );

    assert.equal(
      clockState.lastLeaseIssuedAtMs,
      nowMs
    );

    // 5. A tampered signature must be rejected.
    const tamperedLease: SignedNodeLease = {
      ...lease,
      signature:
        (lease.signature[0] === 'A' ? 'B' : 'A') +
        lease.signature.slice(1),
    };

    assert.throws(() => {
      databaseModule!.verifyAndPersistDataPlaneNodeLease(
        tamperedLease,
        controlPlanePublicKeyPem,
        identity,
        'tenant_db_integration',
        observedTime,
        keyId
      );
    });

    // Confirm the rejected lease did not replace the valid lease.
    const afterRejection =
      databaseModule.getPersistedDataPlaneNodeLease();

    assert.ok(afterRejection);
    assert.deepEqual(afterRejection.signedLease, lease);

    assert.ok(fs.existsSync(databasePath));

    console.log(
      'Database lease integration checks passed.'
    );
  } finally {
    // Close the isolated SQLite connection before removing its directory.
    if (databaseModule) {
      databaseModule.closeDataPlaneDatabase();
    }

    if (previousDatabasePath === undefined) {
      delete process.env.DATA_PLANE_DB_PATH;
    } else {
      process.env.DATA_PLANE_DB_PATH = previousDatabasePath;
    }

    fs.rmSync(directory, {
      recursive: true,
      force: true,
    });
  }
});