import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  canonicalizePolicyPayload,
  type NodeLeasePayload,
  type NodeStatusResponsePayload,
} from "@aindigo/shared";

import { getOrCreateNodeIdentity } from "./node-identity.js";

test("node lease runtime enforces fresh authenticated Control Plane status", async () => {
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), "aindigo-int005-runtime-")
  );

  const previousDbPath = process.env.DATA_PLANE_DB_PATH;
  const previousPublicKeyPath =
    process.env.CONTROL_PLANE_SIGNING_PUBLIC_KEY_PATH;
  const previousKeyId = process.env.CONTROL_PLANE_SIGNING_KEY_ID;

  let databaseModule:
    | typeof import("../db.js")
    | undefined;

  try {
    const databasePath = path.join(directory, "runtime-test.sqlite");
    const identityDirectory = path.join(directory, "node-identity");
    const publicKeyPath = path.join(directory, "cp-public.pem");

    process.env.DATA_PLANE_DB_PATH = databasePath;

    const identity = getOrCreateNodeIdentity(identityDirectory);

    const cpKeys = crypto.generateKeyPairSync("ed25519");

    const publicKeyPem = cpKeys.publicKey.export({
      type: "spki",
      format: "pem",
    }).toString();

    const privateKeyPem = cpKeys.privateKey.export({
      type: "pkcs8",
      format: "pem",
    }).toString();

    const keyId = "int005-runtime-test-key";
    const tenantId = "tenant_int005_runtime";
    const nowMs = Date.now();
    const leaseId = crypto.randomUUID();

    fs.writeFileSync(publicKeyPath, publicKeyPem, { mode: 0o600 });

    process.env.CONTROL_PLANE_SIGNING_PUBLIC_KEY_PATH = publicKeyPath;
    process.env.CONTROL_PLANE_SIGNING_KEY_ID = keyId;

    databaseModule = await import("../db.js");

    const runtime = await import("./node-lease-runtime.js");

    databaseModule.activateDataPlaneNode({
      tenantId,
      orgName: "INT005 Runtime Test",
      subscriptionTier: "COMMUNITY",
      clusterSyncSecret: crypto.randomBytes(32).toString("hex"),
      monthlyRequestLimit: 10000,
    });

    const leasePayload: NodeLeasePayload = {
      schemaVersion: "1.0",
      leaseId,
      keyId,
      tenantId,
      nodeId: identity.nodeId,
      nodePublicKeyFingerprint: identity.publicKeyFingerprint,
      issuedAt: new Date(nowMs - 1000).toISOString(),
      expiresAt: new Date(nowMs + 86_400_000).toISOString(),
      offlineMaxSeconds: 172800,
    };

    const signature = crypto.sign(
      null,
      Buffer.from(
        canonicalizePolicyPayload(leasePayload),
        "utf8"
      ),
      privateKeyPem
    ).toString("base64");

    const signedLease = {
      payload: leasePayload,
      signature,
    };

    databaseModule.verifyAndPersistDataPlaneNodeLease(
      signedLease,
      publicKeyPem,
      identity,
      tenantId,
      nowMs,
      keyId
    );

    databaseModule.recordDataPlaneNodeLeaseClockObservation(nowMs);

    runtime.configureNodeLeaseRuntime(identity);

    console.log("\n[1/5] Verify valid signed lease...");

    const leaseResult = runtime.verifyNodeLeaseRuntime(nowMs);

    assert.equal(leaseResult.status, "ONLINE");
    assert.equal(
      runtime.getNodeLeaseRuntimeStatus().status,
      "STATUS_REQUIRED"
    );

    assert.throws(() => runtime.assertNodeLeaseActive());

    console.log("PASS: Missing authenticated status is rejected.");

    function createStatus(
      status: "ACTIVE" | "REVOKED",
      checkedAtMs: number
    ): NodeStatusResponsePayload {
      return {
        schemaVersion: "1.0",
        nodeId: identity.nodeId,
        tenantId,
        leaseId,
        requestNonce: crypto.randomBytes(32).toString("hex"),
        status,
        checkedAt: new Date(checkedAtMs).toISOString(),
        keyId,
      };
    }

    console.log("\n[2/5] Apply fresh ACTIVE status...");

    runtime.applyAuthenticatedNodeStatus(
      createStatus("ACTIVE", Date.now())
    );

    assert.equal(
      runtime.getNodeLeaseRuntimeStatus().status,
      "ONLINE"
    );

    assert.doesNotThrow(() => runtime.assertNodeLeaseActive());

    console.log("PASS: Fresh ACTIVE status authorizes protected operations.");

    console.log("\n[3/5] Apply REVOKED status...");

    runtime.applyAuthenticatedNodeStatus(
      createStatus("REVOKED", Date.now())
    );

    assert.equal(
      runtime.getNodeLeaseRuntimeStatus().status,
      "NODE_REVOKED"
    );

    assert.throws(() => runtime.assertNodeLeaseActive());

    console.log("PASS: REVOKED status denies protected operations.");

    console.log("\n[4/5] Apply expired status...");

    const staleCheckedAt = Date.now() - 61_001;

    runtime.applyAuthenticatedNodeStatus(
      createStatus("ACTIVE", staleCheckedAt),
      staleCheckedAt
    );

    assert.equal(
      runtime.getNodeLeaseRuntimeStatus().status,
      "STATUS_STALE"
    );

    assert.throws(() => runtime.assertNodeLeaseActive());

    console.log("PASS: Expired status denies protected operations.");

    console.log("\n[5/5] Reverify lease and confirm status resets...");

    const reverified = runtime.verifyNodeLeaseRuntime(Date.now());

    assert.equal(reverified.status, "ONLINE");

    assert.equal(
      runtime.getNodeLeaseRuntimeStatus().status,
      "STATUS_REQUIRED"
    );

    assert.throws(() => runtime.assertNodeLeaseActive());

    console.log("PASS: Lease revalidation requires a new authenticated status.");

    console.log("\n======================================");
    console.log("INT-005 RUNTIME TEST: ALL CHECKS PASSED");
    console.log("======================================");

  } finally {
    if (databaseModule) {
      databaseModule.closeDataPlaneDatabase();
    }

    if (previousDbPath === undefined) {
      delete process.env.DATA_PLANE_DB_PATH;
    } else {
      process.env.DATA_PLANE_DB_PATH = previousDbPath;
    }

    if (previousPublicKeyPath === undefined) {
      delete process.env.CONTROL_PLANE_SIGNING_PUBLIC_KEY_PATH;
    } else {
      process.env.CONTROL_PLANE_SIGNING_PUBLIC_KEY_PATH =
        previousPublicKeyPath;
    }

    if (previousKeyId === undefined) {
      delete process.env.CONTROL_PLANE_SIGNING_KEY_ID;
    } else {
      process.env.CONTROL_PLANE_SIGNING_KEY_ID = previousKeyId;
    }

    fs.rmSync(directory, { recursive: true, force: true });
  }
});
