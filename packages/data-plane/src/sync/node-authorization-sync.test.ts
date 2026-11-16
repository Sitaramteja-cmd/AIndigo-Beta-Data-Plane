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

import { getOrCreateNodeIdentity } from "../crypto/node-identity.js";

test("sync worker requires authenticated ACTIVE status before telemetry", async () => {
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), "aindigo-int005-sync-")
  );

  const previousEnv = {
    db: process.env.DATA_PLANE_DB_PATH,
    publicKey: process.env.CONTROL_PLANE_SIGNING_PUBLIC_KEY_PATH,
    keyId: process.env.CONTROL_PLANE_SIGNING_KEY_ID,
    controlPlaneUrl: process.env.CONTROL_PLANE_URL,
  };

  const previousFetch = globalThis.fetch;

  let database:
    | typeof import("../db.js")
    | undefined;

  try {
    const tenantId = "tenant_int005_sync";
    const keyId = "int005-sync-test-key";
    const nowMs = Date.now();
    const leaseId = crypto.randomUUID();

    const databasePath = path.join(directory, "sync-test.sqlite");
    const identityDirectory = path.join(directory, "node-identity");
    const publicKeyPath = path.join(directory, "cp-public.pem");

    process.env.DATA_PLANE_DB_PATH = databasePath;
    process.env.CONTROL_PLANE_SIGNING_PUBLIC_KEY_PATH = publicKeyPath;
    process.env.CONTROL_PLANE_SIGNING_KEY_ID = keyId;
    process.env.CONTROL_PLANE_URL = "http://127.0.0.1:3000";

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

    fs.writeFileSync(publicKeyPath, publicKeyPem, { mode: 0o600 });

    database = await import("../db.js");
    const runtime = await import("../crypto/node-lease-runtime.js");
    const worker = await import("../sync-worker.js");

    database.activateDataPlaneNode({
      tenantId,
      orgName: "INT005 Sync Test",
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

    const leaseSignature = crypto.sign(
      null,
      Buffer.from(canonicalizePolicyPayload(leasePayload), "utf8"),
      privateKeyPem
    ).toString("base64");

    database.verifyAndPersistDataPlaneNodeLease(
      { payload: leasePayload, signature: leaseSignature },
      publicKeyPem,
      identity,
      tenantId,
      nowMs,
      keyId
    );

    database.recordDataPlaneNodeLeaseClockObservation(nowMs);

    runtime.configureNodeLeaseRuntime(identity);

    assert.equal(runtime.verifyNodeLeaseRuntime(nowMs).status, "ONLINE");

    const receipt = database.createAndQueueAuditReceipt({
      tenantId,
      department: "INT005_TEST",
      modelRequested: "test-model",
      modelRouted: "test-model",
      promptTokens: 10,
      completionTokens: 5,
      costUsd: 0.001,
      savedUsd: 0,
      dlpFlags: [],
      rawPromptText: "synthetic INT005 integration test",
    });

    let rejectStatus = true;
    let telemetryCalls = 0;

    const mockFetch: typeof fetch = async (
      input: RequestInfo | URL,
      init?: RequestInit
    ): Promise<Response> => {
      const requestUrl =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url;

      if (requestUrl.endsWith("/api/v1/nodes/status")) {
        if (rejectStatus) {
          return new Response(
            JSON.stringify({ error: "Simulated Control Plane outage" }),
            { status: 503 }
          );
        }

        const signedRequest = JSON.parse(String(init?.body));

        const payload: NodeStatusResponsePayload = {
          schemaVersion: "1.0",
          nodeId: identity.nodeId,
          tenantId,
          leaseId,
          requestNonce: signedRequest.payload.nonce,
          status: "ACTIVE",
          checkedAt: new Date().toISOString(),
          keyId,
        };

        const signature = crypto.sign(
          null,
          Buffer.from(canonicalizePolicyPayload(payload), "utf8"),
          cpKeys.privateKey
        ).toString("base64");

        return new Response(
          JSON.stringify({ payload, signature }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }
        );
      }

      if (requestUrl.endsWith("/api/v1/telemetry/sync")) {
        telemetryCalls++;

        const body = JSON.parse(String(init?.body));
        const acceptedIds = body.receipts.map(
          (item: { receipt_id: string }) => item.receipt_id
        );

        return new Response(
          JSON.stringify({
            status: "synced",
            count: acceptedIds.length,
            accepted_receipt_ids: acceptedIds,
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }
        );
      }

      throw new Error(`Unexpected test HTTP request: ${requestUrl}`);
    };

    globalThis.fetch = mockFetch;

    console.log("\n[1/2] Simulate failed Control Plane status refresh...");

    const failedCycle = await worker.runControlPlaneSyncCycle();

    assert.equal(telemetryCalls, 0);
    assert.equal(failedCycle.receiptsFlushed, 0);
    assert.match(failedCycle.controlPlaneStatus, /OFFLINE_FAULT_ISOLATED/);
    assert.equal(
      database.fetchPendingReceiptBatch().receipts.length,
      1
    );

    console.log(
      "PASS: Failed status refresh prevents telemetry and preserves the queued receipt."
    );

    console.log("\n[2/2] Simulate successful signed ACTIVE status...");

    rejectStatus = false;

    const successfulCycle = await worker.runControlPlaneSyncCycle();

    assert.equal(telemetryCalls, 1);
    assert.equal(successfulCycle.receiptsFlushed, 1);
    assert.equal(successfulCycle.controlPlaneStatus, "ONLINE_SYNCED");
    assert.equal(
      database.fetchPendingReceiptBatch().receipts.length,
      0
    );

    console.log(
      "PASS: Verified ACTIVE status permits telemetry and acknowledged receipt deletion."
    );

    console.log("\n==============================================");
    console.log("INT-005 SYNC AUTHORIZATION TEST: ALL PASSED");
    console.log("==============================================");
  } finally {
    database?.closeDataPlaneDatabase();

    globalThis.fetch = previousFetch;

    if (previousEnv.db === undefined) {
      delete process.env.DATA_PLANE_DB_PATH;
    } else {
      process.env.DATA_PLANE_DB_PATH = previousEnv.db;
    }

    if (previousEnv.publicKey === undefined) {
      delete process.env.CONTROL_PLANE_SIGNING_PUBLIC_KEY_PATH;
    } else {
      process.env.CONTROL_PLANE_SIGNING_PUBLIC_KEY_PATH =
        previousEnv.publicKey;
    }

    if (previousEnv.keyId === undefined) {
      delete process.env.CONTROL_PLANE_SIGNING_KEY_ID;
    } else {
      process.env.CONTROL_PLANE_SIGNING_KEY_ID = previousEnv.keyId;
    }

    if (previousEnv.controlPlaneUrl === undefined) {
      delete process.env.CONTROL_PLANE_URL;
    } else {
      process.env.CONTROL_PLANE_URL = previousEnv.controlPlaneUrl;
    }

    fs.rmSync(directory, { recursive: true, force: true });
  }
});
