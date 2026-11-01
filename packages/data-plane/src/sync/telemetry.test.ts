import { strict as assert } from "node:assert";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { TelemetryAggregator, TelemetryBatchPayload } from "./telemetry-aggregator.js";
import { computeCanonicalRecordHash } from "../audit/audit-canonical.js";

async function runTelemetryTests() {
  console.log("================================================================");
  console.log(" ☁️ AIndigo Tier 4 — Enterprise Telemetry & Aggregator Test Suite");
  console.log("================================================================");

  const tmpDbPath = path.join(os.tmpdir(), `aindigo-enterprise-telemetry-${Date.now()}.sqlite`);
  const edgeSecret = crypto.randomBytes(32).toString("hex");

  try {
    const db = new DatabaseSync(tmpDbPath);
    const aggregator = new TelemetryAggregator(db);
    aggregator.registerEdgeCredential("org_kla", "edge_node_01", "key_01", edgeSecret);

    const now = Date.now();
    const orgId = "org_kla";
    const edgeNodeId = "edge_node_01";

    const createRecord = (seq: number, prevHash: string, eventType = "BUDGET_WARNING") => {
      const id = `aud_${crypto.randomBytes(8).toString("hex")}`;
      const payloadJson = '{"spend":0.5}';
      const { hash } = computeCanonicalRecordHash({
        id,
        timestamp: now,
        eventType,
        orgId,
        virtualKeyId: "vk_01",
        payload: payloadJson,
        prevHash,
      });
      const signature = crypto.createHmac("sha256", Buffer.from(edgeSecret, "hex")).update(hash, "utf8").digest("hex");
      return { seq, id, timestamp: now, eventType, virtualKeyId: "vk_01", payloadJson, prevHash, hash, signature };
    };

    const rec1 = createRecord(1, "00".repeat(32));
    const rec2 = createRecord(2, rec1.hash);

    const batch1: TelemetryBatchPayload = {
      batchId: "batch_001",
      orgId,
      edgeNodeId,
      timestamp: now,
      records: [rec1, rec2],
      merkleCheckpoint: {
        checkpointHash: crypto.randomBytes(32).toString("hex"),
        recordCount: 2,
        maxSeq: 2,
      },
    };

    const signed1 = TelemetryAggregator.signBatchPayload(batch1, edgeSecret);

    const res1 = aggregator.ingestBatch(signed1.signedJson, signed1.signature, edgeSecret);
    assert.equal(res1.accepted, true);
    assert.equal(res1.processedRecords, 2);
    console.log("✅ 1. Sequence continuity and shared canonical hash verification passed.");

    const rec4 = createRecord(4, rec2.hash);
    const batchGap: TelemetryBatchPayload = {
      batchId: "batch_002",
      orgId,
      edgeNodeId,
      timestamp: now,
      records: [rec4],
    };
    const signedGap = TelemetryAggregator.signBatchPayload(batchGap, edgeSecret);
    const resGap = aggregator.ingestBatch(signedGap.signedJson, signedGap.signature, edgeSecret);
    assert.equal(resGap.accepted, false);
    assert.equal(resGap.error, "INGEST_REJECTED");
    console.log("✅ 2. Sequence gap rejection verified.");

    const tamperedRec = { ...rec1, payloadJson: '{"spend":999.0}' };
    const batchTampered: TelemetryBatchPayload = {
      batchId: "batch_003",
      orgId,
      edgeNodeId,
      timestamp: now,
      records: [tamperedRec],
    };
    const signedTampered = TelemetryAggregator.signBatchPayload(batchTampered, edgeSecret);
    const resTampered = aggregator.ingestBatch(signedTampered.signedJson, signedTampered.signature, edgeSecret);
    assert.equal(resTampered.accepted, false);
    console.log("✅ 3. Cryptographic tamper detection and hash mismatch rejection verified.");

    db.close();
  } finally {
    for (const suffix of ["", "-wal", "-shm"]) {
      const p = `${tmpDbPath}${suffix}`;
      if (fs.existsSync(p)) {
        try { fs.unlinkSync(p); } catch {}
      }
    }
  }

  console.log("================================================================");
  console.log(" 🎉 Tier 4 Module 4.2 Enterprise Telemetry Tests PASSED Successfully");
  console.log("================================================================");
}

runTelemetryTests();