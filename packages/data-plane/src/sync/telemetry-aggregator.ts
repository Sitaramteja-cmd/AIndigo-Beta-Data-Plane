import crypto from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { computeCanonicalRecordHash } from "../audit/audit-canonical.js";

export interface TelemetryRecordInput {
  seq: number;
  id: string;
  timestamp: number;
  eventType: string;
  virtualKeyId: string;
  payloadJson: string;
  prevHash: string;
  hash: string;
  signature: string;
}

export interface TelemetryBatchPayload {
  batchId: string;
  orgId: string;
  edgeNodeId: string;
  timestamp: number;
  records: TelemetryRecordInput[];
  merkleCheckpoint?: {
    checkpointHash: string;
    recordCount: number;
    maxSeq: number;
  };
}

export interface TelemetryIngestResult {
  accepted: boolean;
  processedRecords: number;
  error?: string;
  details?: string;
}

export class TelemetryAggregator {
  private db: DatabaseSync;

  constructor(db: DatabaseSync) {
    this.db = db;
    this.initProductionSchema();
  }

  private initProductionSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS control_plane_telemetry_batches (
        batch_id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        edge_node_id TEXT NOT NULL,
        received_at INTEGER NOT NULL,
        record_count INTEGER NOT NULL,
        merkle_checkpoint_hash TEXT
      );

      CREATE TABLE IF NOT EXISTS control_plane_audit_archive (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        edge_node_id TEXT NOT NULL,
        seq INTEGER NOT NULL,
        timestamp INTEGER NOT NULL,
        event_type TEXT NOT NULL,
        virtual_key_id TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        prev_hash TEXT NOT NULL,
        hash TEXT NOT NULL,
        signature TEXT NOT NULL,
        UNIQUE(org_id, edge_node_id, seq)
      );

      CREATE TABLE IF NOT EXISTS edge_telemetry_cursors (
        org_id TEXT NOT NULL,
        edge_node_id TEXT NOT NULL,
        last_seq INTEGER NOT NULL DEFAULT 0,
        last_hash TEXT NOT NULL,
        PRIMARY KEY (org_id, edge_node_id)
      );

      CREATE TABLE IF NOT EXISTS edge_credential_registry (
        org_id TEXT NOT NULL,
        edge_node_id TEXT NOT NULL,
        key_id TEXT NOT NULL,
        secret_hash TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'ACTIVE',
        created_at INTEGER NOT NULL,
        expires_at INTEGER,
        PRIMARY KEY (org_id, edge_node_id, key_id)
      );

      CREATE TABLE IF NOT EXISTS control_plane_merkle_checkpoints (
        checkpoint_hash TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        edge_node_id TEXT NOT NULL,
        record_count INTEGER NOT NULL,
        max_seq INTEGER NOT NULL,
        received_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS telemetry_ingest_failures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        batch_id TEXT,
        org_id TEXT,
        edge_node_id TEXT,
        received_at INTEGER NOT NULL,
        error_code TEXT NOT NULL,
        error_details TEXT
      );
    `);
  }

  public registerEdgeCredential(orgId: string, edgeNodeId: string, keyId: string, secretHex: string): void {
    if (!/^[0-9a-fA-F]{64,}$/.test(secretHex)) {
      throw new Error("TELEMETRY_CONFIG_ERROR: Edge secret must be a valid hex string with >= 32 bytes entropy.");
    }
    const secretBuf = Buffer.from(secretHex, "hex");
    const secretHash = crypto.createHash("sha256").update(secretBuf).digest("hex");

    this.db.prepare(`
      INSERT INTO edge_credential_registry (org_id, edge_node_id, key_id, secret_hash, status, created_at)
      VALUES (?, ?, ?, ?, 'ACTIVE', ?)
      ON CONFLICT(org_id, edge_node_id, key_id) DO UPDATE SET secret_hash = excluded.secret_hash, status = 'ACTIVE'
    `).run(orgId, edgeNodeId, keyId, secretHash, Date.now());
  }

  private getEdgeSecretBuffer(orgId: string, edgeNodeId: string, secretHex: string): Buffer {
    const secretBuf = Buffer.from(secretHex, "hex");
    const secretHash = crypto.createHash("sha256").update(secretBuf).digest("hex");
    
    const row = this.db.prepare(`
      SELECT key_id FROM edge_credential_registry
      WHERE org_id = ? AND edge_node_id = ? AND secret_hash = ? AND status = 'ACTIVE'
    `).get(orgId, edgeNodeId, secretHash);

    if (!row) {
      throw new Error("UNKNOWN_OR_REVOKED_EDGE_CREDENTIAL");
    }
    return secretBuf;
  }

  public ingestBatch(signedPayloadJson: string, signatureHex: string, activeSecretHex: string): TelemetryIngestResult {
    let payload: TelemetryBatchPayload | undefined;
    try {
      if (!signedPayloadJson || !signatureHex || typeof signatureHex !== "string" || !/^[0-9a-fA-F]{64}$/.test(signatureHex)) {
        return { accepted: false, processedRecords: 0, error: "SIGNATURE_MALFORMED" };
      }

      payload = JSON.parse(signedPayloadJson);
      if (!payload || !payload.batchId || !payload.orgId || !payload.edgeNodeId || !Array.isArray(payload.records)) {
        return { accepted: false, processedRecords: 0, error: "INVALID_TELEMETRY_PAYLOAD" };
      }

      const secret = this.getEdgeSecretBuffer(payload.orgId, payload.edgeNodeId, activeSecretHex);

      const computedSig = crypto.createHmac("sha256", secret).update(signedPayloadJson, "utf8").digest("hex");
      const storedSigBuf = Buffer.from(signatureHex, "hex");
      const computedSigBuf = Buffer.from(computedSig, "hex");

      if (storedSigBuf.length !== computedSigBuf.length || !crypto.timingSafeEqual(storedSigBuf, computedSigBuf)) {
        return { accepted: false, processedRecords: 0, error: "SIGNATURE_VERIFICATION_FAILED" };
      }

      const existingBatch = this.db.prepare(`SELECT batch_id FROM control_plane_telemetry_batches WHERE batch_id = ?`).get(payload.batchId);
      if (existingBatch) {
        return { accepted: true, processedRecords: 0, error: "DUPLICATE_BATCH_ALREADY_INGESTED" };
      }

      this.db.exec("BEGIN IMMEDIATE");
      try {
        let cursor = this.db.prepare(`
          SELECT last_seq, last_hash FROM edge_telemetry_cursors WHERE org_id = ? AND edge_node_id = ?
        `).get(payload.orgId, payload.edgeNodeId) as { last_seq: number; last_hash: string } | undefined;

        let expectedSeq = cursor ? cursor.last_seq + 1 : 1;
        let expectedPrevHash = cursor ? cursor.last_hash : "0000000000000000000000000000000000000000000000000000000000000000";

        const firstRecord = payload.records[0];

if (payload.records.length > 0) {
  if (!firstRecord) {
    throw new Error("TELEMETRY_RECORD_MISSING: First record is missing.");
  }

  if (firstRecord.seq !== expectedSeq) {
    throw new Error(
      `SEQUENCE_CONTINUITY_ERROR: Expected starting seq ${expectedSeq}, got ${firstRecord.seq}`
    );
  }

  if (firstRecord.prevHash !== expectedPrevHash) {
    throw new Error(
      "PREV_HASH_CONTINUITY_ERROR: Genesis prevHash does not match cursor state."
    );
  }
}

        for (let i = 0; i < payload.records.length; i++) {
  const r = payload.records[i];

  if (!r) {
    throw new Error(`TELEMETRY_RECORD_MISSING: Record at index ${i} is missing.`);
  }

  const previousRecord = i > 0 ? payload.records[i - 1] : undefined;

  if (i > 0) {
    if (!previousRecord) {
      throw new Error(
        `TELEMETRY_RECORD_MISSING: Previous record at index ${i - 1} is missing.`
      );
    }

    if (r.seq !== previousRecord.seq + 1) {
      throw new Error(
        `SEQUENCE_GAP_ERROR: Sequence break at seq ${r.seq}`
      );
    }

    if (r.prevHash !== previousRecord.hash) {
      throw new Error(
        `HASH_CHAIN_BROKEN: Record ${r.seq} prevHash does not match preceding record hash.`
      );
    }
  }

  // Use the EXACT shared canonical hash function
  const { hash: computedRecordHash } = computeCanonicalRecordHash({
    id: r.id,
    timestamp: r.timestamp,
    eventType: r.eventType,
    orgId: payload.orgId,
    virtualKeyId: r.virtualKeyId,
    payload: r.payloadJson,
    prevHash: r.prevHash,
  });

  if (computedRecordHash !== r.hash) {
    throw new Error(
      `CRYPTOGRAPHIC_TAMPER_DETECTED: Hash mismatch for record seq ${r.seq}`
    );
  }
}

        this.db.prepare(`
          INSERT INTO control_plane_telemetry_batches (batch_id, org_id, edge_node_id, received_at, record_count, merkle_checkpoint_hash)
          VALUES (?, ?, ?, ?, ?, ?)
        `).run(
          payload.batchId,
          payload.orgId,
          payload.edgeNodeId,
          Date.now(),
          payload.records.length,
          payload.merkleCheckpoint?.checkpointHash ?? null
        );

        const insertStmt = this.db.prepare(`
          INSERT INTO control_plane_audit_archive (
            id, org_id, edge_node_id, seq, timestamp, event_type, virtual_key_id, payload_json, prev_hash, hash, signature
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);

        for (const r of payload.records) {
          const existing = this.db.prepare(`
            SELECT hash, payload_json FROM control_plane_audit_archive WHERE org_id = ? AND edge_node_id = ? AND seq = ?
          `).get(payload.orgId, payload.edgeNodeId, r.seq) as { hash: string; payload_json: string } | undefined;

          if (existing) {
            if (existing.hash !== r.hash || existing.payload_json !== r.payloadJson) {
              throw new Error(`CONFLICTING_RECORD_MUTATION: Seq ${r.seq} already archived with differing content/hash.`);
            }
            continue;
          }

          insertStmt.run(
            r.id,
            payload.orgId,
            payload.edgeNodeId,
            r.seq,
            r.timestamp,
            r.eventType,
            r.virtualKeyId,
            r.payloadJson,
            r.prevHash,
            r.hash,
            r.signature
          );
        }

        if (payload.records.length > 0) {
  const lastRec = payload.records[payload.records.length - 1];

  if (!lastRec) {
    throw new Error("TELEMETRY_RECORD_MISSING: Final record is missing.");
  }

  this.db.prepare(`
            INSERT INTO edge_telemetry_cursors (org_id, edge_node_id, last_seq, last_hash)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(org_id, edge_node_id) DO UPDATE SET last_seq = excluded.last_seq, last_hash = excluded.last_hash
          `).run(payload.orgId, payload.edgeNodeId, lastRec.seq, lastRec.hash);
        }

        if (payload.merkleCheckpoint) {
          this.db.prepare(`
            INSERT OR IGNORE INTO control_plane_merkle_checkpoints (checkpoint_hash, org_id, edge_node_id, record_count, max_seq, received_at)
            VALUES (?, ?, ?, ?, ?, ?)
          `).run(
            payload.merkleCheckpoint.checkpointHash,
            payload.orgId,
            payload.edgeNodeId,
            payload.merkleCheckpoint.recordCount,
            payload.merkleCheckpoint.maxSeq,
            Date.now()
          );
        }

        this.db.exec("COMMIT");
        return { accepted: true, processedRecords: payload.records.length };
      } catch (txErr: any) {
        try { this.db.exec("ROLLBACK"); } catch {}
        throw txErr;
      }
    } catch (err: any) {
      try {
        this.db.prepare(`
          INSERT INTO telemetry_ingest_failures (batch_id, org_id, edge_node_id, received_at, error_code, error_details)
          VALUES (?, ?, ?, ?, ?, ?)
        `).run(
          payload?.batchId ?? null,
          payload?.orgId ?? null,
          payload?.edgeNodeId ?? null,
          Date.now(),
          "INGEST_REJECTED",
          err?.message ?? String(err)
        );
      } catch {}

      return { accepted: false, processedRecords: 0, error: "INGEST_REJECTED", details: err?.message ?? String(err) };
    }
  }

  public static signBatchPayload(payload: TelemetryBatchPayload, secretHex: string): { signedJson: string; signature: string } {
    const json = JSON.stringify(payload);
    const signature = crypto.createHmac("sha256", Buffer.from(secretHex, "hex")).update(json, "utf8").digest("hex");
    return { signedJson: json, signature };
  }
}