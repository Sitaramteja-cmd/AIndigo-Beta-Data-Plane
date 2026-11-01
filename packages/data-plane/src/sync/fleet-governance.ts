import crypto from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { canonicalJsonStringify } from "../audit/audit-canonical.js";

export interface GlobalRevocationCommand {
  commandId: string;
  sequence: number;
  keyId: string;
  orgId: string;
  virtualKeyId: string;
  reason: string;
  issuedAt: number;
  expiresAt: number;
  version: number;
  signature: string;
}

export interface FleetSpendSummary {
  orgId: string;
  totalSpendMicros: number;
  activeKeysCount: number;
  revokedKeysCount: number;
  reportingNodes: string[];
  acknowledgedNodesCount: number;
}

export class FleetGovernanceEngine {
  private db: DatabaseSync;
  private controlPlanePrivateKey?: crypto.KeyObject;
  private activeKeyId: string;

  constructor(db: DatabaseSync, options: { privateKeyPemOrHex?: string; publicKeyPemOrHex?: string; activeKeyId?: string } = {}) {
    this.db = db;
    this.activeKeyId = options.activeKeyId ?? "cp-key-v1";
    this.initGovernanceSchema();

    // 1. Enforce strict private-key isolation (No automatic key generation)
    if (options.privateKeyPemOrHex) {
      this.controlPlanePrivateKey = options.privateKeyPemOrHex.includes("BEGIN PRIVATE KEY")
        ? crypto.createPrivateKey(options.privateKeyPemOrHex)
        : crypto.createPrivateKey({ key: Buffer.from(options.privateKeyPemOrHex, "hex"), format: "der", type: "pkcs8" });
    }

    let publicKeyObj: crypto.KeyObject | undefined;
    if (options.publicKeyPemOrHex) {
      publicKeyObj = options.publicKeyPemOrHex.includes("BEGIN PUBLIC KEY")
        ? crypto.createPublicKey(options.publicKeyPemOrHex)
        : crypto.createPublicKey({ key: Buffer.from(options.publicKeyPemOrHex, "hex"), format: "der", type: "spki" });
    }

    // If both private and public keys are supplied, verify they belong to the same keypair
    if (this.controlPlanePrivateKey && publicKeyObj) {
      const derivedPublicKey = crypto.createPublicKey(this.controlPlanePrivateKey);
      if (!derivedPublicKey.equals(publicKeyObj)) {
        throw new Error("GOVERNOR_CONFIG_ERROR: Supplied private key and public key do not match.");
      }
    } else if (this.controlPlanePrivateKey && !publicKeyObj) {
      publicKeyObj = crypto.createPublicKey(this.controlPlanePrivateKey);
    }

    // Register active public key in signing key registry if provided
    if (publicKeyObj) {
      this.registerSigningKey(this.activeKeyId, publicKeyObj);
    }
  }

  public registerSigningKey(keyId: string, publicKey: crypto.KeyObject | string): void {
    const pubKeyObj = typeof publicKey === "string" ? crypto.createPublicKey(publicKey) : publicKey;
    const pubKeyPem = pubKeyObj.export({ format: "pem", type: "spki" }).toString();

    this.db.prepare(`
      INSERT INTO signing_key_registry (key_id, public_key_pem, status)
      VALUES (?, ?, 'ACTIVE')
      ON CONFLICT(key_id) DO UPDATE SET public_key_pem = excluded.public_key_pem, status = 'ACTIVE'
    `).run(keyId, pubKeyPem);
  }

  private initGovernanceSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS control_plane_revocation_registry (
        org_id TEXT NOT NULL,
        virtual_key_id TEXT NOT NULL,
        reason TEXT NOT NULL,
        revoked_at INTEGER NOT NULL,
        command_id TEXT NOT NULL,
        signature TEXT NOT NULL,
        PRIMARY KEY (org_id, virtual_key_id)
      );

      CREATE TABLE IF NOT EXISTS control_plane_revocation_outbox (
        command_id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        virtual_key_id TEXT NOT NULL,
        sequence INTEGER NOT NULL,
        signed_payload TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'PENDING',
        UNIQUE(org_id, sequence)
      );

      CREATE TABLE IF NOT EXISTS edge_revocation_acknowledgements (
        org_id TEXT NOT NULL,
        command_id TEXT NOT NULL,
        edge_node_id TEXT NOT NULL,
        acknowledged_at INTEGER NOT NULL,
        PRIMARY KEY (org_id, command_id, edge_node_id)
      );

      CREATE TABLE IF NOT EXISTS fleet_governance_audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id TEXT NOT NULL,
        action TEXT NOT NULL,
        actor TEXT NOT NULL,
        details_json TEXT NOT NULL,
        timestamp INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS control_plane_spend_ledger (
        event_id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        virtual_key_id TEXT NOT NULL,
        cost_micros INTEGER NOT NULL,
        timestamp INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS registered_edge_nodes (
        org_id TEXT NOT NULL,
        edge_node_id TEXT NOT NULL,
        PRIMARY KEY (org_id, edge_node_id)
      );

      CREATE TABLE IF NOT EXISTS signing_key_registry (
        key_id TEXT PRIMARY KEY,
        public_key_pem TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'ACTIVE'
      );
    `);
  }

  public issueGlobalRevocation(
    orgId: string,
    virtualKeyId: string,
    reason: string,
    actor = "admin"
  ): GlobalRevocationCommand {
    if (!this.controlPlanePrivateKey) {
      throw new Error("GOVERNOR_SECURITY_ERROR: Private signing key is not present. Edge nodes cannot issue revocations.");
    }

    const issuedAt = Date.now();
    const commandId = `cmd_${crypto.randomBytes(12).toString("hex")}`;
    const expiresAt = issuedAt + 7 * 24 * 60 * 60 * 1000;

    // 2. Eliminate race condition: all checks and sequence generation happen inside an atomic transaction
    let sequence = 1;

    this.db.exec("BEGIN IMMEDIATE");
    try {
      // Validate virtual key ownership and check if already revoked atomically
      const keyRecord = this.db.prepare(`
        SELECT org_id, revoked_at FROM virtual_keys WHERE id = ?
      `).get(virtualKeyId) as { org_id: string; revoked_at: number | null } | undefined;

      if (!keyRecord) {
        throw new Error(`REVOCATION_ERROR: Virtual key ${virtualKeyId} not found.`);
      }
      if (keyRecord.org_id !== orgId) {
        throw new Error(`CROSS_ORG_REVOCATION_ATTEMPT: Key ${virtualKeyId} does not belong to org ${orgId}.`);
      }

      // Conditional UPDATE to prevent race conditions during concurrent revocation
      const updateResult = this.db.prepare(`
        UPDATE virtual_keys
        SET revoked_at = ?
        WHERE id = ? AND org_id = ? AND revoked_at IS NULL
      `).run(issuedAt, virtualKeyId, orgId);

      if (updateResult.changes !== 1) {
        throw new Error(`REVOCATION_ERROR: Key ${virtualKeyId} is already revoked or state changed concurrently.`);
      }

      // Get next sequence number atomically within transaction
      const seqRow = this.db.prepare(`
        SELECT COALESCE(MAX(sequence), 0) + 1 as next_seq FROM control_plane_revocation_outbox WHERE org_id = ?
      `).get(orgId) as { next_seq: number };
      sequence = seqRow.next_seq;

      const canonicalPayloadObj = {
        commandId,
        sequence,
        keyId: this.activeKeyId,
        commandType: "GLOBAL_REVOCATION",
        orgId,
        virtualKeyId,
        reason,
        issuedAt,
        expiresAt,
        version: 1,
      };
      const canonicalJson = canonicalJsonStringify(canonicalPayloadObj);
      const payloadBuffer = Buffer.from(canonicalJson, "utf8");

      const signatureBuf = crypto.sign(null, payloadBuffer, this.controlPlanePrivateKey);
      const signature = signatureBuf.toString("hex");

      const command: GlobalRevocationCommand = {
        ...canonicalPayloadObj,
        signature,
      };

      const signedPayloadString = JSON.stringify(command);

      this.db.prepare(`
        INSERT INTO control_plane_revocation_registry (org_id, virtual_key_id, reason, revoked_at, command_id, signature)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(orgId, virtualKeyId, reason, issuedAt, commandId, signature);

      this.db.prepare(`
        INSERT INTO control_plane_revocation_outbox (command_id, org_id, virtual_key_id, sequence, signed_payload, created_at, status)
        VALUES (?, ?, ?, ?, ?, ?, 'PENDING')
      `).run(commandId, orgId, virtualKeyId, sequence, signedPayloadString, issuedAt);

      this.db.prepare(`
        INSERT INTO fleet_governance_audit_log (org_id, action, actor, details_json, timestamp)
        VALUES (?, 'GLOBAL_REVOCATION_ISSUED', ?, ?, ?)
      `).run(orgId, actor, JSON.stringify({ virtualKeyId, commandId, sequence, reason }), issuedAt);

      this.db.exec("COMMIT");
      return command;
    } catch (err) {
      try { this.db.exec("ROLLBACK"); } catch {}
      throw err;
    }
  }

  public verifyRevocationCommand(command: GlobalRevocationCommand): boolean {
    try {
      // 3. Select trusted public key from signing key registry using command's keyId
      const keyRow = this.db.prepare(`
        SELECT public_key_pem FROM signing_key_registry WHERE key_id = ? AND status = 'ACTIVE'
      `).get(command.keyId) as { public_key_pem: string } | undefined;

      if (!keyRow) {
        return false; // Unknown or retired signing key ID
      }

      const trustedPublicKey = crypto.createPublicKey(keyRow.public_key_pem);

      const { signature, ...payloadWithoutSig } = command;
      const canonicalJson = canonicalJsonStringify(payloadWithoutSig);
      const payloadBuffer = Buffer.from(canonicalJson, "utf8");
      const signatureBuffer = Buffer.from(signature, "hex");

      return crypto.verify(null, payloadBuffer, trustedPublicKey, signatureBuffer);
    } catch {
      return false;
    }
  }

  public acknowledgeRevocation(orgId: string, commandId: string, edgeNodeId: string): void {
    const nodeRecord = this.db.prepare(`
      SELECT edge_node_id FROM registered_edge_nodes WHERE org_id = ? AND edge_node_id = ?
    `).get(orgId, edgeNodeId);

    if (!nodeRecord) {
      throw new Error(`ACKNOWLEDGEMENT_ERROR: Edge node ${edgeNodeId} is not registered for org ${orgId}.`);
    }

    const cmdRecord = this.db.prepare(`
      SELECT command_id FROM control_plane_revocation_outbox WHERE org_id = ? AND command_id = ?
    `).get(orgId, commandId);

    if (!cmdRecord) {
      throw new Error(`ACKNOWLEDGEMENT_ERROR: Command ID ${commandId} not found for org ${orgId}.`);
    }

    this.db.prepare(`
      INSERT INTO edge_revocation_acknowledgements (org_id, command_id, edge_node_id, acknowledged_at)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(org_id, command_id, edge_node_id) DO UPDATE SET acknowledged_at = excluded.acknowledged_at
    `).run(orgId, commandId, edgeNodeId, Date.now());
  }

  public getFleetSpendSummary(orgId: string, activeCommandId?: string): FleetSpendSummary {
    const spendSum = this.db.prepare(`
      SELECT COALESCE(SUM(cost_micros), 0) as total_spend
      FROM control_plane_spend_ledger WHERE org_id = ?
    `).get(orgId) as { total_spend: number };

    const activeKeys = this.db.prepare(`
      SELECT COUNT(*) as cnt
      FROM virtual_keys
      WHERE org_id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)
    `).get(orgId, Date.now()) as { cnt: number };

    const revCount = this.db.prepare(`
      SELECT COUNT(*) as cnt FROM control_plane_revocation_registry WHERE org_id = ?
    `).get(orgId) as { cnt: number };

    const nodes = this.db.prepare(`
      SELECT edge_node_id FROM registered_edge_nodes WHERE org_id = ?
    `).all(orgId) as Array<{ edge_node_id: string }>;

    let ackCount = 0;
    if (activeCommandId) {
      const ackRow = this.db.prepare(`
        SELECT COUNT(DISTINCT edge_node_id) as cnt FROM edge_revocation_acknowledgements WHERE org_id = ? AND command_id = ?
      `).get(orgId, activeCommandId) as { cnt: number };
      ackCount = ackRow.cnt;
    }

    return {
      orgId,
      totalSpendMicros: spendSum.total_spend,
      activeKeysCount: activeKeys.cnt,
      revokedKeysCount: revCount.cnt,
      reportingNodes: nodes.map((n) => n.edge_node_id),
      acknowledgedNodesCount: ackCount,
    };
  }
}