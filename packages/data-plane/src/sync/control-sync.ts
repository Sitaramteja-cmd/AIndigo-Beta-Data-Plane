import crypto from "node:crypto";
import type { VirtualKeyVault } from "../vault/virtual-key-vault.js";
import { usdToMicros } from "../vault/virtual-key-vault.js";

export const MAX_PAYLOAD_SIZE_BYTES = 1024 * 1024; // 1MB limit
export const MAX_OPERATIONS_PER_SYNC = 100; // max items per batch

export interface ControlPlanePolicyPayload {
  version: number;
  timestamp: number;
  orgId: string;
  revokedKeyIds: string[];
  budgetUpdates: Array<{ recordId: string; newBudgetLimitUsd: number }>;
  modelMappingOverrides?: Record<string, string>;
}

export interface SyncResponse {
  success: boolean;
  appliedRevocations: number;
  appliedBudgetUpdates: number;
  appliedModelMappings: number;
  error?: string;
}

export class ControlPlaneSyncClient {
  private vault: VirtualKeyVault;
  private controlPlaneSecret: Buffer;

  constructor(vault: VirtualKeyVault, hmacSecretHex: string) {
    this.vault = vault;

    // Strict HMAC secret validation (at least 32 bytes entropy, valid hex, not weak/all-zero)
    if (!hmacSecretHex || typeof hmacSecretHex !== "string" || !/^[0-9a-fA-F]{64,}$/.test(hmacSecretHex)) {
      throw new Error("SYNC_CONFIG_ERROR: hmacSecretHex must be a valid hex string with at least 64 hex characters (32 bytes).");
    }

    const secretBuf = Buffer.from(hmacSecretHex, "hex");
    if (secretBuf.length < 32) {
      throw new Error("SYNC_CONFIG_ERROR: HMAC secret must provide at least 32 bytes of entropy.");
    }

    const isWeak = secretBuf.every((b) => b === 0) || secretBuf.every((b) => b === 0xff);
    if (isWeak) {
      throw new Error("SYNC_CONFIG_ERROR: Weak or trivial HMAC secret detected.");
    }

    this.controlPlaneSecret = secretBuf;
    this.ensureSyncSchema();
  }

  private ensureSyncSchema(): void {
    const db = (this.vault as any).db;
    db.exec(`
      CREATE TABLE IF NOT EXISTS org_policy_versions (
        org_id TEXT PRIMARY KEY,
        last_version INTEGER NOT NULL DEFAULT 0,
        model_mappings_json TEXT
      );
    `);
  }

  public applyPolicySync(signedPayloadJson: string, signatureHex: string): SyncResponse {
    try {
      if (!signedPayloadJson || Buffer.byteLength(signedPayloadJson, "utf8") > MAX_PAYLOAD_SIZE_BYTES) {
        return { success: false, appliedRevocations: 0, appliedBudgetUpdates: 0, appliedModelMappings: 0, error: "PAYLOAD_TOO_LARGE" };
      }

      if (!signatureHex || typeof signatureHex !== "string" || !/^[0-9a-fA-F]{64}$/.test(signatureHex)) {
        return { success: false, appliedRevocations: 0, appliedBudgetUpdates: 0, appliedModelMappings: 0, error: "SIGNATURE_MALFORMED" };
      }

      const computedSig = crypto
        .createHmac("sha256", this.controlPlaneSecret)
        .update(signedPayloadJson, "utf8")
        .digest("hex");

      const storedSigBuf = Buffer.from(signatureHex, "hex");
      const computedSigBuf = Buffer.from(computedSig, "hex");

      if (storedSigBuf.length !== computedSigBuf.length || !crypto.timingSafeEqual(storedSigBuf, computedSigBuf)) {
        return { success: false, appliedRevocations: 0, appliedBudgetUpdates: 0, appliedModelMappings: 0, error: "SIGNATURE_VERIFICATION_FAILED" };
      }

      const payload: ControlPlanePolicyPayload = JSON.parse(signedPayloadJson);
      const now = Date.now();

      if (payload.timestamp > now + 60000) {
        return { success: false, appliedRevocations: 0, appliedBudgetUpdates: 0, appliedModelMappings: 0, error: "FUTURE_PAYLOAD_TIMESTAMP" };
      }
      if (Math.abs(now - payload.timestamp) > 5 * 60 * 1000) {
        return { success: false, appliedRevocations: 0, appliedBudgetUpdates: 0, appliedModelMappings: 0, error: "STALE_PAYLOAD_TIMESTAMP" };
      }

      if (!payload.orgId || typeof payload.orgId !== "string") {
        return { success: false, appliedRevocations: 0, appliedBudgetUpdates: 0, appliedModelMappings: 0, error: "INVALID_ORG_ID" };
      }

      const revocations = payload.revokedKeyIds ?? [];
      const budgets = payload.budgetUpdates ?? [];
      if (revocations.length > MAX_OPERATIONS_PER_SYNC || budgets.length > MAX_OPERATIONS_PER_SYNC) {
        return { success: false, appliedRevocations: 0, appliedBudgetUpdates: 0, appliedModelMappings: 0, error: "TOO_MANY_OPERATIONS" };
      }

      const db = (this.vault as any).db;
      let revCount = 0;
      let budCount = 0;
      let mapCount = 0;

      db.exec("BEGIN IMMEDIATE");
      try {
        const orgStateRow = db.prepare(`SELECT last_version FROM org_policy_versions WHERE org_id = ?`).get(payload.orgId) as { last_version: number } | undefined;
        const lastVersion = orgStateRow ? orgStateRow.last_version : 0;

        if (payload.version <= lastVersion) {
          db.exec("ROLLBACK");
          return { success: false, appliedRevocations: 0, appliedBudgetUpdates: 0, appliedModelMappings: 0, error: "REPLAYED_OR_OUTDATED_POLICY_VERSION" };
        }

        for (const keyId of revocations) {
          const meta = this.vault.getKeyMetadata(keyId);
          if (!meta || meta.org_id !== payload.orgId) {
            throw new Error(`CROSS_ORG_REVOCATION_ATTEMPT: Key ${keyId} does not belong to org ${payload.orgId}`);
          }
          const revoked = this.vault.revokeKey(keyId, payload.timestamp);
          if (revoked) revCount++;
        }

        for (const update of budgets) {
          if (update.newBudgetLimitUsd < 0) {
            throw new Error("NEGATIVE_BUDGET_VALUE_NOT_ALLOWED");
          }
          const meta = this.vault.getKeyMetadata(update.recordId);
          if (!meta || meta.org_id !== payload.orgId) {
            throw new Error(`CROSS_ORG_BUDGET_UPDATE_ATTEMPT: Key ${update.recordId} does not belong to org ${payload.orgId}`);
          }

          const newLimitMicros = usdToMicros(update.newBudgetLimitUsd);
          db.prepare(`UPDATE virtual_keys SET budget_limit_micros = ? WHERE id = ? AND org_id = ?`).run(newLimitMicros, update.recordId, payload.orgId);
          budCount++;
        }

        if (payload.modelMappingOverrides) {
          for (const [fromModel, toModel] of Object.entries(payload.modelMappingOverrides)) {
            if (!fromModel.trim() || !toModel.trim() || fromModel.trim().toLowerCase() === toModel.trim().toLowerCase()) {
              throw new Error("INVALID_MODEL_MAPPING");
            }
            mapCount++;
          }
          const mappingsJson = JSON.stringify(payload.modelMappingOverrides);
          db.prepare(`
            INSERT INTO org_policy_versions (org_id, last_version, model_mappings_json)
            VALUES (?, ?, ?)
            ON CONFLICT(org_id) DO UPDATE SET last_version = excluded.last_version, model_mappings_json = excluded.model_mappings_json
          `).run(payload.orgId, payload.version, mappingsJson);
        } else {
          db.prepare(`
            INSERT INTO org_policy_versions (org_id, last_version)
            VALUES (?, ?)
            ON CONFLICT(org_id) DO UPDATE SET last_version = excluded.last_version
          `).run(payload.orgId, payload.version);
        }

        db.exec("COMMIT");
      } catch (txErr) {
        try {
          db.exec("ROLLBACK");
        } catch {}
        throw txErr;
      }

      return {
        success: true,
        appliedRevocations: revCount,
        appliedBudgetUpdates: budCount,
        appliedModelMappings: mapCount,
      };
    } catch (err: any) {
      return { success: false, appliedRevocations: 0, appliedBudgetUpdates: 0, appliedModelMappings: 0, error: err?.message ?? "SYNC_EXECUTION_ERROR" };
    }
  }

  public static signPolicyPayload(payload: ControlPlanePolicyPayload, secretHex: string): { signedJson: string; signature: string } {
    const json = JSON.stringify(payload);
    const signature = crypto.createHmac("sha256", Buffer.from(secretHex, "hex")).update(json, "utf8").digest("hex");
    return { signedJson: json, signature };
  }
}