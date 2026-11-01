import crypto from "node:crypto";
import type { DatabaseSync } from "node:sqlite";

export const AUDIT_DOMAIN_SEPARATOR = "AINDIGO_AUDIT_V1";

export interface AuditRecord {
  seq: number;
  id: string;
  timestamp: number;
  eventType: string;
  orgId: string;
  virtualKeyId: string;
  payload: Record<string, unknown>;
  prevHash: string;
  hash: string;
  signature: string;
}

export interface VerificationResult {
  valid: boolean;
  brokenSeq?: number;
  error?: "PREV_HASH_MISMATCH" | "RECORD_HASH_TAMPERED" | "SIGNATURE_MALFORMED" | "SIGNATURE_MISMATCH";
  message?: string;
}

export interface SiemDestinationConfig {
  endpointUrl: string;
  authHeaderName: string;
  authHeaderValue: string;
  format: "splunk_hec" | "sentinel" | "generic";
  timeoutMs?: number;
  maxRetries?: number;
}

export interface SiemDispatchResult {
  success: boolean;
  statusCode?: number;
  attempts: number;
  error?: string;
}

/**
 * Fully recursive canonical JSON serializer.
 * - Sorts keys at every object level recursively.
 * - Preserves array order.
 * - Rejects undefined, functions, symbols, BigInt, non-finite numbers, cyclic objects, and unsupported object types.
 */
export function canonicalJsonStringify(val: unknown, seen = new Set<unknown>()): string {
  if (val === null || val === undefined) {
    if (val === undefined) {
      throw new Error("CANONICAL_JSON_ERROR: undefined values are not supported.");
    }
    return "null";
  }

  const t = typeof val;
  if (t === "boolean" || t === "string") {
    return JSON.stringify(val);
  }

  if (t === "number") {
    if (!Number.isFinite(val)) {
      throw new Error("CANONICAL_JSON_ERROR: non-finite numbers (NaN, Infinity) are not supported.");
    }
    return JSON.stringify(val);
  }

  if (t === "bigint" || t === "symbol" || t === "function") {
    throw new Error(`CANONICAL_JSON_ERROR: type '${t}' is not supported.`);
  }

  if (typeof val === "object") {
    if (
      val instanceof Date ||
      val instanceof Map ||
      val instanceof Set ||
      val instanceof RegExp ||
      val instanceof Error
    ) {
      throw new Error(`CANONICAL_JSON_ERROR: unsupported object type '${val.constructor.name}'.`);
    }

    if (seen.has(val)) {
      throw new Error("CANONICAL_JSON_ERROR: cyclic object detected.");
    }
    seen.add(val);

    try {
      if (Array.isArray(val)) {
        const items = val.map((item) => canonicalJsonStringify(item, seen));
        return "[" + items.join(",") + "]";
      }

      const proto = Object.getPrototypeOf(val);
      if (proto !== Object.prototype && proto !== null) {
        throw new Error("CANONICAL_JSON_ERROR: only plain objects and arrays are supported.");
      }

      const keys = Object.keys(val as Record<string, unknown>).sort();
      const pairs: string[] = [];
      for (const k of keys) {
        const v = (val as Record<string, unknown>)[k];
        if (v === undefined) {
          throw new Error("CANONICAL_JSON_ERROR: undefined values are not supported.");
        }
        pairs.push(JSON.stringify(k) + ":" + canonicalJsonStringify(v, seen));
      }
      return "{" + pairs.join(",") + "}";
    } finally {
      seen.delete(val);
    }
  }

  throw new Error(`CANONICAL_JSON_ERROR: unsupported type '${t}'.`);
}

export class AuditChainManager {
  private db: DatabaseSync;
  private hmacSecret: Buffer;

  constructor(db: DatabaseSync, hmacSecretHex: string) {
    this.db = db;

    if (!hmacSecretHex || typeof hmacSecretHex !== "string" || !/^[0-9a-fA-F]{64,}$/.test(hmacSecretHex)) {
      throw new Error("AUDIT_CONFIG_ERROR: hmacSecretHex must be a valid hex string with at least 64 hex characters (32 bytes).");
    }

    const secretBuf = Buffer.from(hmacSecretHex, "hex");
    if (secretBuf.length < 32) {
      throw new Error("AUDIT_CONFIG_ERROR: HMAC secret must provide at least 32 bytes of entropy.");
    }

    const isWeak = secretBuf.every((b) => b === 0) || secretBuf.every((b) => b === 0xff);
    if (isWeak) {
      throw new Error("AUDIT_CONFIG_ERROR: Weak or trivial HMAC secret detected.");
    }

    this.hmacSecret = secretBuf;
    this.initSchema();
  }

  private initSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS tamper_evident_audit_chain (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        id TEXT NOT NULL UNIQUE,
        timestamp INTEGER NOT NULL,
        event_type TEXT NOT NULL,
        org_id TEXT NOT NULL,
        virtual_key_id TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        prev_hash TEXT NOT NULL,
        hash TEXT NOT NULL,
        signature TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_audit_seq ON tamper_evident_audit_chain(seq);
    `);
  }

  private runInTransaction<T>(fn: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = fn();
      this.db.exec("COMMIT");
      return result;
    } catch (err) {
      try {
        this.db.exec("ROLLBACK");
      } catch {}
      throw err;
    }
  }

  private getLatestHash(): string {
    const row = this.db.prepare(`
      SELECT hash FROM tamper_evident_audit_chain ORDER BY seq DESC LIMIT 1
    `).get() as { hash: string } | undefined;

    return row ? row.hash : "0000000000000000000000000000000000000000000000000000000000000000";
  }

  public recordEvent(
    eventType: string,
    orgId: string,
    virtualKeyId: string,
    payload: Record<string, unknown>,
    nowMs: number = Date.now()
  ): AuditRecord {
    return this.runInTransaction(() => {
      const id = `aud_${crypto.randomBytes(12).toString("hex")}`;
      const prevHash = this.getLatestHash();
      const canonicalPayload = canonicalJsonStringify(payload);

      const hashInput = [
        AUDIT_DOMAIN_SEPARATOR,
        id,
        String(nowMs),
        eventType,
        orgId,
        virtualKeyId,
        canonicalPayload,
        prevHash,
      ].join("|");

      const hash = crypto.createHash("sha256").update(hashInput, "utf8").digest("hex");
      const signature = crypto.createHmac("sha256", this.hmacSecret).update(hash, "utf8").digest("hex");

      const info = this.db.prepare(`
        INSERT INTO tamper_evident_audit_chain (
          id, timestamp, event_type, org_id, virtual_key_id, payload_json, prev_hash, hash, signature
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(id, nowMs, eventType, orgId, virtualKeyId, canonicalPayload, prevHash, hash, signature);

      return {
        seq: Number(info.lastInsertRowid),
        id,
        timestamp: nowMs,
        eventType,
        orgId,
        virtualKeyId,
        payload,
        prevHash,
        hash,
        signature,
      };
    });
  }

  public verifyChain(): VerificationResult {
    const rows = this.db.prepare(`
      SELECT * FROM tamper_evident_audit_chain ORDER BY seq ASC
    `).all() as Array<any>;

    let expectedPrevHash = "0000000000000000000000000000000000000000000000000000000000000000";

    for (const row of rows) {
      if (row.prev_hash !== expectedPrevHash) {
        return { valid: false, brokenSeq: row.seq, error: "PREV_HASH_MISMATCH", message: "Previous hash pointer mismatch." };
      }

      const hashInput = [
        AUDIT_DOMAIN_SEPARATOR,
        row.id,
        String(row.timestamp),
        row.event_type,
        row.org_id,
        row.virtual_key_id,
        row.payload_json,
        row.prev_hash,
      ].join("|");

      const computedHash = crypto.createHash("sha256").update(hashInput, "utf8").digest("hex");

      if (computedHash !== row.hash) {
        return { valid: false, brokenSeq: row.seq, error: "RECORD_HASH_TAMPERED", message: "Hash recalculation failed." };
      }

      const computedSig = crypto.createHmac("sha256", this.hmacSecret).update(row.hash, "utf8").digest("hex");

      if (typeof row.signature !== "string" || !/^[0-9a-fA-F]{64}$/.test(row.signature)) {
        return { valid: false, brokenSeq: row.seq, error: "SIGNATURE_MALFORMED", message: "Stored signature is malformed." };
      }

      const storedSigBuf = Buffer.from(row.signature, "hex");
      const computedSigBuf = Buffer.from(computedSig, "hex");

      if (storedSigBuf.length !== computedSigBuf.length || !crypto.timingSafeEqual(storedSigBuf, computedSigBuf)) {
        return { valid: false, brokenSeq: row.seq, error: "SIGNATURE_MISMATCH", message: "HMAC signature verification failed." };
      }

      expectedPrevHash = row.hash;
    }

    return { valid: true };
  }

  public static async dispatchToSiem(
    records: AuditRecord[],
    config: SiemDestinationConfig,
    fetchImpl: typeof fetch = globalThis.fetch
  ): Promise<SiemDispatchResult> {
    if (!records || records.length === 0) {
      return { success: true, attempts: 0 };
    }

    let bodyData: unknown;
    if (config.format === "splunk_hec") {
      bodyData = records.map((r) => ({
        time: Math.floor(r.timestamp / 1000),
        host: "aindigo-gateway",
        source: `aindigo:audit:${r.orgId}`,
        sourcetype: "aindigo:security:audit",
        event: {
          seq: r.seq,
          id: r.id,
          eventType: r.eventType,
          orgId: r.orgId,
          virtualKeyId: r.virtualKeyId,
          payload: r.payload,
          prevHash: r.prevHash,
          hash: r.hash,
          signature: r.signature,
        },
      }));
    } else if (config.format === "sentinel") {
      bodyData = records.map((r) => ({
        TimeGenerated: new Date(r.timestamp).toISOString(),
        RecordId: r.id,
        SequenceNumber: r.seq,
        EventType: r.eventType,
        OrganizationId: r.orgId,
        VirtualKeyId: r.virtualKeyId,
        AuditPayload: JSON.stringify(r.payload),
        PreviousHash: r.prevHash,
        RecordHash: r.hash,
        HmacSignature: r.signature,
      }));
    } else {
      bodyData = records;
    }

    const payloadString = JSON.stringify(bodyData);
    const maxRetries = config.maxRetries ?? 3;
    const timeoutMs = config.timeoutMs ?? 10000;

    let attempts = 0;
    let lastError = "UNKNOWN_ERROR";

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      attempts = attempt;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);

      try {
        const response = await fetchImpl(config.endpointUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            [config.authHeaderName]: config.authHeaderValue,
          },
          body: payloadString,
          signal: controller.signal,
        });

        clearTimeout(timer);

        if (response.ok) {
          return { success: true, statusCode: response.status, attempts };
        } else {
          lastError = `HTTP_${response.status}`;
          if (response.status < 500) {
            return { success: false, statusCode: response.status, attempts, error: lastError };
          }
        }
      } catch (err: any) {
        clearTimeout(timer);
        lastError = err?.message ?? "NETWORK_ERROR";
      }

      if (attempt < maxRetries) {
        const delay = Math.min(1000 * Math.pow(2, attempt - 1), 10000);
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }

    return { success: false, attempts, error: lastError };
  }

  public static signWebhookPayload(payload: string, secretHex: string): string {
    const secret = Buffer.from(secretHex, "hex");
    return `sha256=${crypto.createHmac("sha256", secret).update(payload, "utf8").digest("hex")}`;
  }
}