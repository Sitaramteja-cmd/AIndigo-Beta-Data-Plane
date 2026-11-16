import crypto from "node:crypto";
import fs from "node:fs";
import util from "node:util";
import { DatabaseSync, StatementSync } from "node:sqlite";

export type BudgetPeriod = "monthly" | "lifetime";

export const MICROS_PER_USD = 1_000_000;
export const DEFAULT_RESERVATION_TTL_MS = 10 * 60 * 1000; // 10 minutes
export const VAULT_INSTANCE_LEASE_DURATION_MS = 45 * 1000; // 45 seconds
export const VAULT_INSTANCE_HEARTBEAT_INTERVAL_MS = 10 * 1000; // 10 seconds
export const VAULT_INSTANCE_RECOVERY_GRACE_MS = 30 * 1000; // 30 seconds

export function usdToMicros(usd: number): number {
  if (typeof usd !== "number" || !Number.isFinite(usd) || usd < 0) {
    throw new Error("VAULT_AMOUNT_ERROR: USD amount must be a non-negative finite number.");
  }
  return Math.round(usd * MICROS_PER_USD);
}

export function microsToUsd(micros: number): number {
  return Number((micros / MICROS_PER_USD).toFixed(6));
}

export interface VirtualKeyMetadata {
  id: string;
  org_id: string;
  name: string;
  key_prefix: string;
  provider: string;
  allowed_models: string[];
  key_version: number;
  budget_limit_micros: number;
  current_spend_micros: number;
  reserved_micros: number;
  budget_limit_usd: number;
  current_spend_usd: number;
  reserved_usd: number;
  budget_period: BudgetPeriod;
  period_reset_at: number;
  expires_at: number | null;
  revoked_at: number | null;
  last_used_at: number | null;
  created_at: number;
}

export interface CreateVirtualKeyInput {
  org_id: string;
  name: string;
  provider: "openai" | "anthropic" | "gemini" | string;
  allowed_models: string[];
  raw_provider_key: string;
  budget_limit_usd: number;
  budget_period?: BudgetPeriod;
  expires_at?: number | null;
  nowMs?: number;
}

export interface ReservationHandle {
  reservation_id: string;
  record_id: string;
  org_id: string;
  period_id: string;
  model: string;
  reserved_micros: number;
  created_at: number;
}

export interface AuthorizeOptions {
  rawVirtualKey: string;
  requestedModel: string;
  downshiftedModel?: string;
  estimatedCostUsd: number;
  nowMs?: number;
}

export type AuthorizeFailureReason =
  | "INVALID_KEY"
  | "REVOKED_KEY"
  | "EXPIRED_KEY"
  | "MODEL_NOT_ALLOWED"
  | "BUDGET_EXCEEDED"
  | "BAD_REQUEST_AMOUNT"
  | "VAULT_DECRYPT_ERROR"
  | "VAULT_INTERNAL_ERROR";

export interface AuthorizeResult {
  valid: boolean;
  reason?: AuthorizeFailureReason;
  reservation_id?: string;
  record_id?: string;
  org_id?: string;
  provider?: string;
  effective_model?: string;
  key_prefix?: string;
  reserved_micros?: number;
  reserved_usd?: number;
  getProviderKey?: () => string;
}

export interface SpendLedgerEntry {
  id: string;
  key_id: string;
  org_id: string;
  ts: number;
  reserved_micros: number;
  actual_micros: number;
  model: string;
  receipt_id: string | null;
}

export interface VaultDiagnosticEvent {
  code: "VAULT_DECRYPT_ERROR" | "VAULT_INTERNAL_ERROR";
  errorClass: string;
  recordId: string | null;
}

class VaultDecryptException extends Error {
  public readonly recordId: string;
  public readonly causeClass: string;
  constructor(recordId: string, causeClass: string) {
    super("VAULT_DECRYPT_ERROR");
    this.name = "VaultDecryptException";
    this.recordId = recordId;
    this.causeClass = causeClass;
  }
}

function getNextMonthlyReset(nowMs: number): number {
  const d = new Date(nowMs);
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 1, 0, 0, 0, 0);
}

export function estimateRequestCostUsd(params: {
  inputTokens: number;
  maxOutputTokens?: number;
  inputPricePerMillionUsd: number;
  outputPricePerMillionUsd: number;
  defaultMaxOutputTokens?: number;
}): number {
  const safeInputTokens = Math.max(0, params.inputTokens);
  const safeOutputTokens = Math.max(
    1,
    params.maxOutputTokens ?? params.defaultMaxOutputTokens ?? 4096
  );
  const inputCost = (safeInputTokens / 1_000_000) * params.inputPricePerMillionUsd;
  const outputCost = (safeOutputTokens / 1_000_000) * params.outputPricePerMillionUsd;
  return Number((inputCost + outputCost).toFixed(6));
}

export class VirtualKeyVault {
  private readonly instanceId: string = crypto.randomUUID();
  private heartbeatTimer: NodeJS.Timeout | null = null;
  private leaseHealthy = false;
  private closed = false;
  private db: DatabaseSync;
  private masterKeys: Map<number, Buffer> = new Map();
  private activeKeyVersion: number;
  private inFlightReservations: Map<string, ReservationHandle> = new Map();
  private onDiagnosticError: (event: VaultDiagnosticEvent) => void;

  // Pre-compiled SQLite statements
  private stmtInsertKey!: StatementSync;
  private stmtGetByHash!: StatementSync;
  private stmtGetById!: StatementSync;
  private stmtRolloverPeriod!: StatementSync;
  private stmtInsertLedger!: StatementSync;
  private stmtRevokeKey!: StatementSync;
  private stmtGetLedgerByKey!: StatementSync;

  constructor(
    keyRingOrHex: string | Record<number, string> | Map<number, string>,
    dbPath: string = ":memory:",
    activeKeyVersion?: number,
    onDiagnosticError?: (event: VaultDiagnosticEvent) => void
  ) {
    if (typeof keyRingOrHex === "string") {
      const targetVer = activeKeyVersion ?? 1;
      this.validateAndLoadKey(targetVer, keyRingOrHex);
      this.activeKeyVersion = targetVer;
    } else if (keyRingOrHex instanceof Map) {
      for (const [ver, hex] of keyRingOrHex.entries()) {
        this.validateAndLoadKey(Number(ver), hex);
      }
      if (this.masterKeys.size === 0) {
        throw new Error("VAULT_INIT_ERROR: Master key ring cannot be empty.");
      }
      this.activeKeyVersion = activeKeyVersion ?? Math.max(...this.masterKeys.keys());
    } else if (keyRingOrHex && typeof keyRingOrHex === "object") {
      for (const [ver, hex] of Object.entries(keyRingOrHex)) {
        this.validateAndLoadKey(Number(ver), hex);
      }
      if (this.masterKeys.size === 0) {
        throw new Error("VAULT_INIT_ERROR: Master key ring cannot be empty.");
      }
      this.activeKeyVersion = activeKeyVersion ?? Math.max(...this.masterKeys.keys());
    } else {
      throw new Error("VAULT_INIT_ERROR: Master key configuration is required.");
    }

    if (!this.masterKeys.has(this.activeKeyVersion)) {
      throw new Error(
        `VAULT_INIT_ERROR: Active master key version ${this.activeKeyVersion} is not loaded in the key ring.`
      );
    }

    this.onDiagnosticError =
      onDiagnosticError ??
      ((evt) => {
        console.error(
          `[AIndigo Vault Diagnostic] code=${evt.code} class=${evt.errorClass} record_id=${evt.recordId ?? "unknown"}`
        );
      });

    this.db = new DatabaseSync(dbPath);
    if (dbPath !== ":memory:" && fs.existsSync(dbPath)) {
      try {
        fs.chmodSync(dbPath, 0o600);
      } catch {
        // Ignore chmod limitations on Windows non-POSIX filesystems
      }
    }

        // Wait for competing SQLite writers instead of immediately returning SQLITE_BUSY.
    // Each process has its own connection and therefore its own busy timeout.
    this.db.exec("PRAGMA busy_timeout = 5000;");

    this.db.exec("PRAGMA journal_mode = WAL;");
    this.db.exec("PRAGMA synchronous = NORMAL;");
    this.db.exec("PRAGMA foreign_keys = ON;");

    this.initSchema();
    this.migrateDurableBudgetReservations();
    this.migrateReservationOwnership();
    this.prepareStatements();
    this.runStartupSelfChecks();
    this.registerInstanceLease(Date.now());
    this.leaseHealthy = true;
    this.startHeartbeat();
  }

  public getActiveKeyVersion(): number {
    return this.activeKeyVersion;
  }

  /**
   * Executes a synchronous callback inside an atomic SQLite `BEGIN IMMEDIATE` transaction.
   * Rolls back automatically if an exception is thrown.
   */
  private runInTransaction<T>(fn: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = fn();
      this.db.exec("COMMIT");
      return result;
    } catch (err) {
      try {
        this.db.exec("ROLLBACK");
      } catch {
        // Ignore rollback error if transaction was already rolled back
      }
      throw err;
    }
  }

  private validateAndLoadKey(version: number, hex: string): void {
    if (!Number.isInteger(version) || version < 1) {
      throw new Error(`VAULT_INIT_ERROR: Invalid key version '${version}'.`);
    }
    if (!hex || typeof hex !== "string" || !/^[0-9a-fA-F]{64}$/.test(hex)) {
      throw new Error(
        `VAULT_INIT_ERROR: Master key for version ${version} must be a 64-character hex string (32 bytes).`
      );
    }
    this.masterKeys.set(version, Buffer.from(hex, "hex"));
  }

  private initSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS virtual_keys (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        name TEXT NOT NULL,
        key_prefix TEXT NOT NULL,
        key_hash TEXT NOT NULL UNIQUE,
        provider TEXT NOT NULL,
        allowed_models TEXT NOT NULL,
        encrypted_provider_key TEXT NOT NULL,
        iv TEXT NOT NULL,
        auth_tag TEXT NOT NULL,
        key_version INTEGER NOT NULL DEFAULT 1,
        budget_limit_micros INTEGER NOT NULL,
        current_spend_micros INTEGER NOT NULL DEFAULT 0,
        reserved_micros INTEGER NOT NULL DEFAULT 0,
        budget_period TEXT NOT NULL DEFAULT 'monthly',
        period_reset_at INTEGER NOT NULL,
        expires_at INTEGER,
        revoked_at INTEGER,
        last_used_at INTEGER,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_virtual_keys_hash ON virtual_keys(key_hash);
      CREATE INDEX IF NOT EXISTS idx_virtual_keys_org ON virtual_keys(org_id);

      CREATE TABLE IF NOT EXISTS spend_ledger (
        id TEXT PRIMARY KEY,
        key_id TEXT NOT NULL,
        org_id TEXT NOT NULL,
        ts INTEGER NOT NULL,
        reserved_micros INTEGER NOT NULL,
        actual_micros INTEGER NOT NULL,
        model TEXT NOT NULL,
        receipt_id TEXT,
        FOREIGN KEY (key_id) REFERENCES virtual_keys(id)
      );
      CREATE INDEX IF NOT EXISTS idx_spend_ledger_key_ts ON spend_ledger(key_id, ts);
      CREATE TABLE IF NOT EXISTS budget_period_usage (
        key_id TEXT NOT NULL,
        period_id TEXT NOT NULL,
        budget_limit_micros INTEGER NOT NULL,
        spent_micros INTEGER NOT NULL DEFAULT 0,
        reserved_micros INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (key_id, period_id),
        FOREIGN KEY (key_id) REFERENCES virtual_keys(id),
        CHECK (budget_limit_micros >= 0),
        CHECK (spent_micros >= 0),
        CHECK (reserved_micros >= 0)
      );

      CREATE TABLE IF NOT EXISTS budget_reservations (
        reservation_id TEXT PRIMARY KEY,
        key_id TEXT NOT NULL,
        org_id TEXT NOT NULL,
        period_id TEXT NOT NULL,
        model TEXT NOT NULL,
        reserved_micros INTEGER NOT NULL,
        actual_micros INTEGER,
        status TEXT NOT NULL,
        receipt_id TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        settled_at INTEGER,
        legacy INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY (key_id) REFERENCES virtual_keys(id),
        CHECK (reserved_micros >= 0),
        CHECK (actual_micros IS NULL OR actual_micros >= 0),
        CHECK (status IN ('RESERVED', 'UNCERTAIN', 'SETTLED', 'RELEASED')),
        CHECK (legacy IN (0, 1))
      );

      CREATE INDEX IF NOT EXISTS idx_budget_reservations_key_period
        ON budget_reservations(key_id, period_id);

      CREATE INDEX IF NOT EXISTS idx_budget_reservations_status_created
        ON budget_reservations(status, created_at);

      CREATE TABLE IF NOT EXISTS vault_migrations (
        migration_id TEXT PRIMARY KEY,
        applied_at INTEGER NOT NULL
      );
    `);
  }


  private migrateDurableBudgetReservations(): void {
    const migrationId = "durable_budget_reservations_v1";

    this.runInTransaction(() => {
      const applied = this.db
        .prepare(
          `SELECT migration_id FROM vault_migrations WHERE migration_id = ?`
        )
        .get(migrationId) as { migration_id: string } | undefined;

      if (applied) {
        return;
      }

      const keys = this.db
        .prepare(`SELECT * FROM virtual_keys ORDER BY id ASC`)
        .all() as any[];

      const insertUsage = this.db.prepare(`
        INSERT INTO budget_period_usage (
          key_id, period_id, budget_limit_micros,
          spent_micros, reserved_micros, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `);

      const insertLegacyReservation = this.db.prepare(`
        INSERT INTO budget_reservations (
          reservation_id, key_id, org_id, period_id, model,
          reserved_micros, actual_micros, status, receipt_id,
          created_at, updated_at, settled_at, legacy
        )
        VALUES (?, ?, ?, ?, ?, ?, NULL, 'UNCERTAIN', NULL, ?, ?, NULL, 1)
      `);

      const migrationNow = Date.now();

      for (const row of keys) {
        const keyId = String(row.id);
        const orgId = String(row.org_id);
        const budgetPeriod = String(row.budget_period);

        const budgetLimitMicros = Number(row.budget_limit_micros);
        const spentMicros = Number(row.current_spend_micros);
        const reservedMicros = Number(row.reserved_micros);
        const createdAt = Number(row.created_at);

        for (const [field, value] of [
          ["budget_limit_micros", budgetLimitMicros],
          ["current_spend_micros", spentMicros],
          ["reserved_micros", reservedMicros],
          ["created_at", createdAt],
        ] as const) {
          if (!Number.isSafeInteger(value) || value < 0) {
            throw new Error(
              `VAULT_MIGRATION_ERROR: Invalid ${field} for key ${keyId}.`
            );
          }
        }

        let periodId: string;
let migratedSpendMicros = spentMicros;

if (budgetPeriod === "lifetime") {
  periodId = "lifetime";
} else if (budgetPeriod === "monthly") {
  const resetAt = Number(row.period_reset_at);
  const resetDate = new Date(resetAt);

  if (
    !Number.isSafeInteger(resetAt) ||
    !Number.isFinite(resetDate.getTime()) ||
    resetDate.getUTCDate() !== 1 ||
    resetDate.getUTCHours() !== 0 ||
    resetDate.getUTCMinutes() !== 0 ||
    resetDate.getUTCSeconds() !== 0 ||
    resetDate.getUTCMilliseconds() !== 0
  ) {
    throw new Error(
      `VAULT_MIGRATION_ERROR: Invalid monthly period reset for key ${keyId}.`
    );
  }

  const periodDate =
    resetAt <= migrationNow
      ? new Date(migrationNow)
      : new Date(
          Date.UTC(
            resetDate.getUTCFullYear(),
            resetDate.getUTCMonth() - 1,
            1
          )
        );

  const year = periodDate.getUTCFullYear();
  const month = String(periodDate.getUTCMonth() + 1).padStart(2, "0");

  periodId = `monthly:${year}-${month}`;

  if (resetAt <= migrationNow) {
    migratedSpendMicros = 0;
  }
} else {
  throw new Error(
    `VAULT_MIGRATION_ERROR: Unsupported budget period for key ${keyId}.`
  );
}

        insertUsage.run(
          keyId,
          periodId,
          budgetLimitMicros,
          migratedSpendMicros,
          reservedMicros,
          createdAt,
          migrationNow
        );

        if (reservedMicros > 0) {
          insertLegacyReservation.run(
            `legacy_${keyId}`,
            keyId,
            orgId,
            periodId,
            "LEGACY_UNKNOWN",
            reservedMicros,
            createdAt,
            migrationNow
          );
        }
      }

      this.db.prepare(`
        INSERT INTO vault_migrations (migration_id, applied_at)
        VALUES (?, ?)
      `).run(migrationId, migrationNow);
    });
  }


  private migrateReservationOwnership(): void {
    const migrationId = "reservation_ownership_v1";
    const migrationNow = Date.now();

    this.runInTransaction(() => {
      const applied = this.db
        .prepare(
          `SELECT migration_id FROM vault_migrations WHERE migration_id = ?`
        )
        .get(migrationId) as { migration_id: string } | undefined;

      if (applied) {
        return;
      }

      const columns = this.db
        .prepare(`PRAGMA table_info(budget_reservations)`)
        .all() as Array<{ name: string }>;

      const hasOwnerId = columns.some(
        (column) => column.name === "owner_id"
      );

      if (!hasOwnerId) {
        this.db.exec(`
          ALTER TABLE budget_reservations
          ADD COLUMN owner_id TEXT;
        `);
      }

      this.db.exec(`
        CREATE TABLE IF NOT EXISTS vault_instances (
          instance_id TEXT PRIMARY KEY,
          created_at INTEGER NOT NULL,
          heartbeat_at INTEGER NOT NULL,
          lease_expires_at INTEGER NOT NULL,
          released_at INTEGER
        );

        CREATE INDEX IF NOT EXISTS idx_budget_reservations_owner_status
          ON budget_reservations(owner_id, status);
      `);

      // Existing reservations have no provable live owner.
      // Preserve their budget holds and mark them uncertain.
      this.db.prepare(`
        UPDATE budget_reservations
        SET status = 'UNCERTAIN',
            updated_at = ?
        WHERE status = 'RESERVED'
          AND owner_id IS NULL
      `).run(migrationNow);

      this.db.prepare(`
        INSERT INTO vault_migrations (migration_id, applied_at)
        VALUES (?, ?)
      `).run(migrationId, migrationNow);
    });
  }

  private registerInstanceLease(nowMs: number): void {
    this.runInTransaction(() => {
      this.db.prepare(`
        INSERT INTO vault_instances (
          instance_id,
          created_at,
          heartbeat_at,
          lease_expires_at,
          released_at
        )
        VALUES (?, ?, ?, ?, NULL)
      `).run(
        this.instanceId,
        nowMs,
        nowMs,
        nowMs + VAULT_INSTANCE_LEASE_DURATION_MS
      );
    });
  }

  private startHeartbeat(): void {
    if (this.heartbeatTimer || this.closed) {
      return;
    }

    this.heartbeatTimer = setInterval(
      () => this.renewInstanceLease(),
      VAULT_INSTANCE_HEARTBEAT_INTERVAL_MS
    );

    this.heartbeatTimer.unref();
  }

  private renewInstanceLease(): void {
    if (this.closed) {
      return;
    }

    try {
      const nowMs = Date.now();

      const result = this.runInTransaction(() => {
        return this.db.prepare(`
          UPDATE vault_instances
          SET heartbeat_at = ?,
              lease_expires_at = ?
          WHERE instance_id = ?
            AND released_at IS NULL
            AND lease_expires_at > ?
        `).run(
          nowMs,
          nowMs + VAULT_INSTANCE_LEASE_DURATION_MS,
          this.instanceId,
          nowMs
        );
      });

      if (Number(result.changes) !== 1) {
        this.leaseHealthy = false;
        this.reportHeartbeatFailure("LeaseNotRenewable");
        return;
      }

      this.leaseHealthy = true;
    } catch (error) {
      this.leaseHealthy = false;
      this.reportHeartbeatFailure(
        error instanceof Error ? error.constructor.name : "UnknownError"
      );
    }
  }

  private reportHeartbeatFailure(errorClass: string): void {
    try {
      this.onDiagnosticError({
        code: "VAULT_INTERNAL_ERROR",
        errorClass,
        recordId: null,
      });
    } catch {
      // Diagnostic callbacks must not interrupt Vault lifecycle management.
    }
  }

  private prepareStatements(): void {
    this.stmtInsertKey = this.db.prepare(`
      INSERT INTO virtual_keys (
        id, org_id, name, key_prefix, key_hash, provider, allowed_models,
        encrypted_provider_key, iv, auth_tag, key_version,
        budget_limit_micros, current_spend_micros, reserved_micros,
        budget_period, period_reset_at, expires_at, revoked_at, last_used_at, created_at
      ) VALUES (
        ?, ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, 0, 0,
        ?, ?, ?, NULL, NULL, ?
      )
    `);

    this.stmtGetByHash = this.db.prepare(`SELECT * FROM virtual_keys WHERE key_hash = ?`);
    this.stmtGetById = this.db.prepare(`SELECT * FROM virtual_keys WHERE id = ?`);

    this.stmtRolloverPeriod = this.db.prepare(`
      UPDATE virtual_keys
      SET current_spend_micros = 0, period_reset_at = ?
      WHERE id = ?
    `);

    this.stmtInsertLedger = this.db.prepare(`
      INSERT INTO spend_ledger (id, key_id, org_id, ts, reserved_micros, actual_micros, model, receipt_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    this.stmtRevokeKey = this.db.prepare(`
      UPDATE virtual_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL
    `);

    this.stmtGetLedgerByKey = this.db.prepare(`
      SELECT * FROM spend_ledger WHERE key_id = ? ORDER BY ts ASC
    `);
  }

  private runStartupSelfChecks(): void {
    const versions = this.db
      .prepare(`SELECT DISTINCT key_version FROM virtual_keys`)
      .all() as Array<{ key_version: number }>;

    let maxDbVersion = 0;
    for (const row of versions) {
      const ver = Number(row.key_version);
      if (!this.masterKeys.has(ver)) {
        this.db.close();
        throw new Error(
          `VAULT_KEY_VERSION_MISMATCH: Database contains rows encrypted with key_version=${ver}, but that master key is not loaded.`
        );
      }
      if (ver > maxDbVersion) {
        maxDbVersion = ver;
      }
    }

    if (maxDbVersion > this.activeKeyVersion) {
      this.db.close();
      throw new Error(
        `VAULT_KEY_VERSION_DOWNGRADE: activeKeyVersion (${this.activeKeyVersion}) cannot be lower than highest database key_version (${maxDbVersion}).`
      );
    }
  }

  public static hashVirtualKey(rawVirtualKey: string): string {
    return crypto.createHash("sha256").update(rawVirtualKey, "utf8").digest("hex");
  }

  private buildAAD(id: string, orgId: string, keyVersion: number): Buffer {
    return Buffer.from(`${id}:${orgId}:${keyVersion}`, "utf8");
  }

  public encryptProviderKey(
    rawProviderKey: string,
    id: string,
    orgId: string,
    keyVersion: number = this.activeKeyVersion
  ): { encrypted: string; iv: string; authTag: string; keyVersion: number } {
    const key = this.masterKeys.get(keyVersion);
    if (!key) {
      throw new Error(`VAULT_CRYPTO_ERROR: Unknown master key version ${keyVersion}`);
    }

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    cipher.setAAD(this.buildAAD(id, orgId, keyVersion));

    let encrypted = cipher.update(rawProviderKey, "utf8", "hex");
    encrypted += cipher.final("hex");
    const authTag = cipher.getAuthTag().toString("hex");

    return {
      encrypted,
      iv: iv.toString("hex"),
      authTag,
      keyVersion,
    };
  }

  public decryptProviderKey(record: {
    id: string;
    org_id: string;
    key_version: number;
    encrypted_provider_key: string;
    iv: string;
    auth_tag: string;
  }): string {
    const ver = Number(record.key_version);
    const key = this.masterKeys.get(ver);
    if (!key) {
      throw new Error(`VAULT_CRYPTO_ERROR: Master key version ${ver} not loaded`);
    }

    const iv = Buffer.from(record.iv, "hex");
    const authTag = Buffer.from(record.auth_tag, "hex");
    if (iv.length !== 12 || authTag.length !== 16) {
      throw new Error("VAULT_CRYPTO_ERROR: Invalid IV or AuthTag length");
    }

    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAAD(this.buildAAD(record.id, record.org_id, ver));
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(record.encrypted_provider_key, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  }

  public createVirtualKey(input: CreateVirtualKeyInput): {
    rawVirtualKey: string;
    metadata: VirtualKeyMetadata;
  } {
    const now = input.nowMs ?? Date.now();

    if (!input.org_id || typeof input.org_id !== "string" || input.org_id.trim().length === 0) {
      throw new Error("VAULT_VALIDATION_ERROR: org_id must be a non-empty string.");
    }
    if (!input.name || typeof input.name !== "string" || input.name.trim().length === 0) {
      throw new Error("VAULT_VALIDATION_ERROR: name must be a non-empty string.");
    }
    if (!input.provider || typeof input.provider !== "string" || input.provider.trim().length === 0) {
      throw new Error("VAULT_VALIDATION_ERROR: provider must be a non-empty string.");
    }
    if (
      !input.raw_provider_key ||
      typeof input.raw_provider_key !== "string" ||
      input.raw_provider_key.trim().length === 0
    ) {
      throw new Error("VAULT_VALIDATION_ERROR: raw_provider_key must be a non-empty string.");
    }
    if (
      !Array.isArray(input.allowed_models) ||
      input.allowed_models.length === 0 ||
      input.allowed_models.some((m) => typeof m !== "string" || m.trim().length === 0)
    ) {
      throw new Error("VAULT_VALIDATION_ERROR: allowed_models must be a non-empty array of model identifiers.");
    }
    if (input.expires_at !== undefined && input.expires_at !== null) {
      if (!Number.isFinite(input.expires_at) || input.expires_at <= now) {
        throw new Error("VAULT_VALIDATION_ERROR: expires_at must be a future timestamp.");
      }
    }

    const budget_limit_micros = usdToMicros(input.budget_limit_usd);

    const id = `vk_rec_${crypto.randomBytes(12).toString("hex")}`;
    const secretHex = crypto.randomBytes(24).toString("hex");
    const rawVirtualKey = `vk-aindigo-${secretHex}`;
    const key_prefix = `vk-aindigo-${secretHex.slice(0, 6)}...${secretHex.slice(-4)}`;
    const key_hash = VirtualKeyVault.hashVirtualKey(rawVirtualKey);

    const normalizedOrgId = input.org_id.trim();
    const normalizedName = input.name.trim();
    const normalizedProvider = input.provider.trim();
    const normalizedModels = input.allowed_models.map((m) => m.trim());

    const { encrypted, iv, authTag, keyVersion } = this.encryptProviderKey(
      input.raw_provider_key,
      id,
      normalizedOrgId,
      this.activeKeyVersion
    );

    const budget_period: BudgetPeriod = input.budget_period ?? "monthly";
    const period_reset_at =
      budget_period === "monthly" ? getNextMonthlyReset(now) : Number.MAX_SAFE_INTEGER;

        const periodDate = new Date(now);
    const year = periodDate.getUTCFullYear();
    const month = String(periodDate.getUTCMonth() + 1).padStart(2, "0");

    const periodId =
      budget_period === "lifetime"
        ? "lifetime"
        : `monthly:${year}-${month}`;

    this.runInTransaction(() => {
      this.stmtInsertKey.run(
        id,
        normalizedOrgId,
        normalizedName,
        key_prefix,
        key_hash,
        normalizedProvider,
        JSON.stringify(normalizedModels),
        encrypted,
        iv,
        authTag,
        keyVersion,
        budget_limit_micros,
        budget_period,
        period_reset_at,
        input.expires_at ?? null,
        now
      );

      this.db.prepare(`
        INSERT INTO budget_period_usage (
          key_id,
          period_id,
          budget_limit_micros,
          spent_micros,
          reserved_micros,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, 0, 0, ?, ?)
      `).run(
        id,
        periodId,
        budget_limit_micros,
        now,
        now
      );
    });

    return {
      rawVirtualKey,
      metadata: {
        id,
        org_id: normalizedOrgId,
        name: normalizedName,
        key_prefix,
        provider: normalizedProvider,
        allowed_models: normalizedModels,
        key_version: keyVersion,
        budget_limit_micros,
        current_spend_micros: 0,
        reserved_micros: 0,
        budget_limit_usd: microsToUsd(budget_limit_micros),
        current_spend_usd: 0,
        reserved_usd: 0,
        budget_period,
        period_reset_at,
        expires_at: input.expires_at ?? null,
        revoked_at: null,
        last_used_at: null,
        created_at: now,
      },
    };
  }


  public authorize(opts: AuthorizeOptions): AuthorizeResult {
    const nowMs = opts.nowMs ?? Date.now();

    if (!opts.rawVirtualKey || !opts.rawVirtualKey.startsWith("vk-aindigo-")) {
      return { valid: false, reason: "INVALID_KEY" };
    }

    if (
      typeof opts.estimatedCostUsd !== "number" ||
      !Number.isFinite(opts.estimatedCostUsd) ||
      opts.estimatedCostUsd < 0
    ) {
      return { valid: false, reason: "BAD_REQUEST_AMOUNT" };
    }

    const reserveMicros = usdToMicros(opts.estimatedCostUsd);
    const incomingHash = VirtualKeyVault.hashVirtualKey(opts.rawVirtualKey);
    const effectiveModel = opts.downshiftedModel ?? opts.requestedModel;

    let candidateRecordId: string | null = null;
    const createdHandle: { current: ReservationHandle | null } = { current: null };

    // Fail closed when this Vault instance does not own a healthy lease.
    if (this.closed || !this.leaseHealthy) {
      return { valid: false, reason: "VAULT_INTERNAL_ERROR" };
    }

    try {
      const result = this.runInTransaction((): AuthorizeResult => {
        const activeLease = this.db.prepare(`
          SELECT instance_id
          FROM vault_instances
          WHERE instance_id = ?
            AND released_at IS NULL
            AND lease_expires_at > ?
        `).get(this.instanceId, Date.now()) as
          | { instance_id: string }
          | undefined;

        if (!activeLease) {
          this.leaseHealthy = false;
          return { valid: false, reason: "VAULT_INTERNAL_ERROR" };
        }

        const row = this.stmtGetByHash.get(incomingHash) as any;

        if (!row) {
          return { valid: false, reason: "INVALID_KEY" };
        }

        candidateRecordId = String(row.id);

        if (row.revoked_at !== null) {
          return {
            valid: false,
            reason: "REVOKED_KEY",
            record_id: candidateRecordId,
            provider: String(row.provider),
            key_prefix: String(row.key_prefix),
          };
        }

        if (row.expires_at !== null && nowMs >= Number(row.expires_at)) {
          return {
            valid: false,
            reason: "EXPIRED_KEY",
            record_id: candidateRecordId,
            provider: String(row.provider),
            key_prefix: String(row.key_prefix),
          };
        }

        const allowedModels: string[] = JSON.parse(String(row.allowed_models));

        const requestedAllowed =
          allowedModels.includes("*") ||
          allowedModels.includes(opts.requestedModel);

        const effectiveAllowed =
          allowedModels.includes("*") ||
          allowedModels.includes(effectiveModel);

        if (!requestedAllowed || !effectiveAllowed) {
          return {
            valid: false,
            reason: "MODEL_NOT_ALLOWED",
            record_id: candidateRecordId,
            provider: String(row.provider),
            key_prefix: String(row.key_prefix),
          };
        }

        const budgetPeriod = String(row.budget_period);

        let periodId: string;

        if (budgetPeriod === "lifetime") {
          periodId = "lifetime";
        } else if (budgetPeriod === "monthly") {
          periodId = `monthly:${new Date(nowMs)
            .toISOString()
            .slice(0, 7)}`;

          if (nowMs >= Number(row.period_reset_at)) {
            this.stmtRolloverPeriod.run(
              getNextMonthlyReset(nowMs),
              candidateRecordId
            );
          }
        } else {
          throw new Error("VAULT_INTERNAL_ERROR: Unsupported budget period.");
        }

        // Ensure the authorization period has a usage record.
        this.db.prepare(`
          INSERT OR IGNORE INTO budget_period_usage (
            key_id,
            period_id,
            budget_limit_micros,
            spent_micros,
            reserved_micros,
            created_at,
            updated_at
          )
          VALUES (?, ?, ?, 0, 0, ?, ?)
        `).run(
          candidateRecordId,
          periodId,
          Number(row.budget_limit_micros),
          nowMs,
          nowMs
        );

        // Authoritative budget check and reservation.
        const usageUpdate = this.db.prepare(`
          UPDATE budget_period_usage
          SET reserved_micros = reserved_micros + ?,
              updated_at = ?
          WHERE key_id = ?
            AND period_id = ?
            AND spent_micros + reserved_micros + ? <= budget_limit_micros
        `).run(
          reserveMicros,
          nowMs,
          candidateRecordId,
          periodId,
          reserveMicros
        );

        if (Number(usageUpdate.changes) !== 1) {
          return {
            valid: false,
            reason: "BUDGET_EXCEEDED",
            record_id: candidateRecordId,
            provider: String(row.provider),
            key_prefix: String(row.key_prefix),
          };
        }

        // Keep the legacy aggregate synchronized temporarily.
        const legacyUpdate = this.db.prepare(`
          UPDATE virtual_keys
          SET reserved_micros = reserved_micros + ?,
              last_used_at = ?
          WHERE id = ?
        `).run(reserveMicros, nowMs, candidateRecordId);

        if (Number(legacyUpdate.changes) !== 1) {
          throw new Error("VAULT_INTERNAL_ERROR: Legacy reservation update failed.");
        }

        const reservationId = `res_${crypto.randomBytes(16).toString("hex")}`;

        // Persist the reservation in the same transaction as the budget hold.
        this.db.prepare(`
          INSERT INTO budget_reservations (
            reservation_id,
            key_id,
            org_id,
            period_id,
            model,
            reserved_micros,
            actual_micros,
            status,
            receipt_id,
            created_at,
            updated_at,
            settled_at,
            legacy,
            owner_id
          )
          VALUES (?, ?, ?, ?, ?, ?, NULL, 'RESERVED', NULL, ?, ?, NULL, 0, ?)
        `).run(
          reservationId,
          candidateRecordId,
          String(row.org_id),
          periodId,
          effectiveModel,
          reserveMicros,
          nowMs,
          nowMs,
          this.instanceId
        );

        let decryptedKey: string;

        try {
          decryptedKey = this.decryptProviderKey(row);
        } catch (cryptoErr: any) {
          const errClass = cryptoErr?.constructor?.name ?? "CryptoError";
          throw new VaultDecryptException(candidateRecordId, errClass);
        }

        const handle: ReservationHandle = {
          reservation_id: reservationId,
          record_id: candidateRecordId,
          org_id: String(row.org_id),
          period_id: periodId,
          model: effectiveModel,
          reserved_micros: reserveMicros,
          created_at: nowMs,
        };

        createdHandle.current = handle;

        const safeResult: AuthorizeResult = {
          valid: true,
          reservation_id: reservationId,
          record_id: candidateRecordId,
          org_id: String(row.org_id),
          provider: String(row.provider),
          effective_model: effectiveModel,
          key_prefix: String(row.key_prefix),
          reserved_micros: reserveMicros,
          reserved_usd: microsToUsd(reserveMicros),
        };

        Object.defineProperty(safeResult, "getProviderKey", {
          value: () => decryptedKey,
          enumerable: false,
          configurable: false,
          writable: false,
        });

        Object.defineProperty(safeResult, util.inspect.custom, {
          value: () => ({
            valid: true,
            reservation_id: reservationId,
            record_id: candidateRecordId,
            org_id: String(row.org_id),
            provider: String(row.provider),
            effective_model: effectiveModel,
            key_prefix: String(row.key_prefix),
            reserved_micros: reserveMicros,
            reserved_usd: microsToUsd(reserveMicros),
            provider_key: "[REDACTED]",
          }),
          enumerable: false,
        });

        return safeResult;
      });

      // Cache the reservation only after SQLite commits successfully.
      if (result.valid && createdHandle.current) {
        this.inFlightReservations.set(createdHandle.current.reservation_id, createdHandle.current);
      }

      return result;
    } catch (err: any) {
      if (err instanceof VaultDecryptException) {
        this.onDiagnosticError({
          code: "VAULT_DECRYPT_ERROR",
          errorClass: err.causeClass,
          recordId: err.recordId,
        });

        return {
          valid: false,
          reason: "VAULT_DECRYPT_ERROR",
          record_id: err.recordId,
        };
      }

      const errorClass = err?.constructor?.name ?? "UnknownError";

      this.onDiagnosticError({
        code: "VAULT_INTERNAL_ERROR",
        errorClass,
        recordId: candidateRecordId,
      });

      return {
        valid: false,
        reason: "VAULT_INTERNAL_ERROR",
        record_id: candidateRecordId ?? undefined,
      };
    }
  }


    public reconcileSpend(
    reservationId: string,
    actualCostUsd: number,
    receiptId: string | null = null,
    nowMs: number = Date.now()
  ): { reconciled: boolean; actual_micros: number } {
    if (
      typeof actualCostUsd !== "number" ||
      !Number.isFinite(actualCostUsd) ||
      actualCostUsd < 0
    ) {
      throw new Error("VAULT_RECONCILE_ERROR: Invalid actual cost.");
    }

    if (!Number.isSafeInteger(nowMs) || nowMs < 0) {
      throw new Error("VAULT_RECONCILE_ERROR: Invalid settlement timestamp.");
    }

    const actualMicros = usdToMicros(actualCostUsd);

    if (!Number.isSafeInteger(actualMicros) || actualMicros < 0) {
      throw new Error("VAULT_RECONCILE_ERROR: Actual cost exceeds safe storage range.");
    }

    const result = this.runInTransaction(() => {
      const reservation = this.db.prepare(`
        SELECT
          reservation_id,
          key_id,
          org_id,
          period_id,
          model,
          reserved_micros,
          status
        FROM budget_reservations
        WHERE reservation_id = ?
      `).get(reservationId) as
        | {
            reservation_id: string;
            key_id: string;
            org_id: string;
            period_id: string;
            model: string;
            reserved_micros: number;
            status: string;
          }
        | undefined;

      if (
        !reservation ||
        (reservation.status !== "RESERVED" &&
          reservation.status !== "UNCERTAIN")
      ) {
        return { reconciled: false, actual_micros: 0 };
      }

      const reservedMicros = Number(reservation.reserved_micros);

      if (
        !Number.isSafeInteger(reservedMicros) ||
        reservedMicros < 0
      ) {
        throw new Error("VAULT_RECONCILE_ERROR: Invalid reservation amount.");
      }

      const usage = this.db.prepare(`
        SELECT spent_micros, reserved_micros
        FROM budget_period_usage
        WHERE key_id = ? AND period_id = ?
      `).get(
        reservation.key_id,
        reservation.period_id
      ) as
        | { spent_micros: number; reserved_micros: number }
        | undefined;

      if (!usage) {
        throw new Error("VAULT_RECONCILE_ERROR: Budget period record is missing.");
      }

      const currentPeriodSpent = Number(usage.spent_micros);
      const currentPeriodReserved = Number(usage.reserved_micros);

      if (
        !Number.isSafeInteger(currentPeriodSpent) ||
        currentPeriodSpent < 0 ||
        !Number.isSafeInteger(currentPeriodReserved) ||
        currentPeriodReserved < reservedMicros ||
        !Number.isSafeInteger(currentPeriodSpent + actualMicros)
      ) {
        throw new Error("VAULT_RECONCILE_ERROR: Budget period accounting is inconsistent.");
      }

      const key = this.db.prepare(`
        SELECT budget_period, reserved_micros, current_spend_micros
        FROM virtual_keys
        WHERE id = ?
      `).get(reservation.key_id) as
        | {
            budget_period: string;
            reserved_micros: number;
            current_spend_micros: number;
          }
        | undefined;

      if (!key) {
        throw new Error("VAULT_RECONCILE_ERROR: Virtual key record is missing.");
      }

      const legacyReserved = Number(key.reserved_micros);
      const legacySpent = Number(key.current_spend_micros);

      if (
        !Number.isSafeInteger(legacyReserved) ||
        legacyReserved < reservedMicros ||
        !Number.isSafeInteger(legacySpent) ||
        legacySpent < 0
      ) {
        throw new Error("VAULT_RECONCILE_ERROR: Legacy budget accounting is inconsistent.");
      }

      const currentPeriodId =
        key.budget_period === "lifetime"
          ? "lifetime"
          : key.budget_period === "monthly"
            ? `monthly:${new Date(nowMs).toISOString().slice(0, 7)}`
            : null;

      if (!currentPeriodId) {
        throw new Error("VAULT_RECONCILE_ERROR: Unsupported budget period.");
      }

      const updateReservation = this.db.prepare(`
        UPDATE budget_reservations
        SET status = 'SETTLED',
            actual_micros = ?,
            receipt_id = ?,
            updated_at = ?,
            settled_at = ?
        WHERE reservation_id = ?
          AND status IN ('RESERVED', 'UNCERTAIN')
      `).run(
        actualMicros,
        receiptId,
        nowMs,
        nowMs,
        reservationId
      );

      if (Number(updateReservation.changes) !== 1) {
        return { reconciled: false, actual_micros: 0 };
      }

      const updateUsage = this.db.prepare(`
        UPDATE budget_period_usage
        SET reserved_micros = reserved_micros - ?,
            spent_micros = spent_micros + ?,
            updated_at = ?
        WHERE key_id = ?
          AND period_id = ?
          AND reserved_micros >= ?
      `).run(
        reservedMicros,
        actualMicros,
        nowMs,
        reservation.key_id,
        reservation.period_id,
        reservedMicros
      );

      if (Number(updateUsage.changes) !== 1) {
        throw new Error("VAULT_RECONCILE_ERROR: Could not settle period usage.");
      }

      // Keep the legacy aggregate synchronized while existing consumers remain.
      // Late settlements affect their original period, not the current month's
      // compatibility spend counter.
      const updateLegacy =
        reservation.period_id === currentPeriodId
          ? this.db.prepare(`
              UPDATE virtual_keys
              SET reserved_micros = reserved_micros - ?,
                  current_spend_micros = current_spend_micros + ?
              WHERE id = ?
                AND reserved_micros >= ?
            `).run(
              reservedMicros,
              actualMicros,
              reservation.key_id,
              reservedMicros
            )
          : this.db.prepare(`
              UPDATE virtual_keys
              SET reserved_micros = reserved_micros - ?
              WHERE id = ?
                AND reserved_micros >= ?
            `).run(
              reservedMicros,
              reservation.key_id,
              reservedMicros
            );

      if (Number(updateLegacy.changes) !== 1) {
        throw new Error("VAULT_RECONCILE_ERROR: Could not update legacy budget totals.");
      }

      // Stable ledger ID makes the ledger entry unique to this reservation.
      this.stmtInsertLedger.run(
        `led_${reservationId}`,
        reservation.key_id,
        reservation.org_id,
        nowMs,
        reservedMicros,
        actualMicros,
        reservation.model,
        receiptId
      );

      return {
        reconciled: true,
        actual_micros: actualMicros,
      };
    });

    if (result.reconciled) {
      this.inFlightReservations.delete(reservationId);
    }

    return result;
  }

    public reapStaleReservations(
    maxAgeMs: number = DEFAULT_RESERVATION_TTL_MS,
    nowMs: number = Date.now()
  ): { reapedCount: number; releasedMicros: number } {
    if (!Number.isSafeInteger(maxAgeMs) || maxAgeMs < 0) {
      throw new Error("VAULT_REAPER_ERROR: Invalid maximum reservation age.");
    }

    if (!Number.isSafeInteger(nowMs) || nowMs < 0) {
      throw new Error("VAULT_REAPER_ERROR: Invalid reaper timestamp.");
    }

    const cutoff = nowMs - maxAgeMs;
    const leaseExpiryCutoff =
      nowMs - VAULT_INSTANCE_RECOVERY_GRACE_MS;

    const markedReservationIds = this.runInTransaction(() => {
      const eligibleReservations = `
        SELECT br.reservation_id
        FROM budget_reservations AS br
        INNER JOIN vault_instances AS vi
          ON vi.instance_id = br.owner_id
        WHERE br.status = 'RESERVED'
          AND br.created_at <= ?
          AND (
            vi.released_at IS NOT NULL
            OR vi.lease_expires_at <= ?
          )
      `;

      const staleRows = this.db.prepare(`
        ${eligibleReservations}
        ORDER BY br.created_at ASC
      `).all(cutoff, leaseExpiryCutoff) as
        Array<{ reservation_id: string }>;

      if (staleRows.length === 0) {
        return [];
      }

      const update = this.db.prepare(`
        UPDATE budget_reservations
        SET status = 'UNCERTAIN',
            updated_at = ?
        WHERE status = 'RESERVED'
          AND reservation_id IN (
            ${eligibleReservations}
          )
      `).run(nowMs, cutoff, leaseExpiryCutoff);

      if (Number(update.changes) !== staleRows.length) {
        throw new Error(
          "VAULT_REAPER_ERROR: Reservation state changed unexpectedly."
        );
      }

      return staleRows.map((row) => row.reservation_id);
    });

    // The database is authoritative. Remove only the local cache entries
    // after the transaction commits. Keep all budget holds intact.
    for (const reservationId of markedReservationIds) {
      this.inFlightReservations.delete(reservationId);
    }

    return {
      reapedCount: markedReservationIds.length,
      releasedMicros: 0,
    };
  }

  public revokeKey(recordId: string, nowMs: number = Date.now()): boolean {
    const res = this.stmtRevokeKey.run(nowMs, recordId);
    return Number(res.changes) > 0;
  }

  public rotateMasterKey(newMasterKeyHex: string, newVersion: number): number {
    this.validateAndLoadKey(newVersion, newMasterKeyHex);
    if (newVersion <= this.activeKeyVersion) {
      throw new Error("VAULT_ROTATE_ERROR: newVersion must be greater than activeKeyVersion.");
    }

    return this.runInTransaction(() => {
      const rows = this.db.prepare(`SELECT * FROM virtual_keys`).all() as any[];
      let rotated = 0;

      const updateStmt = this.db.prepare(`
        UPDATE virtual_keys
        SET encrypted_provider_key = ?, iv = ?, auth_tag = ?, key_version = ?
        WHERE id = ?
      `);

      for (const row of rows) {
        const rawKey = this.decryptProviderKey(row);
        const reEncrypted = this.encryptProviderKey(
          rawKey,
          String(row.id),
          String(row.org_id),
          newVersion
        );
        updateStmt.run(
          reEncrypted.encrypted,
          reEncrypted.iv,
          reEncrypted.authTag,
          newVersion,
          String(row.id)
        );
        rotated++;
      }

      this.activeKeyVersion = newVersion;
      return rotated;
    });
  }

  public getKeyMetadataByVirtualKey(
  rawVirtualKey: string
): VirtualKeyMetadata | null {
  if (
    typeof rawVirtualKey !== "string" ||
    !rawVirtualKey.startsWith("vk-aindigo-")
  ) {
    return null;
  }

  const keyHash = VirtualKeyVault.hashVirtualKey(rawVirtualKey);
  const row = this.stmtGetByHash.get(keyHash) as
    | { id?: string }
    | undefined;

  if (!row?.id) {
    return null;
  }

  return this.getKeyMetadata(String(row.id));
}

  public getKeyMetadata(recordId: string): VirtualKeyMetadata | null {
    const row = this.stmtGetById.get(recordId) as any;
    if (!row) return null;
    const budgetMicros = Number(row.budget_limit_micros);
    const spendMicros = Number(row.current_spend_micros);
    const reservedMicros = Number(row.reserved_micros);

    return {
      id: String(row.id),
      org_id: String(row.org_id),
      name: String(row.name),
      key_prefix: String(row.key_prefix),
      provider: String(row.provider),
      allowed_models: JSON.parse(String(row.allowed_models)),
      key_version: Number(row.key_version),
      budget_limit_micros: budgetMicros,
      current_spend_micros: spendMicros,
      reserved_micros: reservedMicros,
      budget_limit_usd: microsToUsd(budgetMicros),
      current_spend_usd: microsToUsd(spendMicros),
      reserved_usd: microsToUsd(reservedMicros),
      budget_period: row.budget_period as BudgetPeriod,
      period_reset_at: Number(row.period_reset_at),
      expires_at: row.expires_at !== null ? Number(row.expires_at) : null,
      revoked_at: row.revoked_at !== null ? Number(row.revoked_at) : null,
      last_used_at: row.last_used_at !== null ? Number(row.last_used_at) : null,
      created_at: Number(row.created_at),
    };
  }

  public getSpendLedger(recordId: string): SpendLedgerEntry[] {
    const rows = this.stmtGetLedgerByKey.all(recordId) as any[];
    return rows.map((r) => ({
      id: String(r.id),
      key_id: String(r.key_id),
      org_id: String(r.org_id),
      ts: Number(r.ts),
      reserved_micros: Number(r.reserved_micros),
      actual_micros: Number(r.actual_micros),
      model: String(r.model),
      receipt_id: r.receipt_id !== null ? String(r.receipt_id) : null,
    }));
  }

  public close(): void {
    if (this.closed) {
      return;
    }

    this.closed = true;

    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }

    try {
      this.runInTransaction(() => {
        const nowMs = Date.now();

        this.db.prepare(`
          UPDATE budget_reservations
          SET status = 'UNCERTAIN',
              updated_at = ?
          WHERE owner_id = ?
            AND status = 'RESERVED'
        `).run(nowMs, this.instanceId);

        this.db.prepare(`
          UPDATE vault_instances
          SET heartbeat_at = ?,
              lease_expires_at = ?,
              released_at = ?
          WHERE instance_id = ?
            AND released_at IS NULL
        `).run(nowMs, nowMs, nowMs, this.instanceId);
      });
    } finally {
      this.inFlightReservations.clear();
      this.db.close();
    }
  }
}