import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import crypto from 'node:crypto';
import { AuditReceipt } from '@aindigo/shared';
import { hashVirtualKey, encryptSecret } from './crypto.js';

import {
  initializeNodeLeaseStore,
  getPersistedNodeLease,
  getNodeLeaseClockState,
  verifyAndPersistNodeLease,
  recordNodeLeaseClockObservation,
} from './crypto/node-lease-store.js';

const dbPath = process.env.DATA_PLANE_DB_PATH || path.join(process.cwd(), 'dataplane_local.db');
const db = new DatabaseSync(dbPath);

db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA synchronous = NORMAL;');

db.exec(`
  CREATE TABLE IF NOT EXISTS node_activation (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    is_activated INTEGER NOT NULL DEFAULT 0,
    tenant_id TEXT NOT NULL DEFAULT 'unpaired',
    org_name TEXT NOT NULL DEFAULT 'Unactivated Node',
    subscription_tier TEXT NOT NULL DEFAULT 'COMMUNITY',
    cluster_sync_secret TEXT NOT NULL DEFAULT '',
    monthly_request_limit INTEGER NOT NULL DEFAULT 10000,
    requests_used_this_month INTEGER NOT NULL DEFAULT 0,
    quota_period TEXT NOT NULL DEFAULT '',
    activated_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  INSERT OR IGNORE INTO node_activation (id, is_activated, tenant_id, org_name, subscription_tier, cluster_sync_secret, monthly_request_limit, requests_used_this_month)
  VALUES (1, 0, 'unpaired', 'Unactivated Node', 'COMMUNITY', '', 10000, 0);

  CREATE TABLE IF NOT EXISTS virtual_keys (
    key_hash TEXT PRIMARY KEY,
    key_preview TEXT NOT NULL DEFAULT 'vk-aindigo-...9999',
    tenant_id TEXT NOT NULL,
    department TEXT NOT NULL,
    provider TEXT NOT NULL,
    encrypted_upstream_key TEXT NOT NULL,
    key_iv TEXT NOT NULL,
    key_auth_tag TEXT NOT NULL,
    monthly_budget_usd REAL NOT NULL,
    current_spend_usd REAL NOT NULL DEFAULT 0.0,
    finops_saved_usd REAL NOT NULL DEFAULT 0.0,
    dlp_mode TEXT NOT NULL DEFAULT 'redact',
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS audit_receipt_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    receipt_id TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    department TEXT NOT NULL,
    model_requested TEXT NOT NULL,
    model_routed TEXT NOT NULL,
    prompt_tokens INTEGER NOT NULL,
    completion_tokens INTEGER NOT NULL,
    cost_usd REAL NOT NULL,
    saved_usd REAL NOT NULL,
    dlp_flags TEXT NOT NULL,
    prompt_sha256 TEXT NOT NULL,
    previous_receipt_hash TEXT NOT NULL,
    receipt_hmac TEXT NOT NULL,
    created_at TEXT NOT NULL
  );



  CREATE TABLE IF NOT EXISTS receipt_chain_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    last_receipt_hash TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );
`);

// Safely migrate existing databases without resetting their quota usage.
const activationColumns = db
  .prepare('PRAGMA table_info(node_activation)')
  .all() as Array<{ name: string }>;

if (!activationColumns.some((column) => column.name === 'quota_period')) {
  db.exec(`
    ALTER TABLE node_activation
    ADD COLUMN quota_period TEXT NOT NULL DEFAULT ''
  `);
}

// Existing usage belongs to the current UTC month on first migration.
db.prepare(`
  UPDATE node_activation
  SET quota_period = strftime('%Y-%m', 'now')
  WHERE quota_period = ''
`).run();

db.prepare(
  'INSERT OR IGNORE INTO receipt_chain_state (id, last_receipt_hash, updated_at) ' +
  'SELECT 1, COALESCE((SELECT receipt_hmac FROM audit_receipt_queue ORDER BY id DESC LIMIT 1), ?), ?'
).run('0'.repeat(64), new Date().toISOString());

// Initialize persistent node lease and clock checkpoint storage.
// This migration is additive and does not modify existing Data Plane tables.
initializeNodeLeaseStore(db);

export interface NodeActivationState {
  is_activated: number;
  tenant_id: string;
  org_name: string;
  subscription_tier: 'COMMUNITY' | 'SME_PRO' | 'ENTERPRISE';
  cluster_sync_secret: string;
  monthly_request_limit: number;
  requests_used_this_month: number;
  quota_period: string;
}

export function getNodeActivation(): NodeActivationState {
  const state = db
    .prepare('SELECT * FROM node_activation WHERE id = 1')
    .get() as NodeActivationState | undefined;

  if (!state) {
    throw new Error('Data Plane activation record is missing.');
  }

  return state;
}

export function activateDataPlaneNode(params: {
  tenantId: string;
  orgName: string;
  subscriptionTier: 'COMMUNITY' | 'SME_PRO' | 'ENTERPRISE';
  clusterSyncSecret: string;
  monthlyRequestLimit: number;
}): NodeActivationState {
  const tenantId = params.tenantId.trim();

  if (!tenantId || tenantId === 'unpaired') {
    throw new Error('A valid tenant ID is required.');
  }

  if (!params.clusterSyncSecret.trim()) {
    throw new Error('A valid node credential is required.');
  }

  const current = getNodeActivation();

  // An activated node cannot silently move to another tenant.
  if (current.is_activated === 1 && current.tenant_id !== tenantId) {
    throw new Error(
      'This node is already assigned to another tenant. Explicit reprovisioning is required.'
    );
  }

  // Never silently adopt existing keys during first activation.
  const existingKeys = db
    .prepare('SELECT COUNT(*) AS count FROM virtual_keys')
    .get() as { count: number };

  if (current.is_activated !== 1 && existingKeys.count > 0) {
    throw new Error(
      'This node contains existing virtual keys. Review and explicitly reprovision it before activation.'
    );
  }

  db.prepare(`
    UPDATE node_activation
    SET is_activated = 1,
        tenant_id = ?,
        org_name = ?,
        subscription_tier = ?,
        cluster_sync_secret = ?,
        monthly_request_limit = ?,
        activated_at = CURRENT_TIMESTAMP
    WHERE id = 1
  `).run(
    tenantId,
    params.orgName,
    params.subscriptionTier,
    params.clusterSyncSecret,
    params.monthlyRequestLimit
  );

  return getNodeActivation();
}

export function incrementNodeRequestCounter(): {
  used: number;
  limit: number;
  allowed: boolean;
  period: string;
} {
  const currentPeriod = new Date().toISOString().slice(0, 7);

  const result = db.prepare(`
    UPDATE node_activation
    SET requests_used_this_month = CASE
          WHEN quota_period <> ? THEN 1
          ELSE requests_used_this_month + 1
        END,
        quota_period = ?
    WHERE id = 1
      AND CASE
            WHEN quota_period <> ? THEN 0
            ELSE requests_used_this_month
          END < monthly_request_limit
  `).run(currentPeriod, currentPeriod, currentPeriod);

  const state = getNodeActivation();

  return {
    used: state.quota_period === currentPeriod
      ? state.requests_used_this_month
      : 0,
    limit: state.monthly_request_limit,
    allowed: Number(result.changes) === 1,
    period: currentPeriod,
  };
}
export interface VirtualKeyRow {
  key_hash: string;
  key_preview: string;
  tenant_id: string;
  department: string;
  provider: string;
  encrypted_upstream_key: string;
  key_iv: string;
  key_auth_tag: string;
  monthly_budget_usd: number;
  current_spend_usd: number;
  finops_saved_usd: number;
  dlp_mode: 'redact' | 'block' | 'audit';
  is_active: number;
}

const stmtFindKey = db.prepare('SELECT * FROM virtual_keys WHERE key_hash = ? AND is_active = 1');
const stmtListKeys = db.prepare(`
  SELECT key_preview, tenant_id, department, provider,
       monthly_budget_usd, current_spend_usd, finops_saved_usd, dlp_mode, is_active
  FROM virtual_keys WHERE is_active = 1 ORDER BY rowid DESC
`);
const stmtInsertKey = db.prepare(`
  INSERT OR REPLACE INTO virtual_keys (
    key_hash, key_preview, tenant_id, department, provider,
    encrypted_upstream_key, key_iv, key_auth_tag,
    monthly_budget_usd, current_spend_usd, finops_saved_usd, dlp_mode, is_active
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);
const stmtRecordTurnSpend = db.prepare(`
  UPDATE virtual_keys
  SET current_spend_usd = current_spend_usd + ?,
      finops_saved_usd = finops_saved_usd + ?
  WHERE key_hash = ?
`);

const stmtQueueReceipt = db.prepare(`
  INSERT INTO audit_receipt_queue (
    receipt_id, tenant_id, department, model_requested, model_routed,
    prompt_tokens, completion_tokens, cost_usd, saved_usd,
    dlp_flags, prompt_sha256, previous_receipt_hash, receipt_hmac, created_at
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);
const stmtGetReceiptChainState = db.prepare(
  'SELECT last_receipt_hash FROM receipt_chain_state WHERE id = 1'
);
const stmtUpdateReceiptChainState = db.prepare(
  'UPDATE receipt_chain_state SET last_receipt_hash = ?, updated_at = ? WHERE id = 1'
);
const stmtGetQueuedReceipts = db.prepare(`
  SELECT * FROM audit_receipt_queue ORDER BY id ASC LIMIT 100
`);
const stmtDeleteSyncedReceipts = db.prepare(`
  DELETE FROM audit_receipt_queue WHERE id <= ?
`);

export function findVirtualKeyByHash(keyHash: string): VirtualKeyRow | undefined {
  return stmtFindKey.get(keyHash) as VirtualKeyRow | undefined;
}

export function listActiveVirtualKeys() {
  return stmtListKeys.all();
}

export function mintCustomVirtualKey(params: {
  tenantId: string;
  department: string;
  provider: string;
  upstreamApiKey: string;
  monthlyBudgetUsd: number;
  dlpMode: 'redact' | 'block' | 'audit';
}): { virtualKey: string; keyPreview: string; keyHash: string } {
  const randomSuffix = crypto.randomBytes(12).toString('hex');
  const cleanDept = params.department.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 8) || 'team';
  const virtualKey = `vk-aindigo-${cleanDept}-${randomSuffix}`;
  const keyPreview = `${virtualKey.slice(0, 15)}...${virtualKey.slice(-4)}`;
  const keyHash = hashVirtualKey(virtualKey);
  const encrypted = encryptSecret(params.upstreamApiKey.trim());

  stmtInsertKey.run(
    keyHash,
    keyPreview,
    params.tenantId,
    params.department,
    params.provider,
    encrypted.ciphertext,
    encrypted.iv,
    encrypted.authTag,
    params.monthlyBudgetUsd,
    0.0,
    0.0,
    params.dlpMode,
    1
  );

  return { virtualKey, keyPreview, keyHash };
}

export function recordTurnSpendAndSavings(keyHash: string, costUsd: number, savedUsd: number): void {
  stmtRecordTurnSpend.run(costUsd, savedUsd, keyHash);
}

export function setDepartmentSpendLevel(keyHash: string, spendUsd: number): void {
  db.prepare('UPDATE virtual_keys SET current_spend_usd = ? WHERE key_hash = ?').run(spendUsd, keyHash);
}

export function applySyncedPolicy(
  tenantId: string,
  department: string,
  monthlyBudgetUsd: number,
  dlpMode: string
): void {
  db.prepare('UPDATE virtual_keys SET monthly_budget_usd = ?, dlp_mode = ? WHERE tenant_id = ? AND department = ?')
    .run(monthlyBudgetUsd, dlpMode, tenantId, department);
}

export function createAndQueueAuditReceipt(params: {
  tenantId: string;
  department: string;
  modelRequested: string;
  modelRouted: string;
  promptTokens: number;
  completionTokens: number;
  costUsd: number;
  savedUsd: number;
  dlpFlags: string[];
  rawPromptText: string;
}): AuditReceipt {
    const nodeState = getNodeActivation();

  if (
    nodeState.is_activated !== 1 ||
    !nodeState.tenant_id ||
    nodeState.tenant_id === 'unpaired'
  ) {
    throw new Error('Cannot create an audit receipt: Data Plane node is not enrolled.');
  }

  if (!nodeState.cluster_sync_secret?.trim()) {
    throw new Error('Cannot create an audit receipt: node signing credential is unavailable.');
  }

  if (params.tenantId !== nodeState.tenant_id) {
    throw new Error('Cannot create an audit receipt for a different tenant.');
  }

  const activeSecret = nodeState.cluster_sync_secret;
  const activeTenantId = nodeState.tenant_id;
  const receiptId = `rcpt_${crypto.randomUUID()}`;
  const promptSha256 = crypto.createHash('sha256').update(params.rawPromptText).digest('hex');
  const createdAt = new Date().toISOString();

  db.exec('BEGIN IMMEDIATE');

  try {
    const chainState = stmtGetReceiptChainState.get() as
      | { last_receipt_hash: string }
      | undefined;

    if (!chainState || !/^[a-f0-9]{64}$/.test(chainState.last_receipt_hash)) {
      throw new Error('Receipt chain state is missing or invalid.');
    }

    const previousReceiptHash = chainState.last_receipt_hash;
    const canonicalPayload = [
      previousReceiptHash,
      receiptId,
      activeTenantId,
      params.department,
      params.modelRequested,
      params.modelRouted,
      params.promptTokens,
      params.completionTokens,
      params.costUsd.toFixed(6),
      params.savedUsd.toFixed(6),
      params.dlpFlags.join(','),
      promptSha256,
    ].join('|');

    const receiptHmac = crypto
      .createHmac('sha256', activeSecret)
      .update(canonicalPayload)
      .digest('hex');

    stmtQueueReceipt.run(
      receiptId, activeTenantId, params.department,
      params.modelRequested, params.modelRouted,
      params.promptTokens, params.completionTokens,
      params.costUsd, params.savedUsd,
      JSON.stringify(params.dlpFlags), promptSha256,
      previousReceiptHash, receiptHmac, createdAt
    );

    const updateResult = stmtUpdateReceiptChainState.run(receiptHmac, createdAt);
    if (Number(updateResult.changes) !== 1) {
      throw new Error('Receipt chain state update failed.');
    }

    db.exec('COMMIT');

    return {
      receiptId, tenantId: activeTenantId,
      department: params.department,
      modelRequested: params.modelRequested,
      modelRouted: params.modelRouted,
      promptTokens: params.promptTokens,
      completionTokens: params.completionTokens,
      costUsd: params.costUsd, savedUsd: params.savedUsd,
      dlpFlags: params.dlpFlags, promptSha256,
      previousReceiptHash, receiptHmac, createdAt,
    };
  } catch (error) {
    try {
      db.exec('ROLLBACK');
    } catch {
      // Preserve the original receipt creation error.
    }
    throw error;
  }
}

export function fetchPendingReceiptBatch(): { maxId: number; receipts: AuditReceipt[] } {
  const rows = stmtGetQueuedReceipts.all() as any[];
  if (rows.length === 0) return { maxId: 0, receipts: [] };

  let maxId = 0;
  const receipts: AuditReceipt[] = rows.map((r) => {
    if (r.id > maxId) maxId = r.id;
    return {
      receiptId: r.receipt_id,
      tenantId: r.tenant_id,
      department: r.department,
      modelRequested: r.model_requested,
      modelRouted: r.model_routed,
      promptTokens: r.prompt_tokens,
      completionTokens: r.completion_tokens,
      costUsd: r.cost_usd,
      savedUsd: r.saved_usd,
      dlpFlags: JSON.parse(r.dlp_flags),
      promptSha256: r.prompt_sha256,
      previousReceiptHash: r.previous_receipt_hash,
      receiptHmac: r.receipt_hmac,
      createdAt: r.created_at,
    };
  });

  return { maxId, receipts };
}

export function clearSyncedReceiptBatch(maxId: number): void {
  stmtDeleteSyncedReceipts.run(maxId);
}

export function clearAcknowledgedReceipts(receiptIds: string[]): void {
  if (!Array.isArray(receiptIds) || receiptIds.length === 0) {
    return;
  }

  if (
    receiptIds.length > 100 ||
    !receiptIds.every(
      (id) => typeof id === 'string' && id.trim().length > 0
    )
  ) {
    throw new Error('Invalid acknowledged receipt IDs.');
  }

  const uniqueIds = [...new Set(receiptIds)];
  const placeholders = uniqueIds.map(() => '?').join(', ');

  db.prepare(`
    DELETE FROM audit_receipt_queue
    WHERE receipt_id IN (${placeholders})
  `).run(...uniqueIds);
}
/**
 * Tracks whether the legacy Data Plane database has been closed.
 * The database is owned by this module and must only be closed
 * after HTTP requests and background synchronization have drained.
 */
let databaseClosed = false;

/**
 * Returns the currently persisted, schema-validated node lease.
 */
export function getPersistedDataPlaneNodeLease() {
  return getPersistedNodeLease(db);
}

/**
 * Verifies and persists a Control Plane-signed node lease.
 *
 * Cryptographic verification is performed by the existing
 * node-identity implementation through the lease-store module.
 */
export function verifyAndPersistDataPlaneNodeLease(
  leaseInput: unknown,
  controlPlanePublicKeyPem: string,
  identity: Parameters<typeof verifyAndPersistNodeLease>[3],
  expectedTenantId: string,
  nowMs: number = Date.now(),
  expectedKeyId?: string
) {
  return verifyAndPersistNodeLease(
    db,
    leaseInput,
    controlPlanePublicKeyPem,
    identity,
    expectedTenantId,
    nowMs,
    expectedKeyId
  );
}

/**
 * Records a system clock observation and checks rollback tolerance.
 */
export function recordDataPlaneNodeLeaseClockObservation(
  nowMs: number = Date.now()
) {
  return recordNodeLeaseClockObservation(db, nowMs);
}

/**
 * Returns the persisted node lease clock checkpoint.
 */
export function getDataPlaneNodeLeaseClockState() {
  return getNodeLeaseClockState(db);
}

/**
 * Closes the Data Plane SQLite database safely.
 *
 * This operation is idempotent. A failed close does not mark the
 * database as closed, allowing the caller to handle the failure.
 */
export function closeDataPlaneDatabase(): void {
  if (databaseClosed) {
    return;
  }

  db.close();
  databaseClosed = true;
}