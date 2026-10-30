import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import crypto from 'node:crypto';
import { AuditReceipt } from '@aindigo/shared';
import { hashVirtualKey, encryptSecret } from './crypto.js';

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
`);

let lastReceiptHash = '0'.repeat(64);

export interface NodeActivationState {
  is_activated: number;
  tenant_id: string;
  org_name: string;
  subscription_tier: 'COMMUNITY' | 'SME_PRO' | 'ENTERPRISE';
  cluster_sync_secret: string;
  monthly_request_limit: number;
  requests_used_this_month: number;
}

export function getNodeActivation(): NodeActivationState {
  return db.prepare('SELECT * FROM node_activation WHERE id = 1').get() as unknown as NodeActivationState;
}

export function activateDataPlaneNode(params: {
  tenantId: string;
  orgName: string;
  subscriptionTier: 'COMMUNITY' | 'SME_PRO' | 'ENTERPRISE';
  clusterSyncSecret: string;
  monthlyRequestLimit: number;
}): NodeActivationState {
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
    params.tenantId,
    params.orgName,
    params.subscriptionTier,
    params.clusterSyncSecret,
    params.monthlyRequestLimit
  );

  // Also update existing virtual keys to belong to this activated tenant
  db.prepare('UPDATE virtual_keys SET tenant_id = ?').run(params.tenantId);

  return getNodeActivation();
}

export function incrementNodeRequestCounter(): { used: number; limit: number; allowed: boolean } {
  const state = getNodeActivation();
  if (state.requests_used_this_month >= state.monthly_request_limit) {
    return { used: state.requests_used_this_month, limit: state.monthly_request_limit, allowed: false };
  }
  db.prepare('UPDATE node_activation SET requests_used_this_month = requests_used_this_month + 1 WHERE id = 1').run();
  return { used: state.requests_used_this_month + 1, limit: state.monthly_request_limit, allowed: true };
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
  SELECT key_hash, key_preview, tenant_id, department, provider,
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
  const activeSecret =
    nodeState.cluster_sync_secret ||
    process.env.CLUSTER_SYNC_SECRET ||
    'aindigo-cluster-hmac-secret-key-2026-enterprise-verified';
  const activeTenantId = nodeState.tenant_id !== 'unpaired' ? nodeState.tenant_id : params.tenantId;

  const receiptId = `rcpt_${crypto.randomUUID()}`;
  const promptSha256 = crypto.createHash('sha256').update(params.rawPromptText).digest('hex');
  const previousReceiptHash = lastReceiptHash;
  const createdAt = new Date().toISOString();

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

  lastReceiptHash = receiptHmac;

  stmtQueueReceipt.run(
    receiptId,
    activeTenantId,
    params.department,
    params.modelRequested,
    params.modelRouted,
    params.promptTokens,
    params.completionTokens,
    params.costUsd,
    params.savedUsd,
    JSON.stringify(params.dlpFlags),
    promptSha256,
    previousReceiptHash,
    receiptHmac,
    createdAt
  );

  return {
    receiptId,
    tenantId: activeTenantId,
    department: params.department,
    modelRequested: params.modelRequested,
    modelRouted: params.modelRouted,
    promptTokens: params.promptTokens,
    completionTokens: params.completionTokens,
    costUsd: params.costUsd,
    savedUsd: params.savedUsd,
    dlpFlags: params.dlpFlags,
    promptSha256,
    previousReceiptHash,
    receiptHmac,
    createdAt,
  };
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

export function seedDevVirtualKey(rawKey: string, upstreamKey: string): void {
  const keyHash = hashVirtualKey(rawKey);
  const existing = findVirtualKeyByHash(keyHash);
  if (existing) return;

  const encrypted = encryptSecret(upstreamKey);
  const keyPreview = `${rawKey.slice(0, 15)}...${rawKey.slice(-4)}`;

  stmtInsertKey.run(
    keyHash,
    keyPreview,
    'acme_corp',
    'core_engineering',
    'anthropic',
    encrypted.ciphertext,
    encrypted.iv,
    encrypted.authTag,
    100.0,
    0.0,
    0.0,
    'redact',
    1
  );
}
