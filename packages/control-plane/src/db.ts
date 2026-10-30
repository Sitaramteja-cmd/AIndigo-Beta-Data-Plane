import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import crypto from 'node:crypto';
import { AuditReceipt } from '@aindigo/shared';

const dbPath = process.env.CONTROL_PLANE_DB_PATH || path.join(process.cwd(), 'controlplane_cloud.db');
const db = new DatabaseSync(dbPath);

db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA synchronous = NORMAL;');

export type SubscriptionTier = 'COMMUNITY' | 'SME_PRO' | 'ENTERPRISE';

db.exec(`
  CREATE TABLE IF NOT EXISTS tenants (
    tenant_id TEXT PRIMARY KEY,
    org_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    subscription_tier TEXT NOT NULL DEFAULT 'COMMUNITY',
    cluster_sync_token TEXT NOT NULL UNIQUE,
    monthly_request_limit INTEGER NOT NULL DEFAULT 10000,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS tenant_policies (
    tenant_id TEXT NOT NULL,
    department TEXT NOT NULL,
    monthly_budget_usd REAL NOT NULL,
    dlp_mode TEXT NOT NULL DEFAULT 'redact',
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, department)
  );

  CREATE TABLE IF NOT EXISTS verified_audit_receipts (
    receipt_id TEXT PRIMARY KEY,
    data_plane_node_id TEXT NOT NULL,
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
    created_at TEXT NOT NULL,
    ingested_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

const TIER_LIMITS: Record<SubscriptionTier, number> = {
  COMMUNITY: 10_000,
  SME_PRO: 250_000,
  ENTERPRISE: 10_000_000,
};

function hashPassword(password: string, salt: string): string {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

// Seed default demo tenant so existing local tests continue working seamlessly
(function seedDefaultDemoTenant() {
  const existing = db.prepare('SELECT tenant_id FROM tenants WHERE tenant_id = ?').get('acme_corp');
  if (!existing) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = hashPassword('demo1234', salt);
    db.prepare(`
      INSERT INTO tenants (tenant_id, org_name, email, password_hash, password_salt, subscription_tier, cluster_sync_token, monthly_request_limit)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      'acme_corp',
      'Acme Corp (Default Sandbox)',
      'founder@aindigo.dev',
      hash,
      salt,
      'SME_PRO',
      'aindigo-cluster-hmac-secret-key-2026-enterprise-verified',
      250000
    );
    db.prepare(`
      INSERT OR IGNORE INTO tenant_policies (tenant_id, department, monthly_budget_usd, dlp_mode)
      VALUES ('acme_corp', 'core_engineering', 100.0, 'redact')
    `).run();
  }
})();

export function registerTenantUser(params: {
  orgName: string;
  email: string;
  password: string;
  tier: SubscriptionTier;
}) {
  const emailClean = params.email.trim().toLowerCase();
  const existing = db.prepare('SELECT email FROM tenants WHERE email = ?').get(emailClean);
  if (existing) {
    throw new Error('An account with this email already exists.');
  }

  const tenantId = `tnt_${crypto.randomBytes(6).toString('hex')}`;
  const salt = crypto.randomBytes(16).toString('hex');
  const passwordHash = hashPassword(params.password, salt);
  const clusterSyncToken = `aindigo_cst_${crypto.randomBytes(20).toString('hex')}`;
  const limit = TIER_LIMITS[params.tier] || 10_000;

  db.prepare(`
    INSERT INTO tenants (tenant_id, org_name, email, password_hash, password_salt, subscription_tier, cluster_sync_token, monthly_request_limit)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(tenantId, params.orgName.trim(), emailClean, passwordHash, salt, params.tier, clusterSyncToken, limit);

  db.prepare(`
    INSERT INTO tenant_policies (tenant_id, department, monthly_budget_usd, dlp_mode)
    VALUES (?, 'default_engineering', 100.0, 'redact')
  `).run(tenantId);

  return {
    tenantId,
    orgName: params.orgName.trim(),
    email: emailClean,
    subscriptionTier: params.tier,
    clusterSyncToken,
    monthlyRequestLimit: limit,
  };
}

export function authenticateTenantUser(email: string, password: string) {
  const emailClean = email.trim().toLowerCase();
  const row = db.prepare('SELECT * FROM tenants WHERE email = ?').get(emailClean) as any;
  if (!row) return null;

  const computed = hashPassword(password, row.password_salt);
  if (!crypto.timingSafeEqual(Buffer.from(computed, 'hex'), Buffer.from(row.password_hash, 'hex'))) {
    return null;
  }

  return {
    tenantId: row.tenant_id as string,
    orgName: row.org_name as string,
    email: row.email as string,
    subscriptionTier: row.subscription_tier as SubscriptionTier,
    clusterSyncToken: row.cluster_sync_token as string,
    monthlyRequestLimit: row.monthly_request_limit as number,
  };
}

export function findTenantByClusterToken(token: string) {
  return db.prepare('SELECT * FROM tenants WHERE cluster_sync_token = ?').get(token) as any;
}

export function findTenantById(tenantId: string) {
  return db.prepare('SELECT tenant_id, org_name, email, subscription_tier, cluster_sync_token, monthly_request_limit FROM tenants WHERE tenant_id = ?').get(tenantId) as any;
}

export function updateTenantTier(tenantId: string, tier: SubscriptionTier) {
  const limit = TIER_LIMITS[tier] || 10_000;
  db.prepare('UPDATE tenants SET subscription_tier = ?, monthly_request_limit = ? WHERE tenant_id = ?').run(tier, limit, tenantId);
}

const stmtInsertReceipt = db.prepare(`
  INSERT OR IGNORE INTO verified_audit_receipts (
    receipt_id, data_plane_node_id, tenant_id, department,
    model_requested, model_routed, prompt_tokens, completion_tokens,
    cost_usd, saved_usd, dlp_flags, prompt_sha256,
    previous_receipt_hash, receipt_hmac, created_at
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

export function ingestReceiptBatch(nodeId: string, tenantId: string, receipts: AuditReceipt[]): number {
  let inserted = 0;
  for (const r of receipts) {
    const res = stmtInsertReceipt.run(
      r.receiptId,
      nodeId,
      tenantId,
      r.department,
      r.modelRequested,
      r.modelRouted,
      r.promptTokens,
      r.completionTokens,
      r.costUsd,
      r.savedUsd,
      JSON.stringify(r.dlpFlags),
      r.promptSha256,
      r.previousReceiptHash,
      r.receiptHmac,
      r.createdAt
    );
    if (res.changes > 0) inserted++;
  }
  return inserted;
}

export function getTenantPolicies(tenantId: string) {
  return db.prepare('SELECT * FROM tenant_policies WHERE tenant_id = ?').all(tenantId);
}

export function getExecutiveDashboardSummary(tenantId: string) {
  const summary = db.prepare(`
    SELECT
      COUNT(*) as total_requests_governed,
      COALESCE(SUM(prompt_tokens + completion_tokens), 0) as total_tokens_governed,
      ROUND(COALESCE(SUM(cost_usd), 0), 6) as total_spend_usd,
      ROUND(COALESCE(SUM(saved_usd), 0), 6) as total_finops_saved_usd,
      COALESCE(SUM(CASE WHEN dlp_flags != '[]' THEN 1 ELSE 0 END), 0) as prompts_with_secrets_vaulted,
      COALESCE(SUM(CASE WHEN model_requested != model_routed THEN 1 ELSE 0 END), 0) as smart_downgrades_triggered
    FROM verified_audit_receipts
    WHERE tenant_id = ?
  `).get(tenantId);

  const recentReceipts = db.prepare(`
    SELECT receipt_id, tenant_id, department, model_requested, model_routed,
           cost_usd, saved_usd, dlp_flags, prompt_sha256, previous_receipt_hash, receipt_hmac, created_at
    FROM verified_audit_receipts
    WHERE tenant_id = ?
    ORDER BY ingested_at DESC
    LIMIT 10
  `).all(tenantId);

  const tenantInfo = findTenantById(tenantId);

  return {
    tenant: tenantInfo,
    summary,
    recentCryptographicReceipts: recentReceipts,
  };
}
