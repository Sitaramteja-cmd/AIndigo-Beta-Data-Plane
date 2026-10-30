import {
  fetchPendingReceiptBatch,
  clearSyncedReceiptBatch,
  applySyncedPolicy
} from './db.js';

const CONTROL_PLANE_URL = process.env.CONTROL_PLANE_URL || 'http://127.0.0.1:3000';
const DEFAULT_SYNC_SECRET =
  process.env.CLUSTER_SYNC_SECRET ||
  'aindigo-cluster-hmac-secret-key-2026-enterprise-verified';

export interface SyncCycleReport {
  receiptsFlushed: number;
  policiesSynced: number;
  controlPlaneStatus: string;
  error?: string;
}

/**
 * Flushes queued cryptographic receipts to Control Plane and pulls latest tenant policies.
 * Never throws: if Control Plane is offline, Data Plane continues operating off local SQLite.
 */
export async function runControlPlaneSyncCycle(): Promise<SyncCycleReport> {
  let receiptsFlushed = 0;
  let policiesSynced = 0;

  try {
    // 1. Flush queued cryptographic receipts
    const { maxId, receipts } = fetchPendingReceiptBatch();
    if (receipts.length > 0) {
      const normalizedReceipts = receipts.map((r: any) => ({
        receipt_id: r.receiptId || r.receipt_id,
        tenant_id: r.tenantId || r.tenant_id || 'acme_corp',
        department: r.department || 'default',
        model_requested: r.modelRequested || r.model_requested || 'gpt-4o',
        model_routed: r.modelRouted || r.model_routed || 'gpt-4o',
        prompt_tokens: r.promptTokens ?? r.prompt_tokens ?? 0,
        completion_tokens: r.completionTokens ?? r.completion_tokens ?? 0,
        cost_usd: r.costUsd ?? r.cost_usd ?? 0,
        finops_saved_usd: r.finopsSavedUsd ?? r.finops_saved_usd ?? 0,
        dlp_flags: Array.isArray(r.dlpFlags)
          ? JSON.stringify(r.dlpFlags)
          : typeof r.dlp_flags === 'string'
          ? r.dlp_flags
          : '[]',
        prompt_sha256: r.promptSha256 || r.prompt_sha256 || '',
        previous_receipt_hash: r.previousReceiptHash || r.previous_receipt_hash || 'GENESIS',
        receipt_hmac: r.receiptHmac || r.receipt_hmac,
        timestamp: r.createdAt || r.created_at || new Date().toISOString()
      }));

      const res = await fetch(`${CONTROL_PLANE_URL}/api/v1/telemetry/sync`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${DEFAULT_SYNC_SECRET}`,
          'X-Cluster-Sync-Secret': DEFAULT_SYNC_SECRET
        },
        body: JSON.stringify({ receipts: normalizedReceipts })
      });

      if (!res.ok) {
        throw new Error(`Telemetry flush HTTP ${res.status}`);
      }

      clearSyncedReceiptBatch(maxId);
      receiptsFlushed = receipts.length;
    }

    // 2. Pull tenant policies
    try {
      const syncRes = await fetch(`${CONTROL_PLANE_URL}/api/v1/sync`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${DEFAULT_SYNC_SECRET}`,
          'X-Cluster-Sync-Secret': DEFAULT_SYNC_SECRET
        }
      });
      if (syncRes.ok) {
        const data = (await syncRes.json()) as { policies?: any[] };
        if (Array.isArray(data.policies)) {
          for (const p of data.policies) {
            applySyncedPolicy(p.tenant_id, p.department, p.monthly_budget_usd, p.dlp_mode);
            policiesSynced++;
          }
        }
      }
    } catch {
      // Optional policy pull
    }

    return {
      receiptsFlushed,
      policiesSynced,
      controlPlaneStatus: 'ONLINE_SYNCED'
    };
  } catch (err: any) {
    return {
      receiptsFlushed: 0,
      policiesSynced: 0,
      controlPlaneStatus: 'OFFLINE_FAULT_ISOLATED (Queue buffered in local SQLite)',
      error: err?.message || 'Unknown sync error'
    };
  }
}

export function startBackgroundSyncLoop(intervalMs: number = 10_000): void {
  setInterval(() => {
    void runControlPlaneSyncCycle();
  }, intervalMs);
}
