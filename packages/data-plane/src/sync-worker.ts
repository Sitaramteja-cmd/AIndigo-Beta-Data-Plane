
import {
  fetchPendingReceiptBatch,
  clearAcknowledgedReceipts,
  getNodeActivation
} from './db.js';
import { SyncWorkerLifecycle } from './sync/sync-worker-lifecycle.js';
import {
  applyAuthenticatedNodeStatus,
  assertNodeLeaseActive,
  assertNodeLeaseValid,
  getNodeLeaseRuntimeContext,
  getTrustedControlPlaneSigningConfig,
} from './crypto/node-lease-runtime.js';
import { requestNodeStatus } from './crypto/node-status-client.js';

export function resolveControlPlaneUrl(rawUrl: string): string {
  if (!rawUrl || rawUrl !== rawUrl.trim()) {
    throw new Error('CONTROL_PLANE_URL must be a valid, non-empty URL.');
  }

  let parsed: URL;

  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error('CONTROL_PLANE_URL is not a valid URL.');
  }

  if (parsed.username || parsed.password) {
    throw new Error('CONTROL_PLANE_URL must not contain credentials.');
  }

  if (parsed.search || parsed.hash) {
    throw new Error('CONTROL_PLANE_URL must not contain a query or fragment.');
  }

  const isLoopback =
    parsed.hostname === 'localhost' ||
    parsed.hostname === '127.0.0.1' ||
    parsed.hostname === '[::1]' ||
    parsed.hostname === '::1';

  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error('CONTROL_PLANE_URL must use HTTPS.');
  }

  if (parsed.protocol === 'http:' && !isLoopback) {
    throw new Error(
      'CONTROL_PLANE_URL must use HTTPS for non-loopback hosts.'
    );
  }

  const normalizedPath = parsed.pathname.replace(/\/+$/, '');

  return `${parsed.origin}${normalizedPath}`;
}

const CONTROL_PLANE_URL = resolveControlPlaneUrl(
  process.env.CONTROL_PLANE_URL || 'http://127.0.0.1:3000'
);

// Bound each telemetry request so a stalled Control Plane cannot block syncing.
const SYNC_REQUEST_TIMEOUT_MS = 15_000;

export interface SyncCycleReport {
  receiptsFlushed: number;
  policiesSynced: number;
  controlPlaneStatus: string;
  error?: string;
}


/**
 * Flushes queued cryptographic receipts to the Control Plane.
 *
 * Uses the persisted node activation credentials.
 * Deletes only receipts explicitly acknowledged by the Control Plane.
 * If the Control Plane is unavailable, queued receipts remain in SQLite.
 */
async function executeControlPlaneSyncCycle(): Promise<SyncCycleReport> {
  try {
    // A valid lease permits the worker to contact the Control Plane
    // even when the previous authenticated status has expired.
    assertNodeLeaseValid();

    const nodeState = getNodeActivation();

    if (
      nodeState.is_activated !== 1 ||
      !nodeState.tenant_id ||
      nodeState.tenant_id === 'unpaired' ||
      !nodeState.cluster_sync_secret
    ) {
      throw new Error(
        'Data Plane is not activated with valid tenant sync credentials.'
      );
    }

    // Refresh the signed Control Plane status before telemetry.
    // This also runs when the local receipt queue is empty.
    const leaseContext = getNodeLeaseRuntimeContext();
    const trustedSigningConfig = getTrustedControlPlaneSigningConfig();

    const authenticatedStatus = await requestNodeStatus({
      controlPlaneUrl: CONTROL_PLANE_URL,
      controlPlanePublicKeyPem: trustedSigningConfig.publicKeyPem,
      expectedSigningKeyId: trustedSigningConfig.keyId,
      identity: leaseContext.identity,
      tenantId: leaseContext.tenantId,
      leaseId: leaseContext.leaseId,
      timeoutMs: SYNC_REQUEST_TIMEOUT_MS,
    });

    applyAuthenticatedNodeStatus(authenticatedStatus);
    assertNodeLeaseActive();

    const { receipts } = fetchPendingReceiptBatch();

    if (receipts.length === 0) {
      return {
        receiptsFlushed: 0,
        policiesSynced: 0,
        controlPlaneStatus: 'ONLINE_NO_PENDING_RECEIPTS'
      };
    }

    const normalizedReceipts = receipts.map((r) => {
      if (r.tenantId !== nodeState.tenant_id) {
        throw new Error(
          `Receipt ${r.receiptId} belongs to a different tenant.`
        );
      }

      return {
        receipt_id: r.receiptId,
        tenant_id: r.tenantId,
        department: r.department,
        model_requested: r.modelRequested,
        model_routed: r.modelRouted,
        prompt_tokens: r.promptTokens,
        completion_tokens: r.completionTokens,
        cost_usd: r.costUsd,
        finops_saved_usd: r.savedUsd,
        dlp_flags: JSON.stringify(r.dlpFlags),
        prompt_sha256: r.promptSha256,
        previous_receipt_hash: r.previousReceiptHash,
        receipt_hmac: r.receiptHmac,
        timestamp: r.createdAt
      };
    });

    const response = await fetch(
      `${CONTROL_PLANE_URL}/api/v1/telemetry/sync`,
      {
        method: 'POST',
        signal: AbortSignal.timeout(SYNC_REQUEST_TIMEOUT_MS),
        headers: {
          'Content-Type': 'application/json',
          'X-Cluster-Sync-Secret': nodeState.cluster_sync_secret
        },
        body: JSON.stringify({
          receipts: normalizedReceipts
        })
      }
    );

    if (!response.ok) {
      throw new Error(`Telemetry flush HTTP ${response.status}`);
    }

    const result = await response.json() as {
      status?: string;
      count?: number;
      accepted_receipt_ids?: unknown;
    };

    if (
      result.status !== 'synced' ||
      !Array.isArray(result.accepted_receipt_ids)
    ) {
      throw new Error(
        'Control Plane returned an invalid receipt acknowledgement.'
      );
    }

    const submittedIds = new Set(
      normalizedReceipts.map((r) => r.receipt_id)
    );

    const acceptedIds = result.accepted_receipt_ids;

    if (
      acceptedIds.length > normalizedReceipts.length ||
      !acceptedIds.every(
        (id): id is string =>
          typeof id === 'string' && submittedIds.has(id)
      ) ||
      new Set(acceptedIds).size !== acceptedIds.length
    ) {
      throw new Error(
        'Control Plane returned invalid or duplicate receipt acknowledgements.'
      );
    }

    // Remove only receipts explicitly acknowledged by the Control Plane.
    clearAcknowledgedReceipts(acceptedIds);

    return {
      receiptsFlushed: acceptedIds.length,
      policiesSynced: 0,
      controlPlaneStatus:
        acceptedIds.length === normalizedReceipts.length
          ? 'ONLINE_SYNCED'
          : 'ONLINE_PARTIALLY_SYNCED'
    };
  } catch (err: unknown) {
    return {
      receiptsFlushed: 0,
      policiesSynced: 0,
      controlPlaneStatus:
        'OFFLINE_FAULT_ISOLATED (Queue buffered in local SQLite)',
      error: err instanceof Error ? err.message : 'Unknown sync error'
    };
  }
}

const syncLifecycle = new SyncWorkerLifecycle<SyncCycleReport>();

const SHUTDOWN_REPORT: SyncCycleReport = {
  receiptsFlushed: 0,
  policiesSynced: 0,
  controlPlaneStatus: 'SHUTTING_DOWN'
};

/**
 * Public synchronization entry point.
 *
 * Concurrent callers share one active synchronization Promise.
 */
export function runControlPlaneSyncCycle(): Promise<SyncCycleReport> {
  return syncLifecycle.run(
    executeControlPlaneSyncCycle,
    SHUTDOWN_REPORT
  );
}

/**
 * Starts the periodic synchronization loop.
 * Repeated calls do not create duplicate timers.
 */
export function startBackgroundSyncLoop(
  intervalMs: number = 10_000
): void {
  syncLifecycle.start(
    executeControlPlaneSyncCycle,
    intervalMs,
    SHUTDOWN_REPORT
  );
}

/**
 * Stops future scheduled and manually initiated sync cycles.
 * An active cycle is allowed to finish.
 */
export function stopBackgroundSyncLoop(): void {
  syncLifecycle.stop();
}

/**
 * Waits for the currently active synchronization cycle.
 * Returns false if the timeout expires.
 */
export function waitForSyncIdle(timeoutMs: number): Promise<boolean> {
  return syncLifecycle.waitForIdle(timeoutMs);
}
