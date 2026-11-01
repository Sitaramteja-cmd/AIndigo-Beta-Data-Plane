import { SignedReceipt } from "../crypto/node-identity.js";

export interface OutboxItem {
  id: string;
  receipt_id: string;
  payload_json: string;
  status: "pending" | "synced" | "failed";
  retry_count: number;
  next_attempt_at: number;
}

/**
 * Simulates a robust SQLite Outbox queue for Data Plane telemetry sync.
 */
export class TelemetryOutboxQueue {
  private queue: Map<string, OutboxItem> = new Map();

  /**
   * Enqueues a signed receipt into the local outbox in <1ms.
   */
  public enqueue(receipt: SignedReceipt): void {
    const item: OutboxItem = {
      id: `outbox_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
      receipt_id: receipt.receipt_id,
      payload_json: JSON.stringify(receipt),
      status: "pending",
      retry_count: 0,
      next_attempt_at: Date.now(),
    };
    this.queue.set(receipt.receipt_id, item);
  }

  /**
   * Returns pending items ready for batched sync.
   */
  public getPendingBatch(batchSize: number = 50): OutboxItem[] {
    const now = Date.now();
    const pending: OutboxItem[] = [];
    for (const item of this.queue.values()) {
      if (item.status === "pending" && item.next_attempt_at <= now) {
        pending.push(item);
        if (pending.length >= batchSize) break;
      }
    }
    return pending;
  }

  /**
   * Marks items as successfully synced to the Cloud Control Plane.
   */
  public markSynced(receiptIds: string[]): void {
    for (const id of receiptIds) {
      const item = this.queue.get(id);
      if (item) {
        item.status = "synced";
      }
    }
  }

  /**
   * Handles sync failure with exponential backoff.
   */
  public markFailed(receiptIds: string[]): void {
    const now = Date.now();
    for (const id of receiptIds) {
      const item = this.queue.get(id);
      if (item) {
        item.retry_count += 1;
        // Exponential backoff: 2s, 4s, 8s, 16s...
        const backoffMs = Math.min(2000 * Math.pow(2, item.retry_count - 1), 60000);
        item.next_attempt_at = now + backoffMs;
        if (item.retry_count >= 5) {
          item.status = "failed";
        }
      }
    }
  }

  public getQueueStats() {
    let pending = 0;
    let synced = 0;
    let failed = 0;
    for (const item of this.queue.values()) {
      if (item.status === "pending") pending++;
      if (item.status === "synced") synced++;
      if (item.status === "failed") failed++;
    }
    return { pending, synced, failed, total: this.queue.size };
  }
}
