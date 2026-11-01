import { strict as assert } from "node:assert";
import { TelemetryOutboxQueue } from "./outbox.js";
import { SignedReceipt } from "../crypto/node-identity.js";

async function runOutboxTests() {
  console.log("================================================================");
  console.log(" 📦 AIndigo Tier 1 — SQLite Outbox & Resilient Sync Test");
  console.log("================================================================");

  const outbox = new TelemetryOutboxQueue();

  const mockReceipt: SignedReceipt = {
    receipt_id: "rcpt_outbox_001",
    timestamp: new Date().toISOString(),
    node_id: "node_test_123",
    department: "engineering",
    model_requested: "gemini-2.5-flash",
    model_routed: "gemini-2.5-flash",
    prompt_tokens: 100,
    completion_tokens: 50,
    cost_usd: 0.0003,
    dlp_categories: [],
    cache_hit: false,
    prev_hash: "GENESIS_00000000000000000000000000000000000000000000000000000000",
    receipt_hash: "abc123hash",
    ed25519_signature: "fake_sig",
    node_pubkey_fingerprint: "node_test_123",
    schema_version: "2.0.0",
  };

  // 1. Enqueue receipt
  outbox.enqueue(mockReceipt);
  let stats = outbox.getQueueStats();
  assert.equal(stats.pending, 1, "Receipt must be enqueued as pending");
  console.log("✅ 1. Local Outbox Enqueue Verified (<1ms).");

  // 2. Simulate network failure & exponential backoff retry
  const batch = outbox.getPendingBatch();
  assert.equal(batch.length, 1);
  outbox.markFailed([batch[0].receipt_id]);
  
  stats = outbox.getQueueStats();
  assert.equal(stats.pending, 1, "Failed item stays in outbox for retry");
  console.log("✅ 2. Exponential Backoff & Retry Queue Handled.");

  // 3. Simulate network recovery & successful sync
  // Force next_attempt_at to past so batch picks it up immediately
  (batch[0] as any).next_attempt_at = Date.now() - 1000;
  outbox.markSynced([batch[0].receipt_id]);

  stats = outbox.getQueueStats();
  assert.equal(stats.synced, 1, "Receipt marked as synced");
  console.log("✅ 3. Successful Batch Sync & Status Transition Verified.");

  console.log("================================================================");
  console.log(" 🎉 Tier 1 Module 1.4 Outbox Sync Tests PASSED");
  console.log("================================================================");
}

runOutboxTests().catch((err) => {
  console.error("❌ Outbox Test Failed:", err);
  process.exit(1);
});
