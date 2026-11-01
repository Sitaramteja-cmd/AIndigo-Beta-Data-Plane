import { strict as assert } from "node:assert";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";
import { VirtualKeyVault } from "../vault/virtual-key-vault.js";
import { ControlPlaneSyncClient, ControlPlanePolicyPayload } from "./control-sync.js";

async function runSyncTests() {
  console.log("================================================================");
  console.log(" ☁️ AIndigo Tier 4 — Expanded Enterprise Control Sync Test Suite");
  console.log("================================================================");

  const tmpDbPath = path.join(os.tmpdir(), `aindigo-expanded-sync-${Date.now()}.sqlite`);
  const cpSecret = crypto.randomBytes(32).toString("hex");
  const masterKey = crypto.randomBytes(32).toString("hex");

  try {
    // 1. Invalid HMAC Configuration Test
    const vaultInit = new VirtualKeyVault(masterKey, tmpDbPath, 1);
    assert.throws(() => {
      new ControlPlaneSyncClient(vaultInit, "shortsecret");
    }, /SYNC_CONFIG_ERROR/);
    console.log("✅ 1. Invalid HMAC configuration constructor rejection verified.");

    const syncClient = new ControlPlaneSyncClient(vaultInit, cpSecret);
    const now = Date.now();

    const keyOrgA = vaultInit.createVirtualKey({
      org_id: "org_kla",
      name: "Org A Key",
      provider: "openai",
      allowed_models: ["gpt-4o", "gpt-4o-mini"],
      raw_provider_key: "sk-proj-orga",
      budget_limit_usd: 1.00,
      nowMs: now,
    });

    const keyOrgB = vaultInit.createVirtualKey({
      org_id: "org_competitor",
      name: "Org B Key",
      provider: "openai",
      allowed_models: ["gpt-4o"],
      raw_provider_key: "sk-proj-orgb",
      budget_limit_usd: 1.00,
      nowMs: now,
    });

    // 2. Modified Payload After Signing (Signature Rejected)
    const payloadV1: ControlPlanePolicyPayload = {
      version: 1,
      timestamp: now,
      orgId: "org_kla",
      revokedKeyIds: [],
      budgetUpdates: [{ recordId: keyOrgA.metadata.id, newBudgetLimitUsd: 10.00 }],
    };
    const signedV1 = ControlPlaneSyncClient.signPolicyPayload(payloadV1, cpSecret);
    const tamperedJson = signedV1.signedJson.replace("10", "99");
    const resTampered = syncClient.applyPolicySync(tamperedJson, signedV1.signature);
    assert.equal(resTampered.success, false);
    assert.equal(resTampered.error, "SIGNATURE_VERIFICATION_FAILED");
    console.log("✅ 2. Modified payload signature rejection verified.");

    // 3. Expired Timestamp (Older than 5 mins)
    const payloadExpired: ControlPlanePolicyPayload = {
      version: 2,
      timestamp: now - 10 * 60 * 1000,
      orgId: "org_kla",
      revokedKeyIds: [],
      budgetUpdates: [],
    };
    const signedExpired = ControlPlaneSyncClient.signPolicyPayload(payloadExpired, cpSecret);
    const resExpired = syncClient.applyPolicySync(signedExpired.signedJson, signedExpired.signature);
    assert.equal(resExpired.success, false);
    assert.equal(resExpired.error, "STALE_PAYLOAD_TIMESTAMP");
    console.log("✅ 3. Expired timestamp rejection verified.");

    // 4. Future Timestamp (> 60s ahead)
    const payloadFuture: ControlPlanePolicyPayload = {
      version: 2,
      timestamp: now + 5 * 60 * 1000,
      orgId: "org_kla",
      revokedKeyIds: [],
      budgetUpdates: [],
    };
    const signedFuture = ControlPlaneSyncClient.signPolicyPayload(payloadFuture, cpSecret);
    const resFuture = syncClient.applyPolicySync(signedFuture.signedJson, signedFuture.signature);
    assert.equal(resFuture.success, false);
    assert.equal(resFuture.error, "FUTURE_PAYLOAD_TIMESTAMP");
    console.log("✅ 4. Future timestamp rejection verified.");

    // 5. Cross-Org Budget Modification
    const payloadCrossOrgBudget: ControlPlanePolicyPayload = {
      version: 2,
      timestamp: now,
      orgId: "org_kla",
      revokedKeyIds: [],
      budgetUpdates: [{ recordId: keyOrgB.metadata.id, newBudgetLimitUsd: 50.00 }],
    };
    const signedCrossBudget = ControlPlaneSyncClient.signPolicyPayload(payloadCrossOrgBudget, cpSecret);
    const resCrossBudget = syncClient.applyPolicySync(signedCrossBudget.signedJson, signedCrossBudget.signature);
    assert.equal(resCrossBudget.success, false);
    assert.equal(resCrossBudget.error?.includes("CROSS_ORG"), true);
    console.log("✅ 5. Cross-organization budget modification rejected.");

    // 6. Cross-Org Revocation
    const payloadCrossOrgRevoke: ControlPlanePolicyPayload = {
      version: 2,
      timestamp: now,
      orgId: "org_kla",
      revokedKeyIds: [keyOrgB.metadata.id],
      budgetUpdates: [],
    };
    const signedCrossRevoke = ControlPlaneSyncClient.signPolicyPayload(payloadCrossOrgRevoke, cpSecret);
    const resCrossRevoke = syncClient.applyPolicySync(signedCrossRevoke.signedJson, signedCrossRevoke.signature);
    assert.equal(resCrossRevoke.success, false);
    assert.equal(resCrossRevoke.error?.includes("CROSS_ORG"), true);
    console.log("✅ 6. Cross-organization revocation rejected.");

    // 7. Invalid Policy Version (Non-monotonic or equal)
    const payloadValidV2: ControlPlanePolicyPayload = {
      version: 2,
      timestamp: now,
      orgId: "org_kla",
      revokedKeyIds: [],
      budgetUpdates: [{ recordId: keyOrgA.metadata.id, newBudgetLimitUsd: 5.00 }],
    };
    const signedV2 = ControlPlaneSyncClient.signPolicyPayload(payloadValidV2, cpSecret);
    const resV2 = syncClient.applyPolicySync(signedV2.signedJson, signedV2.signature);
    assert.equal(resV2.success, true);

    // Try applying version 1 again (outdated/replayed)
    const resOutdated = syncClient.applyPolicySync(signedV1.signedJson, signedV1.signature);
    assert.equal(resOutdated.success, false);
    assert.equal(resOutdated.error, "REPLAYED_OR_OUTDATED_POLICY_VERSION");
    console.log("✅ 7. Outdated / replayed policy version rejected.");

    // 8. Successful Revocation Followed by Invalid Budget (Entire Transaction Rolled Back)
    const preRevokeMeta = vaultInit.getKeyMetadata(keyOrgA.metadata.id);
    assert.equal(preRevokeMeta?.revoked_at, null);

    const payloadAtomicFail: ControlPlanePolicyPayload = {
      version: 3,
      timestamp: now,
      orgId: "org_kla",
      revokedKeyIds: [keyOrgA.metadata.id], // valid revocation
      budgetUpdates: [{ recordId: "non_existent_key_id", newBudgetLimitUsd: 10.00 }], // invalid update triggers error
    };
    const signedAtomicFail = ControlPlaneSyncClient.signPolicyPayload(payloadAtomicFail, cpSecret);
    const resAtomicFail = syncClient.applyPolicySync(signedAtomicFail.signedJson, signedAtomicFail.signature);
    assert.equal(resAtomicFail.success, false);

    // Verify key A was NOT revoked because transaction rolled back entirely
    const postAtomicMeta = vaultInit.getKeyMetadata(keyOrgA.metadata.id);
    assert.equal(postAtomicMeta?.revoked_at, null, "Revocation must be rolled back due to subsequent error in batch");
    console.log("✅ 8. Atomic transaction rollback on partial failure verified.");

    // 9. Batch limit (101 operations) rejection
    const manyUpdates = Array.from({ length: 101 }, (_, i) => ({ recordId: `key_${i}`, newBudgetLimitUsd: 1.00 }));
    const payloadTooMany: ControlPlanePolicyPayload = {
      version: 3,
      timestamp: now,
      orgId: "org_kla",
      revokedKeyIds: [],
      budgetUpdates: manyUpdates,
    };
    const signedTooMany = ControlPlaneSyncClient.signPolicyPayload(payloadTooMany, cpSecret);
    const resTooMany = syncClient.applyPolicySync(signedTooMany.signedJson, signedTooMany.signature);
    assert.equal(resTooMany.success, false);
    assert.equal(resTooMany.error, "TOO_MANY_OPERATIONS");
    console.log("✅ 9. Maximum operations per sync batch limit enforced.");

    vaultInit.close();
  } finally {
    for (const suffix of ["", "-wal", "-shm"]) {
      const p = `${tmpDbPath}${suffix}`;
      if (fs.existsSync(p)) {
        try { fs.unlinkSync(p); } catch {}
      }
    }
  }

  console.log("================================================================");
  console.log(" 🎉 Tier 4 Module 4.1 Expanded Enterprise Sync Tests PASSED");
  console.log("================================================================");
}

runSyncTests();