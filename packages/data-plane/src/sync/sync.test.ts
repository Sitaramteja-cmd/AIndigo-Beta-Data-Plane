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

    // 7A. Budget increase and decrease must preserve existing spend
    // and outstanding reservations.
    const budgetTestKey = vaultInit.createVirtualKey({
      org_id: "org_kla",
      name: "Budget Update Preservation Test",
      provider: "openai",
      allowed_models: ["gpt-4o"],
      raw_provider_key: "sk-test-budget-update",
      budget_limit_usd: 1.00,
      nowMs: now,
    });

    // Spend $0.30 and hold another $0.40.
    const alreadySpentAuth = vaultInit.authorize({
      rawVirtualKey: budgetTestKey.rawVirtualKey,
      requestedModel: "gpt-4o",
      estimatedCostUsd: 0.50,
    });

    assert.equal(alreadySpentAuth.valid, true);

    const alreadySpentSettlement = vaultInit.reconcileSpend(
      alreadySpentAuth.reservation_id!,
      0.30,
      "rcpt_budget_update_spend"
    );

    assert.equal(alreadySpentSettlement.reconciled, true);

    const outstandingAuth = vaultInit.authorize({
      rawVirtualKey: budgetTestKey.rawVirtualKey,
      requestedModel: "gpt-4o",
      estimatedCostUsd: 0.40,
    });

    assert.equal(outstandingAuth.valid, true);

    // Version 3: Increase budget from $1.00 to $2.00.
    const budgetIncreasePayload: ControlPlanePolicyPayload = {
      version: 3,
      timestamp: Date.now(),
      orgId: "org_kla",
      revokedKeyIds: [],
      budgetUpdates: [{
        recordId: budgetTestKey.metadata.id,
        newBudgetLimitUsd: 2.00,
      }],
    };

    const signedBudgetIncrease =
      ControlPlaneSyncClient.signPolicyPayload(
        budgetIncreasePayload,
        cpSecret
      );

    const budgetIncreaseResult = syncClient.applyPolicySync(
      signedBudgetIncrease.signedJson,
      signedBudgetIncrease.signature
    );

    assert.equal(budgetIncreaseResult.success, true);
    assert.equal(budgetIncreaseResult.appliedBudgetUpdates, 1);

    let budgetMetadata = vaultInit.getKeyMetadata(
      budgetTestKey.metadata.id
    )!;

    assert.equal(budgetMetadata.budget_limit_micros, 2_000_000);
    assert.equal(budgetMetadata.current_spend_micros, 300_000);
    assert.equal(budgetMetadata.reserved_micros, 400_000);

    const syncDb = (vaultInit as any).db;

    const activePeriodId = `monthly:${new Date(now)
      .toISOString()
      .slice(0, 7)}`;

    let activeUsage = syncDb.prepare(`
      SELECT budget_limit_micros, spent_micros, reserved_micros
      FROM budget_period_usage
      WHERE key_id = ? AND period_id = ?
    `).get(
      budgetTestKey.metadata.id,
      activePeriodId
    );

    assert.ok(activeUsage);
    assert.equal(Number(activeUsage.budget_limit_micros), 2_000_000);
    assert.equal(Number(activeUsage.spent_micros), 300_000);
    assert.equal(Number(activeUsage.reserved_micros), 400_000);

    console.log(
      "✅ 7A. Budget increase preserves existing spend and reservations."
    );

    // Version 4: Decrease budget below existing spend + reservations.
    // The update must succeed without clearing or reducing usage.
    const budgetDecreasePayload: ControlPlanePolicyPayload = {
      version: 4,
      timestamp: Date.now(),
      orgId: "org_kla",
      revokedKeyIds: [],
      budgetUpdates: [{
        recordId: budgetTestKey.metadata.id,
        newBudgetLimitUsd: 0.50,
      }],
    };

    const signedBudgetDecrease =
      ControlPlaneSyncClient.signPolicyPayload(
        budgetDecreasePayload,
        cpSecret
      );

    const budgetDecreaseResult = syncClient.applyPolicySync(
      signedBudgetDecrease.signedJson,
      signedBudgetDecrease.signature
    );

    assert.equal(budgetDecreaseResult.success, true);
    assert.equal(budgetDecreaseResult.appliedBudgetUpdates, 1);

    budgetMetadata = vaultInit.getKeyMetadata(
      budgetTestKey.metadata.id
    )!;

    assert.equal(budgetMetadata.budget_limit_micros, 500_000);
    assert.equal(budgetMetadata.current_spend_micros, 300_000);
    assert.equal(budgetMetadata.reserved_micros, 400_000);

    activeUsage = syncDb.prepare(`
      SELECT budget_limit_micros, spent_micros, reserved_micros
      FROM budget_period_usage
      WHERE key_id = ? AND period_id = ?
    `).get(
      budgetTestKey.metadata.id,
      activePeriodId
    );

    assert.ok(activeUsage);
    assert.equal(Number(activeUsage.budget_limit_micros), 500_000);
    assert.equal(Number(activeUsage.spent_micros), 300_000);
    assert.equal(Number(activeUsage.reserved_micros), 400_000);

    // Existing spend + reservations ($0.70) exceed the new $0.50 limit.
    // New requests must be rejected, while the existing reservation remains.
    const deniedAfterDecrease = vaultInit.authorize({
      rawVirtualKey: budgetTestKey.rawVirtualKey,
      requestedModel: "gpt-4o",
      estimatedCostUsd: 0.01,
    });

    assert.equal(deniedAfterDecrease.valid, false);
    assert.equal(deniedAfterDecrease.reason, "BUDGET_EXCEEDED");

    console.log(
      "✅ 7B. Budget decrease preserves usage and blocks additional requests."
    );

    // Version 5: NaN is serialized as JSON null.
    // The signed sync handler must reject it and retain the existing limit.
    const invalidBudgetPayload: ControlPlanePolicyPayload = {
      version: 5,
      timestamp: Date.now(),
      orgId: "org_kla",
      revokedKeyIds: [],
      budgetUpdates: [{
        recordId: budgetTestKey.metadata.id,
        newBudgetLimitUsd: Number.NaN,
      }],
    };

    const signedInvalidBudget =
      ControlPlaneSyncClient.signPolicyPayload(
        invalidBudgetPayload,
        cpSecret
      );

    const invalidBudgetResult = syncClient.applyPolicySync(
      signedInvalidBudget.signedJson,
      signedInvalidBudget.signature
    );

    assert.equal(invalidBudgetResult.success, false);
    assert.equal(invalidBudgetResult.error, "INVALID_BUDGET_VALUE");

    budgetMetadata = vaultInit.getKeyMetadata(
      budgetTestKey.metadata.id
    )!;

    assert.equal(
      budgetMetadata.budget_limit_micros,
      500_000,
      "Invalid budget must not change the configured limit."
    );

    // Since the invalid sync was rolled back, version 5 is still available.
    // Restore the budget to $1.00.
    const restoreBudgetPayload: ControlPlanePolicyPayload = {
      version: 5,
      timestamp: Date.now(),
      orgId: "org_kla",
      revokedKeyIds: [],
      budgetUpdates: [{
        recordId: budgetTestKey.metadata.id,
        newBudgetLimitUsd: 1.00,
      }],
    };

    const signedRestoreBudget =
      ControlPlaneSyncClient.signPolicyPayload(
        restoreBudgetPayload,
        cpSecret
      );

    const restoreBudgetResult = syncClient.applyPolicySync(
      signedRestoreBudget.signedJson,
      signedRestoreBudget.signature
    );

    assert.equal(restoreBudgetResult.success, true);

    budgetMetadata = vaultInit.getKeyMetadata(
      budgetTestKey.metadata.id
    )!;

    assert.equal(budgetMetadata.budget_limit_micros, 1_000_000);
    assert.equal(budgetMetadata.current_spend_micros, 300_000);
    assert.equal(budgetMetadata.reserved_micros, 400_000);

    // Settle the reservation after the budget decrease and restoration.
    const outstandingSettlement = vaultInit.reconcileSpend(
      outstandingAuth.reservation_id!,
      0.35,
      "rcpt_budget_update_late_settlement"
    );

    assert.equal(outstandingSettlement.reconciled, true);
    assert.equal(outstandingSettlement.actual_micros, 350_000);

    budgetMetadata = vaultInit.getKeyMetadata(
      budgetTestKey.metadata.id
    )!;

    assert.equal(budgetMetadata.current_spend_micros, 650_000);
    assert.equal(budgetMetadata.reserved_micros, 0);

    activeUsage = syncDb.prepare(`
      SELECT budget_limit_micros, spent_micros, reserved_micros
      FROM budget_period_usage
      WHERE key_id = ? AND period_id = ?
    `).get(
      budgetTestKey.metadata.id,
      activePeriodId
    );

    assert.ok(activeUsage);
    assert.equal(Number(activeUsage.budget_limit_micros), 1_000_000);
    assert.equal(Number(activeUsage.spent_micros), 650_000);
    assert.equal(Number(activeUsage.reserved_micros), 0);

    console.log(
      "✅ 7C. Invalid budget rejected; restored budget and late settlement verified."
    );

    // 7D. Monthly budget update after UTC rollover but before
    // the first request of the new month.
    const rolloverTestNow = Date.now();

    const previousMonthTimestamp = Date.UTC(
      new Date(rolloverTestNow).getUTCFullYear(),
      new Date(rolloverTestNow).getUTCMonth() - 1,
      15,
      12,
      0,
      0,
      0
    );

    const previousPeriodDate = new Date(previousMonthTimestamp);
    const previousPeriodId =
      `monthly:${previousPeriodDate.toISOString().slice(0, 7)}`;

    const currentPeriodId =
      `monthly:${new Date(rolloverTestNow).toISOString().slice(0, 7)}`;

    const rolloverTestKey = vaultInit.createVirtualKey({
      org_id: "org_kla",
      name: "Monthly Rollover Before First Request",
      provider: "openai",
      allowed_models: ["gpt-4o"],
      raw_provider_key: "sk-test-monthly-rollover",
      budget_limit_usd: 1.25,
      budget_period: "monthly",
      nowMs: previousMonthTimestamp,
    });

    // Confirm the key initially has only the previous month's usage row.
    const previousUsageBefore = syncDb.prepare(`
      SELECT budget_limit_micros, spent_micros, reserved_micros
      FROM budget_period_usage
      WHERE key_id = ? AND period_id = ?
    `).get(
      rolloverTestKey.metadata.id,
      previousPeriodId
    );

    assert.ok(previousUsageBefore);
    assert.equal(Number(previousUsageBefore.budget_limit_micros), 1_250_000);
    assert.equal(Number(previousUsageBefore.spent_micros), 0);
    assert.equal(Number(previousUsageBefore.reserved_micros), 0);

    const currentUsageBefore = syncDb.prepare(`
      SELECT period_id
      FROM budget_period_usage
      WHERE key_id = ? AND period_id = ?
    `).get(
      rolloverTestKey.metadata.id,
      currentPeriodId
    );

    assert.equal(
      currentUsageBefore,
      undefined,
      "Current month must not have a usage row before the policy update."
    );

    // Version 6: Apply the new monthly budget after the UTC month boundary.
    const rolloverBudgetPayload: ControlPlanePolicyPayload = {
      version: 6,
      timestamp: rolloverTestNow,
      orgId: "org_kla",
      revokedKeyIds: [],
      budgetUpdates: [{
        recordId: rolloverTestKey.metadata.id,
        newBudgetLimitUsd: 3.00,
      }],
    };

    const signedRolloverBudget =
      ControlPlaneSyncClient.signPolicyPayload(
        rolloverBudgetPayload,
        cpSecret
      );

    const rolloverBudgetResult = syncClient.applyPolicySync(
      signedRolloverBudget.signedJson,
      signedRolloverBudget.signature
    );

    assert.equal(rolloverBudgetResult.success, true);
    assert.equal(rolloverBudgetResult.appliedBudgetUpdates, 1);

    // The new period must now exist with the updated limit.
    const currentUsageAfter = syncDb.prepare(`
      SELECT budget_limit_micros, spent_micros, reserved_micros
      FROM budget_period_usage
      WHERE key_id = ? AND period_id = ?
    `).get(
      rolloverTestKey.metadata.id,
      currentPeriodId
    );

    assert.ok(currentUsageAfter);
    assert.equal(Number(currentUsageAfter.budget_limit_micros), 3_000_000);
    assert.equal(Number(currentUsageAfter.spent_micros), 0);
    assert.equal(Number(currentUsageAfter.reserved_micros), 0);

    // The historical period must retain its original limit and usage.
    const previousUsageAfter = syncDb.prepare(`
      SELECT budget_limit_micros, spent_micros, reserved_micros
      FROM budget_period_usage
      WHERE key_id = ? AND period_id = ?
    `).get(
      rolloverTestKey.metadata.id,
      previousPeriodId
    );

    assert.ok(previousUsageAfter);
    assert.equal(Number(previousUsageAfter.budget_limit_micros), 1_250_000);
    assert.equal(Number(previousUsageAfter.spent_micros), 0);
    assert.equal(Number(previousUsageAfter.reserved_micros), 0);

    // Verify that a real authorization can use the newly configured
    // budget immediately after the policy update.
    const rolloverAuthorization = vaultInit.authorize({
      rawVirtualKey: rolloverTestKey.rawVirtualKey,
      requestedModel: "gpt-4o",
      estimatedCostUsd: 0.25,
      nowMs: rolloverTestNow,
    });

    assert.equal(rolloverAuthorization.valid, true);

    const rolloverSettlement = vaultInit.reconcileSpend(
      rolloverAuthorization.reservation_id!,
      0.20,
      "rcpt_monthly_rollover_sync"
    );

    assert.equal(rolloverSettlement.reconciled, true);
    assert.equal(rolloverSettlement.actual_micros, 200_000);

    const currentUsageAfterSettlement = syncDb.prepare(`
      SELECT budget_limit_micros, spent_micros, reserved_micros
      FROM budget_period_usage
      WHERE key_id = ? AND period_id = ?
    `).get(
      rolloverTestKey.metadata.id,
      currentPeriodId
    );

    assert.equal(
      Number(currentUsageAfterSettlement.budget_limit_micros),
      3_000_000
    );
    assert.equal(
      Number(currentUsageAfterSettlement.spent_micros),
      200_000
    );
    assert.equal(
      Number(currentUsageAfterSettlement.reserved_micros),
      0
    );

    console.log(
      "✅ 7D. Monthly rollover policy update initializes the new period before the first request; historical period preserved."
    );

    // 8. Successful Revocation Followed by Invalid Budget (Entire Transaction Rolled Back)
    const preRevokeMeta = vaultInit.getKeyMetadata(keyOrgA.metadata.id);
    assert.equal(preRevokeMeta?.revoked_at, null);

    const payloadAtomicFail: ControlPlanePolicyPayload = {
      version: 7,
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
      version: 7,
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