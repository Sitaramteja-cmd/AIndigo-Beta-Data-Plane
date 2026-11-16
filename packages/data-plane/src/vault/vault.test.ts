import { strict as assert } from "node:assert";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import util from "node:util";
import { DatabaseSync } from "node:sqlite";
import {
  VirtualKeyVault,
  VaultDiagnosticEvent,
  estimateRequestCostUsd,
} from "./virtual-key-vault.js";

function runVaultTests() {
  console.log("================================================================");
  console.log(" ðŸ” AIndigo Tier 2 â€” Production Virtual Key Vault Test Suite");
  console.log("================================================================");

  const tmpDbPath = path.join(os.tmpdir(), `aindigo-vault-test-${Date.now()}.sqlite`);
  const masterKeyV1 = crypto.randomBytes(32).toString("hex");
  const masterKeyV2 = crypto.randomBytes(32).toString("hex");
  const rawProviderSecret = "sk-proj-ULTRA-SECRET-PROVIDER-KEY-DO-NOT-LEAK-999";
  const diagnostics: VaultDiagnosticEvent[] = [];

  try {
    // 1. Constructor & createVirtualKey Input Validation
    assert.throws(() => new VirtualKeyVault(""), /VAULT_INIT_ERROR/);
    assert.throws(() => new VirtualKeyVault("1234"), /VAULT_INIT_ERROR/);
    assert.throws(() => new VirtualKeyVault({}), /VAULT_INIT_ERROR/);

    let vault = new VirtualKeyVault(masterKeyV1, tmpDbPath, 1, (evt) => diagnostics.push(evt));

    assert.throws(
      () =>
        vault.createVirtualKey({
          org_id: "   ",
          name: "Key",
          provider: "openai",
          allowed_models: ["gpt-4o"],
          raw_provider_key: rawProviderSecret,
          budget_limit_usd: 1,
        }),
      /org_id must be a non-empty string/
    );
    assert.throws(
      () =>
        vault.createVirtualKey({
          org_id: "org_1",
          name: "Key",
          provider: "openai",
          allowed_models: [],
          raw_provider_key: rawProviderSecret,
          budget_limit_usd: 1,
        }),
      /allowed_models must be a non-empty array/
    );
    assert.throws(
      () =>
        vault.createVirtualKey({
          org_id: "org_1",
          name: "Key",
          provider: "openai",
          allowed_models: ["gpt-4o"],
          raw_provider_key: rawProviderSecret,
          budget_limit_usd: 1,
          expires_at: Date.now() - 5000,
        }),
      /expires_at must be a future timestamp/
    );
    console.log("âœ… 1. Strict Constructor & createVirtualKey Input Validation Verified.");

    // 2. Create Key & Verify Clean Metadata
    const created = vault.createVirtualKey({
      org_id: "org_kla_sec",
      name: "Production Gateway Key",
      provider: "openai",
      allowed_models: ["gpt-4o", "gpt-4o-mini"],
      raw_provider_key: rawProviderSecret,
      budget_limit_usd: 1.00,
      budget_period: "monthly",
    });

    const meta0 = vault.getKeyMetadata(created.metadata.id)!;
    assert.equal("key_hash" in meta0, false);
    assert.equal(meta0.budget_limit_micros, 1_000_000);
        // 2A. Verify durable budget-period initialization
    const budgetDb = new DatabaseSync(tmpDbPath);

    try {
      const now = new Date();
      const year = now.getUTCFullYear();
      const month = String(now.getUTCMonth() + 1).padStart(2, "0");
      const expectedMonthlyPeriod = `monthly:${year}-${month}`;

      const monthlyUsage = budgetDb.prepare(`
        SELECT period_id, budget_limit_micros, spent_micros, reserved_micros
        FROM budget_period_usage
        WHERE key_id = ?
      `).get(created.metadata.id) as {
        period_id: string;
        budget_limit_micros: number;
        spent_micros: number;
        reserved_micros: number;
      } | undefined;

      assert.ok(monthlyUsage, "Monthly budget-period row must exist.");
      assert.equal(monthlyUsage.period_id, expectedMonthlyPeriod);
      assert.equal(monthlyUsage.budget_limit_micros, 1_000_000);
      assert.equal(monthlyUsage.spent_micros, 0);
      assert.equal(monthlyUsage.reserved_micros, 0);

      const lifetimeKey = vault.createVirtualKey({
        org_id: "org_kla_sec",
        name: "Lifetime Budget Test Key",
        provider: "openai",
        allowed_models: ["gpt-4o"],
        raw_provider_key: rawProviderSecret,
        budget_limit_usd: 5.00,
        budget_period: "lifetime",
      });

      const lifetimeUsage = budgetDb.prepare(`
        SELECT period_id, budget_limit_micros, spent_micros, reserved_micros
        FROM budget_period_usage
        WHERE key_id = ?
      `).get(lifetimeKey.metadata.id) as {
        period_id: string;
        budget_limit_micros: number;
        spent_micros: number;
        reserved_micros: number;
      } | undefined;

      assert.ok(lifetimeUsage, "Lifetime budget-period row must exist.");
      assert.equal(lifetimeUsage.period_id, "lifetime");
      assert.equal(lifetimeUsage.budget_limit_micros, 5_000_000);
      assert.equal(lifetimeUsage.spent_micros, 0);
      assert.equal(lifetimeUsage.reserved_micros, 0);

      console.log("âœ… 2A. Monthly & Lifetime Budget Initialization Verified.");
    } finally {
      budgetDb.close();
    }
    console.log("âœ… 2. Micro-USD Storage & Sanitized Metadata Verified.");

    // 2B. UTC monthly rollover and late settlement across month boundary.
    const octoberStart = Date.UTC(2026, 9, 31, 23, 50, 0);
    const novemberStart = Date.UTC(2026, 10, 1, 0, 0, 0);

    const boundaryKey = vault.createVirtualKey({
      org_id: "org_budget_period_test",
      name: "Monthly Boundary Test Key",
      provider: "openai",
      allowed_models: ["gpt-4o"],
      raw_provider_key: rawProviderSecret,
      budget_limit_usd: 1.00,
      budget_period: "monthly",
      nowMs: octoberStart,
    });

    // First October request: $0.80 reserved, $0.75 actually spent.
    const octoberSpend = vault.authorize({
      rawVirtualKey: boundaryKey.rawVirtualKey,
      requestedModel: "gpt-4o",
      estimatedCostUsd: 0.80,
      nowMs: Date.UTC(2026, 9, 31, 23, 59, 10),
    });

    assert.equal(octoberSpend.valid, true);

    const octoberSpendSettlement = vault.reconcileSpend(
      octoberSpend.reservation_id!,
      0.75,
      "rcpt_october_spend",
      Date.UTC(2026, 9, 31, 23, 59, 20)
    );

    assert.equal(octoberSpendSettlement.reconciled, true);

    // Another October request remains outstanding across midnight.
    const octoberPending = vault.authorize({
      rawVirtualKey: boundaryKey.rawVirtualKey,
      requestedModel: "gpt-4o",
      estimatedCostUsd: 0.20,
      nowMs: Date.UTC(2026, 9, 31, 23, 59, 40),
    });

    assert.equal(octoberPending.valid, true);

    // October spend ($0.75) + reservation ($0.20) + request ($0.10)
    // exceeds the October budget.
    const octoberOverBudget = vault.authorize({
      rawVirtualKey: boundaryKey.rawVirtualKey,
      requestedModel: "gpt-4o",
      estimatedCostUsd: 0.10,
      nowMs: Date.UTC(2026, 9, 31, 23, 59, 50),
    });

    assert.equal(octoberOverBudget.valid, false);
    assert.equal(octoberOverBudget.reason, "BUDGET_EXCEEDED");

    // November gets an independent monthly budget.
    // The outstanding October reservation remains in October.
    const novemberRequest = vault.authorize({
      rawVirtualKey: boundaryKey.rawVirtualKey,
      requestedModel: "gpt-4o",
      estimatedCostUsd: 0.90,
      nowMs: novemberStart + 1000,
    });

    assert.equal(
      novemberRequest.valid,
      true,
      "New month must have an independent monthly budget."
    );

    // Late October settlement arrives after November has started.
    // It must update October, not November.
    const octoberLateSettlement = vault.reconcileSpend(
      octoberPending.reservation_id!,
      0.18,
      "rcpt_october_late",
      novemberStart + 2000
    );

    assert.equal(octoberLateSettlement.reconciled, true);
    assert.equal(octoberLateSettlement.actual_micros, 180_000);

    // Settle the November request independently.
    const novemberSettlement = vault.reconcileSpend(
      novemberRequest.reservation_id!,
      0.85,
      "rcpt_november_spend",
      novemberStart + 3000
    );

    assert.equal(novemberSettlement.reconciled, true);
    assert.equal(novemberSettlement.actual_micros, 850_000);

    const boundaryDb = new DatabaseSync(tmpDbPath);

    try {
      const octoberUsage = boundaryDb.prepare(`
        SELECT spent_micros, reserved_micros, budget_limit_micros
        FROM budget_period_usage
        WHERE key_id = ? AND period_id = 'monthly:2026-10'
      `).get(boundaryKey.metadata.id) as
        | {
            spent_micros: number;
            reserved_micros: number;
            budget_limit_micros: number;
          }
        | undefined;

      const novemberUsage = boundaryDb.prepare(`
        SELECT spent_micros, reserved_micros, budget_limit_micros
        FROM budget_period_usage
        WHERE key_id = ? AND period_id = 'monthly:2026-11'
      `).get(boundaryKey.metadata.id) as
        | {
            spent_micros: number;
            reserved_micros: number;
            budget_limit_micros: number;
          }
        | undefined;

      assert.ok(octoberUsage, "October usage record must exist.");
      assert.ok(novemberUsage, "November usage record must exist.");

      assert.equal(Number(octoberUsage.budget_limit_micros), 1_000_000);
      assert.equal(Number(octoberUsage.spent_micros), 930_000);
      assert.equal(Number(octoberUsage.reserved_micros), 0);

      assert.equal(Number(novemberUsage.budget_limit_micros), 1_000_000);
      assert.equal(Number(novemberUsage.spent_micros), 850_000);
      assert.equal(Number(novemberUsage.reserved_micros), 0);

      const lateReservation = boundaryDb.prepare(`
        SELECT status, period_id, actual_micros
        FROM budget_reservations
        WHERE reservation_id = ?
      `).get(octoberPending.reservation_id!) as
        | {
            status: string;
            period_id: string;
            actual_micros: number | null;
          }
        | undefined;

      assert.ok(lateReservation);
      assert.equal(lateReservation.status, "SETTLED");
      assert.equal(lateReservation.period_id, "monthly:2026-10");
      assert.equal(Number(lateReservation.actual_micros), 180_000);
    } finally {
      boundaryDb.close();
    }

    const boundaryMetadata = vault.getKeyMetadata(boundaryKey.metadata.id)!;

    assert.equal(
      boundaryMetadata.current_spend_micros,
      850_000,
      "Legacy current spend should reflect November only."
    );

    assert.equal(boundaryMetadata.reserved_micros, 0);

    console.log(
      "âœ… 2B. UTC Monthly Rollover and Late Settlement Verified."
    );

    // 2C. Lifetime budget must not reset at a monthly boundary.
    const lifetimeBoundaryKey = vault.createVirtualKey({
      org_id: "org_budget_period_test",
      name: "Lifetime Boundary Test Key",
      provider: "openai",
      allowed_models: ["gpt-4o"],
      raw_provider_key: rawProviderSecret,
      budget_limit_usd: 1.00,
      budget_period: "lifetime",
      nowMs: octoberStart,
    });

    const lifetimeSpend = vault.authorize({
      rawVirtualKey: lifetimeBoundaryKey.rawVirtualKey,
      requestedModel: "gpt-4o",
      estimatedCostUsd: 0.80,
      nowMs: Date.UTC(2026, 9, 31, 23, 59, 20),
    });

    assert.equal(lifetimeSpend.valid, true);

    const lifetimeSettlement = vault.reconcileSpend(
      lifetimeSpend.reservation_id!,
      0.75,
      "rcpt_lifetime_spend",
      novemberStart + 2000
    );

    assert.equal(lifetimeSettlement.reconciled, true);

    // November must not reset a lifetime budget.
    const lifetimeOverBudget = vault.authorize({
      rawVirtualKey: lifetimeBoundaryKey.rawVirtualKey,
      requestedModel: "gpt-4o",
      estimatedCostUsd: 0.30,
      nowMs: novemberStart + 3000,
    });

    assert.equal(lifetimeOverBudget.valid, false);
    assert.equal(lifetimeOverBudget.reason, "BUDGET_EXCEEDED");

    const lifetimeDb = new DatabaseSync(tmpDbPath);

    try {
      const lifetimeUsage = lifetimeDb.prepare(`
        SELECT period_id, spent_micros, reserved_micros
        FROM budget_period_usage
        WHERE key_id = ?
      `).get(lifetimeBoundaryKey.metadata.id) as
        | {
            period_id: string;
            spent_micros: number;
            reserved_micros: number;
          }
        | undefined;

      assert.ok(lifetimeUsage);
      assert.equal(lifetimeUsage.period_id, "lifetime");
      assert.equal(Number(lifetimeUsage.spent_micros), 750_000);
      assert.equal(Number(lifetimeUsage.reserved_micros), 0);
    } finally {
      lifetimeDb.close();
    }

    console.log(
      "âœ… 2C. Lifetime Budget Persistence Across Month Boundary Verified."
    );

    // 3. Authorize + One-Shot Reconcile
    const auth1 = vault.authorize({
      rawVirtualKey: created.rawVirtualKey,
      requestedModel: "gpt-4o",
      downshiftedModel: "gpt-4o-mini",
      estimatedCostUsd: 0.60,
    });
    assert.equal(auth1.valid, true);
    assert.equal(auth1.provider, "openai");
    assert.equal(auth1.getProviderKey!(), rawProviderSecret);

    const rec1 = vault.reconcileSpend(auth1.reservation_id!, 0.40, "rcpt_001");
    assert.equal(rec1.reconciled, true);
    assert.equal(vault.reconcileSpend(auth1.reservation_id!, 0.40, "rcpt_001").reconciled, false);
    console.log("âœ… 3. Two-Phase Authorize & One-Shot Reconcile Verified.");

    // 4. Lease-based Stale Reservation Reaper.
    // An old reservation owned by a live instance must remain RESERVED.
    // An old reservation owned by an expired instance becomes UNCERTAIN.
    const t0 = Date.now();
    const hungAuth = vault.authorize({
      rawVirtualKey: created.rawVirtualKey,
      requestedModel: "gpt-4o",
      estimatedCostUsd: 0.55,
      nowMs: t0,
    });
    assert.equal(hungAuth.valid, true);
    assert.equal(vault.getKeyMetadata(created.metadata.id)!.reserved_micros, 550_000);

    // The existing $0.40 spend plus the $0.55 hold leaves insufficient budget.
    const blockedByHung = vault.authorize({
      rawVirtualKey: created.rawVirtualKey,
      requestedModel: "gpt-4o",
      estimatedCostUsd: 0.10,
      nowMs: t0 + 1000,
    });
    assert.equal(blockedByHung.valid, false);
    assert.equal(blockedByHung.reason, "BUDGET_EXCEEDED");

    // Create a second Vault instance and leave one request outstanding.
    const crashedOwnerVault = new VirtualKeyVault(masterKeyV1, tmpDbPath, 1);
    try {
      const crashedKey = crashedOwnerVault.createVirtualKey({
        org_id: "org_crashed_owner_test",
        name: "Crashed Owner Test Key",
        provider: "openai",
        allowed_models: ["gpt-4o"],
        raw_provider_key: rawProviderSecret,
        budget_limit_usd: 1.00,
        budget_period: "monthly",
      });

      const crashedAuth = crashedOwnerVault.authorize({
        rawVirtualKey: crashedKey.rawVirtualKey,
        requestedModel: "gpt-4o",
        estimatedCostUsd: 0.25,
      });
      assert.equal(crashedAuth.valid, true);

      // Stop this instance's heartbeat to simulate process loss.
      const heartbeatTimer = (crashedOwnerVault as any).heartbeatTimer as
        NodeJS.Timeout | null;
      if (heartbeatTimer) {
        clearInterval(heartbeatTimer);
        (crashedOwnerVault as any).heartbeatTimer = null;
      }

      const reaperDb = new DatabaseSync(tmpDbPath);
      const simulatedNow = Date.now();
      const oldReservationTime = simulatedNow - 10 * 60 * 1000 - 1000;

      let crashedOwnerId: string;
      try {
        const ownerRow = reaperDb.prepare(`
          SELECT owner_id
          FROM budget_reservations
          WHERE reservation_id = ?
        `).get(crashedAuth.reservation_id!) as
          | { owner_id: string }
          | undefined;

        assert.ok(ownerRow, "Crashed reservation owner must exist.");
        crashedOwnerId = ownerRow.owner_id;

        // Make both reservations old enough for the age threshold.
        reaperDb.prepare(`
          UPDATE budget_reservations
          SET created_at = ?
          WHERE reservation_id IN (?, ?)
        `).run(
          oldReservationTime,
          hungAuth.reservation_id!,
          crashedAuth.reservation_id!
        );

        // Expire only the simulated crashed instance's lease.
        reaperDb.prepare(`
          UPDATE vault_instances
          SET heartbeat_at = ?,
              lease_expires_at = ?
          WHERE instance_id = ?
        `).run(
          simulatedNow - 60_000,
          simulatedNow - 31_000,
          crashedOwnerId
        );
      } finally {
        reaperDb.close();
      }

      // The original Vault is still heartbeating. Only the crashed owner's
      // reservation should be reaped.
      const reaped = vault.reapStaleReservations(
        10 * 60 * 1000,
        Date.now()
      );

      assert.equal(reaped.reapedCount, 1);
      assert.equal(
        reaped.releasedMicros,
        0,
        "An uncertain provider request must not release its reservation."
      );

      const verifyDb = new DatabaseSync(tmpDbPath);
      try {
        const originalRow = verifyDb.prepare(`
          SELECT status, reserved_micros
          FROM budget_reservations
          WHERE reservation_id = ?
        `).get(hungAuth.reservation_id!) as
          | { status: string; reserved_micros: number }
          | undefined;

        assert.ok(originalRow, "Original reservation row must exist.");
        assert.equal(
          originalRow.status,
          "RESERVED",
          "An old reservation owned by a live Vault instance must not be reaped."
        );
        assert.equal(Number(originalRow.reserved_micros), 550_000);

        const crashedRow = verifyDb.prepare(`
          SELECT status, reserved_micros
          FROM budget_reservations
          WHERE reservation_id = ?
        `).get(crashedAuth.reservation_id!) as
          | { status: string; reserved_micros: number }
          | undefined;

        assert.ok(crashedRow, "Crashed reservation row must exist.");
        assert.equal(crashedRow.status, "UNCERTAIN");
        assert.equal(Number(crashedRow.reserved_micros), 250_000);

        const originalUsage = verifyDb.prepare(`
          SELECT spent_micros, reserved_micros
          FROM budget_period_usage
          WHERE key_id = ?
        `).get(created.metadata.id) as
          | { spent_micros: number; reserved_micros: number }
          | undefined;

        assert.ok(originalUsage, "Original budget usage row must exist.");
        assert.equal(Number(originalUsage.spent_micros), 400_000);
        assert.equal(Number(originalUsage.reserved_micros), 550_000);
      } finally {
        verifyDb.close();
      }

      // The crashed instance can no longer authorize new requests.
      const rejectedAfterLeaseExpiry = crashedOwnerVault.authorize({
        rawVirtualKey: crashedKey.rawVirtualKey,
        requestedModel: "gpt-4o",
        estimatedCostUsd: 0.01,
      });
      assert.equal(rejectedAfterLeaseExpiry.valid, false);
      assert.equal(rejectedAfterLeaseExpiry.reason, "VAULT_INTERNAL_ERROR");

      // Simulate recovery cleanup after the reaper has marked its reservation.
      crashedOwnerVault.close();

      // A late result from the crashed owner's provider request can still settle.
      const crashedLateSettlement = vault.reconcileSpend(
        crashedAuth.reservation_id!,
        0.25,
        "rcpt_crashed_owner_late"
      );
      assert.equal(crashedLateSettlement.reconciled, true);
      assert.equal(crashedLateSettlement.actual_micros, 250_000);
    } finally {
      crashedOwnerVault.close();
    }
    // A late provider result must settle the UNCERTAIN reservation.
    const lateSettlement = vault.reconcileSpend(
      hungAuth.reservation_id!,
      0.55,
      "rcpt_late_001"
    );

    assert.equal(lateSettlement.reconciled, true);
    assert.equal(lateSettlement.actual_micros, 550_000);

    assert.equal(
      vault.getKeyMetadata(created.metadata.id)!.reserved_micros,
      0,
      "Successful late settlement must release the reservation hold."
    );

    // Repeated settlement must not charge or write a second ledger entry.
    const duplicateSettlement = vault.reconcileSpend(
      hungAuth.reservation_id!,
      0.55,
      "rcpt_late_001"
    );

    assert.equal(duplicateSettlement.reconciled, false);

    const settledDb = new DatabaseSync(tmpDbPath);

    try {
      const settledRow = settledDb.prepare(`
        SELECT status, actual_micros, receipt_id
        FROM budget_reservations
        WHERE reservation_id = ?
      `).get(hungAuth.reservation_id!) as
        | {
            status: string;
            actual_micros: number | null;
            receipt_id: string | null;
          }
        | undefined;

      assert.ok(settledRow);
      assert.equal(settledRow.status, "SETTLED");
      assert.equal(Number(settledRow.actual_micros), 550_000);
      assert.equal(settledRow.receipt_id, "rcpt_late_001");

      const ledgerCount = settledDb.prepare(`
        SELECT COUNT(*) AS count
        FROM spend_ledger
        WHERE id = ?
      `).get(`led_${hungAuth.reservation_id}`) as { count: number };

      assert.equal(Number(ledgerCount.count), 1);
    } finally {
      settledDb.close();
    }

    console.log("âœ… 4. Durable Uncertain Reservation, Late Settlement and Idempotency Verified.");


    // 4A. Forced settlement failure must roll back all database changes.
    const rollbackKey = vault.createVirtualKey({
      org_id: "org_vault_rollback_test",
      name: "Settlement Rollback Test Key",
      provider: "openai",
      allowed_models: ["gpt-4o"],
      raw_provider_key: rawProviderSecret,
      budget_limit_usd: 5.00,
      budget_period: "monthly",
    });

    const rollbackAuth = vault.authorize({
      rawVirtualKey: rollbackKey.rawVirtualKey,
      requestedModel: "gpt-4o",
      estimatedCostUsd: 0.25,
    });

    assert.equal(rollbackAuth.valid, true);

    const rollbackReservationId = rollbackAuth.reservation_id!;

    // Inject a database failure specifically at ledger insertion.
    const triggerDb = new DatabaseSync(tmpDbPath);

    try {
      triggerDb.exec(`
        CREATE TRIGGER test_abort_spend_ledger
        BEFORE INSERT ON spend_ledger
        WHEN NEW.id = 'led_${rollbackReservationId}'
        BEGIN
          SELECT RAISE(ABORT, 'forced ledger failure');
        END;
      `);
    } finally {
      triggerDb.close();
    }

    // Settlement must fail and roll back.
    assert.throws(
      () => vault.reconcileSpend(
        rollbackReservationId,
        0.20,
        "rcpt_rollback_test"
      ),
      /forced ledger failure/
    );

    const rollbackCheckDb = new DatabaseSync(tmpDbPath);

    try {
      const reservation = rollbackCheckDb.prepare(`
        SELECT status, actual_micros
        FROM budget_reservations
        WHERE reservation_id = ?
      `).get(rollbackReservationId) as
        | { status: string; actual_micros: number | null }
        | undefined;

      assert.ok(reservation);
      assert.equal(reservation.status, "RESERVED");
      assert.equal(reservation.actual_micros, null);

      const usage = rollbackCheckDb.prepare(`
        SELECT spent_micros, reserved_micros
        FROM budget_period_usage
        WHERE key_id = ? AND period_id = (
          SELECT period_id
          FROM budget_reservations
          WHERE reservation_id = ?
        )
      `).get(
        rollbackKey.metadata.id,
        rollbackReservationId
      ) as
        | { spent_micros: number; reserved_micros: number }
        | undefined;

      assert.ok(usage);
      assert.equal(Number(usage.spent_micros), 0);
      assert.equal(Number(usage.reserved_micros), 250_000);

      const ledgerCount = rollbackCheckDb.prepare(`
        SELECT COUNT(*) AS count
        FROM spend_ledger
        WHERE id = ?
      `).get(`led_${rollbackReservationId}`) as { count: number };

      assert.equal(Number(ledgerCount.count), 0);

      const legacyKey = rollbackCheckDb.prepare(`
        SELECT current_spend_micros, reserved_micros
        FROM virtual_keys
        WHERE id = ?
      `).get(rollbackKey.metadata.id) as
        | { current_spend_micros: number; reserved_micros: number }
        | undefined;

      assert.ok(legacyKey);
      assert.equal(Number(legacyKey.current_spend_micros), 0);
      assert.equal(Number(legacyKey.reserved_micros), 250_000);
    } finally {
      rollbackCheckDb.close();
    }

    // Remove fault injection and retry the same reservation.
    const cleanupDb = new DatabaseSync(tmpDbPath);

    try {
      cleanupDb.exec("DROP TRIGGER test_abort_spend_ledger");
    } finally {
      cleanupDb.close();
    }

    const rollbackRetry = vault.reconcileSpend(
      rollbackReservationId,
      0.20,
      "rcpt_rollback_retry"
    );

    assert.equal(rollbackRetry.reconciled, true);
    assert.equal(rollbackRetry.actual_micros, 200_000);

    console.log(
      "âœ… 4A. Atomic Settlement Rollback and Recovery Verified."
    );


    // 4B. Cross-instance settlement idempotency.
    const crossInstanceKey = vault.createVirtualKey({
      org_id: "org_cross_instance_test",
      name: "Cross Instance Settlement Test",
      provider: "openai",
      allowed_models: ["gpt-4o"],
      raw_provider_key: rawProviderSecret,
      budget_limit_usd: 5.00,
    });

    const crossAuth = vault.authorize({
      rawVirtualKey: crossInstanceKey.rawVirtualKey,
      requestedModel: "gpt-4o",
      estimatedCostUsd: 0.30,
    });

    assert.equal(crossAuth.valid, true);

    const crossReservationId = crossAuth.reservation_id!;

    // Open a second independent Vault connection to the same SQLite database.
    const secondVault = new VirtualKeyVault(
      masterKeyV1,
      tmpDbPath,
      1
    );

    try {
      // First instance settles the reservation.
      const firstSettlement = vault.reconcileSpend(
        crossReservationId,
        0.25,
        "rcpt_cross_instance"
      );

      assert.equal(firstSettlement.reconciled, true);
      assert.equal(firstSettlement.actual_micros, 250_000);

      // Second instance must not settle the same reservation again.
      const secondSettlement = secondVault.reconcileSpend(
        crossReservationId,
        0.25,
        "rcpt_cross_instance"
      );

      assert.equal(secondSettlement.reconciled, false);
      assert.equal(secondSettlement.actual_micros, 0);

      const crossDb = new DatabaseSync(tmpDbPath);

      try {
        const usage = crossDb.prepare(`
          SELECT spent_micros, reserved_micros
          FROM budget_period_usage
          WHERE key_id = ? AND period_id = (
            SELECT period_id
            FROM budget_reservations
            WHERE reservation_id = ?
          )
        `).get(
          crossInstanceKey.metadata.id,
          crossReservationId
        ) as
          | { spent_micros: number; reserved_micros: number }
          | undefined;

        assert.ok(usage);
        assert.equal(Number(usage.spent_micros), 250_000);
        assert.equal(Number(usage.reserved_micros), 0);

        const ledger = crossDb.prepare(`
          SELECT COUNT(*) AS count
          FROM spend_ledger
          WHERE id = ?
        `).get(`led_${crossReservationId}`) as { count: number };

        assert.equal(Number(ledger.count), 1);

      } finally {
        crossDb.close();
      }

    } finally {
      secondVault.close();
    }

    console.log(
      "âœ… 4B. Cross-Instance Settlement Idempotency Verified."
    );


    // 5. Granular Error Classification: BAD_REQUEST_AMOUNT vs VAULT_DECRYPT_ERROR vs VAULT_INTERNAL_ERROR
    const nanAuth = vault.authorize({
      rawVirtualKey: created.rawVirtualKey,
      requestedModel: "gpt-4o",
      estimatedCostUsd: Number.NaN,
    });
    assert.equal(nanAuth.valid, false);
    assert.equal(nanAuth.reason, "BAD_REQUEST_AMOUNT");

    // Corrupt auth_tag in DB directly to trigger VAULT_DECRYPT_ERROR inside authorize()
    const rawDb = new DatabaseSync(tmpDbPath);
    const origRow = rawDb
      .prepare(`SELECT auth_tag, allowed_models FROM virtual_keys WHERE id = ?`)
      .get(created.metadata.id) as { auth_tag: string; allowed_models: string };

    rawDb
      .prepare(`UPDATE virtual_keys SET auth_tag = ? WHERE id = ?`)
      .run("00".repeat(16), created.metadata.id);

    const decryptFailAuth = vault.authorize({
      rawVirtualKey: created.rawVirtualKey,
      requestedModel: "gpt-4o",
      estimatedCostUsd: 0.05,
    });
    assert.equal(decryptFailAuth.valid, false);
    assert.equal(decryptFailAuth.reason, "VAULT_DECRYPT_ERROR");
    assert.equal(
      vault.getKeyMetadata(created.metadata.id)!.reserved_micros,
      0,
      "Failed decryption inside transaction must roll back reserved_micros"
    );
    assert.equal(diagnostics.at(-1)?.code, "VAULT_DECRYPT_ERROR");
    assert.equal(diagnostics.at(-1)?.recordId, created.metadata.id);

    // Corrupt allowed_models JSON in DB to trigger VAULT_INTERNAL_ERROR (SyntaxError)
    rawDb
      .prepare(`UPDATE virtual_keys SET auth_tag = ?, allowed_models = 'NOT_JSON' WHERE id = ?`)
      .run(origRow.auth_tag, created.metadata.id);

    const internalFailAuth = vault.authorize({
      rawVirtualKey: created.rawVirtualKey,
      requestedModel: "gpt-4o",
      estimatedCostUsd: 0.05,
    });
    assert.equal(internalFailAuth.valid, false);
    assert.equal(internalFailAuth.reason, "VAULT_INTERNAL_ERROR");
    assert.equal(diagnostics.at(-1)?.code, "VAULT_INTERNAL_ERROR");
    assert.equal(diagnostics.at(-1)?.errorClass, "SyntaxError");

    // Restore valid row
    rawDb
      .prepare(`UPDATE virtual_keys SET allowed_models = ? WHERE id = ?`)
      .run(origRow.allowed_models, created.metadata.id);
    rawDb.close();
    console.log("âœ… 5. Granular Error Codes & Secret-Free Diagnostic Telemetry Verified.");

    // 6. Zero Secret Leakage in JSON / Inspect / Thrown Errors
    const serialized = JSON.stringify(auth1);
    const inspected = util.inspect(auth1);
    assert.equal(serialized.includes(rawProviderSecret), false);
    assert.equal(inspected.includes(rawProviderSecret), false);
    console.log("âœ… 6. Zero Secret Leakage in JSON & Console Inspect Verified.");

    // 7. Key Ring Highest-Version Default & Downgrade Prevention
    vault.rotateMasterKey(masterKeyV2, 2);
    vault.close();

    // Starting with ONLY v1 key when DB has v2 rows must fail fast on startup
    assert.throws(
      () => new VirtualKeyVault(masterKeyV1, tmpDbPath, 1),
      /VAULT_KEY_VERSION_MISMATCH/,
      "Startup with missing master key version must fail fast"
    );

    // Passing { 1: masterKeyV1, 2: masterKeyV2 } WITHOUT activeKeyVersion must default to version 2!
    vault = new VirtualKeyVault({ 1: masterKeyV1, 2: masterKeyV2 }, tmpDbPath);
    assert.equal(vault.getActiveKeyVersion(), 2, "Key ring must default to highest version (2)");

        const keyOnV2 = vault.createVirtualKey({
      org_id: "org_kla_sec",
      name: "V2 Default Key",
      provider: "anthropic",
      allowed_models: ["claude-3-5-sonnet"],
      raw_provider_key: rawProviderSecret,
      budget_limit_usd: 5.00,
    });

    assert.equal(
      keyOnV2.metadata.key_version,
      2,
      "New keys must encrypt with highest ring version"
    );

    // 7A. Authorize a request, then close the vault before settlement.
    const restartAuth = vault.authorize({
      rawVirtualKey: keyOnV2.rawVirtualKey,
      requestedModel: "claude-3-5-sonnet",
      estimatedCostUsd: 1.25,
    });

    assert.equal(restartAuth.valid, true);
    assert.ok(restartAuth.reservation_id);

    const restartReservationId = restartAuth.reservation_id!;

    assert.equal(
      vault.getKeyMetadata(keyOnV2.metadata.id)!.reserved_micros,
      1_250_000
    );

    // Simulate the original process stopping.
    vault.close();

    // Start a completely new vault instance using the same DB and key ring.
    vault = new VirtualKeyVault(
      { 1: masterKeyV1, 2: masterKeyV2 },
      tmpDbPath
    );

    assert.equal(vault.getActiveKeyVersion(), 2);

    // Startup must preserve the budget hold and mark RESERVED as UNCERTAIN.
    assert.equal(
      vault.getKeyMetadata(keyOnV2.metadata.id)!.reserved_micros,
      1_250_000,
      "Restart must not release an outstanding reservation"
    );

    const restartDb = new DatabaseSync(tmpDbPath);

    try {
      const reservation = restartDb.prepare(`
        SELECT status, reserved_micros, period_id
        FROM budget_reservations
        WHERE reservation_id = ?
      `).get(restartReservationId) as
        | {
            status: string;
            reserved_micros: number;
            period_id: string;
          }
        | undefined;

      assert.ok(reservation, "Reservation must survive vault restart");
      assert.equal(reservation.status, "UNCERTAIN");
      assert.equal(Number(reservation.reserved_micros), 1_250_000);

      const periodUsage = restartDb.prepare(`
        SELECT spent_micros, reserved_micros
        FROM budget_period_usage
        WHERE key_id = ? AND period_id = ?
      `).get(
        keyOnV2.metadata.id,
        reservation.period_id
      ) as
        | { spent_micros: number; reserved_micros: number }
        | undefined;

      assert.ok(periodUsage);
      assert.equal(Number(periodUsage.spent_micros), 0);
      assert.equal(Number(periodUsage.reserved_micros), 1_250_000);
    } finally {
      restartDb.close();
    }

    // Settle after restart: no in-memory ReservationHandle exists in this instance.
    const restartSettlement = vault.reconcileSpend(
      restartReservationId,
      1.10,
      "rcpt_after_restart_001"
    );

    assert.equal(restartSettlement.reconciled, true);
    assert.equal(restartSettlement.actual_micros, 1_100_000);

    // Repeated settlement after restart must remain idempotent.
    const duplicateRestartSettlement = vault.reconcileSpend(
      restartReservationId,
      1.10,
      "rcpt_after_restart_001"
    );

    assert.equal(duplicateRestartSettlement.reconciled, false);

    assert.equal(
      vault.getKeyMetadata(keyOnV2.metadata.id)!.reserved_micros,
      0
    );

    const finalRestartDb = new DatabaseSync(tmpDbPath);

    try {
      const finalReservation = finalRestartDb.prepare(`
        SELECT status, actual_micros, receipt_id
        FROM budget_reservations
        WHERE reservation_id = ?
      `).get(restartReservationId) as
        | {
            status: string;
            actual_micros: number | null;
            receipt_id: string | null;
          }
        | undefined;

      assert.ok(finalReservation);
      assert.equal(finalReservation.status, "SETTLED");
      assert.equal(Number(finalReservation.actual_micros), 1_100_000);
      assert.equal(finalReservation.receipt_id, "rcpt_after_restart_001");

      const finalUsage = finalRestartDb.prepare(`
        SELECT spent_micros, reserved_micros
        FROM budget_period_usage
        WHERE key_id = (
          SELECT key_id FROM budget_reservations WHERE reservation_id = ?
        )
          AND period_id = (
            SELECT period_id FROM budget_reservations WHERE reservation_id = ?
          )
      `).get(
        restartReservationId,
        restartReservationId
      ) as
        | { spent_micros: number; reserved_micros: number }
        | undefined;

      assert.ok(finalUsage);
      assert.equal(Number(finalUsage.spent_micros), 1_100_000);
      assert.equal(Number(finalUsage.reserved_micros), 0);

      const ledgerCount = finalRestartDb.prepare(`
        SELECT COUNT(*) AS count
        FROM spend_ledger
        WHERE id = ?
      `).get(`led_${restartReservationId}`) as { count: number };

      assert.equal(Number(ledgerCount.count), 1);
    } finally {
      finalRestartDb.close();
    }

    console.log("âœ… 7A. Durable Reservation Recovery Across Vault Restart Verified.");

    vault.close();

    // Explicitly passing activeKeyVersion = 1 when DB already has version 2 rows must throw downgrade error
    assert.throws(
      () => new VirtualKeyVault({ 1: masterKeyV1, 2: masterKeyV2 }, tmpDbPath, 1),
      /VAULT_KEY_VERSION_DOWNGRADE/,
      "Must reject activeKeyVersion older than highest DB key_version"
    );
    console.log("âœ… 7. Key Ring Highest-Version Default & Downgrade Protection Verified.");

    // 8. Cost Estimator Check
    const est = estimateRequestCostUsd({
      inputTokens: 2000,
      maxOutputTokens: 1000,
      inputPricePerMillionUsd: 2.50,
      outputPricePerMillionUsd: 10.00,
    });
    assert.equal(est, 0.015);
    console.log("? 8. Request Cost Estimator Verified.");

    // 8A. Authorization commit failure must not populate the in-memory cache.
    const commitTestDbPath = path.join(
      os.tmpdir(),
      `aindigo-vault-commit-test-${Date.now()}.sqlite`
    );
    const commitDiagnostics: VaultDiagnosticEvent[] = [];
    const commitVault = new VirtualKeyVault(
      masterKeyV1,
      commitTestDbPath,
      1,
      (evt) => commitDiagnostics.push(evt)
    );
    const commitDb = new DatabaseSync(commitTestDbPath);

    try {
      const commitKey = commitVault.createVirtualKey({
        org_id: "org_commit_failure_test",
        name: "Commit Failure Test Key",
        provider: "openai",
        allowed_models: ["gpt-4o"],
        raw_provider_key: rawProviderSecret,
        budget_limit_usd: 1.00,
      });

      const vaultDb = (commitVault as any).db;
      const originalExec = vaultDb.exec.bind(vaultDb);

      // Inject failure only at COMMIT; allow ROLLBACK to execute normally.
      vaultDb.exec = function (sql: string) {
        if (sql === "COMMIT") {
          throw new Error("Forced authorization commit failure");
        }
        return originalExec(sql);
      };

      let failedAuth;
      try {
        failedAuth = commitVault.authorize({
          rawVirtualKey: commitKey.rawVirtualKey,
          requestedModel: "gpt-4o",
          estimatedCostUsd: 0.25,
        });
      } finally {
        // Restore the native method before inspecting or closing the Vault.
        vaultDb.exec = originalExec;
      }

      assert.equal(failedAuth.valid, false);
      assert.equal(failedAuth.reason, "VAULT_INTERNAL_ERROR");

      const reservationCount = commitDb.prepare(`
        SELECT COUNT(*) AS count
        FROM budget_reservations
        WHERE key_id = ?
      `).get(commitKey.metadata.id) as { count: number };

      assert.equal(
        Number(reservationCount.count),
        0,
        "Failed authorization must not leave a durable reservation"
      );

      const budgetUsage = commitDb.prepare(`
        SELECT spent_micros, reserved_micros
        FROM budget_period_usage
        WHERE key_id = ?
      `).get(commitKey.metadata.id) as {
        spent_micros: number;
        reserved_micros: number;
      };

      assert.ok(budgetUsage);
      assert.equal(Number(budgetUsage.spent_micros), 0);
      assert.equal(
        Number(budgetUsage.reserved_micros),
        0,
        "Failed authorization must roll back its budget hold"
      );

      assert.equal(
        (commitVault as any).inFlightReservations.size,
        0,
        "Failed authorization must not populate the in-memory reservation cache"
      );

      assert.equal(commitDiagnostics.at(-1)?.code, "VAULT_INTERNAL_ERROR");
      assert.equal(commitDiagnostics.at(-1)?.recordId, commitKey.metadata.id);

      console.log("? 8A. Authorization Commit Failure Rollback Verified.");
    } finally {
      commitVault.close();
      commitDb.close();

      for (const suffix of ["", "-wal", "-shm"]) {
        const p = `${commitTestDbPath}${suffix}`;
        if (fs.existsSync(p)) {
          try { fs.unlinkSync(p); } catch {}
        }
      }
    }
    // 9. Vault instance heartbeat and lease lifecycle.
    // Use an isolated database so simulated lease expiry cannot affect
    // the main Vault instance or its existing reservations.
    const leaseTestDbPath = path.join(
      os.tmpdir(),
      `aindigo-vault-lease-test-${Date.now()}.sqlite`
    );
    const leaseDiagnostics: VaultDiagnosticEvent[] = [];
    const leaseVault = new VirtualKeyVault(
      masterKeyV1,
      leaseTestDbPath,
      1,
      (evt) => leaseDiagnostics.push(evt)
    );
    const leaseDb = new DatabaseSync(leaseTestDbPath);

    try {
      const leaseKey = leaseVault.createVirtualKey({
        org_id: "org_lease_lifecycle_test",
        name: "Lease Lifecycle Test Key",
        provider: "openai",
        allowed_models: ["gpt-4o"],
        raw_provider_key: rawProviderSecret,
        budget_limit_usd: 1.00,
      });

      const initialLease = leaseDb.prepare(`
        SELECT instance_id, heartbeat_at, lease_expires_at, released_at
        FROM vault_instances
      `).get() as {
        instance_id: string;
        heartbeat_at: number;
        lease_expires_at: number;
        released_at: number | null;
      } | undefined;

      assert.ok(initialLease, "Vault must register an instance lease");
      assert.equal(initialLease.released_at, null);
      assert.ok(initialLease.lease_expires_at > Date.now());

      // Trigger renewal directly to keep this test deterministic.
      // This exercises the same method used by the 10-second timer.
      (leaseVault as any).renewInstanceLease();

      const renewedLease = leaseDb.prepare(`
        SELECT heartbeat_at, lease_expires_at, released_at
        FROM vault_instances
        WHERE instance_id = ?
      `).get(initialLease.instance_id) as {
        heartbeat_at: number;
        lease_expires_at: number;
        released_at: number | null;
      } | undefined;

      assert.ok(renewedLease);
      assert.equal(renewedLease.released_at, null);
      assert.ok(
        renewedLease.lease_expires_at > Date.now() + 30_000,
        "Successful heartbeat must extend the lease"
      );

      // Authorization and settlement must work while the renewed lease is healthy.
      const healthyAuth = leaseVault.authorize({
        rawVirtualKey: leaseKey.rawVirtualKey,
        requestedModel: "gpt-4o",
        estimatedCostUsd: 0.10,
      });

      assert.equal(healthyAuth.valid, true);

      const healthySettlement = leaseVault.reconcileSpend(
        healthyAuth.reservation_id!,
        0.08,
        "rcpt_lease_healthy"
      );

      assert.equal(healthySettlement.reconciled, true);

      // Keep one reservation outstanding to verify graceful shutdown recovery.
      const pendingAuth = leaseVault.authorize({
        rawVirtualKey: leaseKey.rawVirtualKey,
        requestedModel: "gpt-4o",
        estimatedCostUsd: 0.20,
      });

      assert.equal(pendingAuth.valid, true);

      // Simulate a lease that has already expired.
      const simulatedExpiry = Date.now() - 1;

      leaseDb.prepare(`
        UPDATE vault_instances
        SET lease_expires_at = ?
        WHERE instance_id = ?
      `).run(simulatedExpiry, initialLease.instance_id);

      // An expired lease must not be renewed or resurrected.
      (leaseVault as any).renewInstanceLease();

      const expiredLease = leaseDb.prepare(`
        SELECT lease_expires_at, released_at
        FROM vault_instances
        WHERE instance_id = ?
      `).get(initialLease.instance_id) as {
        lease_expires_at: number;
        released_at: number | null;
      } | undefined;

      assert.ok(expiredLease);
      assert.equal(expiredLease.lease_expires_at, simulatedExpiry);
      assert.equal(expiredLease.released_at, null);

      assert.equal(
        leaseDiagnostics.at(-1)?.code,
        "VAULT_INTERNAL_ERROR"
      );
      assert.equal(
        leaseDiagnostics.at(-1)?.errorClass,
        "LeaseNotRenewable"
      );
      assert.equal(leaseDiagnostics.at(-1)?.recordId, null);

      // The unhealthy instance must fail closed for new authorizations.
      const rejectedAfterExpiry = leaseVault.authorize({
        rawVirtualKey: leaseKey.rawVirtualKey,
        requestedModel: "gpt-4o",
        estimatedCostUsd: 0.01,
      });

      assert.equal(rejectedAfterExpiry.valid, false);
      assert.equal(rejectedAfterExpiry.reason, "VAULT_INTERNAL_ERROR");

      // Graceful close must preserve the outstanding budget hold,
      // mark its reservation UNCERTAIN, and release the instance lease.
      leaseVault.close();

      const closedReservation = leaseDb.prepare(`
        SELECT status, reserved_micros
        FROM budget_reservations
        WHERE reservation_id = ?
      `).get(pendingAuth.reservation_id!) as {
        status: string;
        reserved_micros: number;
      } | undefined;

      assert.ok(closedReservation);
      assert.equal(closedReservation.status, "UNCERTAIN");
      assert.equal(Number(closedReservation.reserved_micros), 200_000);

      const releasedLease = leaseDb.prepare(`
        SELECT released_at, lease_expires_at
        FROM vault_instances
        WHERE instance_id = ?
      `).get(initialLease.instance_id) as {
        released_at: number | null;
        lease_expires_at: number;
      } | undefined;

      assert.ok(releasedLease);
      assert.notEqual(releasedLease.released_at, null);
      assert.equal(
        releasedLease.lease_expires_at,
        releasedLease.released_at
      );

      // close() must be safe to call more than once.
      leaseVault.close();

      console.log("? 9. Vault Heartbeat and Lease Lifecycle Verified.");
    } finally {
      leaseVault.close();
      leaseDb.close();
    }
  } finally {
    for (const suffix of ["", "-wal", "-shm"]) {
      const p = `${tmpDbPath}${suffix}`;
      if (fs.existsSync(p)) {
        try { fs.unlinkSync(p); } catch {}
      }
    }
  }

  console.log("================================================================");
  console.log(" ðŸŽ‰ Tier 2 Module 2.4 All Production Vault Checks PASSED");
  console.log("================================================================");
}

runVaultTests();
