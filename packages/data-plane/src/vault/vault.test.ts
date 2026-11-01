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
  console.log(" 🔐 AIndigo Tier 2 — Production Virtual Key Vault Test Suite");
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
    console.log("✅ 1. Strict Constructor & createVirtualKey Input Validation Verified.");

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
    console.log("✅ 2. Micro-USD Storage & Sanitized Metadata Verified.");

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
    console.log("✅ 3. Two-Phase Authorize & One-Shot Reconcile Verified.");

    // 4. Stale Reservation Reaper (Hung Stream / Missing finally block)
    const t0 = Date.now();
    const hungAuth = vault.authorize({
      rawVirtualKey: created.rawVirtualKey,
      requestedModel: "gpt-4o",
      estimatedCostUsd: 0.55,
      nowMs: t0,
    });
    assert.equal(hungAuth.valid, true);
    assert.equal(vault.getKeyMetadata(created.metadata.id)!.reserved_micros, 550_000);

    // Next request for $0.10 fails while $0.55 is still held ($0.40 spend + $0.55 reserved + $0.10 = $1.05 > $1.00)
    const blockedByHung = vault.authorize({
      rawVirtualKey: created.rawVirtualKey,
      requestedModel: "gpt-4o",
      estimatedCostUsd: 0.10,
      nowMs: t0 + 1000,
    });
    assert.equal(blockedByHung.valid, false);
    assert.equal(blockedByHung.reason, "BUDGET_EXCEEDED");

    // Run reaper after 10 minutes -> releases the $0.55 reservation
    const reaped = vault.reapStaleReservations(10 * 60 * 1000, t0 + 10 * 60 * 1000 + 1);
    assert.equal(reaped.reapedCount, 1);
    assert.equal(reaped.releasedMicros, 550_000);
    assert.equal(vault.getKeyMetadata(created.metadata.id)!.reserved_micros, 0);

    // Late reconcile on a reaped reservation is a safe no-op
    assert.equal(vault.reconcileSpend(hungAuth.reservation_id!, 0.55).reconciled, false);
    console.log("✅ 4. Stale In-Flight Reservation Reaper Verified.");

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
    console.log("✅ 5. Granular Error Codes & Secret-Free Diagnostic Telemetry Verified.");

    // 6. Zero Secret Leakage in JSON / Inspect / Thrown Errors
    const serialized = JSON.stringify(auth1);
    const inspected = util.inspect(auth1);
    assert.equal(serialized.includes(rawProviderSecret), false);
    assert.equal(inspected.includes(rawProviderSecret), false);
    console.log("✅ 6. Zero Secret Leakage in JSON & Console Inspect Verified.");

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
    assert.equal(keyOnV2.metadata.key_version, 2, "New keys must encrypt with highest ring version");
    vault.close();

    // Explicitly passing activeKeyVersion = 1 when DB already has version 2 rows must throw downgrade error
    assert.throws(
      () => new VirtualKeyVault({ 1: masterKeyV1, 2: masterKeyV2 }, tmpDbPath, 1),
      /VAULT_KEY_VERSION_DOWNGRADE/,
      "Must reject activeKeyVersion older than highest DB key_version"
    );
    console.log("✅ 7. Key Ring Highest-Version Default & Downgrade Protection Verified.");

    // 8. Cost Estimator Check
    const est = estimateRequestCostUsd({
      inputTokens: 2000,
      maxOutputTokens: 1000,
      inputPricePerMillionUsd: 2.50,
      outputPricePerMillionUsd: 10.00,
    });
    assert.equal(est, 0.015);
    console.log("✅ 8. Request Cost Estimator Verified.");
  } finally {
    for (const suffix of ["", "-wal", "-shm"]) {
      const p = `${tmpDbPath}${suffix}`;
      if (fs.existsSync(p)) {
        try { fs.unlinkSync(p); } catch {}
      }
    }
  }

  console.log("================================================================");
  console.log(" 🎉 Tier 2 Module 2.4 All Production Vault Checks PASSED");
  console.log("================================================================");
}

runVaultTests();