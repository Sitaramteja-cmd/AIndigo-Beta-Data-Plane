import { strict as assert } from "node:assert";
import { FinOpsGovernor } from "./finops-governor.js";
import type { VirtualKeyMetadata } from "../vault/virtual-key-vault.js";

function runGovernorTests() {
  console.log("================================================================");
  console.log(" ðŸ’° AIndigo Tier 3 â€” FinOps Governor Hardened Test Suite");
  console.log("================================================================");

  // 1. Constructor Validation Checks
  assert.throws(() => new FinOpsGovernor({ thresholdPercent: 150, modelMappings: {} }), /GOVERNOR_CONFIG_ERROR/);
  assert.throws(() => new FinOpsGovernor({ thresholdPercent: 80, modelMappings: { "gpt-4o": "gpt-4o" } }), /GOVERNOR_CONFIG_ERROR/);
  assert.throws(() => new FinOpsGovernor({ thresholdPercent: 80, modelMappings: { "a": "b", "b": "c" } }), /GOVERNOR_CONFIG_ERROR/);
  console.log("âœ… 1. Constructor Config Validation & Loop Prevention Verified.");

  const governor = new FinOpsGovernor({
    thresholdPercent: 80,
    modelMappings: {
      "gpt-4o": "gpt-4o-mini",
    },
  });

  const baseMeta: VirtualKeyMetadata = {
    id: "vk_rec_123",
    org_id: "org_kla",
    name: "Test Key",
    key_prefix: "vk-aindigo-1234...",
    provider: "openai",
    allowed_models: ["gpt-4o", "gpt-4o-mini"], // Target is allowed
    key_version: 1,
    budget_limit_micros: 1_000_000,
    current_spend_micros: 700_000, // 70% spend
    reserved_micros: 150_000,      // +15% reserved = 85% total utilization >= 80%!
    budget_limit_usd: 1.00,
    current_spend_usd: 0.70,
    reserved_usd: 0.15,
    budget_period: "monthly",
    period_reset_at: Date.now() + 86400000,
    expires_at: null,
    revoked_at: null,
    last_used_at: null,
    created_at: Date.now(),
  };

  // 2. Reserved Spend Inclusion Triggering Downshift
  const res1 = governor.evaluate(baseMeta, "gpt-4o");
  assert.equal(res1.downshifted, true, "Reserved micros push utilization past threshold");
  assert.equal(res1.effectiveModel, "gpt-4o-mini");
  console.log("âœ… 2. Reserved Spend Utilization Trigger Verified.");

  // 3. Allowed Models Policy Restriction (Target Not Allowed)
  const restrictedMeta: VirtualKeyMetadata = {
    ...baseMeta,
    allowed_models: ["gpt-4o"], // gpt-4o-mini NOT allowed!
  };
  const resRestricted = governor.evaluate(restrictedMeta, "gpt-4o");
  assert.equal(resRestricted.downshifted, false, "Must not downshift to a model prohibited by allowed_models");
  assert.equal(resRestricted.reason, "TARGET_NOT_ALLOWED");
  console.log("âœ… 3. Allowed Models Policy Restriction Verified.");

  console.log("================================================================");
  console.log(" ðŸŽ‰ Tier 3 Module 3.2 FinOps Governor Tests PASSED");
  console.log("================================================================");
}

runGovernorTests();
