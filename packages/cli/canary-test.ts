import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { getOrCreateNodeIdentity, signReceiptEd25519 } from "../data-plane/src/crypto/node-identity.js";
import { validateAndLogEgressPayload, EgressPolicyViolationError } from "../data-plane/src/egress/egress-guard.js";

function runCanaryTest() {
  let tempDir: string | undefined;

  try {
    console.log("================================================================");
    console.log(" 🐤 AIndigo Tier 0 — Egress Allowlist & Canary Leakage CI Test");
    console.log("================================================================");

    // Isolate all test artifacts from the real node identity and audit logs.
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "aindigo-canary-"));
    const testLogPath = path.join(tempDir, "egress-audit.jsonl");
    const identity = getOrCreateNodeIdentity(path.join(tempDir, "keys"));

    // Planted canary strings that simulate sensitive customer secrets in a prompt
    const CANARY_PROMPT =
      "Connect to internal-prod.corp using AKIAIOSFODNN7EXAMPLE and ID [Redacted] with CANARY_TOP_SECRET_PROMPT_PAYLOAD_999";

    // 1. Create a legitimate content-free signed receipt after DLP scrubbing
    const cleanReceipt = signReceiptEd25519(
      {
        receipt_id: "rcpt_canary_001",
        timestamp: new Date().toISOString(),
        node_id: identity.nodeId,
        department: "secops_validation",
        model_requested: "gemini-2.5-flash",
        model_routed: "gemini-2.5-flash",
        prompt_tokens: 42,
        completion_tokens: 18,
        cost_usd: 0.00012,
        dlp_categories: ["AWS_ACCESS_KEY", "GOVT_ID", "INTERNAL_HOST"],
        cache_hit: false,
        prev_hash: "GENESIS_00000000000000000000000000000000000000000000000000000000",
        schema_version: "2.0.0",
      },
      identity
    );

    // Test 1: Legitimate metadata receipt must pass and write to isolated audit log
    validateAndLogEgressPayload(cleanReceipt as unknown as Record<string, unknown>, {
      enableLocalAuditLog: true,
      auditLogPath: testLogPath,
    });
    console.log("✅ 1. Legitimate Content-Free Receipt Passed Egress Guard & Logged.");

    // Test 2: Attempt to smuggle raw prompt field (`raw_prompt: CANARY_PROMPT`)
    let blockedUnapprovedField = false;
    try {
      validateAndLogEgressPayload(
        {
          ...cleanReceipt,
          raw_prompt: CANARY_PROMPT,
        },
        { enableLocalAuditLog: true, auditLogPath: testLogPath }
      );
    } catch (err) {
      if (err instanceof EgressPolicyViolationError) {
        blockedUnapprovedField = true;
        console.log(`✅ 2. Unapproved Field Blocked: ${err.message}`);
      }
    }
    if (!blockedUnapprovedField) {
      throw new Error("FAIL: Egress Guard allowed an unapproved field (raw_prompt)!");
    }

    // Test 3: Attempt to smuggle canary secret inside an allowed field (department)
    let blockedSmuggledSecret = false;
    try {
      validateAndLogEgressPayload(
        {
          ...cleanReceipt,
          department: "dept_AKIAIOSFODNN7EXAMPLE",
        },
        { enableLocalAuditLog: true, auditLogPath: testLogPath }
      );
    } catch (err) {
      if (err instanceof EgressPolicyViolationError) {
        blockedSmuggledSecret = true;
        console.log(`✅ 3. Smuggled Secret in Metadata Field Blocked: ${err.message}`);
      }
    }
    if (!blockedSmuggledSecret) {
      throw new Error("FAIL: Egress Guard allowed a secret pattern inside department!");
    }

    // Test 4: Inspect isolated audit log and verify zero canary substrings exist
    const egressLogContent = fs.readFileSync(testLogPath, "utf8");
    const forbiddenCanaries = [
      "AKIAIOSFODNN7EXAMPLE",
      "CANARY_TOP_SECRET_PROMPT_PAYLOAD_999",
      "internal-prod.corp",
    ];

    for (const canary of forbiddenCanaries) {
      if (egressLogContent.includes(canary)) {
        throw new Error(`CRITICAL FAIL: Canary string "${canary}" leaked into egress log!`);
      }
    }

    console.log("✅ 4. Egress Log Audited: 0 bytes of Canary Secrets found in outbound stream.");
    console.log("================================================================");
    console.log(" 🎉 Tier 0 Module 0.3 Canary Egress Test PASSED");
    console.log("================================================================");
  } finally {
    // Remove only the unique temporary directory created by this test.
    if (tempDir) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  }
}

runCanaryTest();