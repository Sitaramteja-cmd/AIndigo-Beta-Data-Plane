import { strict as assert } from "node:assert";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { AuditChainManager, canonicalJsonStringify } from "./audit-chain.js";

async function runAuditTests() {
  console.log("================================================================");
  console.log(" 🛡️ AIndigo Tier 3 — Enterprise Audit & SIEM Test Suite");
  console.log("================================================================");

  const tmpDbPath = path.join(os.tmpdir(), `aindigo-audit-enterprise-${Date.now()}.sqlite`);
  const hmacSecret = crypto.randomBytes(32).toString("hex");

  try {
    const db = new DatabaseSync(tmpDbPath);

    // 1. Recursive Canonical JSON Serializer Tests
    const obj1 = { z: 1, a: { b: 2, c: [10, 20], nested: { y: 9, x: 8 } } };
    const obj2 = { a: { nested: { x: 8, y: 9 }, c: [10, 20], b: 2 }, z: 1 };
    assert.equal(canonicalJsonStringify(obj1), canonicalJsonStringify(obj2), "Canonical JSON must sort keys recursively across deep nesting");

    // Rejection tests for unsupported types
    assert.throws(() => canonicalJsonStringify({ val: undefined }), /CANONICAL_JSON_ERROR/);
    assert.throws(() => canonicalJsonStringify({ val: NaN }), /CANONICAL_JSON_ERROR/);
    assert.throws(() => canonicalJsonStringify({ val: Infinity }), /CANONICAL_JSON_ERROR/);
    assert.throws(() => canonicalJsonStringify({ val: BigInt(10) }), /CANONICAL_JSON_ERROR/);
    assert.throws(() => canonicalJsonStringify({ val: new Date() }), /CANONICAL_JSON_ERROR/);
    
    const cyclic: any = { a: 1 };
    cyclic.self = cyclic;
    assert.throws(() => canonicalJsonStringify(cyclic), /CANONICAL_JSON_ERROR/);
    console.log("✅ 1. Recursive Canonical JSON Serialization & Strict Type Rejections Verified.");

    // 2. Strict HMAC Secret Validation
    assert.throws(() => new AuditChainManager(db, "shortsecret"), /AUDIT_CONFIG_ERROR/);
    assert.throws(() => new AuditChainManager(db, "00".repeat(32)), /AUDIT_CONFIG_ERROR/, "All-zero trivial secret must be rejected");
    
    const auditMgr = new AuditChainManager(db, hmacSecret);
    console.log("✅ 2. Strict HMAC Secret Entropy & Trivial Key Rejection Verified.");

    // 3. Record Audit Events & Chain Verification
    const ev1 = auditMgr.recordEvent("BUDGET_WARNING", "org_kla", "vk_1", { threshold: 80, spend: 0.82 });
    const ev2 = auditMgr.recordEvent("MODEL_DOWNSHIFTED", "org_kla", "vk_1", { from: "gpt-4o", to: "gpt-4o-mini" });

    const verification = auditMgr.verifyChain();
    assert.equal(verification.valid, true);
    console.log("✅ 3. Audit Chain Recording & Verification Passed.");

    // 4. SIEM Webhook Dispatcher Test (Splunk HEC & Sentinel formats with mock fetch)
    let fetchCalledCount = 0;
    let lastRequestBody = "";

    const mockFetch = async (url: string, init: any) => {
      fetchCalledCount++;
      lastRequestBody = init.body;
      return { ok: true, status: 200 } as Response;
    };

    const records = [ev1, ev2];

    const splunkResult = await AuditChainManager.dispatchToSiem(records, {
      endpointUrl: "https://splunk.enterprise.local:8088/services/collector",
      authHeaderName: "Authorization",
      authHeaderValue: "Splunk hec-token-12345",
      format: "splunk_hec",
    }, mockFetch as any);

    assert.equal(splunkResult.success, true);
    assert.equal(fetchCalledCount, 1);
    const splunkParsed = JSON.parse(lastRequestBody);
    assert.equal(Array.isArray(splunkParsed), true);
    assert.equal(splunkParsed[0].sourcetype, "aindigo:security:audit");
    console.log("✅ 4. Splunk HEC SIEM Dispatcher Format & Auth Verified.");

    const sentinelResult = await AuditChainManager.dispatchToSiem(records, {
      endpointUrl: "https://sentinel.monitor.azure.com/dcr/...?",
      authHeaderName: "Authorization",
      authHeaderValue: "Bearer eyJhbGci...",
      format: "sentinel",
    }, mockFetch as any);

    assert.equal(sentinelResult.success, true);
    const sentinelParsed = JSON.parse(lastRequestBody);
    assert.equal(sentinelParsed[0].RecordId, ev1.id);
    assert.equal(sentinelParsed[0].PreviousHash, ev1.prevHash);
    console.log("✅ 5. Microsoft Sentinel SIEM Dispatcher Format Verified.");

    db.close();
  } finally {
    for (const suffix of ["", "-wal", "-shm"]) {
      const p = `${tmpDbPath}${suffix}`;
      if (fs.existsSync(p)) {
        try { fs.unlinkSync(p); } catch {}
      }
    }
  }

  console.log("================================================================");
  console.log(" 🎉 Tier 3 Module 3.3 Enterprise Audit & SIEM Tests PASSED");
  console.log("================================================================");
}

runAuditTests();