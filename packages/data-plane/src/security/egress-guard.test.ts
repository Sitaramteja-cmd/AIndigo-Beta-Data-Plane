import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { validateAndSanitizeEgressReceipt, TelemetryBatchPayload } from "./egress-guard.js";

test("Step 2C Hardened Egress Guard & Canary CI Test Suite", () => {
  process.env.AINDIGO_EGRESS_LOG = "true";

  // Generate an Ed25519 control plane keypair for cryptographic signature testing
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  const validPayload: TelemetryBatchPayload = {
    orgId: "org_kla",
    edgeNodeId: "edge_node_01",
    sequenceStart: 1,
    sequenceEnd: 10,
    batchTimestamp: Date.now(),
    spendLedgerEvents: [
      {
        eventId: "ev_01",
        virtualKeyId: "vk_01",
        costMicros: 1500,
        timestamp: Date.now(),
      },
    ],
    auditMerkleRoot: crypto.createHash("sha256").update("merkle").digest("hex"),
    metricsSummary: {
      totalSpendMicros: 1500,
      activeKeysCount: 2,
      revokedKeysCount: 0,
      redactionsCount: 1,
    },
  };

  const canonicalJson = JSON.stringify(validPayload);
  const payloadHash = crypto.createHash("sha256").update(canonicalJson).digest("hex");
  const signatureBuf = crypto.sign(null, Buffer.from(payloadHash, "hex"), privateKey);
  const signature = signatureBuf.toString("base64");

  const validEnvelope = {
    receiptId: "rcpt_test_01",
    schemaVersion: "v2.0",
    orgId: "org_kla",
    edgeNodeId: "edge_node_01",
    timestamp: Date.now(),
    payloadHash,
    signature,
    payload: validPayload,
  };

  // 1. Valid signed payload passes validation successfully
  const sanitized = validateAndSanitizeEgressReceipt(validEnvelope, publicKey);
  assert.equal(sanitized.orgId, "org_kla");
  console.log("✅ Valid cryptographically signed egress payload verified successfully.");

  // 2. Finding 1: Nested unknown field inside spendLedgerEvents must be rejected
  const nestedMaliciousPayload = {
    ...validEnvelope,
    payload: {
      ...validPayload,
      spendLedgerEvents: [
        {
          eventId: "ev_01",
          virtualKeyId: "vk_01",
          costMicros: 1500,
          timestamp: Date.now(),
          raw_prompt: "Confidential customer prompt smuggling attempt",
        },
      ],
    },
  };
  assert.throws(() => {
    validateAndSanitizeEgressReceipt(nestedMaliciousPayload, publicKey);
  }, /EGRESS_SECURITY_VIOLATION/);
  console.log("✅ Finding 1: Nested unknown field rejected.");

  // 3. Finding 2: Tampered payload hash / signature mismatch must be rejected
  const tamperedEnvelope = {
    ...validEnvelope,
    payload: {
      ...validPayload,
      spendLedgerEvents: [
        {
          eventId: "ev_01",
          virtualKeyId: "vk_01",
          costMicros: 999999, // modified spend after signing
          timestamp: Date.now(),
        },
      ],
    },
  };
  assert.throws(() => {
    validateAndSanitizeEgressReceipt(tamperedEnvelope, publicKey);
  }, /EGRESS_INTEGRITY_VIOLATION|EGRESS_SIGNATURE_VIOLATION/);
  console.log("✅ Finding 2: Tampered payload integrity violation intercepted.");

  // 4. Finding 3: Embedded canary values inside an allowed field must be rejected
  const embeddedCanaryPayload = {
    ...validEnvelope,
    payload: {
      ...validPayload,
      spendLedgerEvents: [
        {
          eventId: "ev_01",
          virtualKeyId: "vk_01_CANARY_SECRET_999_LEAK",
          costMicros: 1500,
          timestamp: Date.now(),
        },
      ],
    },
  };
  assert.throws(() => {
    validateAndSanitizeEgressReceipt(embeddedCanaryPayload, publicKey);
  }, /EGRESS_SECURITY_VIOLATION/);
  console.log("✅ Finding 3: Embedded canary string inside valid field rejected.");

  // 5. Finding 6: Verify egress-audit.jsonl records metadata only and never exposes payloads or prompts
  const logPath = path.resolve(process.cwd(), "logs", "egress-audit.jsonl");
  if (fs.existsSync(logPath)) {
    const logContent = fs.readFileSync(logPath, "utf8");
    assert.equal(logContent.includes("CANARY_SECRET"), false, "CRITICAL: Canary found in audit log!");
    assert.equal(logContent.includes("spendLedgerEvents"), false, "CRITICAL: Payload details leaked in audit log!");
    console.log("✅ Finding 6: Audit log verified metadata-only (zero payload leakage).");
  }
});