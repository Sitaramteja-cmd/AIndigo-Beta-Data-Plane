import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export interface SpendLedgerEvent {
  eventId: string;
  virtualKeyId: string;
  costMicros: number;
  timestamp: number;
}

export interface MetricsSummary {
  totalSpendMicros: number;
  activeKeysCount: number;
  revokedKeysCount: number;
  redactionsCount: number;
}

export interface TelemetryBatchPayload {
  orgId: string;
  edgeNodeId: string;
  sequenceStart: number;
  sequenceEnd: number;
  batchTimestamp: number;
  spendLedgerEvents: SpendLedgerEvent[];
  auditMerkleRoot: string;
  metricsSummary: MetricsSummary;
}

export interface EgressReceiptEnvelope {
  receiptId: string;
  schemaVersion: string;
  orgId: string;
  edgeNodeId: string;
  timestamp: number;
  payloadHash: string;
  signature: string;
  payload: TelemetryBatchPayload;
}

const ALLOWED_TOP_LEVEL_KEYS = new Set([
  "receiptId",
  "schemaVersion",
  "orgId",
  "edgeNodeId",
  "timestamp",
  "payloadHash",
  "signature",
  "payload",
]);

const ALLOWED_PAYLOAD_KEYS = new Set([
  "orgId",
  "edgeNodeId",
  "sequenceStart",
  "sequenceEnd",
  "batchTimestamp",
  "spendLedgerEvents",
  "auditMerkleRoot",
  "metricsSummary",
]);

const ALLOWED_SPEND_EVENT_KEYS = new Set(["eventId", "virtualKeyId", "costMicros", "timestamp"]);
const ALLOWED_METRICS_KEYS = new Set(["totalSpendMicros", "activeKeysCount", "revokedKeysCount", "redactionsCount"]);

const HEX_64_REGEX = /^[a-f0-9]{64}$/i;
const BASE64_SIG_REGEX = /^[A-Za-z0-9+/=]{64,128}$/;

/**
 * Deep recursive check for forbidden prompt terms or suspicious tokens inside arbitrary strings.
 */
function scanStringForForbiddenContent(val: string): void {
  const upper = val.toUpperCase();
  if (
    upper.includes("CANARY_SECRET") ||
    upper.includes("RAW_PROMPT") ||
    upper.includes("USER_MESSAGE") ||
    upper.includes("PROMPT_TEXT") ||
    upper.includes("CONFIDENTIAL")
  ) {
    throw new Error("EGRESS_SECURITY_VIOLATION: Forbidden prompt content or canary token detected in telemetry field!");
  }
}


/**
 * Hardened Egress Allowlist & Integrity Validator:
 * - Validates schema version, organization IDs, and safe integer ranges.
 * - Validates nested spend events and metrics against dedicated allowlists.
 * - Verifies payload cryptographic hash (SHA-256) and Ed25519 signature.
 * - Produces a freshly allocated sanitized output object.
 * - Appends metadata-only audit logs (never logs raw payloads or prompts).
 */
export function validateAndSanitizeEgressReceipt(
  rawInput: unknown,
  controlPlanePublicKeyPem: string
): EgressReceiptEnvelope {
  try {
    if (!rawInput || typeof rawInput !== "object") {
      throw new Error("EGRESS_VALIDATION_ERROR: Egress payload must be a non-null object.");
    }

    const obj = rawInput as Record<string, unknown>;

    // 1. Top-level allowlist validation
    for (const key of Object.keys(obj)) {
      if (!ALLOWED_TOP_LEVEL_KEYS.has(key)) {
        throw new Error(`EGRESS_SECURITY_VIOLATION: Unauthorized top-level egress field: "${key}"`);
      }
    }

    const { receiptId, schemaVersion, orgId, edgeNodeId, timestamp, payloadHash, signature, payload } = obj;

    if (typeof receiptId !== "string" || !receiptId || receiptId.length > 64) {
      throw new Error("Invalid or missing receiptId");
    }
    if (schemaVersion !== "v2.0" && schemaVersion !== "v2-enterprise") {
      throw new Error(`Unsupported schemaVersion: "${schemaVersion}"`);
    }
    if (typeof orgId !== "string" || !orgId) throw new Error("Missing orgId");
    if (typeof edgeNodeId !== "string" || !edgeNodeId) throw new Error("Missing edgeNodeId");
    if (
  typeof timestamp !== "number" ||
  !Number.isSafeInteger(timestamp) ||
  timestamp <= 0
) {
  throw new Error("Invalid timestamp");
}

    if (typeof payloadHash !== "string" || !HEX_64_REGEX.test(payloadHash)) {
      throw new Error("Invalid or malformed payloadHash (expected 64-char hex SHA-256)");
    }
    if (typeof signature !== "string" || !BASE64_SIG_REGEX.test(signature)) {
      throw new Error("Invalid or malformed signature format");
    }

    if (!payload || typeof payload !== "object") {
      throw new Error("Missing payload object");
    }

    const pObj = payload as Record<string, unknown>;

    // 2. Payload allowlist validation
    for (const key of Object.keys(pObj)) {
      if (!ALLOWED_PAYLOAD_KEYS.has(key)) {
        throw new Error(`EGRESS_SECURITY_VIOLATION: Unauthorized payload field: "${key}"`);
      }
    }

    if (pObj.orgId !== orgId || pObj.edgeNodeId !== edgeNodeId) {
      throw new Error("Envelope and payload organization/node identity mismatch");
    }

    if (!Number.isSafeInteger(pObj.sequenceStart) || (pObj.sequenceStart as number) < 0) {
      throw new Error("Invalid sequenceStart");
    }
    if (!Number.isSafeInteger(pObj.sequenceEnd) || (pObj.sequenceEnd as number) < 0) {
      throw new Error("Invalid sequenceEnd");
    }
    if ((pObj.sequenceStart as number) > (pObj.sequenceEnd as number)) {
      throw new Error("sequenceStart cannot exceed sequenceEnd");
    }
    if (!Number.isSafeInteger(pObj.batchTimestamp) || (pObj.batchTimestamp as number) <= 0) {
      throw new Error("Invalid batchTimestamp");
    }

    // 3. Recursive inspection of spend events & metrics
    const spendEvents = pObj.spendLedgerEvents;
    if (!Array.isArray(spendEvents)) throw new Error("spendLedgerEvents must be an array");
    const sanitizedSpendEvents: SpendLedgerEvent[] = [];

    for (const ev of spendEvents) {
      if (!ev || typeof ev !== "object") throw new Error("Invalid spend event object");
      const evRec = ev as Record<string, unknown>;
      for (const k of Object.keys(evRec)) {
        if (!ALLOWED_SPEND_EVENT_KEYS.has(k)) {
          throw new Error(`EGRESS_SECURITY_VIOLATION: Unknown spend event property: "${k}"`);
        }
      }
      if (typeof evRec.eventId !== "string" || !evRec.eventId) throw new Error("Invalid eventId");
      if (typeof evRec.virtualKeyId !== "string" || !evRec.virtualKeyId) throw new Error("Invalid virtualKeyId");
      if (!Number.isSafeInteger(evRec.costMicros) || (evRec.costMicros as number) < 0) {
        throw new Error("Invalid costMicros");
      }
      if (
  typeof timestamp !== "number" ||
  !Number.isSafeInteger(timestamp) ||
  timestamp <= 0
) {
  throw new Error("Invalid timestamp");
}

      scanStringForForbiddenContent(evRec.eventId);
      scanStringForForbiddenContent(evRec.virtualKeyId);

      sanitizedSpendEvents.push({
        eventId: evRec.eventId,
        virtualKeyId: evRec.virtualKeyId,
        costMicros: evRec.costMicros as number,
        timestamp: evRec.timestamp as number,
      });
    }

    if (typeof pObj.auditMerkleRoot !== "string" || !HEX_64_REGEX.test(pObj.auditMerkleRoot)) {
      throw new Error("Invalid auditMerkleRoot hash");
    }

    const metrics = pObj.metricsSummary;
    if (!metrics || typeof metrics !== "object") throw new Error("Missing metricsSummary");
    const mRec = metrics as Record<string, unknown>;
    for (const k of Object.keys(mRec)) {
      if (!ALLOWED_METRICS_KEYS.has(k)) {
        throw new Error(`EGRESS_SECURITY_VIOLATION: Unknown metrics property: "${k}"`);
      }
    }
    if (!Number.isSafeInteger(mRec.totalSpendMicros) || (mRec.totalSpendMicros as number) < 0) throw new Error("Invalid totalSpendMicros");
    if (!Number.isSafeInteger(mRec.activeKeysCount) || (mRec.activeKeysCount as number) < 0) throw new Error("Invalid activeKeysCount");
    if (!Number.isSafeInteger(mRec.revokedKeysCount) || (mRec.revokedKeysCount as number) < 0) throw new Error("Invalid revokedKeysCount");
    if (!Number.isSafeInteger(mRec.redactionsCount) || (mRec.redactionsCount as number) < 0) throw new Error("Invalid redactionsCount");

    const sanitizedMetrics: MetricsSummary = {
      totalSpendMicros: mRec.totalSpendMicros as number,
      activeKeysCount: mRec.activeKeysCount as number,
      revokedKeysCount: mRec.revokedKeysCount as number,
      redactionsCount: mRec.redactionsCount as number,
    };

    const sanitizedPayload: TelemetryBatchPayload = {
      orgId: pObj.orgId as string,
      edgeNodeId: pObj.edgeNodeId as string,
      sequenceStart: pObj.sequenceStart as number,
      sequenceEnd: pObj.sequenceEnd as number,
      batchTimestamp: pObj.batchTimestamp as number,
      spendLedgerEvents: sanitizedSpendEvents,
      auditMerkleRoot: pObj.auditMerkleRoot as string,
      metricsSummary: sanitizedMetrics,
    };


// 4. Cryptographic Integrity Verification (Hash + Ed25519 Signature)
const canonicalPayloadString = JSON.stringify(sanitizedPayload);
const computedHash = crypto
  .createHash("sha256")
  .update(canonicalPayloadString)
  .digest("hex");

if (computedHash !== payloadHash) {
  throw new Error(
    "EGRESS_INTEGRITY_VIOLATION: Payload cryptographic hash does not match computed SHA-256 digest!"
  );
}

// Control Plane public key is mandatory.
if (
  typeof controlPlanePublicKeyPem !== "string" ||
  !controlPlanePublicKeyPem.trim()
) {
  throw new Error(
    "EGRESS_SIGNATURE_VIOLATION: Control Plane public key is required"
  );
}

// Accept only Ed25519 public keys.
const publicKey = crypto.createPublicKey(controlPlanePublicKeyPem);

if (publicKey.asymmetricKeyType !== "ed25519") {
  throw new Error(
    "EGRESS_SIGNATURE_VIOLATION: Invalid public key type"
  );
}

// Validate canonical Base64 encoding and Ed25519 signature length (64 bytes).
const signatureBytes = Buffer.from(signature, "base64");

if (
  signatureBytes.length !== 64 ||
  signatureBytes.toString("base64") !== signature
) {
  throw new Error(
    "EGRESS_SIGNATURE_VIOLATION: Invalid Ed25519 signature encoding"
  );
}

// Always verify the signature.
const isSignatureValid = crypto.verify(
  null,
  Buffer.from(payloadHash, "hex"),
  publicKey,
  signatureBytes
);

if (!isSignatureValid) {
  throw new Error(
    "EGRESS_SIGNATURE_VIOLATION: Ed25519 signature verification failed"
  );
}

    // 5. Construct Immutable Sanitized Envelope
    const sanitizedEnvelope: EgressReceiptEnvelope = {
      receiptId: receiptId as string,
      schemaVersion: schemaVersion as string,
      orgId: orgId as string,
      edgeNodeId: edgeNodeId as string,
      timestamp: timestamp as number,
      payloadHash: payloadHash as string,
      signature: signature as string,
      payload: sanitizedPayload,
    };

    // 6. Metadata-Only Audit Logging (Never logs payloads, prompts, or credentials)
    if (process.env.AINDIGO_EGRESS_LOG === "true") {
      const logDir = path.resolve(process.cwd(), "logs");
      if (!fs.existsSync(logDir)) {
        fs.mkdirSync(logDir, { recursive: true });
      }
      const logPath = path.join(logDir, "egress-audit.jsonl");
      const metadataRecord = {
        timestamp: Date.now(),
        receiptId: sanitizedEnvelope.receiptId,
        orgId: sanitizedEnvelope.orgId,
        edgeNodeId: sanitizedEnvelope.edgeNodeId,
        payloadHash: sanitizedEnvelope.payloadHash,
        outcome: "SUCCESS",
      };
      fs.appendFileSync(logPath, JSON.stringify(metadataRecord) + "\n", "utf8");
    }

    return sanitizedEnvelope;
  } catch (err: any) {
    // Log rejection metadata if enabled
    if (process.env.AINDIGO_EGRESS_LOG === "true") {
      try {
        const logDir = path.resolve(process.cwd(), "logs");
        if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });
        const logPath = path.join(logDir, "egress-audit.jsonl");
        const rejectionRecord = {
          timestamp: Date.now(),
          outcome: "REJECTED",
          reason: err.message ?? "Unknown validation failure",
        };
        fs.appendFileSync(logPath, JSON.stringify(rejectionRecord) + "\n", "utf8");
      } catch {}
    }
    throw err;
  }
}
