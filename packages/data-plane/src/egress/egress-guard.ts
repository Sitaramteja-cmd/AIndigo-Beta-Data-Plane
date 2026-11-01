import fs from "node:fs";
import path from "node:path";
import { SignedReceipt } from "../crypto/node-identity";

/**
 * Strict allowlist of keys permitted to leave the Customer Data Plane
 * toward the Cloud Control Plane. Any other key triggers an immediate abort.
 */
export const ALLOWED_EGRESS_KEYS = new Set<string>([
  "receipt_id",
  "timestamp",
  "node_id",
  "department",
  "model_requested",
  "model_routed",
  "prompt_tokens",
  "completion_tokens",
  "cost_usd",
  "dlp_categories",
  "cache_hit",
  "prev_hash",
  "schema_version",
  "receipt_hash",
  "ed25519_signature",
  "node_pubkey_fingerprint",
]);

/**
 * High-risk secret patterns that must NEVER appear inside metadata string fields
 * (e.g., if someone accidentally passes a key inside `department` or `model_requested`).
 */
const FORBIDDEN_VALUE_PATTERNS: Array<{ name: string; regex: RegExp }> = [
  { name: "AWS_ACCESS_KEY", regex: /AKIA[0-9A-Z]{16}/i },
  { name: "UPSTREAM_API_KEY", regex: /\b(sk-[a-zA-Z0-9_-]{16,}|AIza[0-9A-Za-z_-]{30,})\b/ },
  { name: "CANARY_SENTINEL", regex: /CANARY_TOP_SECRET/i },
];

export class EgressPolicyViolationError extends Error {
  constructor(message: string) {
    super(`[EGRESS_GUARD_BLOCKED] ${message}`);
    this.name = "EgressPolicyViolationError";
  }
}

export interface EgressGuardOptions {
  enableLocalAuditLog?: boolean;
  auditLogPath?: string;
}

/**
 * Validates and sanitizes an outbound telemetry payload before it leaves the Data Plane.
 * Throws EgressPolicyViolationError if any unapproved key, oversized string, or secret pattern is found.
 */
export function validateAndLogEgressPayload(
  payload: Record<string, unknown>,
  options: EgressGuardOptions = {}
): SignedReceipt {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new EgressPolicyViolationError("Egress payload must be a non-null JSON object.");
  }

  const keys = Object.keys(payload);

  // 1. Strict Schema Allowlist Check
  for (const key of keys) {
    if (!ALLOWED_EGRESS_KEYS.has(key)) {
      throw new EgressPolicyViolationError(
        `Unapproved field "${key}" detected in outbound Control Plane payload. Transmission aborted.`
      );
    }
  }

  // 2. Field Type, Length & Forbidden Pattern Inspection
  for (const [key, value] of Object.entries(payload)) {
    if (typeof value === "string") {
      const maxLen = key === "ed25519_signature" ? 256 : 128;
      if (value.length > maxLen) {
        throw new EgressPolicyViolationError(
          `Field "${key}" exceeds maximum metadata length (${value.length} > ${maxLen}). Possible raw prompt leakage.`
        );
      }

      for (const pattern of FORBIDDEN_VALUE_PATTERNS) {
        if (pattern.regex.test(value)) {
          throw new EgressPolicyViolationError(
            `Forbidden secret pattern (${pattern.name}) detected inside metadata field "${key}". Transmission aborted.`
          );
        }
      }
    } else if (Array.isArray(value)) {
      if (key !== "dlp_categories") {
        throw new EgressPolicyViolationError(`Unexpected array in field "${key}".`);
      }
      for (const item of value) {
        if (typeof item !== "string" || item.length > 64) {
          throw new EgressPolicyViolationError(`Invalid item in dlp_categories array.`);
        }
      }
    } else if (typeof value !== "number" && typeof value !== "boolean") {
      throw new EgressPolicyViolationError(
        `Invalid primitive type "${typeof value}" for field "${key}".`
      );
    }
  }

  // 3. Optional Local Egress Audit Log (AINDIGO_EGRESS_LOG=true)
  const shouldLog =
    options.enableLocalAuditLog ?? process.env.AINDIGO_EGRESS_LOG === "true";

  if (shouldLog) {
    const logFile =
      options.auditLogPath ?? path.resolve(process.cwd(), "egress-audit.jsonl");
    const logLine = JSON.stringify({
      egress_verified_at: new Date().toISOString(),
      payload,
    });
    fs.appendFileSync(logFile, logLine + "\n", "utf8");
  }

  return payload as unknown as SignedReceipt;
}
