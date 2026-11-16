import crypto from "node:crypto";

import type { LicenseTier } from "@aindigo/shared";

export interface LicensePayload {
  schemaVersion: string;
  licenseId: string;
  licenseVersion: number;
  orgId: string;
  deploymentId: string;
  tier: LicenseTier;
  maxRequestsPerMinute: number;
  features: string[];
  issuer: string;
  audience: string;
  keyId: string;
  issuedAt: number;
  expiresAt: number;
}

export interface SignedLicenseBundle {
  payload: LicensePayload;
  signature: string; // Base64 Ed25519 signature
}

export type KeyStatus = "ACTIVE" | "VERIFY_ONLY" | "REVOKED";

export interface KeyStoreEntry {
  publicKeyPem: string;
  status: KeyStatus;
}

export interface VerifiedLicenseResult {
  active: boolean;
  tier: LicenseTier;
  maxRequestsPerMinute: number;
  features: string[];
  reason: string;
}

const SUPPORTED_SCHEMA_VERSION = "v2.0";
const EXPECTED_ISSUER = "aindigo-control-plane";
const EXPECTED_AUDIENCE = "aindigo-edge";

const ALLOWED_TIERS = new Set<LicenseTier>(["FREE", "TEAM", "ENTERPRISE"]);
const ALLOWED_FEATURES = new Set<string>([
  "advanced_dlp",
  "streaming_sse",
  "merkle_audit",
  "fleet_governance",
]);

const MAX_LICENSE_LIFETIME_MS = 365 * 24 * 60 * 60 * 1000; // 1 year max
const MAX_FEATURES_COUNT = 16;
const MAX_STRING_LENGTH = 128;
const MAX_BUNDLE_SIZE_BYTES = 8192;

/**
 * Strict canonical JSON serialization rejecting cycles, undefined, non-finite numbers, and non-plain objects.
 */
export function canonicalizePayload(payload: LicensePayload): string {
  const seen = new Set<unknown>();

  function sortKeys(obj: unknown): unknown {
    if (obj === null || (typeof obj !== "object" && typeof obj !== "string" && typeof obj !== "number" && typeof obj !== "boolean")) {
      if (typeof obj === "undefined" || typeof obj === "function" || typeof obj === "symbol") {
        throw new Error("CANONICALIZATION_ERROR: Unsupported value type");
      }
      return obj;
    }

    if (typeof obj === "number") {
      if (!Number.isFinite(obj)) {
        throw new Error("CANONICALIZATION_ERROR: Non-finite numbers are not allowed");
      }
      return obj;
    }

    if (typeof obj === "string" || typeof obj === "boolean") {
      return obj;
    }

    if (seen.has(obj)) {
      throw new Error("CANONICALIZATION_ERROR: Circular reference detected");
    }
    seen.add(obj);

    if (Array.isArray(obj)) {
      return obj.map(sortKeys);
    }

    const plainObj = obj as Record<string, unknown>;
    const proto = Object.getPrototypeOf(plainObj);
    if (proto !== Object.prototype && proto !== null) {
      throw new Error("CANONICALIZATION_ERROR: Non-plain object not allowed");
    }

    const sortedObj: Record<string, unknown> = {};
    const keys = Object.keys(plainObj).sort();
    for (const k of keys) {
      sortedObj[k] = sortKeys(plainObj[k]);
    }
    seen.delete(obj);
    return sortedObj;
  }

  const cleaned = sortKeys(payload);
  const jsonStr = JSON.stringify(cleaned);
  if (jsonStr.length > MAX_BUNDLE_SIZE_BYTES) {
    throw new Error("CANONICALIZATION_ERROR: Payload exceeds maximum size");
  }
  return jsonStr;
}

/**
 * Hardened offline license verifier enforcing signature verification BEFORE claim inspection,
 * key lifecycle states (ACTIVE / VERIFY_ONLY / REVOKED), and license version replay protection.
 */
export function verifyAndEvaluateLicense(
  bundle: SignedLicenseBundle,
  expectedOrgId: string,
  expectedDeploymentId: string,
  trustedKeyStore: Record<string, KeyStoreEntry>,
  lastObservedLicenseVersions: Map<string, number>,
  currentTimeMs: number = Date.now()
): VerifiedLicenseResult {
  const FREE_TIER_FALLBACK: VerifiedLicenseResult = {
    active: true,
    tier: "FREE",
    maxRequestsPerMinute: 60,
    features: ["basic_dlp"],
    reason: "FALLBACK_TO_FREE_TIER",
  };

  try {
    if (!bundle || !bundle.payload || typeof bundle.signature !== "string") {
      return { ...FREE_TIER_FALLBACK, reason: "INVALID_BUNDLE_STRUCTURE" };
    }

    if (!Number.isSafeInteger(currentTimeMs) || currentTimeMs <= 0) {
      return { ...FREE_TIER_FALLBACK, reason: "INVALID_CURRENT_TIME" };
    }

    const { payload, signature } = bundle;

    if (!payload.keyId || typeof payload.keyId !== "string" || !Object.hasOwn(trustedKeyStore, payload.keyId)) {
      return { ...FREE_TIER_FALLBACK, reason: "UNKNOWN_OR_UNTRUSTED_KEY_ID" };
    }

    const keyEntry = trustedKeyStore[payload.keyId];

if (!keyEntry) {
  return {
    ...FREE_TIER_FALLBACK,
    reason: "UNKNOWN_OR_UNTRUSTED_KEY_ID"
  };
}

if (keyEntry.status === "REVOKED") {
  return {
    ...FREE_TIER_FALLBACK,
    reason: "REVOKED_SIGNING_KEY"
  };
}

const publicKeyPem = keyEntry.publicKeyPem;

    try {
      const pubKeyObj = crypto.createPublicKey(publicKeyPem);
      if (pubKeyObj.asymmetricKeyType !== "ed25519") {
        return { ...FREE_TIER_FALLBACK, reason: "INVALID_SIGNING_KEY_TYPE" };
      }
    } catch {
      return { ...FREE_TIER_FALLBACK, reason: "INVALID_PUBLIC_KEY_PEM" };
    }

    let signatureBuffer: Buffer;
    try {
      signatureBuffer = Buffer.from(signature, "base64");
      if (signatureBuffer.length !== 64 || signatureBuffer.toString("base64") !== signature) {
        return { ...FREE_TIER_FALLBACK, reason: "INVALID_SIGNATURE_FORMAT" };
      }
    } catch {
      return { ...FREE_TIER_FALLBACK, reason: "MALFORMED_BASE64_SIGNATURE" };
    }

    let canonicalPayload: string;
    try {
      canonicalPayload = canonicalizePayload(payload);
    } catch {
      return { ...FREE_TIER_FALLBACK, reason: "CANONICALIZATION_FAILURE" };
    }

    const isValidSig = crypto.verify(
      null,
      Buffer.from(canonicalPayload, "utf8"),
      publicKeyPem,
      signatureBuffer
    );

    if (!isValidSig) {
      return { ...FREE_TIER_FALLBACK, reason: "SIGNATURE_VERIFICATION_FAILED_FALLBACK" };
    }

    if (payload.schemaVersion !== SUPPORTED_SCHEMA_VERSION) {
      return { ...FREE_TIER_FALLBACK, reason: "UNSUPPORTED_SCHEMA_VERSION" };
    }
    if (typeof payload.licenseId !== "string" || payload.licenseId.trim() === "" || payload.licenseId.length > MAX_STRING_LENGTH) {
      return { ...FREE_TIER_FALLBACK, reason: "INVALID_LICENSE_ID" };
    }
    if (!Number.isSafeInteger(payload.licenseVersion) || payload.licenseVersion <= 0) {
      return { ...FREE_TIER_FALLBACK, reason: "INVALID_LICENSE_VERSION" };
    }

    const minAllowedVersion = lastObservedLicenseVersions.get(payload.licenseId) ?? 0;
    if (payload.licenseVersion < minAllowedVersion) {
      return { ...FREE_TIER_FALLBACK, reason: "LICENSE_VERSION_ROLLBACK_REPLAY" };
    }

    if (payload.issuer !== EXPECTED_ISSUER || payload.audience !== EXPECTED_AUDIENCE) {
      return { ...FREE_TIER_FALLBACK, reason: "INVALID_ISSUER_OR_AUDIENCE" };
    }

    if (!payload.orgId || typeof payload.orgId !== "string" || payload.orgId.length > MAX_STRING_LENGTH || payload.orgId !== expectedOrgId) {
      return { ...FREE_TIER_FALLBACK, reason: "ORG_ID_MISMATCH" };
    }
    if (!payload.deploymentId || typeof payload.deploymentId !== "string" || payload.deploymentId.length > MAX_STRING_LENGTH || payload.deploymentId !== expectedDeploymentId) {
      return { ...FREE_TIER_FALLBACK, reason: "DEPLOYMENT_ID_MISMATCH" };
    }
    if (!ALLOWED_TIERS.has(payload.tier)) {
      return { ...FREE_TIER_FALLBACK, reason: "INVALID_LICENSE_TIER" };
    }
    if (!Number.isSafeInteger(payload.maxRequestsPerMinute) || payload.maxRequestsPerMinute <= 0 || payload.maxRequestsPerMinute > 100000) {
      return { ...FREE_TIER_FALLBACK, reason: "INVALID_REQUEST_LIMIT" };
    }
    if (!Number.isSafeInteger(payload.issuedAt) || payload.issuedAt <= 0 || payload.issuedAt > currentTimeMs + 60000) {
      return { ...FREE_TIER_FALLBACK, reason: "INVALID_ISSUED_AT_TIMESTAMP" };
    }
    if (!Number.isSafeInteger(payload.expiresAt) || payload.expiresAt <= currentTimeMs) {
      return { ...FREE_TIER_FALLBACK, reason: "LICENSE_EXPIRED_GRACEFUL_DEGRADATION" };
    }
    if (payload.expiresAt <= payload.issuedAt) {
      return { ...FREE_TIER_FALLBACK, reason: "INVALID_EXPIRY_BEFORE_ISSUED" };
    }
    if (payload.expiresAt - payload.issuedAt > MAX_LICENSE_LIFETIME_MS) {
      return { ...FREE_TIER_FALLBACK, reason: "LICENSE_LIFETIME_EXCEEDED" };
    }

    if (!Array.isArray(payload.features) || payload.features.length > MAX_FEATURES_COUNT) {
      return { ...FREE_TIER_FALLBACK, reason: "INVALID_FEATURES_FORMAT_OR_COUNT" };
    }
    if (payload.features.length === 0) {
      return { ...FREE_TIER_FALLBACK, reason: "EMPTY_FEATURE_ARRAY" };
    }

    const featureSet = new Set<string>();
    for (const feat of payload.features) {
      if (typeof feat !== "string" || !ALLOWED_FEATURES.has(feat)) {
        return { ...FREE_TIER_FALLBACK, reason: "UNKNOWN_OR_UNSUPPORTED_FEATURE" };
      }
      if (featureSet.has(feat)) {
        return { ...FREE_TIER_FALLBACK, reason: "DUPLICATE_FEATURE_ENTRY" };
      }
      featureSet.add(feat);
    }

    lastObservedLicenseVersions.set(payload.licenseId, Math.max(minAllowedVersion, payload.licenseVersion));

    return {
      active: true,
      tier: payload.tier,
      maxRequestsPerMinute: payload.maxRequestsPerMinute,
      features: [...payload.features],
      reason: "VALID_ENTERPRISE_LICENSE",
    };
  } catch {
    return { ...FREE_TIER_FALLBACK, reason: "VERIFICATION_EXCEPTION_FALLBACK" };
  }
}
export type { LicenseTier };
