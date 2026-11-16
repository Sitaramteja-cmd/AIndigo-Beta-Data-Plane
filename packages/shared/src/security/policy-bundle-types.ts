/**
 * Shared license tier contract for AIndigo.
 */
export type LicenseTier = "FREE" | "TEAM" | "ENTERPRISE";

export type PolicySchemaVersion = "1.0";

export type PolicyFallbackStrategy =
  | "SAME_PROVIDER"
  | "CROSS_PROVIDER"
  | "NONE";

export type PolicyAction =
  | "ALLOW"
  | "REDACT"
  | "BLOCK";

export interface PolicyEntitlements {
  licenseId: string;
  licenseVersion: number;
  tier: LicenseTier;
  maxRequestsPerMinute: number;
  allowedModels: string[];
}

export interface AllowedUpstream {
  provider: string;
  endpoint: string;
  enabled: boolean;
}

export interface PolicyFallback {
  enabled: boolean;
  strategy: PolicyFallbackStrategy;
}

export interface PolicyRouting {
  allowedUpstreams: AllowedUpstream[];
  fallback: PolicyFallback;
}

export interface PolicySecurity {
  egressAllowlist: string[];
  enforceHttps: boolean;
}

export interface PolicyChecksumValidator {
  validatorId: string;
  enabled: boolean;
}

export interface PolicyRedactionRule {
  category: string;
  action: PolicyAction;
  enabled: boolean;
}

export interface PolicyDlp {
  enabled: boolean;
  checksumValidators: PolicyChecksumValidator[];
  redactionRules: PolicyRedactionRule[];
}

export interface PolicyBundlePayload {
  schemaVersion: PolicySchemaVersion;
  bundleId: string;
  keyId: string;
  orgId: string;
  edgeNodeId: string;
  version: number;
  issuedAt: number;
  expiresAt: number;
  entitlements: PolicyEntitlements;
  routing: PolicyRouting;
  security: PolicySecurity;
  featureFlags: Record<string, boolean>;
  dlp: PolicyDlp;
}

export interface PolicyBundleEnvelope {
  payload: PolicyBundlePayload;
  signature: string;
}

export type PolicyRejectionReason =
  | "INVALID_ENVELOPE"
  | "INVALID_POLICY_STRUCTURE"
  | "INVALID_CURRENT_TIME"
  | "UNKNOWN_OR_UNTRUSTED_KEY_ID"
  | "REVOKED_SIGNING_KEY"
  | "INVALID_SIGNING_KEY_TYPE"
  | "INVALID_PUBLIC_KEY"
  | "INVALID_SIGNATURE_FORMAT"
  | "SIGNATURE_VERIFICATION_FAILED"
  | "CANONICALIZATION_FAILURE"
  | "UNSUPPORTED_SCHEMA_VERSION"
  | "ORG_BINDING_MISMATCH"
  | "EDGE_NODE_BINDING_MISMATCH"
  | "POLICY_EXPIRED"
  | "INVALID_POLICY_LIFETIME"
  | "INVALID_ISSUED_AT"
  | "CLOCK_ROLLBACK_DETECTED"
  | "VERSION_ROLLBACK_DETECTED"
  | "VERSION_COLLISION"
  | "LICENSE_BINDING_MISMATCH"
  | "POLICY_EXCEEDS_LICENSE_ENTITLEMENTS";

export type PolicyVerificationResult =
  | {
      valid: true;
      reason: "VALID_POLICY";
      payload: PolicyBundlePayload;
    }
  | {
      valid: false;
      reason: PolicyRejectionReason;
    };