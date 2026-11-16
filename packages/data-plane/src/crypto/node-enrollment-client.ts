import crypto from "node:crypto";
import { z } from "zod";

import {
  EnrollmentCodeSchema,
  NodeEnrollmentChallengeRequestSchema,
  NodeEnrollmentChallengeSchema,
  NodeEnrollmentProofRequestSchema,
  SignedNodeLeaseSchema,
  type NodeEnrollmentChallenge,
  type SignedNodeLease,
} from "@aindigo/shared";

import {
  signNodeEnrollmentChallenge,
  verifyNodeLease,
  type NodeIdentity,
} from "./node-identity.js";

const EnrollmentProofResponseSchema = z.object({
  nodeId: z.string().min(1),
  tenantId: z.string().min(1).max(128),
  publicKeyFingerprint: z.string().regex(/^[a-f0-9]{16}$/),
  label: z.string().min(1).max(100),
  enrolledAt: z.string().datetime(),
  signedLease: SignedNodeLeaseSchema,
}).strict();

export interface NodeEnrollmentClientOptions {
  controlPlaneUrl: string;
  enrollmentCode: string;
  controlPlanePublicKeyPem: string;
  expectedSigningKeyId: string;
  identity: NodeIdentity;

  fetchImpl?: typeof fetch;
  timeoutMs?: number;

  persistLease: (
    lease: SignedNodeLease,
    publicKeyPem: string,
    identity: NodeIdentity,
    tenantId: string,
    nowMs: number,
    expectedKeyId: string
  ) => unknown;
}

export interface NodeEnrollmentResult {
  nodeId: string;
  tenantId: string;
  publicKeyFingerprint: string;
  label: string;
  enrolledAt: string;
  leaseId: string;
  leaseExpiresAt: string;
}

function enrollmentError(message: string): Error {
  return new Error(`NODE_ENROLLMENT_CLIENT_ERROR: ${message}`);
}

function validateBaseUrl(rawUrl: string): string {
  if (!rawUrl || rawUrl !== rawUrl.trim()) {
    throw enrollmentError("Invalid Control Plane URL.");
  }

  let parsed: URL;

  try {
    parsed = new URL(rawUrl);
  } catch {
    throw enrollmentError("Invalid Control Plane URL.");
  }

  if (
    parsed.protocol !== "https:" &&
    parsed.protocol !== "http:"
  ) {
    throw enrollmentError("Unsupported Control Plane URL protocol.");
  }

  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw enrollmentError("Invalid Control Plane URL configuration.");
  }

  const isLoopback =
    parsed.hostname === "localhost" ||
    parsed.hostname === "127.0.0.1" ||
    parsed.hostname === "::1" ||
    parsed.hostname === "[::1]";

  if (parsed.protocol === "http:" && !isLoopback) {
    throw enrollmentError("HTTPS is required for remote Control Plane hosts.");
  }

  return `${parsed.origin}${parsed.pathname.replace(/\/+$/, "")}`;
}

async function postJson(
  url: string,
  body: unknown,
  fetchImpl: typeof fetch,
  timeoutMs: number
): Promise<unknown> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetchImpl(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    if (!response.ok) {
      throw enrollmentError(
        `Control Plane enrollment request failed with HTTP ${response.status}.`
      );
    }

    try {
      return await response.json();
    } catch {
      throw enrollmentError("Control Plane returned invalid JSON.");
    }
  } catch (error) {
    if (
      error instanceof Error &&
      error.message.startsWith("NODE_ENROLLMENT_CLIENT_ERROR:")
    ) {
      throw error;
    }

    if (controller.signal.aborted) {
      throw enrollmentError("Control Plane enrollment request timed out.");
    }

    throw enrollmentError("Unable to communicate with the Control Plane.");
  } finally {
    clearTimeout(timeout);
  }
}

export async function enrollDataPlaneNode(
  options: NodeEnrollmentClientOptions
): Promise<NodeEnrollmentResult> {
  const {
    controlPlaneUrl,
    enrollmentCode,
    controlPlanePublicKeyPem,
    expectedSigningKeyId,
    identity,
    persistLease,
  } = options;

  const timeoutMs = options.timeoutMs ?? 15_000;
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;

  if (
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < 1_000 ||
    timeoutMs > 60_000
  ) {
    throw enrollmentError("Invalid enrollment request timeout.");
  }

  if (typeof fetchImpl !== "function") {
    throw enrollmentError("HTTP fetch implementation is unavailable.");
  }

  if (!controlPlanePublicKeyPem?.trim()) {
    throw enrollmentError("Pinned Control Plane public key is required.");
  }

  if (
    typeof expectedSigningKeyId !== "string" ||
    !expectedSigningKeyId.trim() ||
    expectedSigningKeyId.length > 128
  ) {
    throw enrollmentError("Expected Control Plane signing key ID is required.");
  }

  if (typeof persistLease !== "function") {
    throw enrollmentError("Lease persistence implementation is required.");
  }

  const baseUrl = validateBaseUrl(controlPlaneUrl);

  const validatedCode = EnrollmentCodeSchema.safeParse(enrollmentCode);

  if (!validatedCode.success) {
    throw enrollmentError("Invalid enrollment code format.");
  }

  const clientNonce = crypto.randomBytes(32).toString("hex");

  const challengeRequest = NodeEnrollmentChallengeRequestSchema.parse({
    enrollmentCode: validatedCode.data,
    nodeId: identity.nodeId,
    nodePublicKeyPem: identity.publicKeyPem,
    clientNonce,
  });

  const challengeResponse = await postJson(
    `${baseUrl}/api/v1/nodes/enrollment/challenge`,
    challengeRequest,
    fetchImpl,
    timeoutMs
  );

  const challengeResult =
    NodeEnrollmentChallengeSchema.safeParse(challengeResponse);

  if (!challengeResult.success) {
    throw enrollmentError("Control Plane returned an invalid challenge.");
  }

  const challenge: NodeEnrollmentChallenge = challengeResult.data;

  if (
    challenge.nodeId !== identity.nodeId ||
    challenge.nodePublicKeyFingerprint !== identity.publicKeyFingerprint ||
    challenge.clientNonce !== clientNonce
  ) {
    throw enrollmentError("Enrollment challenge identity binding mismatch.");
  }

  const nowMs = Date.now();

  if (
    Date.parse(challenge.issuedAt) > nowMs + 60_000 ||
    Date.parse(challenge.expiresAt) <= nowMs
  ) {
    throw enrollmentError("Enrollment challenge is expired or not yet valid.");
  }

  const signature = signNodeEnrollmentChallenge(challenge, identity);

  const proofRequest = NodeEnrollmentProofRequestSchema.parse({
    challengeId: challenge.challengeId,
    nodeId: identity.nodeId,
    signature,
  });

  const proofResponse = await postJson(
    `${baseUrl}/api/v1/nodes/enrollment/proof`,
    proofRequest,
    fetchImpl,
    timeoutMs
  );

  const enrollmentResult =
    EnrollmentProofResponseSchema.safeParse(proofResponse);

  if (!enrollmentResult.success) {
    throw enrollmentError("Control Plane returned an invalid enrollment response.");
  }

  const result = enrollmentResult.data;

  if (
    result.nodeId !== identity.nodeId ||
    result.publicKeyFingerprint !== identity.publicKeyFingerprint
  ) {
    throw enrollmentError("Enrollment response identity binding mismatch.");
  }

  const lease = SignedNodeLeaseSchema.parse(result.signedLease);

  if (
  lease.payload.tenantId !== result.tenantId ||
  lease.payload.nodeId !== identity.nodeId ||
  lease.payload.nodePublicKeyFingerprint !== identity.publicKeyFingerprint
) {
  throw enrollmentError("Signed lease does not match the enrollment response.");
}

if (lease.payload.keyId !== expectedSigningKeyId) {
  throw enrollmentError("Unexpected Control Plane signing key ID.");
}

  // First verification gate: independently verify the CP signature
// and all lease bindings before allowing persistence.
verifyNodeLease(
  lease,
  controlPlanePublicKeyPem,
  identity,
  result.tenantId,
  Date.now(),
  expectedSigningKeyId
);

// Second verification gate: the database wrapper independently
// verifies the lease again before committing it to SQLite.
persistLease(
  lease,
  controlPlanePublicKeyPem,
  identity,
  result.tenantId,
  Date.now(),
  expectedSigningKeyId
);

  return {
    nodeId: result.nodeId,
    tenantId: result.tenantId,
    publicKeyFingerprint: result.publicKeyFingerprint,
    label: result.label,
    enrolledAt: result.enrolledAt,
    leaseId: lease.payload.leaseId,
    leaseExpiresAt: lease.payload.expiresAt,
  };
}
