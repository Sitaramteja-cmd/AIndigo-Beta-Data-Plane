import { z } from 'zod';

export const NODE_ENROLLMENT_SCHEMA_VERSION = '1.0';

export const NodeIdSchema = z.string()
  .regex(/^node_[a-f0-9]{16}$/);

export const EnrollmentCodeSchema = z.string()
  .min(32)
  .max(256)
  .regex(/^[A-Za-z0-9_-]+$/);

export const PublicKeyPemSchema = z.string()
  .min(100)
  .max(4096)
  .refine(
    value =>
      value.includes('-----BEGIN PUBLIC KEY-----') &&
      value.includes('-----END PUBLIC KEY-----'),
    'Expected a PEM-encoded public key'
  );

export const NonceSchema = z.string()
  .regex(/^[a-f0-9]{64}$/);

// Ed25519 signatures are exactly 64 bytes.
// Their canonical Base64 representation is exactly 88 characters.
export const Ed25519SignatureSchema = z.string()
  .regex(
    /^[A-Za-z0-9+/]{85}[AQgw]==$/,
    'Expected a canonical Base64-encoded 64-byte Ed25519 signature'
  );
export const EnrollmentCodeCreateRequestSchema = z.object({
  label: z.string().trim().min(1).max(100),
}).strict();

export const EnrollmentCodeCreateResponseSchema = z.object({
  enrollmentCode: EnrollmentCodeSchema,
  expiresAt: z.string().datetime(),
}).strict();

export const NodeEnrollmentChallengeRequestSchema = z.object({
  enrollmentCode: EnrollmentCodeSchema,
  nodeId: NodeIdSchema,
  nodePublicKeyPem: PublicKeyPemSchema,
  clientNonce: NonceSchema,
}).strict();

export const NodeEnrollmentChallengeSchema = z.object({
  schemaVersion: z.literal(NODE_ENROLLMENT_SCHEMA_VERSION),
  challengeId: z.string().uuid(),
  nodeId: NodeIdSchema,
  nodePublicKeyFingerprint: z.string().regex(/^[a-f0-9]{16}$/),
  clientNonce: NonceSchema,
  serverNonce: NonceSchema,
  issuedAt: z.string().datetime(),
  expiresAt: z.string().datetime(),
}).strict().refine(
  value => Date.parse(value.expiresAt) > Date.parse(value.issuedAt),
  'Challenge expiry must be later than issuance'
);

export const NodeEnrollmentProofRequestSchema = z.object({
  challengeId: z.string().uuid(),
  nodeId: NodeIdSchema,
  signature: Ed25519SignatureSchema,
}).strict();

export const NodeLeasePayloadSchema = z.object({
  schemaVersion: z.literal(NODE_ENROLLMENT_SCHEMA_VERSION),
  leaseId: z.string().uuid(),
  keyId: z.string().min(1).max(128),
  tenantId: z.string().min(1).max(128),
  nodeId: NodeIdSchema,
  nodePublicKeyFingerprint: z.string().regex(/^[a-f0-9]{16}$/),
  issuedAt: z.string().datetime(),
  expiresAt: z.string().datetime(),
  offlineMaxSeconds: z.number().int().positive().max(172800),
}).strict().refine(
  value => {
    const lifetime =
      (Date.parse(value.expiresAt) - Date.parse(value.issuedAt)) / 1000;

    return lifetime > 0 && lifetime <= value.offlineMaxSeconds;
  },
  'Lease lifetime must be positive and within its offline limit'
);

export const SignedNodeLeaseSchema = z.object({
  payload: NodeLeasePayloadSchema,
  signature: Ed25519SignatureSchema,
}).strict();

export type EnrollmentCodeCreateRequest =
  z.infer<typeof EnrollmentCodeCreateRequestSchema>;

export type EnrollmentCodeCreateResponse =
  z.infer<typeof EnrollmentCodeCreateResponseSchema>;

export type NodeEnrollmentChallengeRequest =
  z.infer<typeof NodeEnrollmentChallengeRequestSchema>;

export type NodeEnrollmentChallenge =
  z.infer<typeof NodeEnrollmentChallengeSchema>;

export type NodeEnrollmentProofRequest =
  z.infer<typeof NodeEnrollmentProofRequestSchema>;

export type NodeLeasePayload =
  z.infer<typeof NodeLeasePayloadSchema>;

export type SignedNodeLease =
  z.infer<typeof SignedNodeLeaseSchema>;


// -----------------------------------------------------------------------------
// Signed node-status protocol (INT-005)
// -----------------------------------------------------------------------------

export const NodeStatusRequestPayloadSchema = z.object({
  schemaVersion: z.literal(NODE_ENROLLMENT_SCHEMA_VERSION),
  nodeId: NodeIdSchema,
  tenantId: z.string().min(1).max(128),
  leaseId: z.string().uuid(),
  nodePublicKeyFingerprint: z.string().regex(/^[a-f0-9]{16}$/),
  timestamp: z.string().datetime(),
  nonce: NonceSchema,
}).strict();

export const SignedNodeStatusRequestSchema = z.object({
  payload: NodeStatusRequestPayloadSchema,
  signature: Ed25519SignatureSchema,
}).strict();

export const NodeStatusResponsePayloadSchema = z.object({
  schemaVersion: z.literal(NODE_ENROLLMENT_SCHEMA_VERSION),
  nodeId: NodeIdSchema,
  tenantId: z.string().min(1).max(128),
  leaseId: z.string().uuid(),
  requestNonce: NonceSchema,
  status: z.enum(['ACTIVE', 'REVOKED']),
  checkedAt: z.string().datetime(),
  keyId: z.string().min(1).max(128),
}).strict();

export const SignedNodeStatusResponseSchema = z.object({
  payload: NodeStatusResponsePayloadSchema,
  signature: Ed25519SignatureSchema,
}).strict();

export type NodeStatusRequestPayload =
  z.infer<typeof NodeStatusRequestPayloadSchema>;

export type SignedNodeStatusRequest =
  z.infer<typeof SignedNodeStatusRequestSchema>;

export type NodeStatusResponsePayload =
  z.infer<typeof NodeStatusResponsePayloadSchema>;

export type SignedNodeStatusResponse =
  z.infer<typeof SignedNodeStatusResponseSchema>;
