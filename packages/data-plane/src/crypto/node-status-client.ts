import crypto from 'node:crypto';

import {
  canonicalizePolicyPayload,
  NodeStatusRequestPayloadSchema,
  SignedNodeStatusRequestSchema,
  SignedNodeStatusResponseSchema,
  type NodeStatusResponsePayload,
  type SignedNodeStatusRequest,
} from '@aindigo/shared';

import type { NodeIdentity } from './node-identity.js';

const MAX_CLOCK_SKEW_MS = 60_000;
const MAX_STATUS_AGE_MS = 60_000;
const DEFAULT_TIMEOUT_MS = 15_000;

export interface CreateNodeStatusRequestOptions {
  identity: NodeIdentity;
  tenantId: string;
  leaseId: string;
  nowMs?: number;
  nonce?: string;
}

export interface VerifyNodeStatusResponseOptions {
  controlPlanePublicKeyPem: string;
  expectedSigningKeyId: string;
  identity: NodeIdentity;
  tenantId: string;
  leaseId: string;
  requestNonce: string;
  nowMs?: number;
  maxAgeMs?: number;
}

export interface RequestNodeStatusOptions
  extends Omit<VerifyNodeStatusResponseOptions, 'requestNonce'> {
  controlPlaneUrl: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

function statusClientError(message: string): Error {
  return new Error(`NODE_STATUS_CLIENT_ERROR: ${message}`);
}

function validateNow(nowMs: number): void {
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) {
    throw statusClientError('Invalid local clock value.');
  }
}

function getEd25519PublicKey(publicKeyPem: string): crypto.KeyObject {
  const key = crypto.createPublicKey(publicKeyPem);

  if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519') {
    throw statusClientError('Pinned Control Plane public key must be Ed25519.');
  }

  return key;
}

function getEd25519PrivateKey(
  privateKeyPem: string,
  expectedPublicKeyPem: string
): crypto.KeyObject {
  const privateKey = crypto.createPrivateKey(privateKeyPem);

  if (
    privateKey.type !== 'private' ||
    privateKey.asymmetricKeyType !== 'ed25519'
  ) {
    throw statusClientError('Node private key must be Ed25519.');
  }

  const derivedPublic = crypto.createPublicKey(privateKey).export({
    type: 'spki',
    format: 'der',
  });

  const expectedPublic = crypto.createPublicKey(expectedPublicKeyPem).export({
    type: 'spki',
    format: 'der',
  });

  if (!derivedPublic.equals(expectedPublic)) {
    throw statusClientError('Node identity keypair does not match.');
  }

  return privateKey;
}

function validateControlPlaneUrl(rawUrl: string): string {
  if (!rawUrl || rawUrl !== rawUrl.trim()) {
    throw statusClientError('Invalid Control Plane URL.');
  }

  let parsed: URL;

  try {
    parsed = new URL(rawUrl);
  } catch {
    throw statusClientError('Invalid Control Plane URL.');
  }

  if (
    parsed.protocol !== 'https:' &&
    parsed.protocol !== 'http:'
  ) {
    throw statusClientError('Unsupported Control Plane URL protocol.');
  }

  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw statusClientError('Invalid Control Plane URL configuration.');
  }

  const isLoopback =
    parsed.hostname === 'localhost' ||
    parsed.hostname === '127.0.0.1' ||
    parsed.hostname === '::1' ||
    parsed.hostname === '[::1]';

  if (parsed.protocol === 'http:' && !isLoopback) {
    throw statusClientError('HTTPS is required for remote Control Plane hosts.');
  }

  return `${parsed.origin}${parsed.pathname.replace(/\/+$/, '')}`;
}

export function createSignedNodeStatusRequest(
  options: CreateNodeStatusRequestOptions
): SignedNodeStatusRequest {
  const nowMs = options.nowMs ?? Date.now();
  validateNow(nowMs);

  if (
    !options.identity ||
    !options.tenantId?.trim() ||
    !options.leaseId?.trim()
  ) {
    throw statusClientError('Node identity, tenant and lease are required.');
  }

  const nonce = options.nonce ?? crypto.randomBytes(32).toString('hex');

  const payload = NodeStatusRequestPayloadSchema.parse({
    schemaVersion: '1.0',
    nodeId: options.identity.nodeId,
    tenantId: options.tenantId,
    leaseId: options.leaseId,
    nodePublicKeyFingerprint: options.identity.publicKeyFingerprint,
    timestamp: new Date(nowMs).toISOString(),
    nonce,
  });

  const privateKey = getEd25519PrivateKey(
    options.identity.privateKeyPem,
    options.identity.publicKeyPem
  );

  const canonicalPayload = canonicalizePolicyPayload(payload);

  const signature = crypto.sign(
    null,
    Buffer.from(canonicalPayload, 'utf8'),
    privateKey
  );

  if (signature.length !== 64) {
    throw statusClientError('Invalid Ed25519 request signature length.');
  }

  return SignedNodeStatusRequestSchema.parse({
    payload: JSON.parse(canonicalPayload),
    signature: signature.toString('base64'),
  });
}

export function verifySignedNodeStatusResponse(
  responseInput: unknown,
  options: VerifyNodeStatusResponseOptions
): NodeStatusResponsePayload {
  const nowMs = options.nowMs ?? Date.now();
  const maxAgeMs = options.maxAgeMs ?? MAX_STATUS_AGE_MS;

  validateNow(nowMs);

  if (
    !Number.isSafeInteger(maxAgeMs) ||
    maxAgeMs < 1 ||
    maxAgeMs > MAX_STATUS_AGE_MS
  ) {
    throw statusClientError('Invalid node-status maximum age.');
  }

  if (
    !options.controlPlanePublicKeyPem?.trim() ||
    !options.expectedSigningKeyId?.trim() ||
    !options.tenantId?.trim() ||
    !options.leaseId?.trim() ||
    !options.requestNonce?.trim()
  ) {
    throw statusClientError('Trusted response verification context is incomplete.');
  }

  const parsed = SignedNodeStatusResponseSchema.safeParse(responseInput);

  if (!parsed.success) {
    throw statusClientError('Control Plane returned an invalid signed status response.');
  }

  const { payload, signature } = parsed.data;

  if (
    payload.nodeId !== options.identity.nodeId ||
    payload.tenantId !== options.tenantId ||
    payload.leaseId !== options.leaseId ||
    payload.requestNonce !== options.requestNonce
  ) {
    throw statusClientError('Signed status response identity binding mismatch.');
  }

  if (payload.keyId !== options.expectedSigningKeyId) {
    throw statusClientError('Unexpected Control Plane signing key ID.');
  }

  const checkedAtMs = Date.parse(payload.checkedAt);

  if (
    !Number.isFinite(checkedAtMs) ||
    checkedAtMs > nowMs + MAX_CLOCK_SKEW_MS ||
    nowMs - checkedAtMs > maxAgeMs
  ) {
    throw statusClientError('Control Plane node status is stale or not yet valid.');
  }

  const publicKey = getEd25519PublicKey(
    options.controlPlanePublicKeyPem
  );

  const signatureBytes = Buffer.from(signature, 'base64');

  if (
    signatureBytes.length !== 64 ||
    signatureBytes.toString('base64') !== signature
  ) {
    throw statusClientError('Invalid Control Plane signature encoding.');
  }

  const canonicalPayload = canonicalizePolicyPayload(payload);

  const valid = crypto.verify(
    null,
    Buffer.from(canonicalPayload, 'utf8'),
    publicKey,
    signatureBytes
  );

  if (!valid) {
    throw statusClientError('Control Plane node-status signature verification failed.');
  }

  return payload;
}

export async function requestNodeStatus(
  options: RequestNodeStatusOptions
): Promise<NodeStatusResponsePayload> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;

  if (
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < 1_000 ||
    timeoutMs > 60_000
  ) {
    throw statusClientError('Invalid node-status request timeout.');
  }

  if (typeof fetchImpl !== 'function') {
    throw statusClientError('HTTP fetch implementation is unavailable.');
  }

  const baseUrl = validateControlPlaneUrl(options.controlPlaneUrl);

  const request = createSignedNodeStatusRequest({
    identity: options.identity,
    tenantId: options.tenantId,
    leaseId: options.leaseId,
  });

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetchImpl(
      `${baseUrl}/api/v1/nodes/status`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify(request),
        signal: controller.signal,
      }
    );

    if (!response.ok) {
      throw statusClientError(
        `Control Plane node-status request failed with HTTP ${response.status}.`
      );
    }

    let responseBody: unknown;

    try {
      responseBody = await response.json();
    } catch {
      throw statusClientError('Control Plane returned invalid status JSON.');
    }

    return verifySignedNodeStatusResponse(responseBody, {
      controlPlanePublicKeyPem: options.controlPlanePublicKeyPem,
      expectedSigningKeyId: options.expectedSigningKeyId,
      identity: options.identity,
      tenantId: options.tenantId,
      leaseId: options.leaseId,
      requestNonce: request.payload.nonce,
    });
  } catch (error) {
    if (
      error instanceof Error &&
      error.message.startsWith('NODE_STATUS_CLIENT_ERROR:')
    ) {
      throw error;
    }

    if (controller.signal.aborted) {
      throw statusClientError('Control Plane node-status request timed out.');
    }

    throw statusClientError('Unable to communicate with the Control Plane.');
  } finally {
    clearTimeout(timeout);
  }
}
