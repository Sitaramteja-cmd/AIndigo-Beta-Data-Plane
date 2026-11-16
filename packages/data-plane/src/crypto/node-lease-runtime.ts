import fs from 'node:fs';
import path from 'node:path';

import type { NodeStatusResponsePayload } from '@aindigo/shared';

import {
  getDataPlaneNodeLeaseClockState,
  getNodeActivation,
  getPersistedDataPlaneNodeLease,
  recordDataPlaneNodeLeaseClockObservation,
} from '../db.js';

import {
  verifyNodeLease,
  type NodeIdentity,
} from './node-identity.js';

const CLOCK_ROLLBACK_TOLERANCE_MS = 5 * 60 * 1000;
const MAX_NODE_STATUS_AGE_MS = 60_000;

export type NodeLeaseRuntimeStatus =
  | 'UNCONFIGURED'
  | 'UNENROLLED'
  | 'LEASE_INVALID'
  | 'CLOCK_ROLLBACK'
  | 'TENANT_MISMATCH'
  | 'ACTIVATION_INVALID'
  | 'STATUS_REQUIRED'
  | 'STATUS_STALE'
  | 'NODE_REVOKED'
  | 'ONLINE';

export interface NodeLeaseRuntimeState {
  status: NodeLeaseRuntimeStatus;
  reason?: string;
  tenantId?: string;
  nodeId?: string;
  leaseId?: string;
  expiresAt?: string;
}

export interface NodeLeaseRuntimeContext {
  identity: NodeIdentity;
  tenantId: string;
  leaseId: string;
}

export interface TrustedControlPlaneSigningConfig {
  publicKeyPem: string;
  keyId: string;
}

let nodeIdentity: NodeIdentity | null = null;

let leaseState: NodeLeaseRuntimeState = {
  status: 'UNCONFIGURED',
};

let authenticatedNodeStatus: NodeStatusResponsePayload | null = null;

export function configureNodeLeaseRuntime(
  identity: NodeIdentity
): void {
  nodeIdentity = identity;
  authenticatedNodeStatus = null;

  leaseState = {
    status: 'UNCONFIGURED',
  };
}

export function verifyNodeLeaseRuntime(
  nowMs: number = Date.now()
): NodeLeaseRuntimeState {
  authenticatedNodeStatus = null;

  const fail = (
    status: NodeLeaseRuntimeStatus,
    reason: string
  ): NodeLeaseRuntimeState => {
    leaseState = { status, reason };
    return leaseState;
  };

  try {
    if (!nodeIdentity) {
      return fail(
        'UNCONFIGURED',
        'Node lease runtime identity has not been configured.'
      );
    }

    const persisted = getPersistedDataPlaneNodeLease();

    if (!persisted) {
      return fail(
        'UNENROLLED',
        'No persisted signed node lease was found.'
      );
    }

    const publicKeyPath =
      process.env.CONTROL_PLANE_SIGNING_PUBLIC_KEY_PATH?.trim();

    const expectedKeyId =
      process.env.CONTROL_PLANE_SIGNING_KEY_ID?.trim();

    if (!publicKeyPath || !expectedKeyId) {
      return fail(
        'LEASE_INVALID',
        'Trusted Control Plane signing configuration is incomplete.'
      );
    }

    const resolvedPublicKeyPath = path.resolve(
      process.cwd(),
      publicKeyPath
    );

    const controlPlanePublicKeyPem = fs.readFileSync(
      resolvedPublicKeyPath,
      'utf8'
    );

    const verifiedLease = verifyNodeLease(
      persisted.signedLease,
      controlPlanePublicKeyPem,
      nodeIdentity,
      persisted.tenantId,
      nowMs,
      expectedKeyId
    );

    const payload = verifiedLease.payload;
    const issuedAtMs = Date.parse(payload.issuedAt);
    const expiresAtMs = Date.parse(payload.expiresAt);

    if (
      persisted.tenantId !== payload.tenantId ||
      persisted.nodeId !== payload.nodeId ||
      persisted.leaseId !== payload.leaseId ||
      persisted.keyId !== payload.keyId ||
      persisted.issuedAtMs !== issuedAtMs ||
      persisted.expiresAtMs !== expiresAtMs
    ) {
      return fail(
        'LEASE_INVALID',
        'Persisted lease metadata does not match its signed payload.'
      );
    }

    const clock = getDataPlaneNodeLeaseClockState();

    if (
      clock.lastObservedWallClockMs > 0 &&
      nowMs + CLOCK_ROLLBACK_TOLERANCE_MS <
        clock.lastObservedWallClockMs
    ) {
      return fail(
        'CLOCK_ROLLBACK',
        'System clock rollback exceeded the permitted tolerance.'
      );
    }

    if (clock.lastLeaseIssuedAtMs !== issuedAtMs) {
      return fail(
        'LEASE_INVALID',
        'Lease issuance checkpoint does not match the persisted lease.'
      );
    }

    const activation = getNodeActivation();

    if (
      activation.is_activated !== 1 ||
      !activation.tenant_id ||
      activation.tenant_id === 'unpaired'
    ) {
      return fail(
        'ACTIVATION_INVALID',
        'Data Plane activation is incomplete.'
      );
    }

    if (activation.tenant_id !== payload.tenantId) {
      return fail(
        'TENANT_MISMATCH',
        'Activated tenant does not match the signed node lease.'
      );
    }

    recordDataPlaneNodeLeaseClockObservation(nowMs);

    leaseState = {
      status: 'ONLINE',
      tenantId: payload.tenantId,
      nodeId: payload.nodeId,
      leaseId: payload.leaseId,
      expiresAt: payload.expiresAt,
    };

    return { ...leaseState };
  } catch {
    return fail(
      'LEASE_INVALID',
      'Persisted node lease verification failed.'
    );
  }
}

/**
 * Returns the underlying lease state without requiring a fresh
 * Control Plane status response. Used only by the status refresh path.
 */
export function getNodeLeaseValidityState(): NodeLeaseRuntimeState {
  if (
    leaseState.status === 'ONLINE' &&
    leaseState.expiresAt &&
    Date.parse(leaseState.expiresAt) <= Date.now()
  ) {
    leaseState = {
      status: 'LEASE_INVALID',
      reason: 'Persisted node lease has expired.',
    };

    authenticatedNodeStatus = null;
  }

  return { ...leaseState };
}

/**
 * Returns the current effective runtime state.
 * ONLINE requires both a valid signed lease and a fresh authenticated
 * ACTIVE response from the Control Plane.
 */
export function getNodeLeaseRuntimeStatus(): NodeLeaseRuntimeState {
  const currentLease = getNodeLeaseValidityState();

  if (currentLease.status !== 'ONLINE') {
    return currentLease;
  }

  if (!authenticatedNodeStatus) {
    return {
      ...currentLease,
      status: 'STATUS_REQUIRED',
      reason: 'A fresh authenticated Control Plane node status is required.',
    };
  }

  if (authenticatedNodeStatus.status === 'REVOKED') {
    return {
      ...currentLease,
      status: 'NODE_REVOKED',
      reason: 'The Control Plane has revoked this node.',
    };
  }

  const checkedAtMs = Date.parse(authenticatedNodeStatus.checkedAt);

  if (
    !Number.isFinite(checkedAtMs) ||
    Date.now() - checkedAtMs > MAX_NODE_STATUS_AGE_MS ||
    checkedAtMs > Date.now() + 60_000
  ) {
    authenticatedNodeStatus = null;

    return {
      ...currentLease,
      status: 'STATUS_STALE',
      reason: 'Authenticated Control Plane node status has expired.',
    };
  }

  return currentLease;
}

/**
 * Provides the verified node identity and lease binding to the
 * status refresh worker. Does not expose signing private keys.
 */
export function getNodeLeaseRuntimeContext(): NodeLeaseRuntimeContext {
  const state = getNodeLeaseValidityState();

  if (
    state.status !== 'ONLINE' ||
    !nodeIdentity ||
    !state.tenantId ||
    !state.leaseId
  ) {
    throw new Error(
      `DATA_PLANE_LEASE_REQUIRED: ${state.status}`
    );
  }

  return {
    identity: nodeIdentity,
    tenantId: state.tenantId,
    leaseId: state.leaseId,
  };
}

/**
 * Loads the existing pinned Control Plane public key configuration.
 * The private signing key is never read or exposed here.
 */
export function getTrustedControlPlaneSigningConfig():
  TrustedControlPlaneSigningConfig {
  const publicKeyPath =
    process.env.CONTROL_PLANE_SIGNING_PUBLIC_KEY_PATH?.trim();

  const keyId =
    process.env.CONTROL_PLANE_SIGNING_KEY_ID?.trim();

  if (!publicKeyPath || !keyId) {
    throw new Error(
      'Trusted Control Plane signing configuration is incomplete.'
    );
  }

  const resolvedPublicKeyPath = path.resolve(
    process.cwd(),
    publicKeyPath
  );

  const publicKeyPem = fs.readFileSync(
    resolvedPublicKeyPath,
    'utf8'
  );

  if (!publicKeyPem.trim()) {
    throw new Error('Trusted Control Plane public key is empty.');
  }

  return {
    publicKeyPem,
    keyId,
  };
}

/**
 * Accepts only an already cryptographically authenticated status
 * response that matches the currently verified lease context.
 */
export function applyAuthenticatedNodeStatus(
  payload: NodeStatusResponsePayload,
  nowMs: number = Date.now()
): void {
  const context = getNodeLeaseRuntimeContext();

  if (
    payload.nodeId !== context.identity.nodeId ||
    payload.tenantId !== context.tenantId ||
    payload.leaseId !== context.leaseId
  ) {
    throw new Error(
      'Authenticated node status does not match the active lease.'
    );
  }

  const checkedAtMs = Date.parse(payload.checkedAt);

  if (
    !Number.isFinite(checkedAtMs) ||
    checkedAtMs > nowMs + 60_000 ||
    nowMs - checkedAtMs > MAX_NODE_STATUS_AGE_MS
  ) {
    throw new Error(
      'Authenticated node status is stale or not yet valid.'
    );
  }

  authenticatedNodeStatus = payload;
}

/**
 * Lease-only assertion. The background worker uses this to refresh
 * an expired or missing status without locking itself out.
 */
export function assertNodeLeaseValid(): void {
  const state = getNodeLeaseValidityState();

  if (state.status !== 'ONLINE') {
    throw new Error(
      `DATA_PLANE_LEASE_REQUIRED: ${state.status}`
    );
  }
}

/**
 * Protected operations require a valid lease and a fresh ACTIVE
 * Control Plane status. Missing, stale or revoked status fails closed.
 */
export function assertNodeLeaseActive(): void {
  const state = getNodeLeaseRuntimeStatus();

  if (state.status !== 'ONLINE') {
    throw new Error(
      `DATA_PLANE_LEASE_REQUIRED: ${state.status}`
    );
  }
}
