import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  canonicalizePolicyPayload,
  type NodeEnrollmentChallenge,
  type NodeLeasePayload,
  type SignedNodeLease,
} from "@aindigo/shared";

import {
  getOrCreateNodeIdentity,
  verifyNodeLease,
  type NodeIdentity,
} from "./node-identity.js";

import {
  enrollDataPlaneNode,
} from "./node-enrollment-client.js";

const ENROLLMENT_CODE = "A".repeat(48);
const KEY_ID = "cp-enrollment-test-key";
const TENANT_ID = "tenant_alpha";

function temporaryDirectory(): string {
  return fs.mkdtempSync(
    path.join(os.tmpdir(), "aindigo-enrollment-client-")
  );
}

function createSignedLease(
  identity: NodeIdentity,
  overrides: Partial<NodeLeasePayload> = {}
): {
  lease: SignedNodeLease;
  publicKeyPem: string;
} {
  const keys = crypto.generateKeyPairSync("ed25519");
  const now = Date.now();

  const payload: NodeLeasePayload = {
    schemaVersion: "1.0",
    leaseId: crypto.randomUUID(),
    keyId: KEY_ID,
    tenantId: TENANT_ID,
    nodeId: identity.nodeId,
    nodePublicKeyFingerprint: identity.publicKeyFingerprint,
    issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 86_400_000).toISOString(),
    offlineMaxSeconds: 172800,
    ...overrides,
  };

  const signature = crypto.sign(
    null,
    Buffer.from(canonicalizePolicyPayload(payload), "utf8"),
    keys.privateKey
  ).toString("base64");

  return {
    lease: {
      payload,
      signature,
    },
    publicKeyPem: keys.publicKey.export({
      type: "spki",
      format: "pem",
    }).toString(),
  };
}

function createChallenge(
  identity: NodeIdentity,
  clientNonce: string,
  overrides: Partial<NodeEnrollmentChallenge> = {}
): NodeEnrollmentChallenge {
  const now = Date.now();

  return {
    schemaVersion: "1.0",
    challengeId: crypto.randomUUID(),
    nodeId: identity.nodeId,
    nodePublicKeyFingerprint: identity.publicKeyFingerprint,
    clientNonce,
    serverNonce: crypto.randomBytes(32).toString("hex"),
    issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 60_000).toISOString(),
    ...overrides,
  };
}

function createTestContext() {
  const directory = temporaryDirectory();
  const identity = getOrCreateNodeIdentity(directory);
  const signedLease = createSignedLease(identity);

  let persistenceCalls = 0;

  const persistLease = (
    lease: SignedNodeLease,
    publicKeyPem: string,
    nodeIdentity: NodeIdentity,
    tenantId: string,
    nowMs: number,
    expectedKeyId: string
  ) => {
    persistenceCalls++;

    return verifyNodeLease(
      lease,
      publicKeyPem,
      nodeIdentity,
      tenantId,
      nowMs,
      expectedKeyId
    );
  };

  return {
    directory,
    identity,
    signedLease,
    persistLease,
    getPersistenceCalls: () => persistenceCalls,
  };
}

function cleanup(directory: string): void {
  fs.rmSync(directory, {
    recursive: true,
    force: true,
  });
}

function createSuccessfulFetch(
  identity: NodeIdentity,
  lease: SignedNodeLease,
  challengeOverrides: Partial<NodeEnrollmentChallenge> = {},
  responseOverrides: Record<string, unknown> = {}
): typeof fetch {
  let requestCount = 0;

  return (async (_input: RequestInfo | URL, init?: RequestInit) => {
    requestCount++;

    const body = JSON.parse(String(init?.body));

    if (requestCount === 1) {
      const challenge = createChallenge(
        identity,
        body.clientNonce,
        challengeOverrides
      );

      return new Response(JSON.stringify(challenge), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }

    assert.equal(body.nodeId, identity.nodeId);
    assert.equal(typeof body.signature, "string");
    assert.equal(body.signature.length, 88);

    const proofResponse = {
      nodeId: identity.nodeId,
      tenantId: TENANT_ID,
      publicKeyFingerprint: identity.publicKeyFingerprint,
      label: "Test Data Plane",
      enrolledAt: new Date().toISOString(),
      signedLease: lease,
      ...responseOverrides,
    };

    return new Response(JSON.stringify(proofResponse), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }) as typeof fetch;
}

test("completes enrollment and verifies the signed lease", async () => {
  const context = createTestContext();

  try {
    const fetchImpl = createSuccessfulFetch(
      context.identity,
      context.signedLease.lease
    );

    const result = await enrollDataPlaneNode({
      controlPlaneUrl: "http://127.0.0.1:3000",
      enrollmentCode: ENROLLMENT_CODE,
      controlPlanePublicKeyPem:
        context.signedLease.publicKeyPem,
      expectedSigningKeyId: KEY_ID,
      identity: context.identity,
      fetchImpl,
      persistLease: context.persistLease,
    });

    assert.equal(result.nodeId, context.identity.nodeId);
    assert.equal(result.tenantId, TENANT_ID);
    assert.equal(
      result.publicKeyFingerprint,
      context.identity.publicKeyFingerprint
    );
    assert.equal(result.leaseId, context.signedLease.lease.payload.leaseId);
    assert.equal(context.getPersistenceCalls(), 1);
  } finally {
    cleanup(context.directory);
  }
});

test("rejects an invalid enrollment code before network access", async () => {
  const context = createTestContext();

  try {
    let fetchCalls = 0;

    const fetchImpl = (async () => {
      fetchCalls++;
      return new Response("{}", { status: 200 });
    }) as typeof fetch;

    await assert.rejects(
      enrollDataPlaneNode({
        controlPlaneUrl: "http://127.0.0.1:3000",
        enrollmentCode: "invalid",
        controlPlanePublicKeyPem:
          context.signedLease.publicKeyPem,
        expectedSigningKeyId: KEY_ID,
        identity: context.identity,
        fetchImpl,
        persistLease: context.persistLease,
      }),
      /Invalid enrollment code/
    );

    assert.equal(fetchCalls, 0);
    assert.equal(context.getPersistenceCalls(), 0);
  } finally {
    cleanup(context.directory);
  }
});

test("rejects a challenge with a mismatched client nonce", async () => {
  const context = createTestContext();

  try {
    const fetchImpl = createSuccessfulFetch(
      context.identity,
      context.signedLease.lease,
      {
        clientNonce: crypto.randomBytes(32).toString("hex"),
      }
    );

    await assert.rejects(
      enrollDataPlaneNode({
        controlPlaneUrl: "http://127.0.0.1:3000",
        enrollmentCode: ENROLLMENT_CODE,
        controlPlanePublicKeyPem:
          context.signedLease.publicKeyPem,
        expectedSigningKeyId: KEY_ID,
        identity: context.identity,
        fetchImpl,
        persistLease: context.persistLease,
      }),
      /identity binding mismatch/
    );

    assert.equal(context.getPersistenceCalls(), 0);
  } finally {
    cleanup(context.directory);
  }
});

test("rejects an expired enrollment challenge", async () => {
  const context = createTestContext();

  try {
    const expired = new Date(Date.now() - 60_000).toISOString();

    const fetchImpl = createSuccessfulFetch(
      context.identity,
      context.signedLease.lease,
      {
        issuedAt: new Date(Date.now() - 120_000).toISOString(),
        expiresAt: expired,
      }
    );

    await assert.rejects(
      enrollDataPlaneNode({
        controlPlaneUrl: "http://127.0.0.1:3000",
        enrollmentCode: ENROLLMENT_CODE,
        controlPlanePublicKeyPem:
          context.signedLease.publicKeyPem,
        expectedSigningKeyId: KEY_ID,
        identity: context.identity,
        fetchImpl,
        persistLease: context.persistLease,
      }),
      /expired or not yet valid/
    );

    assert.equal(context.getPersistenceCalls(), 0);
  } finally {
    cleanup(context.directory);
  }
});

test("rejects a lease with a mismatched tenant", async () => {
  const context = createTestContext();

  try {
    const fetchImpl = createSuccessfulFetch(
      context.identity,
      context.signedLease.lease,
      {},
      {
        tenantId: "tenant_beta",
      }
    );

    await assert.rejects(
      enrollDataPlaneNode({
        controlPlaneUrl: "http://127.0.0.1:3000",
        enrollmentCode: ENROLLMENT_CODE,
        controlPlanePublicKeyPem:
          context.signedLease.publicKeyPem,
        expectedSigningKeyId: KEY_ID,
        identity: context.identity,
        fetchImpl,
        persistLease: context.persistLease,
      }),
      /Signed lease does not match/
    );

    assert.equal(context.getPersistenceCalls(), 0);
  } finally {
    cleanup(context.directory);
  }
});

test("rejects an invalid lease signature without persistence", async () => {
  const context = createTestContext();

  try {
    const tamperedLease: SignedNodeLease = {
      ...context.signedLease.lease,
      signature: Buffer.alloc(64).toString("base64"),
    };

    const fetchImpl = createSuccessfulFetch(
      context.identity,
      tamperedLease
    );

    await assert.rejects(
      enrollDataPlaneNode({
        controlPlaneUrl: "http://127.0.0.1:3000",
        enrollmentCode: ENROLLMENT_CODE,
        controlPlanePublicKeyPem:
          context.signedLease.publicKeyPem,
        expectedSigningKeyId: KEY_ID,
        identity: context.identity,
        fetchImpl,
        persistLease: context.persistLease,
      }),
      /signature verification failed/
    );

    assert.equal(context.getPersistenceCalls(), 0);
  } finally {
    cleanup(context.directory);
  }
});

test("rejects an unexpected Control Plane signing key ID", async () => {
  const context = createTestContext();

  try {
    const fetchImpl = createSuccessfulFetch(
      context.identity,
      context.signedLease.lease
    );

    await assert.rejects(
      enrollDataPlaneNode({
        controlPlaneUrl: "http://127.0.0.1:3000",
        enrollmentCode: ENROLLMENT_CODE,
        controlPlanePublicKeyPem:
          context.signedLease.publicKeyPem,
        expectedSigningKeyId: "unexpected-key",
        identity: context.identity,
        fetchImpl,
        persistLease: context.persistLease,
      }),
      /signing key ID/
    );

    assert.equal(context.getPersistenceCalls(), 0);
  } finally {
    cleanup(context.directory);
  }
});

test("rejects insecure remote HTTP Control Plane URLs", async () => {
  const context = createTestContext();

  try {
    await assert.rejects(
      enrollDataPlaneNode({
        controlPlaneUrl: "http://example.com",
        enrollmentCode: ENROLLMENT_CODE,
        controlPlanePublicKeyPem:
          context.signedLease.publicKeyPem,
        expectedSigningKeyId: KEY_ID,
        identity: context.identity,
        fetchImpl: (async () => new Response("{}")) as typeof fetch,
        persistLease: context.persistLease,
      }),
      /HTTPS is required/
    );

    assert.equal(context.getPersistenceCalls(), 0);
  } finally {
    cleanup(context.directory);
  }
});
