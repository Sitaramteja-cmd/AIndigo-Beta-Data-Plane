import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  canonicalizePolicyPayload,
  type NodeStatusRequestPayload,
} from "@aindigo/shared";

import {
  signNodeStatusResponse,
  verifyNodeStatusRequest,
} from "./node-status.js";

import type {
  RegisteredNodeRecord,
} from "../enrollment/node-enrollment-store.js";

import type {
  ControlPlaneSigningKey,
} from "./control-plane-signing-key.js";

function generateEd25519Pair() {
  return crypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
}

function fingerprint(publicKeyPem: string): string {
  return crypto.createHash("sha256")
    .update(publicKeyPem.trim(), "utf8")
    .digest("hex")
    .slice(0, 16);
}

function createNode(
  publicKeyPem: string,
  status: "ACTIVE" | "REVOKED" = "ACTIVE",
): RegisteredNodeRecord {
  const fp = fingerprint(publicKeyPem);

  return {
    node_id: `node_${fp}`,
    tenant_id: "tenant_status_test",
    public_key_pem: publicKeyPem,
    public_key_fingerprint: fp,
    label: "Status test node",
    status,
    enrolled_at: 1_800_000_000_000,
    last_seen_at: null,
    lease_id: "d9f8c3d4-8d8a-4a3e-9c1a-7c3e7d5a1b22",
    lease_expires_at: 1_900_000_000_000,
    revoked_at: status === "REVOKED" ? 1_800_000_001_000 : null,
  };
}

function createRequest(
  node: RegisteredNodeRecord,
  privateKeyPem: string,
  nowMs: number,
  overrides: Partial<NodeStatusRequestPayload> = {},
) {
  const payload: NodeStatusRequestPayload = {
    schemaVersion: "1.0",
    nodeId: node.node_id,
    tenantId: node.tenant_id,
    leaseId: node.lease_id!,
    nodePublicKeyFingerprint: node.public_key_fingerprint,
    timestamp: new Date(nowMs).toISOString(),
    nonce: crypto.randomBytes(32).toString("hex"),
    ...overrides,
  };

  const signature = crypto.sign(
    null,
    Buffer.from(canonicalizePolicyPayload(payload), "utf8"),
    crypto.createPrivateKey(privateKeyPem),
  ).toString("base64");

  return { payload, signature };
}

function createSigningKey(): ControlPlaneSigningKey {
  const pair = generateEd25519Pair();

  return {
    keyId: "cp-test-key-v1",
    privateKeyPem: pair.privateKey,
    publicKeyPem: pair.publicKey,
  };
}

test("accepts a valid signed status request", () => {
  const pair = generateEd25519Pair();
  const now = 1_800_000_000_000;
  const node = createNode(pair.publicKey);
  const request = createRequest(node, pair.privateKey, now);

  assert.ok(verifyNodeStatusRequest(request, node, now));
});

test("rejects a status request signed by another node key", () => {
  const registeredPair = generateEd25519Pair();
  const otherPair = generateEd25519Pair();
  const now = 1_800_000_000_000;
  const node = createNode(registeredPair.publicKey);
  const request = createRequest(node, otherPair.privateKey, now);

  assert.equal(verifyNodeStatusRequest(request, node, now), null);
});

test("rejects a status request with a mismatched tenant", () => {
  const pair = generateEd25519Pair();
  const now = 1_800_000_000_000;
  const node = createNode(pair.publicKey);
  const request = createRequest(node, pair.privateKey, now, {
    tenantId: "another_tenant",
  });

  assert.equal(verifyNodeStatusRequest(request, node, now), null);
});

test("rejects a status request with a mismatched lease", () => {
  const pair = generateEd25519Pair();
  const now = 1_800_000_000_000;
  const node = createNode(pair.publicKey);
  const request = createRequest(node, pair.privateKey, now, {
    leaseId: crypto.randomUUID(),
  });

  assert.equal(verifyNodeStatusRequest(request, node, now), null);
});

test("rejects a stale status request timestamp", () => {
  const pair = generateEd25519Pair();
  const now = 1_800_000_000_000;
  const node = createNode(pair.publicKey);
  const request = createRequest(node, pair.privateKey, now - 60_001);

  assert.equal(verifyNodeStatusRequest(request, node, now), null);
});

test("rejects a tampered status request signature", () => {
  const pair = generateEd25519Pair();
  const now = 1_800_000_000_000;
  const node = createNode(pair.publicKey);
  const request = createRequest(node, pair.privateKey, now);

  const tampered = {
    ...request,
    payload: {
      ...request.payload,
      tenantId: "tampered_tenant",
    },
  };

  assert.equal(verifyNodeStatusRequest(tampered, node, now), null);
});

test("authenticates a revoked node so it can receive a signed revocation status", () => {
  const pair = generateEd25519Pair();
  const now = 1_800_000_000_000;
  const node = createNode(pair.publicKey, "REVOKED");
  const request = createRequest(node, pair.privateKey, now);

  assert.ok(verifyNodeStatusRequest(request, node, now));
});

test("signs a valid ACTIVE or REVOKED response with the Control Plane key", () => {
  const signingKey = createSigningKey();

  for (const status of ["ACTIVE", "REVOKED"] as const) {
    const payload = {
      schemaVersion: "1.0" as const,
      nodeId: "node_0123456789abcdef",
      tenantId: "tenant_status_test",
      leaseId: "d9f8c3d4-8d8a-4a3e-9c1a-7c3e7d5a1b22",
      requestNonce: crypto.randomBytes(32).toString("hex"),
      status,
      checkedAt: new Date(1_800_000_000_000).toISOString(),
      keyId: signingKey.keyId,
    };

    const signed = signNodeStatusResponse(payload, signingKey);
    const signatureValid = crypto.verify(
      null,
      Buffer.from(canonicalizePolicyPayload(signed.payload), "utf8"),
      crypto.createPublicKey(signingKey.publicKeyPem),
      Buffer.from(signed.signature, "base64"),
    );

    assert.equal(signed.payload.status, status);
    assert.equal(signatureValid, true);
  }
});

test("rejects a response signed with a mismatched Control Plane keypair", () => {
  const signingKey = createSigningKey();
  const otherPair = generateEd25519Pair();

  const mismatchedKey: ControlPlaneSigningKey = {
    ...signingKey,
    privateKeyPem: otherPair.privateKey,
  };

  assert.throws(
    () => signNodeStatusResponse({
      schemaVersion: "1.0",
      nodeId: "node_0123456789abcdef",
      tenantId: "tenant_status_test",
      leaseId: "d9f8c3d4-8d8a-4a3e-9c1a-7c3e7d5a1b22",
      requestNonce: crypto.randomBytes(32).toString("hex"),
      status: "ACTIVE",
      checkedAt: new Date(1_800_000_000_000).toISOString(),
      keyId: signingKey.keyId,
    }, mismatchedKey),
    /keypair mismatch/,
  );
});
