import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  canonicalizePolicyPayload,
  type NodeStatusResponsePayload,
} from "@aindigo/shared";

import type { NodeIdentity } from "./node-identity.js";

import {
  createSignedNodeStatusRequest,
  verifySignedNodeStatusResponse,
  requestNodeStatus,
} from "./node-status-client.js";

const TENANT_ID = "tenant_int005_test";
const LEASE_ID = "a6fc6275-b651-4917-9e1f-bf4d5872c0ff";
const KEY_ID = "aindigo-cp-ed25519-test";

function createIdentity(): NodeIdentity {
  const keys = crypto.generateKeyPairSync("ed25519");

  const publicKeyPem = keys.publicKey.export({
    type: "spki",
    format: "pem",
  }).toString();

  const privateKeyPem = keys.privateKey.export({
    type: "pkcs8",
    format: "pem",
  }).toString();

  const publicKeyFingerprint = crypto
    .createHash("sha256")
    .update(publicKeyPem.trim())
    .digest("hex")
    .slice(0, 16);

  return {
    nodeId: `node_${publicKeyFingerprint}`,
    publicKeyPem,
    privateKeyPem,
    publicKeyFingerprint,
  };
}

function createSignedResponse(
  identity: NodeIdentity,
  overrides: Partial<NodeStatusResponsePayload> = {},
  signingKey = crypto.generateKeyPairSync("ed25519"),
) {
  const payload: NodeStatusResponsePayload = {
    schemaVersion: "1.0",
    nodeId: identity.nodeId,
    tenantId: TENANT_ID,
    leaseId: LEASE_ID,
    requestNonce: crypto.randomBytes(32).toString("hex"),
    status: "ACTIVE",
    checkedAt: new Date().toISOString(),
    keyId: KEY_ID,
    ...overrides,
  };

  const signature = crypto.sign(
    null,
    Buffer.from(canonicalizePolicyPayload(payload), "utf8"),
    signingKey.privateKey,
  ).toString("base64");

  return {
    response: { payload, signature },
    publicKeyPem: signingKey.publicKey.export({
      type: "spki",
      format: "pem",
    }).toString(),
  };
}

function verificationOptions(
  identity: NodeIdentity,
  publicKeyPem: string,
  requestNonce: string,
) {
  return {
    controlPlanePublicKeyPem: publicKeyPem,
    expectedSigningKeyId: KEY_ID,
    identity,
    tenantId: TENANT_ID,
    leaseId: LEASE_ID,
    requestNonce,
  };
}

test("creates a valid signed node-status request", () => {
  const identity = createIdentity();
  const nowMs = Date.now();
  const nonce = crypto.randomBytes(32).toString("hex");

  const request = createSignedNodeStatusRequest({
    identity,
    tenantId: TENANT_ID,
    leaseId: LEASE_ID,
    nowMs,
    nonce,
  });

  assert.equal(request.payload.nodeId, identity.nodeId);
  assert.equal(request.payload.tenantId, TENANT_ID);
  assert.equal(request.payload.leaseId, LEASE_ID);
  assert.equal(request.payload.nonce, nonce);
  assert.equal(request.payload.nodePublicKeyFingerprint, identity.publicKeyFingerprint);
  assert.equal(request.signature.length, 88);

  const valid = crypto.verify(
    null,
    Buffer.from(canonicalizePolicyPayload(request.payload), "utf8"),
    crypto.createPublicKey(identity.publicKeyPem),
    Buffer.from(request.signature, "base64"),
  );

  assert.equal(valid, true);
});

test("accepts a correctly signed ACTIVE response", () => {
  const identity = createIdentity();
  const requestNonce = crypto.randomBytes(32).toString("hex");
  const signed = createSignedResponse(identity, { requestNonce });

  const result = verifySignedNodeStatusResponse(
    signed.response,
    verificationOptions(identity, signed.publicKeyPem, requestNonce),
  );

  assert.equal(result.status, "ACTIVE");
  assert.equal(result.nodeId, identity.nodeId);
  assert.equal(result.tenantId, TENANT_ID);
  assert.equal(result.leaseId, LEASE_ID);
});

test("accepts a correctly signed REVOKED response for caller enforcement", () => {
  const identity = createIdentity();
  const requestNonce = crypto.randomBytes(32).toString("hex");
  const signed = createSignedResponse(identity, {
    requestNonce,
    status: "REVOKED",
  });

  const result = verifySignedNodeStatusResponse(
    signed.response,
    verificationOptions(identity, signed.publicKeyPem, requestNonce),
  );

  assert.equal(result.status, "REVOKED");
});

test("rejects a response whose payload was tampered with", () => {
  const identity = createIdentity();
  const requestNonce = crypto.randomBytes(32).toString("hex");
  const signed = createSignedResponse(identity, { requestNonce });

  const tampered = {
    ...signed.response,
    payload: {
      ...signed.response.payload,
      status: "REVOKED",
    },
  };

  assert.throws(
    () => verifySignedNodeStatusResponse(
      tampered,
      verificationOptions(identity, signed.publicKeyPem, requestNonce),
    ),
    /signature verification failed/,
  );
});

test("rejects a response signed by an untrusted Control Plane key", () => {
  const identity = createIdentity();
  const requestNonce = crypto.randomBytes(32).toString("hex");
  const signed = createSignedResponse(identity, { requestNonce });
  const wrongKeys = crypto.generateKeyPairSync("ed25519");

  const wrongPublicKeyPem = wrongKeys.publicKey.export({
    type: "spki",
    format: "pem",
  }).toString();

  assert.throws(
    () => verifySignedNodeStatusResponse(
      signed.response,
      verificationOptions(identity, wrongPublicKeyPem, requestNonce),
    ),
    /signature verification failed/,
  );
});

test("rejects mismatched node, tenant, lease and request nonce bindings", () => {
  const identity = createIdentity();
  const requestNonce = crypto.randomBytes(32).toString("hex");

  const cases: Array<{
    name: string;
    overrides: Partial<NodeStatusResponsePayload>;
  }> = [
    {
      name: "node",
      overrides: { nodeId: `node_${"f".repeat(16)}` },
    },
    {
      name: "tenant",
      overrides: { tenantId: "tenant_other" },
    },
    {
      name: "lease",
      overrides: { leaseId: crypto.randomUUID() },
    },
    {
      name: "nonce",
      overrides: { requestNonce: crypto.randomBytes(32).toString("hex") },
    },
  ];

  for (const item of cases) {
    const signer = crypto.generateKeyPairSync("ed25519");

    const signed = createSignedResponse(
      identity,
      {
        requestNonce,
        ...item.overrides,
      },
      signer,
    );

    assert.throws(
      () => verifySignedNodeStatusResponse(
        signed.response,
        verificationOptions(identity, signed.publicKeyPem, requestNonce),
      ),
      /identity binding mismatch/,
      `Expected mismatched ${item.name} to be rejected`,
    );
  }
});
test("rejects a stale Control Plane status response", () => {
  const identity = createIdentity();
  const requestNonce = crypto.randomBytes(32).toString("hex");
  const nowMs = Date.now();
  const signed = createSignedResponse(identity, {
    requestNonce,
    checkedAt: new Date(nowMs - 120_000).toISOString(),
  });

  assert.throws(
    () => verifySignedNodeStatusResponse(
      signed.response,
      {
        ...verificationOptions(identity, signed.publicKeyPem, requestNonce),
        nowMs,
      },
    ),
    /stale or not yet valid/,
  );
});

test("rejects a response timestamp too far in the future", () => {
  const identity = createIdentity();
  const requestNonce = crypto.randomBytes(32).toString("hex");
  const nowMs = Date.now();
  const signed = createSignedResponse(identity, {
    requestNonce,
    checkedAt: new Date(nowMs + 120_000).toISOString(),
  });

  assert.throws(
    () => verifySignedNodeStatusResponse(
      signed.response,
      {
        ...verificationOptions(identity, signed.publicKeyPem, requestNonce),
        nowMs,
      },
    ),
    /stale or not yet valid/,
  );
});

test("rejects an unexpected Control Plane signing key ID", () => {
  const identity = createIdentity();
  const requestNonce = crypto.randomBytes(32).toString("hex");
  const signed = createSignedResponse(identity, {
    requestNonce,
    keyId: "unexpected-key",
  });

  assert.throws(
    () => verifySignedNodeStatusResponse(
      signed.response,
      verificationOptions(identity, signed.publicKeyPem, requestNonce),
    ),
    /Unexpected Control Plane signing key ID/,
  );
});

test("rejects malformed signed status responses", () => {
  const identity = createIdentity();
  const requestNonce = crypto.randomBytes(32).toString("hex");
  const signed = createSignedResponse(identity, { requestNonce });

  assert.throws(
    () => verifySignedNodeStatusResponse(
      { payload: signed.response.payload, signature: "invalid" },
      verificationOptions(identity, signed.publicKeyPem, requestNonce),
    ),
    /invalid signed status response/,
  );
});

test("sends a signed status request and verifies the HTTP response", async () => {
  const identity = createIdentity();
  const signingKeys = crypto.generateKeyPairSync("ed25519");

  const controlPlanePublicKeyPem = signingKeys.publicKey.export({
    type: "spki",
    format: "pem",
  }).toString();

  let fetchCalls = 0;

  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    fetchCalls++;

    assert.equal(String(input), "http://127.0.0.1:3000/api/v1/nodes/status");
    assert.equal(init?.method, "POST");

    const request = JSON.parse(String(init?.body));
    assert.equal(request.payload.nodeId, identity.nodeId);
    assert.equal(request.payload.tenantId, TENANT_ID);
    assert.equal(request.payload.leaseId, LEASE_ID);

    const payload: NodeStatusResponsePayload = {
      schemaVersion: "1.0",
      nodeId: identity.nodeId,
      tenantId: TENANT_ID,
      leaseId: LEASE_ID,
      requestNonce: request.payload.nonce,
      status: "ACTIVE",
      checkedAt: new Date().toISOString(),
      keyId: KEY_ID,
    };

    const signature = crypto.sign(
      null,
      Buffer.from(canonicalizePolicyPayload(payload), "utf8"),
      signingKeys.privateKey,
    ).toString("base64");

    return new Response(
      JSON.stringify({ payload, signature }),
      {
        status: 200,
        headers: { "Content-Type": "application/json" },
      },
    );
  }) as typeof fetch;

  const result = await requestNodeStatus({
    controlPlaneUrl: "http://127.0.0.1:3000",
    controlPlanePublicKeyPem,
    expectedSigningKeyId: KEY_ID,
    identity,
    tenantId: TENANT_ID,
    leaseId: LEASE_ID,
    fetchImpl,
  });

  assert.equal(fetchCalls, 1);
  assert.equal(result.status, "ACTIVE");
  assert.equal(result.nodeId, identity.nodeId);
});
