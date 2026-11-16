import test from "node:test";
import assert from "node:assert/strict";

import {
  NodeStatusRequestPayloadSchema,
  SignedNodeStatusRequestSchema,
  NodeStatusResponsePayloadSchema,
  SignedNodeStatusResponseSchema,
} from "../src/security/node-enrollment.ts";

const validRequest = {
  schemaVersion: "1.0",
  nodeId: "node_0123456789abcdef",
  tenantId: "tenant_alpha",
  leaseId: "a6fc6275-b651-4917-9e1f-bf4d5872c0ff",
  nodePublicKeyFingerprint: "0123456789abcdef",
  timestamp: "2026-11-15T09:00:00.000Z",
  nonce: "a".repeat(64),
};

const validResponse = {
  schemaVersion: "1.0",
  nodeId: "node_0123456789abcdef",
  tenantId: "tenant_alpha",
  leaseId: "a6fc6275-b651-4917-9e1f-bf4d5872c0ff",
  requestNonce: "a".repeat(64),
  status: "ACTIVE",
  checkedAt: "2026-11-15T09:00:01.000Z",
  keyId: "aindigo-cp-ed25519-v1",
};

const validSignature = Buffer.alloc(64).toString("base64");

test("accepts a valid node-status request payload", () => {
  assert.equal(NodeStatusRequestPayloadSchema.safeParse(validRequest).success, true);
});

test("rejects a node-status request with an invalid nonce", () => {
  assert.equal(
    NodeStatusRequestPayloadSchema.safeParse({
      ...validRequest,
      nonce: "invalid",
    }).success,
    false,
  );
});

test("rejects unexpected request fields", () => {
  assert.equal(
    NodeStatusRequestPayloadSchema.safeParse({
      ...validRequest,
      unexpected: true,
    }).success,
    false,
  );
});

test("accepts a valid signed node-status request envelope", () => {
  assert.equal(
    SignedNodeStatusRequestSchema.safeParse({
      payload: validRequest,
      signature: validSignature,
    }).success,
    true,
  );
});

test("rejects an invalid request signature encoding", () => {
  assert.equal(
    SignedNodeStatusRequestSchema.safeParse({
      payload: validRequest,
      signature: "invalid",
    }).success,
    false,
  );
});

test("accepts ACTIVE and REVOKED response payloads", () => {
  assert.equal(NodeStatusResponsePayloadSchema.safeParse(validResponse).success, true);

  assert.equal(
    NodeStatusResponsePayloadSchema.safeParse({
      ...validResponse,
      status: "REVOKED",
    }).success,
    true,
  );
});

test("rejects an unknown node status", () => {
  assert.equal(
    NodeStatusResponsePayloadSchema.safeParse({
      ...validResponse,
      status: "UNKNOWN",
    }).success,
    false,
  );
});

test("rejects unexpected response fields", () => {
  assert.equal(
    NodeStatusResponsePayloadSchema.safeParse({
      ...validResponse,
      admin: true,
    }).success,
    false,
  );
});

test("accepts a valid signed node-status response envelope", () => {
  assert.equal(
    SignedNodeStatusResponseSchema.safeParse({
      payload: validResponse,
      signature: validSignature,
    }).success,
    true,
  );
});

test("rejects a response with an invalid request nonce", () => {
  assert.equal(
    SignedNodeStatusResponseSchema.safeParse({
      payload: {
        ...validResponse,
        requestNonce: "invalid",
      },
      signature: validSignature,
    }).success,
    false,
  );
});
