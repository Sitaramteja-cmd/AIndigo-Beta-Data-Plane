import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  getOrCreateNodeIdentity,
  signNodeEnrollmentChallenge,
  verifyNodeLease,
} from "./node-identity.js";

import {
  canonicalizePolicyPayload,
  type NodeEnrollmentChallenge,
  type NodeLeasePayload,
} from "@aindigo/shared";

function temporaryDirectory(): string {
  return fs.mkdtempSync(
    path.join(os.tmpdir(), "aindigo-enrollment-")
  );
}

function sampleChallenge(
  nodeId: string,
  fingerprint: string
): NodeEnrollmentChallenge {
  const issuedAt = new Date();
  const expiresAt = new Date(issuedAt.getTime() + 60_000);

  return {
    schemaVersion: "1.0",
    challengeId: crypto.randomUUID(),
    nodeId,
    nodePublicKeyFingerprint: fingerprint,
    clientNonce: crypto.randomBytes(32).toString("hex"),
    serverNonce: crypto.randomBytes(32).toString("hex"),
    issuedAt: issuedAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
  };
}

test("signs a valid enrollment challenge with the existing node identity", () => {
  const directory = temporaryDirectory();

  try {
    const identity = getOrCreateNodeIdentity(directory);
    const challenge = sampleChallenge(
      identity.nodeId,
      identity.publicKeyFingerprint
    );

    const signature = signNodeEnrollmentChallenge(
      challenge,
      identity
    );

    const signatureBytes = Buffer.from(signature, "base64");

    assert.equal(signatureBytes.length, 64);
    assert.equal(signatureBytes.toString("base64"), signature);

    const publicKey = crypto.createPublicKey(identity.publicKeyPem);

    assert.equal(
      crypto.verify(
        null,
        Buffer.from(
          canonicalizePolicyPayload(challenge),
          "utf8"
        ),
        publicKey,
        signatureBytes
      ),
      true
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects a challenge with a different node ID", () => {
  const directory = temporaryDirectory();

  try {
    const identity = getOrCreateNodeIdentity(directory);
    const challenge = sampleChallenge(
      "node_0000000000000000",
      identity.publicKeyFingerprint
    );

    assert.throws(
      () => signNodeEnrollmentChallenge(challenge, identity),
      /does not match/
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects a challenge with a different public-key fingerprint", () => {
  const directory = temporaryDirectory();

  try {
    const identity = getOrCreateNodeIdentity(directory);
    const challenge = sampleChallenge(
      identity.nodeId,
      "0000000000000000"
    );

    assert.throws(
      () => signNodeEnrollmentChallenge(challenge, identity),
      /does not match/
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects a malformed enrollment challenge", () => {
  const directory = temporaryDirectory();

  try {
    const identity = getOrCreateNodeIdentity(directory);
    const challenge = {
      ...sampleChallenge(
        identity.nodeId,
        identity.publicKeyFingerprint
      ),
      serverNonce: "invalid",
    };

    assert.throws(
      () => signNodeEnrollmentChallenge(
        challenge as NodeEnrollmentChallenge,
        identity
      ),
      /Invalid node enrollment challenge/
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects an identity whose metadata does not match its keypair", () => {
  const directory = temporaryDirectory();

  try {
    const identity = getOrCreateNodeIdentity(directory);
    const challenge = sampleChallenge(
      identity.nodeId,
      identity.publicKeyFingerprint
    );

    const tamperedIdentity = {
      ...identity,
      publicKeyFingerprint: "0000000000000000",
    };

    assert.throws(
      () => signNodeEnrollmentChallenge(
        challenge,
        tamperedIdentity
      ),
      /does not match/
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects a signature when the challenge is modified after signing", () => {
  const directory = temporaryDirectory();

  try {
    const identity = getOrCreateNodeIdentity(directory);
    const challenge = sampleChallenge(
      identity.nodeId,
      identity.publicKeyFingerprint
    );

    const signature = signNodeEnrollmentChallenge(
      challenge,
      identity
    );

    const tamperedChallenge = {
      ...challenge,
      serverNonce: crypto.randomBytes(32).toString("hex"),
    };

    const publicKey = crypto.createPublicKey(identity.publicKeyPem);

    assert.equal(
      crypto.verify(
        null,
        Buffer.from(
          canonicalizePolicyPayload(tamperedChallenge),
          "utf8"
        ),
        publicKey,
        Buffer.from(signature, "base64")
      ),
      false
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});


function createSignedLeaseScenario(
  identity: ReturnType<typeof getOrCreateNodeIdentity>,
  nowMs: number = Date.now(),
  overrides: Partial<NodeLeasePayload> = {}
) {
  const { publicKey, privateKey } =
    crypto.generateKeyPairSync("ed25519");

  const keyId = "cp-enrollment-test-key";

  const payload: NodeLeasePayload = {
    schemaVersion: "1.0",
    leaseId: crypto.randomUUID(),
    keyId,
    tenantId: "tenant_alpha",
    nodeId: identity.nodeId,
    nodePublicKeyFingerprint: identity.publicKeyFingerprint,
    issuedAt: new Date(nowMs).toISOString(),
    expiresAt: new Date(nowMs + 86_400_000).toISOString(),
    offlineMaxSeconds: 172800,
    ...overrides,
  };

  const signature = crypto.sign(
    null,
    Buffer.from(canonicalizePolicyPayload(payload), "utf8"),
    privateKey
  ).toString("base64");

  return {
    lease: {
      payload,
      signature,
    },
    controlPlanePublicKeyPem: publicKey.export({
      type: "spki",
      format: "pem",
    }).toString(),
    keyId,
  };
}

test("verifies a valid Control Plane-signed node lease", () => {
  const directory = temporaryDirectory();

  try {
    const identity = getOrCreateNodeIdentity(directory);
    const now = Date.now();

    const scenario = createSignedLeaseScenario(identity, now);

    const verified = verifyNodeLease(
      scenario.lease,
      scenario.controlPlanePublicKeyPem,
      identity,
      "tenant_alpha",
      now,
      scenario.keyId
    );

    assert.equal(verified.payload.nodeId, identity.nodeId);
    assert.equal(verified.payload.tenantId, "tenant_alpha");
    assert.equal(verified.payload.keyId, scenario.keyId);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects a lease belonging to another tenant", () => {
  const directory = temporaryDirectory();

  try {
    const identity = getOrCreateNodeIdentity(directory);
    const scenario = createSignedLeaseScenario(identity);

    assert.throws(
      () => verifyNodeLease(
        scenario.lease,
        scenario.controlPlanePublicKeyPem,
        identity,
        "tenant_beta",
        Date.now(),
        scenario.keyId
      ),
      /tenant binding mismatch/
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects a lease belonging to another node", () => {
  const directory = temporaryDirectory();

  try {
    const identity = getOrCreateNodeIdentity(directory);

    const scenario = createSignedLeaseScenario(identity, Date.now(), {
      nodeId: "node_0000000000000000",
    });

    assert.throws(
      () => verifyNodeLease(
        scenario.lease,
        scenario.controlPlanePublicKeyPem,
        identity,
        "tenant_alpha",
        Date.now(),
        scenario.keyId
      ),
      /does not match this Data Plane identity/
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects a lease with a mismatched node fingerprint", () => {
  const directory = temporaryDirectory();

  try {
    const identity = getOrCreateNodeIdentity(directory);

    const scenario = createSignedLeaseScenario(identity, Date.now(), {
      nodePublicKeyFingerprint: "0000000000000000",
    });

    assert.throws(
      () => verifyNodeLease(
        scenario.lease,
        scenario.controlPlanePublicKeyPem,
        identity,
        "tenant_alpha",
        Date.now(),
        scenario.keyId
      ),
      /does not match this Data Plane identity/
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects a lease whose payload was modified after signing", () => {
  const directory = temporaryDirectory();

  try {
    const identity = getOrCreateNodeIdentity(directory);
    const scenario = createSignedLeaseScenario(identity);

    const tamperedLease = {
      ...scenario.lease,
      payload: {
        ...scenario.lease.payload,
        tenantId: "tenant_modified",
      },
    };

    assert.throws(
      () => verifyNodeLease(
        tamperedLease,
        scenario.controlPlanePublicKeyPem,
        identity,
        "tenant_modified",
        Date.now(),
        scenario.keyId
      ),
      /signature verification failed/
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects a lease signed by an untrusted Control Plane key", () => {
  const directory = temporaryDirectory();

  try {
    const identity = getOrCreateNodeIdentity(directory);
    const scenario = createSignedLeaseScenario(identity);

    const wrongKeyPair = crypto.generateKeyPairSync("ed25519");

    const wrongPublicKeyPem = wrongKeyPair.publicKey.export({
      type: "spki",
      format: "pem",
    }).toString();

    assert.throws(
      () => verifyNodeLease(
        scenario.lease,
        wrongPublicKeyPem,
        identity,
        "tenant_alpha",
        Date.now(),
        scenario.keyId
      ),
      /signature verification failed/
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects a lease with an unexpected signing key ID", () => {
  const directory = temporaryDirectory();

  try {
    const identity = getOrCreateNodeIdentity(directory);
    const scenario = createSignedLeaseScenario(identity);

    assert.throws(
      () => verifyNodeLease(
        scenario.lease,
        scenario.controlPlanePublicKeyPem,
        identity,
        "tenant_alpha",
        Date.now(),
        "unexpected-key"
      ),
      /signing key ID mismatch/
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects an expired but correctly signed lease", () => {
  const directory = temporaryDirectory();

  try {
    const identity = getOrCreateNodeIdentity(directory);
    const now = Date.now();

    const scenario = createSignedLeaseScenario(identity, now - 120_000, {
      expiresAt: new Date(now - 1_000).toISOString(),
    });

    assert.throws(
      () => verifyNodeLease(
        scenario.lease,
        scenario.controlPlanePublicKeyPem,
        identity,
        "tenant_alpha",
        now,
        scenario.keyId
      ),
      /expired or not yet valid/
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects a lease issued too far in the future", () => {
  const directory = temporaryDirectory();

  try {
    const identity = getOrCreateNodeIdentity(directory);
    const now = Date.now();

    const scenario = createSignedLeaseScenario(identity, now + 120_000);

    assert.throws(
      () => verifyNodeLease(
        scenario.lease,
        scenario.controlPlanePublicKeyPem,
        identity,
        "tenant_alpha",
        now,
        scenario.keyId
      ),
      /expired or not yet valid/
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
