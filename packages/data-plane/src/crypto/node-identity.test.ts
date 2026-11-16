import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  getOrCreateNodeIdentity,
  signReceiptEd25519,
  verifyReceiptEd25519,
  type UnsignedReceiptPayload,
} from "./node-identity.js";

function temporaryDirectory(): string {
  return fs.mkdtempSync(
    path.join(os.tmpdir(), "aindigo-node-identity-")
  );
}

function samplePayload(nodeId: string): UnsignedReceiptPayload {
  return {
    receipt_id: "receipt-test-001",
    timestamp: new Date().toISOString(),
    node_id: nodeId,
    department: "security",
    model_requested: "gemini-2.5-flash",
    model_routed: "gemini-2.5-flash",
    prompt_tokens: 100,
    completion_tokens: 50,
    cost_usd: 0.001,
    dlp_categories: ["API_KEY", "EMAIL"],
    cache_hit: false,
    prev_hash: "GENESIS",
    schema_version: "2.0.0",
  };
}

test("generates a new Ed25519 identity on first boot", () => {
  const directory = temporaryDirectory();

  try {
    const identity = getOrCreateNodeIdentity(directory);

    assert.match(identity.nodeId, /^node_[a-f0-9]{16}$/);
    assert.equal(identity.publicKeyFingerprint.length, 16);

    assert.equal(
      fs.existsSync(path.join(directory, "node_ed25519_private.pem")),
      true
    );

    assert.equal(
      fs.existsSync(path.join(directory, "node_ed25519_public.pem")),
      true
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("loads an existing identity without changing its key files", () => {
  const directory = temporaryDirectory();

  try {
    const first = getOrCreateNodeIdentity(directory);

    const privatePath = path.join(directory, "node_ed25519_private.pem");
    const publicPath = path.join(directory, "node_ed25519_public.pem");

    const privateHash = crypto.createHash("sha256")
      .update(fs.readFileSync(privatePath))
      .digest("hex");

    const publicHash = crypto.createHash("sha256")
      .update(fs.readFileSync(publicPath))
      .digest("hex");

    const second = getOrCreateNodeIdentity(directory);

    assert.equal(second.nodeId, first.nodeId);
    assert.equal(second.publicKeyFingerprint, first.publicKeyFingerprint);

    assert.equal(
      crypto.createHash("sha256").update(fs.readFileSync(privatePath)).digest("hex"),
      privateHash
    );

    assert.equal(
      crypto.createHash("sha256").update(fs.readFileSync(publicPath)).digest("hex"),
      publicHash
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("loads an existing identity without attempting directory creation", () => {
  const directory = temporaryDirectory();

  try {
    const first = getOrCreateNodeIdentity(directory);
    const originalMkdirDescriptor = Object.getOwnPropertyDescriptor(
      fs,
      "mkdirSync"
    );

    assert.ok(originalMkdirDescriptor);

    try {
      Object.defineProperty(fs, "mkdirSync", {
        ...originalMkdirDescriptor,
        value: () => {
          throw new Error("Read-only identity directory");
        },
      });

      const loaded = getOrCreateNodeIdentity(directory);

      assert.equal(loaded.nodeId, first.nodeId);
      assert.equal(
        loaded.publicKeyFingerprint,
        first.publicKeyFingerprint
      );
    } finally {
      Object.defineProperty(
        fs,
        "mkdirSync",
        originalMkdirDescriptor
      );
    }
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
test("fails closed when only the private key exists", () => {
  const directory = temporaryDirectory();

  try {
    fs.writeFileSync(
      path.join(directory, "node_ed25519_private.pem"),
      "existing-private-key"
    );

    assert.throws(
      () => getOrCreateNodeIdentity(directory),
      /Incomplete node identity/
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("fails closed when only the public key exists", () => {
  const directory = temporaryDirectory();

  try {
    fs.writeFileSync(
      path.join(directory, "node_ed25519_public.pem"),
      "existing-public-key"
    );

    assert.throws(
      () => getOrCreateNodeIdentity(directory),
      /Incomplete node identity/
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects a mismatched Ed25519 keypair", () => {
  const directory = temporaryDirectory();

  try {
    const first = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    const second = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    fs.writeFileSync(
      path.join(directory, "node_ed25519_private.pem"),
      first.privateKey
    );

    fs.writeFileSync(
      path.join(directory, "node_ed25519_public.pem"),
      second.publicKey
    );

    assert.throws(
      () => getOrCreateNodeIdentity(directory),
      /do not match/
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects non-Ed25519 identity keys", () => {
  const directory = temporaryDirectory();

  try {
    const rsa = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    fs.writeFileSync(
      path.join(directory, "node_ed25519_private.pem"),
      rsa.privateKey
    );

    fs.writeFileSync(
      path.join(directory, "node_ed25519_public.pem"),
      rsa.publicKey
    );

    assert.throws(
      () => getOrCreateNodeIdentity(directory),
      /must be Ed25519/
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("signs and verifies a valid receipt", () => {
  const directory = temporaryDirectory();

  try {
    const identity = getOrCreateNodeIdentity(directory);
    const receipt = signReceiptEd25519(
      samplePayload(identity.nodeId),
      identity
    );

    assert.equal(
      verifyReceiptEd25519(receipt, identity.publicKeyPem).valid,
      true
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects a receipt signed with an incorrect node identity", () => {
  const directory = temporaryDirectory();

  try {
    const identity = getOrCreateNodeIdentity(directory);

    assert.throws(
      () => signReceiptEd25519(
        samplePayload("node_invalid"),
        identity
      ),
      /does not match/
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects a receipt with a modified cost", () => {
  const directory = temporaryDirectory();

  try {
    const identity = getOrCreateNodeIdentity(directory);

    const receipt = signReceiptEd25519(
      samplePayload(identity.nodeId),
      identity
    );

    const tampered = {
      ...receipt,
      cost_usd: 999,
    };

    assert.equal(
      verifyReceiptEd25519(tampered, identity.publicKeyPem).valid,
      false
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects a receipt with an incorrect fingerprint", () => {
  const directory = temporaryDirectory();

  try {
    const identity = getOrCreateNodeIdentity(directory);

    const receipt = signReceiptEd25519(
      samplePayload(identity.nodeId),
      identity
    );

    const tampered = {
      ...receipt,
      node_pubkey_fingerprint: "0000000000000000",
    };

    assert.equal(
      verifyReceiptEd25519(tampered, identity.publicKeyPem).valid,
      false
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects verification using a different trusted public key", () => {
  const directory = temporaryDirectory();

  try {
    const identity = getOrCreateNodeIdentity(directory);

    const receipt = signReceiptEd25519(
      samplePayload(identity.nodeId),
      identity
    );

    const other = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    assert.equal(
      verifyReceiptEd25519(receipt, other.publicKey).valid,
      false
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects malformed signature encoding", () => {
  const directory = temporaryDirectory();

  try {
    const identity = getOrCreateNodeIdentity(directory);

    const receipt = signReceiptEd25519(
      samplePayload(identity.nodeId),
      identity
    );

    const tampered = {
      ...receipt,
      ed25519_signature: "invalid",
    };

    assert.equal(
      verifyReceiptEd25519(tampered, identity.publicKeyPem).valid,
      false
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});