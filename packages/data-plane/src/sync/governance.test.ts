import { strict as assert } from "node:assert";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { FleetGovernanceEngine } from "./fleet-governance.js";

async function runGovernanceTests() {
  console.log("================================================================");
  console.log(" ☁️ AIndigo Tier 4 — Hardened Enterprise Governance Test Suite");
  console.log("================================================================");

  const tmpDbPath = path.join(os.tmpdir(), `aindigo-hardened-gov-${Date.now()}.sqlite`);
  const kp = crypto.generateKeyPairSync("ed25519");
  const privateKeyPem = kp.privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  const publicKeyPem = kp.publicKey.export({ format: "pem", type: "spki" }).toString();

  try {
    const db = new DatabaseSync(tmpDbPath);

    // 1. Initialize engine first so tables are created
    const cpEngine = new FleetGovernanceEngine(db, { privateKeyPemOrHex: privateKeyPem, publicKeyPemOrHex: publicKeyPem, activeKeyId: "cp-key-v1" });

    // 2. Insert mock data after schema initialization
    db.exec(`
      CREATE TABLE IF NOT EXISTS virtual_keys (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        revoked_at INTEGER,
        expires_at INTEGER
      );
      INSERT INTO virtual_keys (id, org_id, revoked_at) VALUES ('vk_target_01', 'org_kla', NULL);
      INSERT INTO registered_edge_nodes (org_id, edge_node_id) VALUES ('org_kla', 'edge_node_01');
    `);

    // 3. Edge Node Isolation Test: Initialized with ONLY public key should throw when issuing revocation
    const edgeNodeEngine = new FleetGovernanceEngine(db, { publicKeyPemOrHex: publicKeyPem, activeKeyId: "cp-key-v1" });
    assert.throws(() => {
      edgeNodeEngine.issueGlobalRevocation("org_kla", "vk_target_01", "TEST");
    }, /GOVERNOR_SECURITY_ERROR/);
    console.log("✅ 1. Edge node private-key isolation enforced successfully.");

    // 4. Control Plane Engine Revocation
    const command = cpEngine.issueGlobalRevocation("org_kla", "vk_target_01", "KEY_ROTATION");
    assert.equal(command.keyId, "cp-key-v1");
    console.log("✅ 2. Control plane revocation issued with signing key ID verified.");

    // 5. Verify Revocation using Signing Key Registry Lookup
    const isValid = cpEngine.verifyRevocationCommand(command);
    assert.equal(isValid, true);
    console.log("✅ 3. Command signature verified against signing-key registry.");

    db.close();
  } finally {
    for (const suffix of ["", "-wal", "-shm"]) {
      const p = `${tmpDbPath}${suffix}`;
      if (fs.existsSync(p)) {
        try { fs.unlinkSync(p); } catch {}
      }
    }
  }

  console.log("================================================================");
  console.log(" 🎉 Tier 4 Module 4.3 Hardened Governance Tests PASSED");
  console.log("================================================================");
}

runGovernanceTests();