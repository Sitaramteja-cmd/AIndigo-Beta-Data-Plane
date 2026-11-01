import fs from "node:fs";
import {
  getOrCreateNodeIdentity,
  signReceiptEd25519,
  verifyReceiptEd25519,
  SignedReceipt,
} from "../data-plane/src/crypto/node-identity";

export function verifyReceiptChain(
  receipts: SignedReceipt[],
  publicKeyPem: string
): { valid: boolean; checkedCount: number; error?: string } {
  let expectedPrevHash = "GENESIS_00000000000000000000000000000000000000000000000000000000";

  for (let i = 0; i < receipts.length; i++) {
    const r = receipts[i];
    if (r.prev_hash !== expectedPrevHash) {
      return {
        valid: false,
        checkedCount: i,
        error: `Chain gap/break at index ${i} (${r.receipt_id}): expected prev_hash=${expectedPrevHash}, found=${r.prev_hash}`,
      };
    }

    const singleCheck = verifyReceiptEd25519(r, publicKeyPem);
    if (!singleCheck.valid) {
      return {
        valid: false,
        checkedCount: i,
        error: singleCheck.reason,
      };
    }

    expectedPrevHash = r.receipt_hash;
  }

  return { valid: true, checkedCount: receipts.length };
}

function runSelfTest() {
  console.log("================================================================");
  console.log(" 🔐 AIndigo Tier 0 — Ed25519 Node Identity & Chain Self-Test");
  console.log("================================================================");

  const identity = getOrCreateNodeIdentity();
  console.log(`✅ 1. Node Identity Ready:`);
  console.log(`   • Node ID            : ${identity.nodeId}`);
  console.log(`   • PubKey Fingerprint : ${identity.publicKeyFingerprint}`);

  const chain: SignedReceipt[] = [];
  let prevHash = "GENESIS_00000000000000000000000000000000000000000000000000000000";

  for (let i = 1; i <= 3; i++) {
    const signed = signReceiptEd25519(
      {
        receipt_id: `rcpt_test_00${i}`,
        timestamp: new Date().toISOString(),
        node_id: identity.nodeId,
        department: "core_engineering",
        model_requested: "gemini-2.5-flash",
        model_routed: "gemini-2.5-flash",
        prompt_tokens: 120 * i,
        completion_tokens: 80 * i,
        cost_usd: 0.0004 * i,
        dlp_categories: i === 2 ? ["AWS_ACCESS_KEY", "GOVT_ID"] : [],
        cache_hit: false,
        prev_hash: prevHash,
        schema_version: "2.0.0",
      },
      identity
    );
    chain.push(signed);
    prevHash = signed.receipt_hash;
  }

  console.log(`✅ 2. Signed 3-Receipt Chain with Ed25519 Private Key.`);
  console.log(`   • Receipt #1 Hash : ${chain[0].receipt_hash.slice(0, 24)}...`);
  console.log(`   • Receipt #2 Sig  : ${chain[1].ed25519_signature.slice(0, 24)}...`);

  const validResult = verifyReceiptChain(chain, identity.publicKeyPem);
  if (!validResult.valid) {
    console.error(`❌ Unexpected verification failure: ${validResult.error}`);
    process.exit(1);
  }
  console.log(`✅ 3. Public-Key Offline Verification Passed (${validResult.checkedCount}/3 receipts verified).`);

  // Tamper test: alter cost_usd on Receipt #2 by $0.0001
  const tamperedChain = JSON.parse(JSON.stringify(chain)) as SignedReceipt[];
  tamperedChain[1].cost_usd = 99.9999;
  const tamperResult = verifyReceiptChain(tamperedChain, identity.publicKeyPem);

  if (!tamperResult.valid) {
    console.log(`✅ 4. Tamper Detection Passed! Caught modification immediately:`);
    console.log(`   • Reason: ${tamperResult.error}`);
  } else {
    console.error(`❌ Tamper detection failed! Modified receipt was accepted.`);
    process.exit(1);
  }

  console.log("================================================================");
  console.log(" 🎉 Tier 0 Module 0.2 Self-Test PASSED (Zero existing files touched)");
  console.log("================================================================");
}

const args = process.argv.slice(2);
if (args.includes("--selftest") || args.length === 0) {
  runSelfTest();
} else {
  const receiptsIdx = args.indexOf("--receipts");
  const pubkeyIdx = args.indexOf("--pubkey");
  if (receiptsIdx === -1 || pubkeyIdx === -1) {
    console.error("Usage: npx tsx packages/cli/verify.ts --receipts <file.json> --pubkey <node_ed25519_public.pem>");
    process.exit(1);
  }
  const receipts = JSON.parse(fs.readFileSync(args[receiptsIdx + 1], "utf8")) as SignedReceipt[];
  const pubKeyPem = fs.readFileSync(args[pubkeyIdx + 1], "utf8");
  const res = verifyReceiptChain(receipts, pubKeyPem);
  if (res.valid) {
    console.log(`✅ VERIFIED: All ${res.checkedCount} receipts in chain are authentic and untampered.`);
  } else {
    console.error(`❌ FAILED: ${res.error}`);
    process.exit(1);
  }
}
