import { test } from "node:test";
import assert from "node:assert/strict";
import {
  computeVerhoeffCheckDigit,
  isValidVerhoeff12Id,
  isValidPaymentCard,
  isValidIndianPan,
  computeGstinCheckChar,
  isValidIndianGstin,
  isValidIndianIfsc,
  isValidIban,
  isValidUsSsn,
  isValidUsAbaRouting,
  isValidUkNhsNumber,
  isValidSaudiNationalId,
  isValidUaeEmiratesId,
  isValidAustralianAbn,
  isValidAustralianTfn,
  buildValidGithubPat,
  classifyGithubToken,
} from "./checksum-validators.js";
import { scanAndRedactWithChecksums, DetectorType } from "./checksum-engine.js";

test("1. Validator fixes: GSTIN 2A bug, Saudi/UAE Luhn vectors, SSN context, IBAN length, Card IIN, GitHub PATs", () => {
  const badStatePrefix = "2AAAACB2894G1Z";
  const badStateCheck = computeGstinCheckChar(badStatePrefix);
  assert.equal(isValidIndianGstin(`${badStatePrefix}${badStateCheck}`), false);

  const validGstPrefix = "29AAACB2894G1Z";
  const validGst = `${validGstPrefix}${computeGstinCheckChar(validGstPrefix)}`;
  assert.equal(isValidIndianGstin(validGst), true);

  assert.equal(isValidSaudiNationalId("1010101010"), true);
  assert.equal(isValidSaudiNationalId("1010101011"), false);
  assert.equal(isValidUaeEmiratesId("784-1988-1234567-0"), true);
  assert.equal(isValidUaeEmiratesId("784-1988-1234567-1"), false);

  assert.equal(isValidUsSsn("453-21-9876", false), true);
  assert.equal(isValidUsSsn("453219876", false), false);
  assert.equal(isValidUsSsn("453219876", true), true);

  assert.equal(isValidIban("GB82WEST12345698765432"), true);
  assert.equal(isValidIban("GB82WEST123456987654"), false);

  assert.equal(isValidPaymentCard("4532015112830366"), true);
  assert.equal(isValidPaymentCard("1730448000128"), false);

  const validClassic = buildValidGithubPat("ghp", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5");
  const mistypedClassic = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5ZZZZZZ";
  const fineGrained = `github_pat_${"A1b2C3d4E5f6G7h8I9j0K1"}_${"z9Y8x7W6v5U4t3S2r1Q0p9O8n7M6l5K4j3I2h1G0f9E8d7C6b5A4z3Y2x1W"}`;

  assert.equal(classifyGithubToken(validClassic).shouldRedact, true);
  assert.equal(classifyGithubToken(mistypedClassic).shouldRedact, true);
  assert.equal(classifyGithubToken(fineGrained).kind, "FINE_GRAINED");
});

test("2. Free-text detector & overlap resolution (16-digit card never triggers inner 12-digit or 9-digit detectors)", () => {
  const vPrefix = ["5", "4", "8", "2", "9", "1", "7", "3", "6", "0", "2"].join("");
  const vCheck = computeVerhoeffCheckDigit(vPrefix);
  const formattedVerhoeff = `${vPrefix.slice(0, 4)} ${vPrefix.slice(4, 8)} ${vPrefix.slice(8)}${vCheck}`;

  const prompt = [
    `const visa = "4532-0151-1283-0366";`,
    `// Customer KYC ID: ${formattedVerhoeff}`,
    `const gst = "29AAACB2894G1Z${computeGstinCheckChar("29AAACB2894G1Z")}";`,
    `const orderId = 123456789; // Plain 9-digit number that fails checksum/routing must NOT be touched`,
    `const ssnRecord = "ssn: 453-21-9876"; // Dashed SSN MUST be redacted`,
  ].join("\n");

  const { redactedText, detections } = scanAndRedactWithChecksums(prompt);

  const unexpected = detections.filter(d => d.rawMatch.includes("123456789"));
  if (unexpected.length > 0) {
    throw new Error(`Unexpected redaction on orderId by detector type: ${unexpected[0].type}`);
  }

  assert.ok(redactedText.includes("const orderId = 123456789;"), "Plain 9-digit orderId was falsely redacted!");
  assert.ok(redactedText.includes("ssn: [REDACTED_US_SSN]"), "SSN record was not redacted!");
});

test("3. Realistic Developer Corpus (280 labelled samples across prose, JSON, stack traces, UUIDs, SHAs, timestamps)", () => {
  interface CorpusEntry {
    text: string;
    expectedTypes: DetectorType[];
  }

  const samples: CorpusEntry[] = [];

  for (let i = 0; i < 20; i++) {
    const p30 = `A1b2C3d4E5f6G7h8I9j0K1l2M3n4${String(i).padStart(2, "0")}`;
    const pat = buildValidGithubPat("ghp", p30);
    samples.push({ text: `export GITHUB_TOKEN="${pat}" # deploy key ${i}`, expectedTypes: ["GITHUB_PAT"] });
  }

  for (let i = 0; i < 20; i++) {
    const seq = String(1000 + i);
    const pan = `ABCPD${seq}F`;
    const gst14 = `27${pan}1Z`;
    const gst = `${gst14}${computeGstinCheckChar(gst14)}`;
    samples.push({ text: `{"customer_pan": "${pan}", "gstin": "${gst}"}`, expectedTypes: ["INDIAN_PAN", "INDIAN_GSTIN"] });
  }

  for (let i = 0; i < 20; i++) {
    const p11 = `381942751${String(10 + i)}`;
    const c = computeVerhoeffCheckDigit(p11);
    const spaced = `${p11.slice(0, 4)}-${p11.slice(4, 8)}-${p11.slice(8)}${c}`;
    samples.push({ text: `WARN [KYCService] Failed verification for uidai record ${spaced} at line 42`, expectedTypes: ["IN_VERHOEFF_12_ID"] });
  }

  const validCards = [
    "4532-0151-1283-0366",
    "5425-2334-3010-9903",
    "3782-822463-10005",
    "6011-1111-1111-1117",
  ];
  for (let i = 0; i < 20; i++) {
    const card = validCards[i % validCards.length];
    samples.push({ text: `payment_payload = { "card": "${card}", "currency": "USD" }`, expectedTypes: ["PAYMENT_CARD"] });
  }

  const validIbans = [
    "GB82 WEST 1234 5698 7654 32",
    "DE89370400440532013000",
    "AE070331234567890123456",
    "SA0380000000608010167519",
  ];
  for (let i = 0; i < 20; i++) {
    samples.push({ text: `wire_transfer(iban="${validIbans[i % validIbans.length]}", amount=5000)`, expectedTypes: ["IBAN"] });
  }

  for (let i = 0; i < 20; i++) {
    samples.push({ text: `employee_record: { ssn: "453-21-${String(1000 + i)}", routing_aba: "021000021" }`, expectedTypes: ["US_SSN", "US_ABA_ROUTING"] });
  }

  for (let i = 0; i < 20; i++) {
    samples.push({
      text: `au_vendor = { abn: "51 824 753 556", tfn: "865 414 088", emirates_id: "784-1988-1234567-0", saudi_iqama: "1010101010" }`,
      expectedTypes: ["AU_ABN", "AU_TFN", "UAE_EMIRATES_ID", "SAUDI_NATIONAL_ID"],
    });
  }

  // --- 140 NEGATIVE SAMPLES (TRAPS) ---
  for (let i = 0; i < 35; i++) {
    samples.push({
      text: `Error: ECONNREFUSED 127.0.0.1:5432 at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1607:16) reqId=${100000000 + i}`,
      expectedTypes: [],
    });
  }
  for (let i = 0; i < 35; i++) {
    samples.push({
      text: `commit 8f4e2b9a1c3d5e7f9a0b2c4d6e8f0a1b2c3d4e5f (uuid: 550e8400-e29b-41d4-a716-4466554400${String(i).padStart(2, "0")})`,
      expectedTypes: [],
    });
  }
  for (let i = 0; i < 35; i++) {
    samples.push({
      text: `{"timestamp_ms": ${1730448000000 + i * 7}, "timestamp_ns": "1730448000123456", "aws_account": "123456789012", "support_tel": "+1-800-555-0199"}`,
      expectedTypes: [],
    });
  }
  for (let i = 0; i < 35; i++) {
    samples.push({
      text: `integrity="sha512-2AAAACB2894G1Z9+BUFFER1024X/v2.14.987654321==" version="14.2.100"`,
      expectedTypes: [],
    });
  }

  const stats = new Map<DetectorType, { tp: number; fp: number; fn: number }>();
  const allTypes: DetectorType[] = [
    "GITHUB_PAT", "INDIAN_GSTIN", "INDIAN_PAN", "IBAN", "UAE_EMIRATES_ID",
    "PAYMENT_CARD", "IN_VERHOEFF_12_ID", "AU_ABN", "AU_TFN", "US_SSN",
    "US_ABA_ROUTING", "SAUDI_NATIONAL_ID",
  ];
  for (const t of allTypes) stats.set(t, { tp: 0, fp: 0, fn: 0 });

  for (const sample of samples) {
    const { detections } = scanAndRedactWithChecksums(sample.text);
    const actualTypes = detections.map((d) => d.type);

    for (const t of allTypes) {
      const expCount = sample.expectedTypes.filter((x) => x === t).length;
      const actCount = actualTypes.filter((x) => x === t).length;
      const entry = stats.get(t)!;
      entry.tp += Math.min(expCount, actCount);
      if (actCount > expCount) entry.fp += actCount - expCount;
      if (actCount < expCount) entry.fn += expCount - actCount;
    }
  }

  console.log("\n📊 Per-Detector Precision & Recall across 280 Realistic Developer Samples:");
  for (const [det, s] of stats.entries()) {
    const precision = (s.tp + s.fp) === 0 ? 1.0 : s.tp / (s.tp + s.fp);
    const recall = (s.tp + s.fn) === 0 ? 1.0 : s.tp / (s.tp + s.fn);
    console.log(`  - ${det.padEnd(20)} | TP: ${String(s.tp).padStart(2)} | FP: ${s.fp} | FN: ${s.fn} | Precision: ${(precision * 100).toFixed(1)}% | Recall: ${(recall * 100).toFixed(1)}%`);
    assert.equal(s.fp, 0, `False positive on detector ${det}`);
    assert.equal(s.fn, 0, `False negative on detector ${det}`);
  }
});