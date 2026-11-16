import { strict as assert } from "node:assert";
import {
  isValidPaymentCard,
  isValidIndianPan,
} from "./checksum-validators.js";
import { scanAndRedactWithChecksums } from "./checksum-engine.js";

function runChecksumTests() {
  console.log("==============================================================");
  console.log("AIndigo Tier 2 — Checksum DLP Engine Test");
  console.log("==============================================================");

  // 1. Payment card checksum validation
  const validVisa = "4000 0000 0000 0002";
  const invalidCard = "1234 5678 1234 5673";

  assert.equal(isValidPaymentCard(validVisa), true);
  assert.equal(isValidPaymentCard(invalidCard), false);
  console.log("1. Payment card checksum validation passed.");

  // 2. Indian PAN validation
  assert.equal(isValidIndianPan("ABCPE1234F"), true);
  assert.equal(isValidIndianPan("12345ABCDE"), false);
  console.log("2. Indian PAN validation passed.");

  // 3. Full-text scanning and redaction
  const promptText =
    "My valid card is 4000 0000 0000 0002 and my fake order ID is " +
    "1234 5678 1234 5673 with PAN ABCPE1234F.";

  const result = scanAndRedactWithChecksums(promptText);

  assert.equal(
    result.redactedText.includes("[REDACTED_PAYMENT_CARD]"),
    true,
    "Valid card must be redacted"
  );

  assert.equal(
    result.redactedText.includes("1234 5678 1234 5673"),
    true,
    "Invalid card must remain untouched"
  );

  assert.equal(
    result.redactedText.includes("[REDACTED_INDIAN_PAN]"),
    true,
    "Valid PAN must be redacted"
  );

  assert.equal(
    result.detections.some((d) => d.type === "PAYMENT_CARD"),
    true
  );

  assert.equal(
    result.detections.some((d) => d.type === "INDIAN_PAN"),
    true
  );

  console.log("3. Full-text detection and false-positive prevention passed.");
  console.log("Redacted output:", result.redactedText);

  console.log("==============================================================");
  console.log("Checksum DLP Engine Tests PASSED");
  console.log("==============================================================");
}

runChecksumTests();
