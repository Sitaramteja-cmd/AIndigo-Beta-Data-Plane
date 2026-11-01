import { strict as assert } from 'node:assert';
import { validateLuhn, validatePan, scanAndRedactWithChecksums } from './checksum-engine.js';

function runChecksumTests() {
  console.log('================================================================');
  console.log(' 🧮 AIndigo Tier 2 — Mathematical Checksum DLP Engine Test');
  console.log('================================================================');

  // 1. Test Luhn Algorithm (Valid Visa vs Invalid Card)
  const validVisa = '4000 0000 0000 0002'; // Valid Luhn test card
  const invalidCard = '1234 5678 1234 5673'; // Guaranteed invalid Luhn checksum
  
  assert.equal(validateLuhn(validVisa), true, 'Valid credit card must pass Luhn check');
  assert.equal(validateLuhn(invalidCard), false, 'Invalid credit card checksum must fail');
  console.log('✅ 1. Luhn Checksum Validation Verified.');

  // 2. Test PAN Format
  assert.equal(validatePan('ABCDE1234F'), true, 'Valid PAN format passes');
  assert.equal(validatePan('12345ABCDE'), false, 'Invalid PAN format fails');
  console.log('✅ 2. PAN Structural Validation Verified.');

  // 3. Test Full Text Scan with False-Positive Prevention
  const promptText = 'My valid card is 4000 0000 0000 0002 and my fake order ID is 1234 5678 1234 5673 with PAN ABCDE1234F.';
  const result = scanAndRedactWithChecksums(promptText);

  assert.equal(result.redactedText.includes('[REDACTED_CREDIT_CARD]'), true, 'Valid card must be redacted');
  assert.equal(result.redactedText.includes('1234 5678 1234 5673'), true, 'Invalid card (false positive) must remain untouched');
  assert.equal(result.redactedText.includes('[REDACTED_PAN]'), true, 'Valid PAN must be redacted');
  assert.equal(result.detectedCategories.includes('CREDIT_CARD'), true);
  assert.equal(result.detectedCategories.includes('PAN_CARD'), true);

  console.log('✅ 3. False-Positive Prevention Test Passed Successfully.');
  console.log('   • Scanned Output: ' + result.redactedText);

  console.log('================================================================');
  console.log(' 🎉 Tier 2 Module 2.2 Checksum DLP Tests PASSED');
  console.log('================================================================');
}

runChecksumTests();