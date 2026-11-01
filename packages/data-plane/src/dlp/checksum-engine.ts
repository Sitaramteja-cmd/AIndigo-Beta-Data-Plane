/**
 * Mathematical Checksum & DLP Verification Engine
 * Eliminates false positives by validating numbers against Luhn and structural checksums.
 */

/**
 * Validates a credit card number using the Luhn algorithm.
 */
export function validateLuhn(cardNumber: string): boolean {
  const sanitized = cardNumber.replace(/\D/g, "");
  if (sanitized.length < 13 || sanitized.length > 19) return false;

  let sum = 0;
  let shouldDouble = false;

  for (let i = sanitized.length - 1; i >= 0; i--) {
    let digit = parseInt(sanitized.charAt(i), 10);

    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }

    sum += digit;
    shouldDouble = !shouldDouble;
  }

  return sum % 10 === 0;
}

/**
 * Validates Indian PAN format (5 uppercase letters, 4 digits, 1 uppercase letter).
 */
export function validatePan(pan: string): boolean {
  const panRegex = /^[A-Z]{5}[0-9]{4}[A-Z]{1}$/;
  return panRegex.test(pan);
}

/**
 * Validates 12-digit Aadhaar structural format (must not start with 0 or 1).
 */
export function validateAadhaar(aadhaar: string): boolean {
  const sanitized = aadhaar.replace(/\D/g, "");
  if (sanitized.length !== 12) return false;
  if (sanitized.startsWith("0") || sanitized.startsWith("1")) return false;
  return true;
}

/**
 * Scans text, applies regex + mathematical checksum verification, and redacts sensitive items.
 */
export function scanAndRedactWithChecksums(text: string): {
  redactedText: string;
  detectedCategories: string[];
} {
  const detectedCategories = new Set<string>();
  let redactedText = text;

  // 1. Credit Card Check (13-19 digits with Luhn)
  const ccRegex = /\b(?:\d[ -]*){13,19}\b/g;
  redactedText = redactedText.replace(ccRegex, (match) => {
    if (validateLuhn(match)) {
      detectedCategories.add("CREDIT_CARD");
      return "[REDACTED_CREDIT_CARD]";
    }
    return match;
  });

  // 2. PAN Check
  const panRegex = /\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b/g;
  redactedText = redactedText.replace(panRegex, (match) => {
    if (validatePan(match)) {
      detectedCategories.add("PAN_CARD");
      return "[REDACTED_PAN]";
    }
    return match;
  });

  // 3. Aadhaar Check
  const aadhaarRegex = /\b\d{4}[ -]?\d{4}[ -]?\d{4}\b/g;
  redactedText = redactedText.replace(aadhaarRegex, (match) => {
    if (validateAadhaar(match)) {
      detectedCategories.add("AADHAAR");
      return "[REDACTED_AADHAAR]";
    }
    return match;
  });

  return {
    redactedText,
    detectedCategories: Array.from(detectedCategories),
  };
}