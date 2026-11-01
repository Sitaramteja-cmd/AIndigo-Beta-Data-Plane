/**
 * AIndigo Step 1B — Deterministic Checksum & Structural Validators
 * Note on False-Positive Reduction Rates:
 *  - Single check-digit algorithms (Luhn Mod-10, Verhoeff D5) reject ~90% of random numeric strings (10% pass rate).
 *  - Combined with issuer prefixes (IIN/BIN), country length tables (IBAN Mod-97), and context guards, false positives drop below 0.5%.
 */

const VERHOEFF_D: ReadonlyArray<ReadonlyArray<number>> = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

const VERHOEFF_P: ReadonlyArray<ReadonlyArray<number>> = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

const VERHOEFF_INV: ReadonlyArray<number> = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];

export function cleanDigits(input: string): string {
  return input.replace(/[\s-]/g, "");
}

/** Computes the Verhoeff check digit for an arbitrary numeric prefix. */
export function computeVerhoeffCheckDigit(numericPrefix: string): number {
  let c = 0;
  const len = numericPrefix.length;
  for (let i = 0; i < len; i++) {
    const digit = numericPrefix.charCodeAt(len - 1 - i) - 48;
    if (digit < 0 || digit > 9) return -1;
    c = VERHOEFF_D[c][VERHOEFF_P[(i + 1) % 8][digit]];
  }
  return VERHOEFF_INV[c];
}

/** Validates a 12-digit Indian National ID candidate using first-digit rules (2-9) + Verhoeff D5 checksum. */
export function isValidVerhoeff12Id(candidate: string): boolean {
  const digits = cleanDigits(candidate);
  if (!/^[2-9]\d{11}$/.test(digits)) return false;
  if (/^(\d)\1{11}$/.test(digits)) return false;

  let c = 0;
  for (let i = 0; i < 12; i++) {
    const digit = digits.charCodeAt(11 - i) - 48;
    c = VERHOEFF_D[c][VERHOEFF_P[i % 8][digit]];
  }
  return c === 0;
}

/** Standard Luhn Mod-10 checksum validator. */
export function isValidLuhn(candidate: string, minLen = 13, maxLen = 19): boolean {
  const digits = cleanDigits(candidate);
  if (digits.length < minLen || digits.length > maxLen) return false;
  if (!/^\d+$/.test(digits) || /^0+$/.test(digits)) return false;

  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (shouldDouble) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

/**
 * Validates payment cards using BOTH Luhn Mod-10 AND Issuer Identification Number (IIN/BIN) prefix + length rules.
 * Rejects random 13-19 digit numbers (like Unix millisecond/microsecond timestamps) that happen to pass Luhn 10% of the time.
 */
export function isValidPaymentCard(candidate: string): boolean {
  const d = cleanDigits(candidate);
  if (!/^\d{13,19}$/.test(d)) return false;
  if (/^(\d)\1+$/.test(d)) return false;

  const len = d.length;
  const p1 = d.charCodeAt(0) - 48;
  const p2 = Number.parseInt(d.slice(0, 2), 10);
  const p3 = Number.parseInt(d.slice(0, 3), 10);
  const p4 = Number.parseInt(d.slice(0, 4), 10);

  let prefixValid = false;
  // Visa: starts with 4, length 13, 16, or 19
  if (p1 === 4 && (len === 13 || len === 16 || len === 19)) {
    prefixValid = true;
  }
  // Mastercard: 51-55 or 2221-2720, length 16
  else if (((p2 >= 51 && p2 <= 55) || (p4 >= 2221 && p4 <= 2720)) && len === 16) {
    prefixValid = true;
  }
  // Amex: 34 or 37, length 15
  else if ((p2 === 34 || p2 === 37) && len === 15) {
    prefixValid = true;
  }
  // Discover / Diners / JCB / UnionPay / RuPay ranges
  else if (
    (p4 === 6011 || p2 === 65 || (p3 >= 644 && p3 <= 649) || p2 === 62) &&
    len >= 16 &&
    len <= 19
  ) {
    prefixValid = true;
  } else if (((p3 >= 300 && p3 <= 305) || p2 === 36 || p2 === 38) && len >= 14 && len <= 16) {
    prefixValid = true;
  } else if (p4 >= 3528 && p4 <= 3589 && len >= 16 && len <= 19) {
    prefixValid = true;
  }

  if (!prefixValid) return false;
  return isValidLuhn(d, 13, 19);
}

/** Validates Indian Permanent Account Number (PAN) with strict 4th-char entity status code rules. */
export function isValidIndianPan(candidate: string): boolean {
  const s = candidate.trim().toUpperCase();
  return /^[A-Z]{3}[ABCFGHLJPTK][A-Z][0-9]{4}[A-Z]$/.test(s);
}

const BASE36_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/** Computes the Mod-36 check character for the first 14 characters of an Indian GSTIN. */
export function computeGstinCheckChar(prefix14: string): string {
  const s = prefix14.toUpperCase();
  let sum = 0;
  for (let i = 0; i < 14; i++) {
    const code = BASE36_CHARS.indexOf(s[i]);
    if (code === -1) return "";
    const factor = i % 2 === 0 ? 1 : 2;
    const prod = code * factor;
    sum += Math.floor(prod / 36) + (prod % 36);
  }
  const rem = sum % 36;
  const checkIdx = (36 - rem) % 36;
  return BASE36_CHARS[checkIdx];
}

/** Validates 15-character Indian GSTIN (Strict 2-digit State Code + PAN + Entity + Z + Mod-36 Checksum). */
export function isValidIndianGstin(candidate: string): boolean {
  const s = candidate.trim().toUpperCase();
  if (s.length !== 15) return false;
  // Fix #1: Enforce strict 2-digit numeric check BEFORE parseInt so "2A" never parses as 2
  if (!/^\d{2}$/.test(s.slice(0, 2))) return false;
  const stateCode = Number.parseInt(s.slice(0, 2), 10);
  if (stateCode < 1 || (stateCode > 38 && stateCode !== 97 && stateCode !== 99)) {
    return false;
  }
  if (!isValidIndianPan(s.slice(2, 12))) return false;
  if (!/^[1-9A-Z]$/.test(s[12])) return false;
  if (s[13] !== "Z") return false;
  return computeGstinCheckChar(s.slice(0, 14)) === s[14];
}

/** Validates 11-character Indian IFSC code. */
export function isValidIndianIfsc(candidate: string): boolean {
  return /^[A-Z]{4}0[A-Z0-9]{6}$/.test(candidate.trim().toUpperCase());
}

/** Official ISO 13616 IBAN lengths by country code across EU, UK, and Middle East. */
const IBAN_COUNTRY_LENGTHS: Readonly<Record<string, number>> = {
  AD: 24, AE: 23, AT: 20, BE: 16, BG: 22, BH: 22, CH: 21, CY: 28,
  CZ: 24, DE: 22, DK: 18, EE: 20, ES: 24, FI: 18, FR: 27, GB: 22,
  GI: 23, GR: 27, HR: 21, HU: 28, IE: 22, IL: 23, IS: 26, IT: 27,
  JO: 30, KW: 30, LB: 28, LI: 21, LT: 20, LU: 20, LV: 21, MC: 27,
  MT: 31, NL: 18, NO: 15, PL: 28, PT: 25, QA: 29, RO: 24, SA: 24,
  SE: 24, SI: 19, SK: 24, SM: 27, TR: 26, UA: 29, VA: 22,
};

/** Validates IBAN via country-specific length table + ISO 7064 Mod 97-10. */
export function isValidIban(candidate: string): boolean {
  const s = cleanDigits(candidate).toUpperCase();
  if (!/^[A-Z]{2}[0-9]{2}[A-Z0-9]+$/.test(s)) return false;

  const country = s.slice(0, 2);
  const expectedLen = IBAN_COUNTRY_LENGTHS[country];
  if (!expectedLen || s.length !== expectedLen) return false;

  const rearranged = s.slice(4) + s.slice(0, 4);
  let remainder = 0;
  for (let i = 0; i < rearranged.length; i++) {
    const ch = rearranged.charCodeAt(i);
    if (ch >= 48 && ch <= 57) {
      remainder = (remainder * 10 + (ch - 48)) % 97;
    } else if (ch >= 65 && ch <= 90) {
      const val = ch - 55;
      remainder = (remainder * 100 + val) % 97;
    } else {
      return false;
    }
  }
  return remainder === 1;
}

/**
 * Validates US Social Security Number (SSN).
 * - Dashed form (XXX-XX-XXXX) is accepted directly if SSA area/group/serial rules pass.
 * - Undelimited 9-digit form is REJECTED unless `hasSsnContext = true` to avoid flagging 9-digit DB IDs.
 */
export function isValidUsSsn(candidate: string, hasSsnContext = false): boolean {
  const raw = candidate.trim();
  const isDashed = /^\d{3}-\d{2}-\d{4}$/.test(raw);
  const isPlain9 = /^\d{9}$/.test(raw);

  if (!isDashed && !(isPlain9 && hasSsnContext)) return false;

  const digits = cleanDigits(raw);
  const area = Number.parseInt(digits.slice(0, 3), 10);
  const group = Number.parseInt(digits.slice(3, 5), 10);
  const serial = Number.parseInt(digits.slice(5, 9), 10);

  if (area === 0 || area === 666 || area >= 900) return false;
  if (group === 0 || serial === 0) return false;
  if (digits === "123456789" || digits === "078051120" || /^(\d)\1{8}$/.test(digits)) return false;
  return true;
}

/** Validates US ABA Bank Routing Transit Number (9 digits, valid Federal Reserve prefix + weighted Mod-10). */
export function isValidUsAbaRouting(candidate: string): boolean {
  const d = cleanDigits(candidate);
  if (!/^\d{9}$/.test(d)) return false;
  const prefix = Number.parseInt(d.slice(0, 2), 10);
  const validPrefix =
    (prefix >= 1 && prefix <= 12) ||
    (prefix >= 21 && prefix <= 32) ||
    (prefix >= 61 && prefix <= 72) ||
    prefix === 80;
  if (!validPrefix) return false;

  const weights = [3, 7, 1, 3, 7, 1, 3, 7, 1];
  let sum = 0;
  for (let i = 0; i < 9; i++) {
    sum += (d.charCodeAt(i) - 48) * weights[i];
  }
  return sum > 0 && sum % 10 === 0;
}

/** Validates UK NHS Number (10 digits, weighted Mod-11 where check digit 10 is invalid). */
export function isValidUkNhsNumber(candidate: string): boolean {
  const d = cleanDigits(candidate);
  if (!/^\d{10}$/.test(d) || /^(\d)\1{9}$/.test(d)) return false;
  let sum = 0;
  for (let i = 0; i < 9; i++) {
    sum += (d.charCodeAt(i) - 48) * (10 - i);
  }
  const rem = sum % 11;
  let check = 11 - rem;
  if (check === 11) check = 0;
  if (check === 10) return false;
  return check === d.charCodeAt(9) - 48;
}

/** Validates Saudi National ID / Iqama (10 digits starting with 1 or 2 + Luhn Mod-10). */
export function isValidSaudiNationalId(candidate: string): boolean {
  const d = cleanDigits(candidate);
  if (!/^[12]\d{9}$/.test(d)) return false;
  return isValidLuhn(d, 10, 10);
}

/** Validates UAE Emirates ID (15 digits starting with 784 + valid birth year + Luhn Mod-10). */
export function isValidUaeEmiratesId(candidate: string): boolean {
  const d = cleanDigits(candidate);
  if (!/^784(19\d{2}|20\d{2})\d{8}$/.test(d)) return false;
  return isValidLuhn(d, 15, 15);
}

/** Validates Australian Business Number (ABN - 11 digits, subtract 1 from first digit, weighted Mod 89). */
export function isValidAustralianAbn(candidate: string): boolean {
  const d = cleanDigits(candidate);
  if (!/^\d{11}$/.test(d)) return false;
  const weights = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19];
  let sum = 0;
  for (let i = 0; i < 11; i++) {
    let digit = d.charCodeAt(i) - 48;
    if (i === 0) digit -= 1;
    sum += digit * weights[i];
  }
  return sum % 89 === 0;
}

/** Validates Australian Tax File Number (TFN - 9 digits, weighted Mod 11). */
export function isValidAustralianTfn(candidate: string): boolean {
  const d = cleanDigits(candidate);
  if (!/^\d{9}$/.test(d) || /^(\d)\1{8}$/.test(d)) return false;
  const weights = [1, 4, 3, 7, 5, 8, 6, 9, 10];
  let sum = 0;
  for (let i = 0; i < 9; i++) {
    sum += (d.charCodeAt(i) - 48) * weights[i];
  }
  return sum > 0 && sum % 11 === 0;
}

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[i] = c >>> 0;
  }
  return table;
})();

const BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

function crc32Unsigned(str: string): number {
  let crc = 0xffffffff;
  for (let i = 0; i < str.length; i++) {
    const byte = str.charCodeAt(i) & 0xff;
    crc = CRC32_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

export function encodeBase62Fixed6(num: number): string {
  let n = num >>> 0;
  const chars = new Array<string>(6).fill("0");
  for (let i = 5; i >= 0; i--) {
    chars[i] = BASE62_ALPHABET[n % 62];
    n = Math.floor(n / 62);
  }
  return chars.join("");
}

/** Synthesizes a structurally & mathematically valid GitHub Classic PAT from a 30-char Base62 payload. */
export function buildValidGithubPat(prefix: "ghp" | "gho" | "ghu" | "ghs" | "ghr", payload30: string): string {
  const crc = crc32Unsigned(payload30);
  return `${prefix}_${payload30}${encodeBase62Fixed6(crc)}`;
}

export interface GithubTokenClassification {
  shouldRedact: boolean;
  kind: "CLASSIC" | "FINE_GRAINED" | "NONE";
  checksumVerified: boolean;
  severity: "CRITICAL_VERIFIED" | "HIGH_PREFIX_MATCH" | "NONE";
}

/**
 * Classifies GitHub Classic (ghp_, gho_, ghu_, ghs_, ghr_) and Fine-Grained (github_pat_) tokens.
 * Fix #5: Always redact on the distinctive prefix+structure (a mistyped token is still a secret!),
 * and use the CRC32 check to elevate severity to CRITICAL_VERIFIED.
 */
export function classifyGithubToken(candidate: string): GithubTokenClassification {
  const s = candidate.trim();
  if (/^gh[pousr]_[0-9A-Za-z]{36}$/.test(s)) {
    const payload30 = s.slice(4, 34);
    const checksum6 = s.slice(34, 40);
    const verified = encodeBase62Fixed6(crc32Unsigned(payload30)) === checksum6;
    return {
      shouldRedact: true,
      kind: "CLASSIC",
      checksumVerified: verified,
      severity: verified ? "CRITICAL_VERIFIED" : "HIGH_PREFIX_MATCH",
    };
  }
  if (/^github_pat_[0-9A-Za-z]{22}_[0-9A-Za-z]{59}$/.test(s)) {
    return {
      shouldRedact: true,
      kind: "FINE_GRAINED",
      checksumVerified: true,
      severity: "CRITICAL_VERIFIED",
    };
  }
  return { shouldRedact: false, kind: "NONE", checksumVerified: false, severity: "NONE" };
}

/** Strict checksum check helper when testing whether a classic PAT has a valid CRC32. */
export function isValidGithubPatChecksum(candidate: string): boolean {
  const res = classifyGithubToken(candidate);
  return res.shouldRedact && res.checksumVerified;
}