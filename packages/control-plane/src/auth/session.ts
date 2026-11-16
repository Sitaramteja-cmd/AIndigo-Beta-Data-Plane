import {
  createHash,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

/**
 * Browser sessions expire after 24 hours.
 */
export const SESSION_TTL_MS = 24 * 60 * 60 * 1000;

/**
 * Generate a cryptographically random opaque browser session token.
 *
 * The raw token must only be returned to the browser once.
 * Never store or log this value.
 */
export function createSessionToken(): string {
  return `aindigo_sess_${randomBytes(32).toString("hex")}`;
}

/**
 * Generate a SHA-256 fingerprint for database storage.
 *
 * Store this fingerprint, never the raw session token.
 */
export function hashSessionToken(token: string): string {
  if (typeof token !== "string" || token.length === 0) {
    throw new Error("A valid session token is required.");
  }

  return createHash("sha256")
    .update(token, "utf8")
    .digest("hex");
}

/**
 * Compare a supplied token with its stored fingerprint.
 *
 * Returns false for malformed fingerprints and invalid tokens.
 */
export function verifySessionToken(
  token: string,
  storedHash: string,
): boolean {
  if (
    typeof token !== "string" ||
    token.length === 0 ||
    typeof storedHash !== "string" ||
    !/^[a-f0-9]{64}$/i.test(storedHash)
  ) {
    return false;
  }

  const suppliedHash = Buffer.from(hashSessionToken(token), "hex");
  const expectedHash = Buffer.from(storedHash, "hex");

  return timingSafeEqual(suppliedHash, expectedHash);
}

/**
 * Calculate the session expiry timestamp.
 */
export function getSessionExpiry(
  createdAt: Date = new Date(),
): Date {
  if (
    !(createdAt instanceof Date) ||
    !Number.isFinite(createdAt.getTime())
  ) {
    throw new Error("A valid session creation date is required.");
  }

  return new Date(createdAt.getTime() + SESSION_TTL_MS);
}
