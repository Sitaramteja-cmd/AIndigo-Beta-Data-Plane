import crypto from 'node:crypto';
import fs from 'node:fs';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96-bit IV recommended for GCM

/**
 * Resolve the Data Plane master key.
 *
 * Preferred source:
 *   DATA_PLANE_MASTER_KEY_FILE
 *
 * Backward-compatible fallback:
 *   DATA_PLANE_MASTER_KEY
 *
 * The key must be exactly 32 bytes represented as 64 hexadecimal characters.
 */
export function getMasterKey(): Buffer {
  const secretFile = process.env.DATA_PLANE_MASTER_KEY_FILE;

  let hex: string | undefined;

  if (secretFile) {
    try {
      // Remove only trailing line endings commonly added to mounted secret files.
      hex = fs.readFileSync(secretFile, 'utf8').replace(/[\r\n]+$/, '');
    } catch {
      throw new Error(
        'CRITICAL_SECURITY_CONFIG: Unable to read DATA_PLANE_MASTER_KEY_FILE.',
      );
    }
  } else {
    hex = process.env.DATA_PLANE_MASTER_KEY;
  }

  if (!hex || !/^[a-fA-F0-9]{64}$/.test(hex)) {
    throw new Error(
      'CRITICAL_SECURITY_CONFIG: Master key must be a 64-character hexadecimal string (32 bytes). Configure DATA_PLANE_MASTER_KEY_FILE or DATA_PLANE_MASTER_KEY.',
    );
  }

  return Buffer.from(hex, 'hex');
}

export function hashVirtualKey(virtualKey: string): string {
  return crypto.createHash('sha256').update(virtualKey).digest('hex');
}

export function verifyKeyHashSafe(candidateHash: string, storedHash: string): boolean {
  if (candidateHash.length !== storedHash.length) {
    return false;
  }

  const a = Buffer.from(candidateHash, 'hex');
  const b = Buffer.from(storedHash, 'hex');

  if (a.length !== b.length || a.length === 0) {
    return false;
  }

  return crypto.timingSafeEqual(a, b);
}

export interface EncryptedPayload {
  ciphertext: string;
  iv: string;
  authTag: string;
}

export function encryptSecret(plaintext: string): EncryptedPayload {
  const masterKey = getMasterKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, masterKey, iv);

  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const authTag = cipher.getAuthTag().toString('hex');

  return {
    ciphertext: encrypted,
    iv: iv.toString('hex'),
    authTag,
  };
}

export function decryptSecret(payload: EncryptedPayload): string {
  const masterKey = getMasterKey();
  const iv = Buffer.from(payload.iv, 'hex');
  const authTag = Buffer.from(payload.authTag, 'hex');
  const decipher = crypto.createDecipheriv(ALGORITHM, masterKey, iv);

  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(payload.ciphertext, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}