import argon2 from "argon2";

/**
 * Enterprise Password Security Configuration (Argon2id)
 * Tuned for optimal memory hardness and CPU cost to prevent GPU brute-forcing.
 */
const ARGON_OPTIONS: argon2.Options = {
  type: argon2.argon2id,
  memoryCost: 19456, // 19 MB RAM
  timeCost: 2,       // 2 iterations
  parallelism: 1,    // 1 thread
};

/**
 * Hashes a plaintext enterprise administrator or user password securely.
 */
export async function hashPassword(plainTextPassword: string): Promise<string> {
  if (!plainTextPassword || plainTextPassword.length < 8) {
    throw new Error("Password must be at least 8 characters long.");
  }
  return await argon2.hash(plainTextPassword, ARGON_OPTIONS);
}

/**
 * Verifies a plaintext password against a stored Argon2id hash.
 */
export async function verifyPassword(
  hashedPassword: string,
  plainTextPassword: string
): Promise<boolean> {
  try {
    return await argon2.verify(hashedPassword, plainTextPassword);
  } catch {
    return false;
  }
}
