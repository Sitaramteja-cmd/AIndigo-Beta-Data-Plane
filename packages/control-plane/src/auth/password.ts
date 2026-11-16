
import {
  argon2id,
  hash,
  verify,
  type HashOptions,
} from "argon2";

const ARGON_OPTIONS: HashOptions = {
  type: argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
};

export async function hashPassword(
  plainTextPassword: string
): Promise<string> {
  if (!plainTextPassword || plainTextPassword.length < 8) {
    throw new Error("Password must be at least 8 characters long.");
  }

  return hash(plainTextPassword, ARGON_OPTIONS);
}

export async function verifyPassword(
  hashedPassword: string,
  plainTextPassword: string
): Promise<boolean> {
  if (!hashedPassword || !plainTextPassword) {
    return false;
  }

  try {
    return await verify(hashedPassword, plainTextPassword);
  } catch {
    return false;
  }
}
