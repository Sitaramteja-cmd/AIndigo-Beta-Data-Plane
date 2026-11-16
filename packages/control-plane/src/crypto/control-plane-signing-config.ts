import path from "node:path";

import {
  loadControlPlaneSigningKey,
  type ControlPlaneSigningKey,
} from "./control-plane-signing-key.js";

export type SigningKeyEnvironment = Readonly<
  Record<string, string | undefined>
>;

export function loadControlPlaneSigningKeyFromEnvironment(
  environment: SigningKeyEnvironment
): ControlPlaneSigningKey | null {
  const keyId = environment.CONTROL_PLANE_SIGNING_KEY_ID?.trim();
  const privateKeyPath =
    environment.CONTROL_PLANE_SIGNING_PRIVATE_KEY_PATH?.trim();
  const publicKeyPath =
    environment.CONTROL_PLANE_SIGNING_PUBLIC_KEY_PATH?.trim();

  const values = [keyId, privateKeyPath, publicKeyPath];
  const provided = values.some(Boolean);
  const complete = values.every(Boolean);

  if (provided && !complete) {
    throw new Error(
      "CONTROL_PLANE_SIGNING_KEY_ERROR: All three signing-key environment variables are required"
    );
  }

  if (
    environment.NODE_ENV === "production" &&
    !complete
  ) {
    throw new Error(
      "CONTROL_PLANE_SIGNING_KEY_ERROR: Production requires a configured signing identity"
    );
  }

  if (!complete) {
    return null;
  }

  return loadControlPlaneSigningKey({
    keyId: keyId!,
    privateKeyPath: path.resolve(privateKeyPath!),
    publicKeyPath: path.resolve(publicKeyPath!),
  });
}
