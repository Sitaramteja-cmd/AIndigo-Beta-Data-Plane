import dotenv from "dotenv";

import {
  createPublicKey,
} from "node:crypto";
import {
  existsSync,
  readFileSync,
  statSync,
} from "node:fs";
import path from "node:path";
import {
  fileURLToPath,
} from "node:url";

import {
  getOrCreateNodeIdentity,
} from "../data-plane/src/crypto/node-identity.js";

import {
  enrollDataPlaneNode,
} from "../data-plane/src/crypto/node-enrollment-client.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Match the environment file used by the Data Plane workspace.
dotenv.config({
  path: path.resolve(__dirname, "../data-plane/.env"),
});

interface EnrollmentConfig {
  controlPlaneUrl: string;
  publicKeyPath: string;
  signingKeyId: string;
  databasePath: string;
  nodeKeysDir: string;
  controlPlanePublicKeyPem: string;
}

function validateConfig(): EnrollmentConfig {
  const controlPlaneUrl =
    process.env.CONTROL_PLANE_URL?.trim() ||
    "http://127.0.0.1:3000";

  const publicKeyPath = process.env
    .CONTROL_PLANE_SIGNING_PUBLIC_KEY_PATH
    ?.trim();

  const signingKeyId = process.env
    .CONTROL_PLANE_SIGNING_KEY_ID
    ?.trim();

  const configuredDatabasePath =
    process.env.DATA_PLANE_DB_PATH?.trim();

  if (!publicKeyPath) {
    throw new Error(
      "Missing CONTROL_PLANE_SIGNING_PUBLIC_KEY_PATH."
    );
  }

  if (!signingKeyId) {
    throw new Error(
      "Missing CONTROL_PLANE_SIGNING_KEY_ID."
    );
  }

  if (!configuredDatabasePath) {
    throw new Error(
      "Missing DATA_PLANE_DB_PATH. Configure an explicit database path."
    );
  }

  let parsedUrl: URL;

  try {
    parsedUrl = new URL(controlPlaneUrl);
  } catch {
    throw new Error("CONTROL_PLANE_URL is not a valid URL.");
  }

  if (
    parsedUrl.username ||
    parsedUrl.password ||
    parsedUrl.search ||
    parsedUrl.hash
  ) {
    throw new Error(
      "CONTROL_PLANE_URL must not contain credentials, query parameters or fragments."
    );
  }

  const isLoopback =
    parsedUrl.hostname === "localhost" ||
    parsedUrl.hostname === "127.0.0.1" ||
    parsedUrl.hostname === "::1" ||
    parsedUrl.hostname === "[::1]";

  if (
    parsedUrl.protocol !== "https:" &&
    !(parsedUrl.protocol === "http:" && isLoopback)
  ) {
    throw new Error(
      "CONTROL_PLANE_URL must use HTTPS except for local loopback development."
    );
  }

  const resolvedPublicKeyPath = path.resolve(
    process.cwd(),
    publicKeyPath
  );

  if (!existsSync(resolvedPublicKeyPath)) {
    throw new Error(
      "The configured Control Plane public key file does not exist."
    );
  }

  const controlPlanePublicKeyPem =
    readFileSync(resolvedPublicKeyPath, "utf8");

  let publicKey;

  try {
    publicKey = createPublicKey(controlPlanePublicKeyPem);
  } catch {
    throw new Error(
      "The configured Control Plane public key is invalid."
    );
  }

  if (
    publicKey.type !== "public" ||
    publicKey.asymmetricKeyType !== "ed25519"
  ) {
    throw new Error(
      "The pinned Control Plane public key must be an Ed25519 public key."
    );
  }

  const dataPlaneDirectory = path.resolve(
    __dirname,
    "../data-plane"
  );

  const databasePath = path.isAbsolute(configuredDatabasePath)
    ? path.resolve(configuredDatabasePath)
    : path.resolve(dataPlaneDirectory, configuredDatabasePath);

  if (!existsSync(databasePath) || !statSync(databasePath).isFile()) {
    throw new Error(
      "DATA_PLANE_DB_PATH must point to an existing SQLite database file. The CLI will not create a new database."
    );
  }

  const nodeKeysDir = path.resolve(
    process.env.AINDIGO_NODE_KEYS_DIR?.trim() ||
      path.resolve(__dirname, "../../.keys")
  );

  return {
    controlPlaneUrl: parsedUrl.toString().replace(/\/+$/, ""),
    publicKeyPath: resolvedPublicKeyPath,
    signingKeyId,
    databasePath,
    nodeKeysDir,
    controlPlanePublicKeyPem,
  };
}

async function readHiddenEnrollmentCode(): Promise<string> {
  if (
    !process.stdin.isTTY ||
    typeof process.stdin.setRawMode !== "function"
  ) {
    throw new Error(
      "Secure enrollment-code input requires an interactive terminal. Run this command directly in PowerShell."
    );
  }

  process.stdout.write(
    "Enter the Control Plane enrollment code (input hidden): "
  );

  process.stdin.setRawMode(true);
  process.stdin.resume();

  return await new Promise<string>((resolve, reject) => {
    let value = "";
    let settled = false;

    const cleanup = () => {
      process.stdin.off("data", onData);
      process.stdin.off("error", onError);

      try {
        process.stdin.setRawMode(false);
      } catch {
        // Best-effort terminal restoration.
      }

      process.stdin.pause();
      process.stdout.write("\n");
    };

    const finish = (
      error?: Error,
      result?: string
    ) => {
      if (settled) return;
      settled = true;
      cleanup();

      if (error) {
        reject(error);
      } else {
        resolve(result ?? "");
      }
    };

    const onError = (error: Error) => {
      finish(error);
    };

    const onData = (chunk: Buffer) => {
      const input = chunk.toString("utf8");

      for (const character of input) {
        if (character === "\u0003") {
          finish(new Error("Enrollment cancelled."));
          return;
        }

        if (character === "\r" || character === "\n") {
          if (value.length === 0) {
            process.stdout.write(
              "\nEnrollment code cannot be empty. Try again: "
            );
            continue;
          }

          finish(undefined, value);
          return;
        }

        if (
          character === "\u007f" ||
          character === "\b"
        ) {
          value = value.slice(0, -1);
          continue;
        }

        if (/^[A-Za-z0-9_-]$/.test(character)) {
          value += character;
        }
      }
    };

    process.stdin.on("data", onData);
    process.stdin.on("error", onError);
  });
}

async function main(): Promise<void> {
  let enrollmentCode = "";
  let database:
    | typeof import("../data-plane/src/db.js")
    | undefined;

  try {
    console.log("\nAIndigo Data Plane Node Enrollment");
    console.log("----------------------------------");

    // Validate all configuration before opening the Data Plane database.
    const config = validateConfig();

    console.log("Configuration validated.");
    console.log("Control Plane:", config.controlPlaneUrl);
    console.log("Database:", config.databasePath);
    console.log("Node keys directory:", config.nodeKeysDir);
    console.log("Control Plane signing key ID:", config.signingKeyId);

    // Load or create the persistent local Ed25519 node identity.
    const identity = getOrCreateNodeIdentity(
      config.nodeKeysDir
    );

    console.log("\nData Plane node identity ready.");
    console.log("Node ID:", identity.nodeId);
    console.log(
      "Public key fingerprint:",
      identity.publicKeyFingerprint
    );

    // The enrollment code is entered without terminal echo.
    enrollmentCode = await readHiddenEnrollmentCode();

    if (!/^[A-Za-z0-9_-]{32,256}$/.test(enrollmentCode)) {
      throw new Error(
        "Enrollment code format is invalid. Generate a new code from the Control Plane."
      );
    }

    console.log("\nOpening the existing Data Plane database...");
    process.env.DATA_PLANE_DB_PATH = config.databasePath;
    database = await import("../data-plane/src/db.js");

    console.log("Database initialized.");
    console.log("\nStarting Control Plane enrollment...");

    const result = await enrollDataPlaneNode({
      controlPlaneUrl: config.controlPlaneUrl,
      enrollmentCode,
      controlPlanePublicKeyPem:
        config.controlPlanePublicKeyPem,
      expectedSigningKeyId: config.signingKeyId,
      identity,

      // Persist the verified lease using the already-open database.
      persistLease: (
        lease,
        publicKeyPem,
        nodeIdentity,
        tenantId,
        nowMs,
        expectedKeyId
      ) => {
        return database!.verifyAndPersistDataPlaneNodeLease(
          lease,
          publicKeyPem,
          nodeIdentity,
          tenantId,
          nowMs,
          expectedKeyId
        );
      },
    });

    console.log("\nEnrollment successful.");
    console.log("---------------------");
    console.log("Node ID:", result.nodeId);
    console.log("Tenant ID:", result.tenantId);
    console.log(
      "Public key fingerprint:",
      result.publicKeyFingerprint
    );
    console.log("Node label:", result.label);
    console.log("Lease ID:", result.leaseId);
    console.log("Lease expires:", result.leaseExpiresAt);

    console.log(
      "\nThe signed node lease has been verified and persisted locally."
    );
  } finally {
    // Do not retain the enrollment code in the CLI variable.
    enrollmentCode = "";

    if (database) {
      database.closeDataPlaneDatabase();
    }
  }
}

main().catch((error: unknown) => {
  const message =
    error instanceof Error
      ? error.message
      : "An unexpected enrollment error occurred.";

  console.error("\nEnrollment failed:", message);
  process.exitCode = 1;
});
