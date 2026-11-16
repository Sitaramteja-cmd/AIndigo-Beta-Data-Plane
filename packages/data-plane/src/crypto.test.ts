import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  decryptSecret,
  encryptSecret,
  getMasterKey,
} from './crypto.js';

const VALID_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

function withEnvironment(
  values: Record<string, string | undefined>,
  callback: () => void,
): void {
  const previous = new Map<string, string | undefined>();

  for (const key of Object.keys(values)) {
    previous.set(key, process.env[key]);
  }

  try {
    for (const [key, value] of Object.entries(values)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }

    callback();
  } finally {
    for (const [key, value] of previous) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
}

test('reads a valid master key from the environment fallback', () => {
  withEnvironment(
    {
      DATA_PLANE_MASTER_KEY: VALID_KEY,
      DATA_PLANE_MASTER_KEY_FILE: undefined,
    },
    () => {
      assert.deepEqual(getMasterKey(), Buffer.from(VALID_KEY, 'hex'));
    },
  );
});

test('reads a valid master key from a secret file', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'aindigo-crypto-'));
  const secretPath = path.join(directory, 'master-key');

  try {
    fs.writeFileSync(secretPath, `${VALID_KEY}\n`, 'utf8');

    withEnvironment(
      {
        DATA_PLANE_MASTER_KEY: undefined,
        DATA_PLANE_MASTER_KEY_FILE: secretPath,
      },
      () => {
        assert.deepEqual(getMasterKey(), Buffer.from(VALID_KEY, 'hex'));
      },
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('secret file takes precedence over environment fallback', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'aindigo-crypto-'));
  const secretPath = path.join(directory, 'master-key');

  const fileKey = 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789';

  try {
    fs.writeFileSync(secretPath, fileKey, 'utf8');

    withEnvironment(
      {
        DATA_PLANE_MASTER_KEY: VALID_KEY,
        DATA_PLANE_MASTER_KEY_FILE: secretPath,
      },
      () => {
        assert.deepEqual(getMasterKey(), Buffer.from(fileKey, 'hex'));
      },
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('rejects a missing configured secret file without falling back', () => {
  withEnvironment(
    {
      DATA_PLANE_MASTER_KEY: VALID_KEY,
      DATA_PLANE_MASTER_KEY_FILE: path.join(os.tmpdir(), 'aindigo-missing-secret'),
    },
    () => {
      assert.throws(
        () => getMasterKey(),
        /CRITICAL_SECURITY_CONFIG/,
      );
    },
  );
});

test('rejects an invalid hexadecimal environment key', () => {
  withEnvironment(
    {
      DATA_PLANE_MASTER_KEY: 'z'.repeat(64),
      DATA_PLANE_MASTER_KEY_FILE: undefined,
    },
    () => {
      assert.throws(
        () => getMasterKey(),
        /CRITICAL_SECURITY_CONFIG/,
      );
    },
  );
});

test('rejects a secret file containing an invalid key', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'aindigo-crypto-'));
  const secretPath = path.join(directory, 'master-key');

  try {
    fs.writeFileSync(secretPath, `${'a'.repeat(63)}x`, 'utf8');

    withEnvironment(
      {
        DATA_PLANE_MASTER_KEY: undefined,
        DATA_PLANE_MASTER_KEY_FILE: secretPath,
      },
      () => {
        assert.throws(
          () => getMasterKey(),
          /CRITICAL_SECURITY_CONFIG/,
        );
      },
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('AES-256-GCM encryption and decryption remain compatible', () => {
  withEnvironment(
    {
      DATA_PLANE_MASTER_KEY: VALID_KEY,
      DATA_PLANE_MASTER_KEY_FILE: undefined,
    },
    () => {
      const plaintext = 'aindigo-provider-credential-test';
      const encrypted = encryptSecret(plaintext);

      assert.equal(decryptSecret(encrypted), plaintext);
      assert.equal(encrypted.iv.length, 24);
      assert.equal(encrypted.authTag.length, 32);
    },
  );
});