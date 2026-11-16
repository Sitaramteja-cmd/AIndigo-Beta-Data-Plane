import test from 'node:test';
import assert from 'node:assert/strict';

import { InMemoryRateLimiter } from './rate-limiter.js';

const MINUTE = 60 * 1000;

test('1. Allows requests below the configured limit', () => {
  let now = 1_000;
  const limiter = new InMemoryRateLimiter(() => now);

  for (let i = 0; i < 10; i++) {
    assert.equal(limiter.check('login', '127.0.0.1'), null);
  }

  assert.equal(limiter.bucketCount, 1);
});

test('2. Blocks requests after the configured limit', () => {
  const limiter = new InMemoryRateLimiter(() => 1_000);

  for (let i = 0; i < 10; i++) {
    limiter.check('login', '127.0.0.1');
  }

  assert.equal(
    limiter.check('login', '127.0.0.1'),
    900,
  );
});

test('3. Returns a Retry-After value rounded up to seconds', () => {
  let now = 1_000;
  const limiter = new InMemoryRateLimiter(() => now);

  for (let i = 0; i < 10; i++) {
    limiter.check('login', '127.0.0.1');
  }

  now += 1_500;

  assert.equal(
    limiter.check('login', '127.0.0.1'),
    899,
  );
});

test('4. Resets a bucket after its configured window expires', () => {
  let now = 1_000;
  const limiter = new InMemoryRateLimiter(() => now);

  for (let i = 0; i < 10; i++) {
    limiter.check('login', '127.0.0.1');
  }

  assert.equal(
    limiter.check('login', '127.0.0.1'),
    900,
  );

  now += 15 * MINUTE;

  assert.equal(
    limiter.check('login', '127.0.0.1'),
    null,
  );
});

test('5. Keeps endpoint buckets independent', () => {
  const limiter = new InMemoryRateLimiter(() => 1_000);

  for (let i = 0; i < 10; i++) {
    limiter.check('login', '127.0.0.1');
  }

  assert.equal(
    limiter.check('login', '127.0.0.1'),
    900,
  );

  assert.equal(
    limiter.check('enrollment-code-create', '127.0.0.1'),
    null,
  );
});

test('6. Keeps client address buckets independent', () => {
  const limiter = new InMemoryRateLimiter(() => 1_000);

  for (let i = 0; i < 10; i++) {
    limiter.check('login', '127.0.0.1');
  }

  assert.equal(
    limiter.check('login', '127.0.0.2'),
    null,
  );
});

test('7. Uses the correct window for registration', () => {
  let now = 1_000;
  const limiter = new InMemoryRateLimiter(() => now);

  for (let i = 0; i < 5; i++) {
    limiter.check('register', '127.0.0.1');
  }

  assert.equal(
    limiter.check('register', '127.0.0.1'),
    3_600,
  );

  now += 15 * MINUTE;

  assert.equal(
    limiter.check('register', '127.0.0.1'),
    2_700,
  );
});

test('8. Cleans expired buckets using each bucket actual window', () => {
  let now = 1_000;
  const limiter = new InMemoryRateLimiter(() => now);

  // Fill the registration bucket to its five-request limit.
  for (let i = 0; i < 5; i++) {
    assert.equal(limiter.check('register', '192.0.2.1'), null);
  }

  limiter.check('login', '192.0.2.2');

  assert.equal(limiter.bucketCount, 2);

  // The login bucket expires, but registration still has 44 minutes.
  now += 16 * MINUTE;

  // Reach operation 256 to trigger periodic cleanup.
  for (let i = 0; i < 250; i++) {
    limiter.check('login', `198.51.100.${i}`);
  }

  // The expired login bucket is removed; registration remains.
  assert.equal(limiter.bucketCount, 251);

  // The sixth registration request is still blocked.
  assert.equal(
    limiter.check('register', '192.0.2.1'),
    2_640,
  );
});

test('9. Bounds memory usage when many addresses connect', () => {
  const limiter = new InMemoryRateLimiter(
    () => 1_000,
    2,
  );

  limiter.check('login', '192.0.2.1');
  limiter.check('login', '192.0.2.2');
  limiter.check('login', '192.0.2.3');

  assert.equal(limiter.bucketCount, 2);
});

test('10. Rejects invalid bucket capacity', () => {
  assert.throws(
    () => new InMemoryRateLimiter(Date.now, 0),
    /maxBuckets must be a positive safe integer/,
  );
});

test('11. Limits registered-node revocation attempts', () => {
  const limiter = new InMemoryRateLimiter(() => 1_000);

  for (let i = 0; i < 10; i++) {
    assert.equal(limiter.check('node-revoke', '127.0.0.1'), null);
  }

  assert.equal(
    limiter.check('node-revoke', '127.0.0.1'),
    900,
  );
});