import test from 'node:test';
import assert from 'node:assert/strict';

import { HttpRequestLifecycle } from './request-lifecycle.js';

test('1. Tracks active requests', () => {
  const lifecycle = new HttpRequestLifecycle();

  const release = lifecycle.tryAcquire();

  assert.ok(release);
  assert.equal(lifecycle.activeCount, 1);
  assert.equal(lifecycle.isDraining, false);

  release();

  assert.equal(lifecycle.activeCount, 0);
});

test('2. Refuses new work after draining starts', () => {
  const lifecycle = new HttpRequestLifecycle();

  const release = lifecycle.tryAcquire();

  assert.ok(release);

  lifecycle.startDraining();

  assert.equal(lifecycle.isDraining, true);
  assert.equal(lifecycle.tryAcquire(), null);
  assert.equal(lifecycle.activeCount, 1);

  release();

  assert.equal(lifecycle.activeCount, 0);
});

test('3. Request release is idempotent', () => {
  const lifecycle = new HttpRequestLifecycle();

  const release = lifecycle.tryAcquire();

  assert.ok(release);

  release();
  release();

  assert.equal(lifecycle.activeCount, 0);
});

test('4. Waits until active requests finish', async () => {
  const lifecycle = new HttpRequestLifecycle();

  const release = lifecycle.tryAcquire();

  assert.ok(release);

  const idlePromise = lifecycle.waitForIdle(1_000);

  release();

  assert.equal(await idlePromise, true);
  assert.equal(lifecycle.activeCount, 0);
});

test('5. Returns false when requests do not finish before timeout', async () => {
  const lifecycle = new HttpRequestLifecycle();

  const release = lifecycle.tryAcquire();

  assert.ok(release);

  const idle = await lifecycle.waitForIdle(10);

  assert.equal(idle, false);
  assert.equal(lifecycle.activeCount, 1);

  release();
});

test('6. Rejects invalid timeout values', async () => {
  const lifecycle = new HttpRequestLifecycle();

  await assert.rejects(
    lifecycle.waitForIdle(-1),
    /non-negative safe integer/,
  );

  await assert.rejects(
    lifecycle.waitForIdle(Number.NaN),
    /non-negative safe integer/,
  );
});
