import { strict as assert } from 'node:assert';
import { SyncWorkerLifecycle } from './sync-worker-lifecycle.js';

function deferred<T>() {
  let resolve!: (value: T) => void;

  const promise = new Promise<T>((res) => {
    resolve = res;
  });

  return { promise, resolve };
}

async function runLifecycleTests() {
  console.log('==============================================================');
  console.log(' AIndigo — Sync Worker Lifecycle Tests');
  console.log('==============================================================');

  // 1. Concurrent calls share the same active Promise.
  {
    const lifecycle = new SyncWorkerLifecycle<string>();
    const gate = deferred<string>();

    let executions = 0;

    const task = async () => {
      executions++;
      return gate.promise;
    };

    const first = lifecycle.run(task, 'STOPPED');
    const second = lifecycle.run(task, 'STOPPED');

    assert.equal(first, second);
    assert.equal(executions, 0);

    await Promise.resolve();

    assert.equal(executions, 1);

    gate.resolve('COMPLETED');

    assert.equal(await first, 'COMPLETED');
    assert.equal(await second, 'COMPLETED');

    console.log('PASS 1 — Concurrent callers share one active Promise.');
  }

  // 2. Wait for active synchronization.
  {
    const lifecycle = new SyncWorkerLifecycle<string>();
    const gate = deferred<string>();

    const active = lifecycle.run(
      () => gate.promise,
      'STOPPED'
    );

    assert.equal(await lifecycle.waitForIdle(10), false);

    gate.resolve('COMPLETED');

    await active;

    assert.equal(await lifecycle.waitForIdle(100), true);

    console.log('PASS 2 — Wait-for-idle correctly tracks active work.');
  }

  // 3. Stop prevents new work but preserves active work.
  {
    const lifecycle = new SyncWorkerLifecycle<string>();
    const gate = deferred<string>();

    let executions = 0;

    const task = async () => {
      executions++;
      return gate.promise;
    };

    const active = lifecycle.run(task, 'STOPPED');

    await Promise.resolve();

    lifecycle.stop();

    const afterStop = await lifecycle.run(task, 'STOPPED');

    assert.equal(afterStop, 'STOPPED');
    assert.equal(executions, 1);
    assert.equal(lifecycle.isStopped, true);

    gate.resolve('COMPLETED');

    assert.equal(await active, 'COMPLETED');

    console.log('PASS 3 — Shutdown prevents new work and preserves active work.');
  }

  // 4. Background timer starts only once.
  {
    const lifecycle = new SyncWorkerLifecycle<string>();

    const task = async () => 'COMPLETED';

    lifecycle.start(task, 1000, 'STOPPED');
    lifecycle.start(task, 1000, 'STOPPED');

    assert.equal(lifecycle.hasTimer, true);

    lifecycle.stop();

    assert.equal(lifecycle.hasTimer, false);

    console.log('PASS 4 — Timer startup is idempotent and stoppable.');
  }

  // 5. Invalid intervals are rejected.
  {
    const lifecycle = new SyncWorkerLifecycle<string>();

    assert.throws(
      () => lifecycle.start(async () => 'OK', 0, 'STOPPED')
    );

    assert.throws(
      () => lifecycle.start(async () => 'OK', -1, 'STOPPED')
    );

    console.log('PASS 5 — Invalid timer intervals are rejected.');
  }

  console.log('==============================================================');
  console.log(' ALL SYNC WORKER LIFECYCLE TESTS PASSED');
  console.log('==============================================================');
}

runLifecycleTests().catch((error) => {
  console.error('SYNC LIFECYCLE TEST FAILED:', error);
  process.exitCode = 1;
});
