import test from 'node:test';
import assert from 'node:assert/strict';

import {
  createGracefulShutdown,
  type ShutdownServer,
  type ShutdownRequestLifecycle,
} from './shutdown-orchestrator.js';

class FakeServer implements ShutdownServer {
  public closeCalls = 0;
  public idleCloseCalls = 0;
  public forceCloseCalls = 0;

  private closeCallback: ((error?: Error) => void) | null = null;

  constructor(
    private readonly options: {
      closeImmediately?: boolean;
      closeError?: Error;
      closeOnForce?: boolean;
    } = {},
  ) {}

  public close(callback: (error?: Error) => void): void {
    this.closeCalls += 1;
    this.closeCallback = callback;

    if (this.options.closeImmediately ?? true) {
      this.completeClose();
    }
  }

  public closeIdleConnections(): void {
    this.idleCloseCalls += 1;
  }

  public closeAllConnections(): void {
    this.forceCloseCalls += 1;

    if (this.options.closeOnForce) {
      this.completeClose();
    }
  }

  public completeClose(): void {
    const callback = this.closeCallback;

    if (!callback) {
      return;
    }

    this.closeCallback = null;
    callback(this.options.closeError);
  }
}

class FakeRequests implements ShutdownRequestLifecycle {
  public startDrainingCalls = 0;
  public waitCalls: number[] = [];
  public activeCount = 0;

  constructor(private readonly results: boolean[] = [true]) {}

  public startDraining(): void {
    this.startDrainingCalls += 1;
  }

  public async waitForIdle(timeoutMs: number): Promise<boolean> {
    this.waitCalls.push(timeoutMs);
    return this.results.shift() ?? true;
  }
}

function createLogger() {
  return {
    log: () => undefined,
    error: () => undefined,
  };
}

function createHarness(options: {
  server?: FakeServer;
  requests?: FakeRequests;
  gracePeriodMs?: number;
  recoveryPeriodMs?: number;
  serverCloseTimeoutMs?: number;
} = {}) {
  const server = options.server ?? new FakeServer();
  const requests = options.requests ?? new FakeRequests();

  let closeDatabaseCalls = 0;

  const shutdown = createGracefulShutdown(
    {
      server,
      requests,
      closeDatabase: () => {
        closeDatabaseCalls += 1;
      },
      logger: createLogger(),
    },
    {
      gracePeriodMs: options.gracePeriodMs ?? 10,
      recoveryPeriodMs: options.recoveryPeriodMs ?? 10,
      serverCloseTimeoutMs: options.serverCloseTimeoutMs ?? 10,
    },
  );

  return {
    shutdown,
    server,
    requests,
    get closeDatabaseCalls() {
      return closeDatabaseCalls;
    },
  };
}

test('1. Normal shutdown closes database after HTTP server closure', async () => {
  const harness = createHarness();

  const outcome = await harness.shutdown('SIGTERM');

  assert.equal(outcome, 'CLOSED');
  assert.equal(harness.server.closeCalls, 1);
  assert.equal(harness.server.idleCloseCalls, 1);
  assert.equal(harness.requests.startDrainingCalls, 1);
  assert.equal(harness.closeDatabaseCalls, 1);
});

test('2. Repeated shutdown calls share one operation', async () => {
  const harness = createHarness();

  const first = harness.shutdown('SIGTERM');
  const second = harness.shutdown('SIGINT');

  assert.strictEqual(first, second);

  assert.equal(await first, 'CLOSED');
  assert.equal(await second, 'CLOSED');
  assert.equal(harness.server.closeCalls, 1);
  assert.equal(harness.closeDatabaseCalls, 1);
});

test('3. Active requests are force-closed after grace timeout', async () => {
  const requests = new FakeRequests([false, true]);
  const harness = createHarness({ requests });

  const outcome = await harness.shutdown('SIGTERM');

  assert.equal(outcome, 'CLOSED');
  assert.equal(harness.server.forceCloseCalls, 1);
  assert.equal(harness.closeDatabaseCalls, 1);
  assert.deepEqual(requests.waitCalls, [10, 10]);
});

test('4. Unrecovered requests prevent database closure', async () => {
  const requests = new FakeRequests([false, false]);
  const harness = createHarness({ requests });

  const outcome = await harness.shutdown('SIGTERM');

  assert.equal(outcome, 'WORK_DRAIN_FAILED');
  assert.equal(harness.server.forceCloseCalls, 1);
  assert.equal(harness.closeDatabaseCalls, 0);
});

test('5. Server close timeout forces connections and retries confirmation', async () => {
  const server = new FakeServer({
    closeImmediately: false,
    closeOnForce: true,
  });

  const harness = createHarness({
    server,
    serverCloseTimeoutMs: 0,
  });

  const outcome = await harness.shutdown('SIGTERM');

  assert.equal(outcome, 'CLOSED');
  assert.equal(server.forceCloseCalls, 1);
  assert.equal(harness.closeDatabaseCalls, 1);
});

test('6. Server that never confirms closure keeps database open', async () => {
  const server = new FakeServer({
    closeImmediately: false,
    closeOnForce: false,
  });

  const harness = createHarness({
    server,
    serverCloseTimeoutMs: 0,
  });

  const outcome = await harness.shutdown('SIGTERM');

  assert.equal(outcome, 'SERVER_CLOSE_TIMEOUT');
  assert.equal(harness.closeDatabaseCalls, 0);
});

test('7. Server close callback error keeps database open', async () => {
  const server = new FakeServer({
    closeImmediately: true,
    closeError: new Error('Simulated close failure'),
  });

  const harness = createHarness({ server });

  const outcome = await harness.shutdown('SIGTERM');

  assert.equal(outcome, 'SERVER_CLOSE_FAILED');
  assert.equal(harness.closeDatabaseCalls, 0);
});

test('8. Invalid timeout configuration is rejected', () => {
  assert.throws(
    () => createGracefulShutdown(
      {
        server: new FakeServer(),
        requests: new FakeRequests(),
        closeDatabase: () => undefined,
        logger: createLogger(),
      },
      { gracePeriodMs: -1 },
    ),
    /gracePeriodMs must be a non-negative safe integer/,
  );
});

test('9. Database close failure returns FAILED', async () => {
  const shutdown = createGracefulShutdown(
    {
      server: new FakeServer(),
      requests: new FakeRequests(),
      closeDatabase: () => {
        throw new Error('Simulated database close failure');
      },
      logger: createLogger(),
    },
    {
      gracePeriodMs: 10,
      recoveryPeriodMs: 10,
      serverCloseTimeoutMs: 10,
    },
  );

  assert.equal(await shutdown('SIGTERM'), 'FAILED');
});
