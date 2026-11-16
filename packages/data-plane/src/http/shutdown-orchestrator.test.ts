import test from 'node:test';
import assert from 'node:assert/strict';

import {
  createGracefulShutdown,
  type ShutdownServer,
  type ShutdownRequestLifecycle,
  type ShutdownOutcome,
} from './shutdown-orchestrator.js';

class FakeServer implements ShutdownServer {
  public closeCalls = 0;
  public idleCloseCalls = 0;
  public forceCloseCalls = 0;

  private closeCallback: ((error?: Error) => void) | null = null;
  private closeImmediately: boolean;
  private closeError: Error | null;

  constructor(options?: {
    closeImmediately?: boolean;
    closeError?: Error;
    closeOnForce?: boolean;
  }) {
    this.closeImmediately = options?.closeImmediately ?? true;
    this.closeError = options?.closeError ?? null;
    this.closeOnForce = options?.closeOnForce ?? false;
  }

  private closeOnForce: boolean;

  public close(callback: (error?: Error) => void): void {
    this.closeCalls += 1;
    this.closeCallback = callback;

    if (this.closeImmediately) {
      this.completeClose();
    }
  }

  public closeIdleConnections(): void {
    this.idleCloseCalls += 1;
  }

  public closeAllConnections(): void {
    this.forceCloseCalls += 1;

    if (this.closeOnForce) {
      this.completeClose();
    }
  }

  public completeClose(): void {
    const callback = this.closeCallback;

    if (!callback) {
      return;
    }

    this.closeCallback = null;
    callback(this.closeError ?? undefined);
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

    const result = this.results.shift();

    return result ?? true;
  }
}

function createTestLogger(): {
  log: (...args: unknown[]) => void;
  error: (...args: unknown[]) => void;
} {
  return {
    log: () => undefined,
    error: () => undefined,
  };
}

function createHarness(options?: {
  server?: FakeServer;
  requests?: FakeRequests;
  syncResults?: boolean[];
  gracePeriodMs?: number;
  recoveryPeriodMs?: number;
  serverCloseTimeoutMs?: number;
}) {
  const server = options?.server ?? new FakeServer();
  const requests = options?.requests ?? new FakeRequests();
  const events: string[] = [];

  let stopSyncCalls = 0;
  let closeDatabaseCalls = 0;

  const syncResults = options?.syncResults ?? [true];

  const shutdown = createGracefulShutdown(
    {
      server,
      requests,
      stopSync: () => {
        stopSyncCalls += 1;
        events.push('stopSync');
      },
      waitForSyncIdle: async () => syncResults.shift() ?? true,
      closeDatabase: () => {
        closeDatabaseCalls += 1;
        events.push('closeDatabase');
      },
      logger: createTestLogger(),
    },
    {
      gracePeriodMs: options?.gracePeriodMs ?? 10,
      recoveryPeriodMs: options?.recoveryPeriodMs ?? 10,
      serverCloseTimeoutMs: options?.serverCloseTimeoutMs ?? 10,
    },
  );

  return {
    shutdown,
    server,
    requests,
    events,
    get stopSyncCalls() {
      return stopSyncCalls;
    },
    get closeDatabaseCalls() {
      return closeDatabaseCalls;
    },
  };
}

test('1. Normal shutdown closes the database after server closure', async () => {
  const harness = createHarness();

  const outcome = await harness.shutdown('SIGTERM');

  assert.equal(outcome, 'CLOSED');
  assert.equal(harness.server.closeCalls, 1);
  assert.equal(harness.server.idleCloseCalls, 1);
  assert.equal(harness.closeDatabaseCalls, 1);
  assert.equal(harness.requests.startDrainingCalls, 1);
  assert.equal(harness.stopSyncCalls, 1);
  assert.deepEqual(harness.events, ['stopSync', 'closeDatabase']);
});

test('2. Shutdown waits for both HTTP requests and sync work', async () => {
  const requests = new FakeRequests([true]);
  const harness = createHarness({
    requests,
    syncResults: [true],
  });

  const outcome = await harness.shutdown('SIGINT');

  assert.equal(outcome, 'CLOSED');
  assert.deepEqual(requests.waitCalls, [10]);
  assert.equal(harness.closeDatabaseCalls, 1);
});

test('3. Repeated shutdown calls share one shutdown operation', async () => {
  const harness = createHarness();

  const first = harness.shutdown('SIGTERM');
  const second = harness.shutdown('SIGINT');

  assert.strictEqual(first, second);

  const [firstOutcome, secondOutcome] = await Promise.all([
    first,
    second,
  ]);

  assert.equal(firstOutcome, 'CLOSED');
  assert.equal(secondOutcome, 'CLOSED');
  assert.equal(harness.server.closeCalls, 1);
  assert.equal(harness.requests.startDrainingCalls, 1);
  assert.equal(harness.stopSyncCalls, 1);
  assert.equal(harness.closeDatabaseCalls, 1);
});

test('4. HTTP timeout force-closes connections before recovery', async () => {
  const requests = new FakeRequests([false, true]);
  const harness = createHarness({ requests });

  const outcome = await harness.shutdown('SIGTERM');

  assert.equal(outcome, 'CLOSED');
  assert.equal(harness.server.forceCloseCalls, 1);
  assert.equal(harness.closeDatabaseCalls, 1);
  assert.deepEqual(requests.waitCalls, [10, 10]);
});

test('5. Sync timeout alone does not force-close HTTP connections', async () => {
  const harness = createHarness({
    syncResults: [false, true],
  });

  const outcome = await harness.shutdown('SIGTERM');

  assert.equal(outcome, 'CLOSED');
  assert.equal(harness.server.forceCloseCalls, 0);
  assert.equal(harness.closeDatabaseCalls, 1);
});

test('6. Unrecovered HTTP work prevents database closure', async () => {
  const requests = new FakeRequests([false, false]);
  const harness = createHarness({ requests });

  const outcome = await harness.shutdown('SIGTERM');

  assert.equal(outcome, 'WORK_DRAIN_FAILED');
  assert.equal(harness.server.forceCloseCalls, 1);
  assert.equal(harness.closeDatabaseCalls, 0);
});

test('7. Unrecovered sync work prevents database closure', async () => {
  const harness = createHarness({
    syncResults: [false, false],
  });

  const outcome = await harness.shutdown('SIGTERM');

  assert.equal(outcome, 'WORK_DRAIN_FAILED');
  assert.equal(harness.server.forceCloseCalls, 0);
  assert.equal(harness.closeDatabaseCalls, 0);
});

test('8. Server close timeout force-closes connections and retries confirmation', async () => {
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
  assert.equal(server.closeCalls, 1);
  assert.equal(server.forceCloseCalls, 1);
  assert.equal(harness.closeDatabaseCalls, 1);
});

test('9. Server that never confirms closure keeps database open', async () => {
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
  assert.equal(server.forceCloseCalls, 1);
  assert.equal(harness.closeDatabaseCalls, 0);
});

test('10. Server close callback error keeps database open', async () => {
  const server = new FakeServer({
    closeImmediately: true,
    closeError: new Error('Simulated server close failure'),
  });

  const harness = createHarness({ server });

  const outcome = await harness.shutdown('SIGTERM');

  assert.equal(outcome, 'SERVER_CLOSE_FAILED');
  assert.equal(harness.closeDatabaseCalls, 0);
});

test('11. Invalid timeout configuration is rejected', () => {
  const server = new FakeServer();
  const requests = new FakeRequests();

  assert.throws(
    () => createGracefulShutdown(
      {
        server,
        requests,
        stopSync: () => undefined,
        waitForSyncIdle: async () => true,
        closeDatabase: () => undefined,
        logger: createTestLogger(),
      },
      { gracePeriodMs: -1 },
    ),
    /gracePeriodMs must be a non-negative safe integer/,
  );
});

test('12. Database close failure returns FAILED', async () => {
  const server = new FakeServer();
  const requests = new FakeRequests();

  const shutdown = createGracefulShutdown(
    {
      server,
      requests,
      stopSync: () => undefined,
      waitForSyncIdle: async () => true,
      closeDatabase: () => {
        throw new Error('Simulated database close failure');
      },
      logger: createTestLogger(),
    },
    {
      gracePeriodMs: 10,
      recoveryPeriodMs: 10,
      serverCloseTimeoutMs: 10,
    },
  );

  const outcome: ShutdownOutcome = await shutdown('SIGTERM');

  assert.equal(outcome, 'FAILED');
});