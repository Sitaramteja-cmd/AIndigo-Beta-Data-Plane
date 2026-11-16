import test from 'node:test';

import assert from 'node:assert/strict';

import { createServer, type Server } from 'node:http';

import { once } from 'node:events';



import { HttpRequestLifecycle } from './request-lifecycle.js';

import { createGracefulShutdown } from './shutdown-orchestrator.js';



test('real HTTP server drains active request before database closure', async () => {

  const requests = new HttpRequestLifecycle();



  let signalRequestEntered!: () => void;

  const requestEntered = new Promise<void>((resolve) => {

    signalRequestEntered = resolve;

  });



  let releaseHeldRequest!: () => void;

  const heldRequestReleased = new Promise<void>((resolve) => {

    releaseHeldRequest = resolve;

  });



  let databaseCloseCalls = 0;

  let databaseClosedAfterServer = false;

  let databaseClosedAfterRequests = false;



  const server: Server = createServer(async (req, res) => {

    const release = requests.tryAcquire();



    if (!release) {

      res.writeHead(503, {

        'content-type': 'application/json',

        'connection': 'close',

      });



      res.end(JSON.stringify({ error: 'SERVER_DRAINING' }));

      return;

    }



    try {

      if (req.url === '/hold') {

        signalRequestEntered();



        await heldRequestReleased;



        res.writeHead(200, { 'content-type': 'text/plain' });

        res.end('request-completed');

        return;

      }



      res.writeHead(200, { 'content-type': 'text/plain' });

      res.end('ok');

    } finally {

      release();

    }

  });



  server.listen(0, '127.0.0.1');

  await once(server, 'listening');



  const address = server.address();



  assert.ok(address);

  assert.equal(typeof address, 'object');



  const url = `http://127.0.0.1:${address.port}`;



  const shutdown = createGracefulShutdown(

    {

      server,

      requests,

      closeDatabase: () => {

        databaseCloseCalls += 1;

        databaseClosedAfterServer = !server.listening;

        databaseClosedAfterRequests = requests.activeCount === 0;

      },

      logger: {

        log: () => undefined,

        error: (...args: unknown[]) => {

          process.stderr.write(

            `[runtime-test] ${args.map(String).join(' ')}\n`,

          );

        },

      },

    },

    {

      gracePeriodMs: 2_000,

      recoveryPeriodMs: 1_000,

      serverCloseTimeoutMs: 2_000,

    },

  );



  try {

    const activeRequest = fetch(`${url}/hold`, {

      headers: { connection: 'close' },

    });



    await requestEntered;



    assert.equal(requests.activeCount, 1);

    assert.equal(requests.isDraining, false);



    const shutdownPromise = shutdown('SIGTERM');



    assert.equal(requests.isDraining, true);

    assert.equal(requests.activeCount, 1);



    // The lifecycle refuses new application work during draining.

    assert.equal(requests.tryAcquire(), null);



    // Existing work is allowed to finish.

    releaseHeldRequest();



    const response = await activeRequest;



    assert.equal(response.status, 200);

    assert.equal(await response.text(), 'request-completed');



    const outcome = await shutdownPromise;



    assert.equal(outcome, 'CLOSED');

    assert.equal(server.listening, false);

    assert.equal(requests.activeCount, 0);



    assert.equal(databaseCloseCalls, 1);

    assert.equal(databaseClosedAfterServer, true);

    assert.equal(databaseClosedAfterRequests, true);

  } finally {

    // Ensure a failed assertion cannot leave the test server running.

    releaseHeldRequest();



    if (server.listening) {

      await new Promise<void>((resolve) => {

        server.close(() => resolve());

        server.closeAllConnections();

      });

    }

  }

});
