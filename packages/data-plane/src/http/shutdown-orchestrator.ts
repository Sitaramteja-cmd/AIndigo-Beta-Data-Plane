export interface ShutdownServer {
  close(callback: (error?: Error) => void): void;
  closeIdleConnections(): void;
  closeAllConnections(): void;
}

export interface ShutdownRequestLifecycle {
  startDraining(): void;
  readonly activeCount: number;
  waitForIdle(timeoutMs: number): Promise<boolean>;
}

export interface GracefulShutdownDependencies {
  server: ShutdownServer;
  requests: ShutdownRequestLifecycle;
  stopSync(): void;
  waitForSyncIdle(timeoutMs: number): Promise<boolean>;
  closeDatabase(): void;
  logger?: Pick<Console, 'log' | 'error'>;
}

export interface GracefulShutdownTimeouts {
  gracePeriodMs?: number;
  recoveryPeriodMs?: number;
  serverCloseTimeoutMs?: number;
}

export type ShutdownOutcome =
  | 'CLOSED'
  | 'WORK_DRAIN_FAILED'
  | 'SERVER_CLOSE_TIMEOUT'
  | 'SERVER_CLOSE_FAILED'
  | 'FAILED';

type ServerCloseResult = 'CLOSED' | 'TIMEOUT' | 'ERROR';

const DEFAULT_TIMEOUTS: Required<GracefulShutdownTimeouts> = {
  gracePeriodMs: 30_000,
  recoveryPeriodMs: 15_000,
  serverCloseTimeoutMs: 5_000,
};

function validateTimeout(name: string, value: number): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(
      `${name} must be a non-negative safe integer.`,
    );
  }
}

export function createGracefulShutdown(
  dependencies: GracefulShutdownDependencies,
  configuredTimeouts: GracefulShutdownTimeouts = {},
): (signal: NodeJS.Signals) => Promise<ShutdownOutcome> {
  const logger = dependencies.logger ?? console;

  const timeouts: Required<GracefulShutdownTimeouts> = {
    ...DEFAULT_TIMEOUTS,
    ...configuredTimeouts,
  };

  validateTimeout('gracePeriodMs', timeouts.gracePeriodMs);
  validateTimeout('recoveryPeriodMs', timeouts.recoveryPeriodMs);
  validateTimeout('serverCloseTimeoutMs', timeouts.serverCloseTimeoutMs);

  let shutdownPromise: Promise<ShutdownOutcome> | null = null;

  return (signal: NodeJS.Signals): Promise<ShutdownOutcome> => {
    if (shutdownPromise) {
      return shutdownPromise;
    }

    shutdownPromise = (async (): Promise<ShutdownOutcome> => {
      logger.log(
        `[shutdown] Received ${signal}. Starting graceful shutdown.`,
      );

      dependencies.requests.startDraining();
      dependencies.stopSync();

      // Start closing the listener immediately. Existing requests
      // are allowed to finish during the drain period.
      const serverClosed = new Promise<void>((resolve, reject) => {
        dependencies.server.close((error) => {
          if (error) {
            reject(error);
          } else {
            resolve();
          }
        });
      });

      // Observe rejection immediately, while preserving the original
      // Promise result for the later shutdown decision.
      void serverClosed.catch((error: unknown) => {
        logger.error(
          '[shutdown] HTTP server close callback failed:',
          error,
        );
      });

      dependencies.server.closeIdleConnections();

      const [requestsIdle, syncIdle] = await Promise.all([
        dependencies.requests.waitForIdle(timeouts.gracePeriodMs),
        dependencies.waitForSyncIdle(timeouts.gracePeriodMs),
      ]);

      if (!requestsIdle || !syncIdle) {
        logger.error(
          '[shutdown] Grace period expired. ' +
          `Active HTTP requests: ${dependencies.requests.activeCount}; ` +
          `Sync idle: ${syncIdle}.`,
        );

        // A slow sync operation alone must not terminate HTTP
        // connections that have already drained successfully.
        if (!requestsIdle) {
          dependencies.server.closeAllConnections();
        }

        const [requestsRecovered, syncRecovered] = await Promise.all([
          dependencies.requests.waitForIdle(timeouts.recoveryPeriodMs),
          dependencies.waitForSyncIdle(timeouts.recoveryPeriodMs),
        ]);

        if (!requestsRecovered || !syncRecovered) {
          logger.error(
            '[shutdown] Recovery period expired. ' +
            'Database will remain open because application work ' +
            'may still be active.',
          );

          return 'WORK_DRAIN_FAILED';
        }
      }

      const waitForServerClose = async (): Promise<ServerCloseResult> => {
        let timeoutHandle: ReturnType<typeof setTimeout> | undefined;

        try {
          return await Promise.race([
            serverClosed.then<ServerCloseResult, ServerCloseResult>(
              () => 'CLOSED',
              () => 'ERROR',
            ),
            new Promise<ServerCloseResult>((resolve) => {
              timeoutHandle = setTimeout(
                () => resolve('TIMEOUT'),
                timeouts.serverCloseTimeoutMs,
              );
            }),
          ]);
        } finally {
          if (timeoutHandle !== undefined) {
            clearTimeout(timeoutHandle);
          }
        }
      };

      let serverResult = await waitForServerClose();

      if (serverResult === 'ERROR') {
        logger.error(
          '[shutdown] HTTP server close failed. Database will remain open.',
        );

        return 'SERVER_CLOSE_FAILED';
      }

      if (serverResult === 'TIMEOUT') {
        logger.error(
          '[shutdown] HTTP server close timed out. ' +
          'Forcing remaining connections closed.',
        );

        dependencies.server.closeAllConnections();

        serverResult = await waitForServerClose();
      }

      if (serverResult !== 'CLOSED') {
        logger.error(
          '[shutdown] HTTP server closure could not be confirmed. ' +
          'Database will remain open.',
        );

        return 'SERVER_CLOSE_TIMEOUT';
      }

      dependencies.closeDatabase();

      logger.log(
        '[shutdown] HTTP server stopped and database closed safely.',
      );

      return 'CLOSED';
    })().catch((error: unknown) => {
      logger.error('[shutdown] Graceful shutdown failed:', error);
      return 'FAILED';
    });

    return shutdownPromise;
  };
}