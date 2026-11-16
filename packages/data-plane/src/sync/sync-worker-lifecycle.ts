export type SyncTask<T> = () => Promise<T>;

export class SyncWorkerLifecycle<T> {
  private timer: ReturnType<typeof setInterval> | null = null;

  private activeRun: Promise<T> | null = null;

  private stopped = false;

  /**
   * Runs one synchronization cycle.
   *
   * Concurrent callers receive the same active Promise.
   * No new cycle starts after shutdown.
   */
  public run(
    task: SyncTask<T>,
    stoppedResult: T
  ): Promise<T> {
    if (this.stopped) {
      return Promise.resolve(stoppedResult);
    }

    if (this.activeRun) {
      return this.activeRun;
    }

    const currentRun = Promise.resolve().then(task);

    this.activeRun = currentRun;

    const clearActiveRun = () => {
      if (this.activeRun === currentRun) {
        this.activeRun = null;
      }
    };

    currentRun.then(clearActiveRun, clearActiveRun);

    return currentRun;
  }

  /**
   * Starts the periodic synchronization timer.
   * Repeated calls do not create duplicate timers.
   */
  public start(
    task: SyncTask<T>,
    intervalMs: number,
    stoppedResult: T
  ): void {
    if (!Number.isSafeInteger(intervalMs) || intervalMs <= 0) {
      throw new Error('Sync interval must be a positive safe integer.');
    }

    if (this.stopped || this.timer !== null) {
      return;
    }

    this.timer = setInterval(() => {
      void this.run(task, stoppedResult);
    }, intervalMs);
  }

  /**
   * Stops future scheduled synchronization and prevents new cycles.
   * An already-running cycle is allowed to finish.
   */
  public stop(): void {
    this.stopped = true;

    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  /**
   * Waits for the active cycle to finish.
   *
   * Returns false if the timeout expires.
   * Does not cancel the active operation.
   */
  public async waitForIdle(timeoutMs: number): Promise<boolean> {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 0) {
      throw new Error('Sync idle timeout must be a non-negative safe integer.');
    }

    const active = this.activeRun;

    if (!active) {
      return true;
    }

    if (timeoutMs === 0) {
      return false;
    }

    let timeoutHandle: ReturnType<typeof setTimeout> | undefined;

    try {
      return await Promise.race([
        active.then(
          () => true,
          () => true
        ),
        new Promise<boolean>((resolve) => {
          timeoutHandle = setTimeout(() => resolve(false), timeoutMs);
        })
      ]);
    } finally {
      if (timeoutHandle !== undefined) {
        clearTimeout(timeoutHandle);
      }
    }
  }

  public get isRunning(): boolean {
    return this.activeRun !== null;
  }

  public get isStopped(): boolean {
    return this.stopped;
  }

  public get hasTimer(): boolean {
    return this.timer !== null;
  }
}
