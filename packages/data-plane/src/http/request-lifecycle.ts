export class HttpRequestLifecycle {
  private draining = false;
  private activeRequests = 0;
  private readonly idleWaiters = new Set<() => void>();

  public get isDraining(): boolean {
    return this.draining;
  }

  public get activeCount(): number {
    return this.activeRequests;
  }

  public tryAcquire(): (() => void) | null {
    if (this.draining) {
      return null;
    }

    this.activeRequests += 1;

    let released = false;

    return () => {
      if (released) {
        return;
      }

      released = true;
      this.activeRequests -= 1;

      if (this.activeRequests === 0) {
        for (const resolve of this.idleWaiters) {
          resolve();
        }

        this.idleWaiters.clear();
      }
    };
  }

  public startDraining(): void {
    this.draining = true;

    if (this.activeRequests === 0) {
      for (const resolve of this.idleWaiters) {
        resolve();
      }

      this.idleWaiters.clear();
    }
  }

  public async waitForIdle(timeoutMs: number): Promise<boolean> {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 0) {
      throw new Error('timeoutMs must be a non-negative safe integer.');
    }

    if (this.activeRequests === 0) {
      return true;
    }

    return new Promise<boolean>((resolve) => {
      let settled = false;

      const finish = (idle: boolean) => {
        if (settled) {
          return;
        }

        settled = true;
        clearTimeout(timer);
        this.idleWaiters.delete(onIdle);
        resolve(idle);
      };

      const onIdle = () => finish(true);
      const timer = setTimeout(() => finish(false), timeoutMs);

      this.idleWaiters.add(onIdle);

      // Protect against the active count reaching zero
      // between the initial check and waiter registration.
      if (this.activeRequests === 0) {
        finish(true);
      }
    });
  }
}