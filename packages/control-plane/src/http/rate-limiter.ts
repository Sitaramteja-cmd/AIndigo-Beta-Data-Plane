export type RateLimitEndpoint =
  | 'login'
  | 'register'
  | 'enrollment-code-create'
  | 'enrollment-code-revoke'
  | 'node-revoke'
  | 'node-status-ip'
  | 'node-status-node'
  | 'enrollment-challenge'
  | 'enrollment-proof';

type RateLimitPolicy = {
  maxAttempts: number;
  windowMs: number;
};

type RateLimitBucket = {
  windowStartedAt: number;
  count: number;
  windowMs: number;
};

const RATE_LIMIT_POLICIES: Record<RateLimitEndpoint, RateLimitPolicy> = {
  login: { maxAttempts: 10, windowMs: 15 * 60 * 1000 },
  register: { maxAttempts: 5, windowMs: 60 * 60 * 1000 },
  'enrollment-code-create': { maxAttempts: 10, windowMs: 15 * 60 * 1000 },
  'enrollment-code-revoke': { maxAttempts: 20, windowMs: 15 * 60 * 1000 },
  'node-revoke': { maxAttempts: 10, windowMs: 15 * 60 * 1000 },
  'node-status-ip': { maxAttempts: 3000, windowMs: 15 * 60 * 1000 },
  'node-status-node': { maxAttempts: 120, windowMs: 15 * 60 * 1000 },
  'enrollment-challenge': { maxAttempts: 30, windowMs: 15 * 60 * 1000 },
  'enrollment-proof': { maxAttempts: 20, windowMs: 15 * 60 * 1000 },
};

export class InMemoryRateLimiter {
  private readonly buckets = new Map<string, RateLimitBucket>();
  private operations = 0;

  constructor(
    private readonly now: () => number = Date.now,
    private readonly maxBuckets = 10_000,
  ) {
    if (!Number.isSafeInteger(maxBuckets) || maxBuckets < 1) {
      throw new Error('maxBuckets must be a positive safe integer');
    }
  }

  get bucketCount(): number {
    return this.buckets.size;
  }

  check(
    endpoint: RateLimitEndpoint,
    remoteAddress: string | undefined,
  ): number | null {
    const now = this.now();
    const limits = RATE_LIMIT_POLICIES[endpoint];

    const clientIp = (remoteAddress || 'unknown').slice(0, 128);
    const bucketKey = `${endpoint}:${clientIp}`;

    this.operations += 1;

    // Periodically remove expired buckets using their actual configured windows.
    if (this.operations % 256 === 0) {
      for (const [key, bucket] of this.buckets) {
        if (now - bucket.windowStartedAt >= bucket.windowMs) {
          this.buckets.delete(key);
        }
      }
    }

    let bucket = this.buckets.get(bucketKey);

    if (!bucket || now - bucket.windowStartedAt >= limits.windowMs) {
      // Prevent unbounded memory growth from distinct client addresses.
      if (!bucket && this.buckets.size >= this.maxBuckets) {
        const oldestKey = this.buckets.keys().next().value;

        if (oldestKey !== undefined) {
          this.buckets.delete(oldestKey);
        }
      }

      bucket = {
        windowStartedAt: now,
        count: 0,
        windowMs: limits.windowMs,
      };

      this.buckets.set(bucketKey, bucket);
    }

    if (bucket.count >= limits.maxAttempts) {
      return Math.max(
        1,
        Math.ceil(
          (bucket.windowStartedAt + limits.windowMs - now) / 1000,
        ),
      );
    }

    bucket.count += 1;
    return null;
  }
}
