import { describe, expect, it } from 'vitest';
import {
  createPasswordService,
  PasswordLimiter,
  PasswordLimiterBusyError,
} from '../src/auth/passwords.js';

function gate() {
  const releases: (() => void)[] = [];
  return {
    wait: () => new Promise<void>((resolve) => releases.push(resolve)),
    releaseOne: () => releases.shift()?.(),
    get pending() {
      return releases.length;
    },
  };
}

const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

describe('PasswordLimiter (F-5)', () => {
  it('runs at most `concurrency` operations, queues up to `maxQueue`, refuses the rest', async () => {
    const limiter = new PasswordLimiter({ concurrency: 2, maxQueue: 1, retryAfterSeconds: 3 });
    const g = gate();
    let running = 0;
    let peak = 0;
    const work = async () => {
      running += 1;
      peak = Math.max(peak, running);
      await g.wait();
      running -= 1;
      return 'done';
    };
    const accepted = [limiter.run(work), limiter.run(work), limiter.run(work)];
    await tick();
    expect(limiter.active).toBe(2);
    expect(limiter.queued).toBe(1);
    await expect(limiter.run(work)).rejects.toMatchObject({
      name: 'PasswordLimiterBusyError',
      retryAfterSeconds: 3,
    });

    while (g.pending > 0 || limiter.active > 0) {
      g.releaseOne();
      await tick();
    }
    expect(await Promise.all(accepted)).toEqual(['done', 'done', 'done']);
    expect(peak).toBe(2);
    expect(limiter.active).toBe(0);
    expect(limiter.queued).toBe(0);
  });

  it('frees the slot when work throws', async () => {
    const limiter = new PasswordLimiter({ concurrency: 1, maxQueue: 0 });
    await expect(limiter.run(() => Promise.reject(new Error('boom')))).rejects.toThrow('boom');
    expect(limiter.active).toBe(0);
    await expect(limiter.run(() => Promise.resolve(1))).resolves.toBe(1);
  });

  it('rejects invalid settings', () => {
    expect(() => new PasswordLimiter({ concurrency: 0, maxQueue: 0 })).toThrow(RangeError);
    expect(() => new PasswordLimiter({ concurrency: 1, maxQueue: -1 })).toThrow(RangeError);
  });

  it('puts hashing and verification behind the same limiter', async () => {
    const g = gate();
    const service = createPasswordService({
      limiter: new PasswordLimiter({ concurrency: 1, maxQueue: 0 }),
      params: undefined,
      verifier: async () => {
        await g.wait();
        return true;
      },
      hasher: () => Promise.resolve('unused'),
    });
    const verifying = service.verify('synthetic password', 'synthetic hash');
    await tick();
    await expect(service.hash('synthetic password')).rejects.toBeInstanceOf(
      PasswordLimiterBusyError,
    );
    g.releaseOne();
    await expect(verifying).resolves.toBe(true);
    await expect(service.hash('synthetic password')).resolves.toBe('unused');
  });
});
