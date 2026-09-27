/**
 * Admission control: a bounded number of requests of one kind run at once, a short queue waits
 * behind them, and anything beyond is turned away at once. Device agents use it so a fleet
 * checking in together can't take every database connection from the people using the console.
 */
export class Gate {
  private running = 0;
  private waiting: (() => void)[] = [];

  constructor(
    readonly concurrency: number,
    readonly maxQueue: number,
    readonly maxWaitMs: number,
  ) {}

  /** Resolves to a release function, or null when the request should be shed. */
  async acquire(): Promise<(() => void) | null> {
    if (this.running < this.concurrency) {
      this.running++;
      return this.releaser();
    }
    if (this.waiting.length >= this.maxQueue) return null;
    return new Promise((resolve) => {
      const wake = () => {
        clearTimeout(timer);
        resolve(this.releaser()); // the slot was handed over by release(); running is unchanged
      };
      const timer = setTimeout(() => {
        const i = this.waiting.indexOf(wake);
        if (i >= 0) this.waiting.splice(i, 1);
        resolve(null);
      }, this.maxWaitMs);
      this.waiting.push(wake);
    });
  }

  get stats() {
    return { running: this.running, waiting: this.waiting.length };
  }

  private releaser() {
    let done = false;
    return () => {
      if (done) return;
      done = true;
      const next = this.waiting.shift();
      if (next) next();
      else this.running--;
    };
  }
}

/** Seconds a shed client should wait: spread over [base, 2×base) so a fleet doesn't return in lockstep. */
export const retryAfter = (base: number) => base + Math.floor(Math.random() * base);
