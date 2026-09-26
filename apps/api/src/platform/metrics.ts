/**
 * Minimal Prometheus metrics (text exposition format 0.0.4), no dependencies.
 * Scraped from /metrics; the OpenTelemetry exporter can replace this later.
 */

type Labels = Record<string, string>;
const key = (l: Labels) => Object.keys(l).sort().map((k) => `${k}="${String(l[k]).replace(/["\\\n]/g, "_")}"`).join(",");

class Counter {
  private values = new Map<string, number>();
  constructor(readonly name: string, readonly help: string) {}
  inc(labels: Labels = {}, n = 1) {
    const k = key(labels);
    this.values.set(k, (this.values.get(k) ?? 0) + n);
  }
  render() {
    const lines = [`# HELP ${this.name} ${this.help}`, `# TYPE ${this.name} counter`];
    for (const [k, v] of this.values) lines.push(`${this.name}${k ? `{${k}}` : ""} ${v}`);
    return lines.join("\n");
  }
}

class Histogram {
  private series = new Map<string, { buckets: number[]; sum: number; count: number }>();
  constructor(readonly name: string, readonly help: string, readonly bounds: number[]) {}
  observe(labels: Labels, v: number) {
    const k = key(labels);
    let s = this.series.get(k);
    if (!s) this.series.set(k, (s = { buckets: this.bounds.map(() => 0), sum: 0, count: 0 }));
    this.bounds.forEach((b, i) => v <= b && s!.buckets[i]!++);
    s.sum += v;
    s.count++;
  }
  render() {
    const lines = [`# HELP ${this.name} ${this.help}`, `# TYPE ${this.name} histogram`];
    for (const [k, s] of this.series) {
      const pre = k ? `${k},` : "";
      this.bounds.forEach((b, i) => lines.push(`${this.name}_bucket{${pre}le="${b}"} ${s.buckets[i]}`));
      lines.push(`${this.name}_bucket{${pre}le="+Inf"} ${s.count}`, `${this.name}_sum${k ? `{${k}}` : ""} ${s.sum}`, `${this.name}_count${k ? `{${k}}` : ""} ${s.count}`);
    }
    return lines.join("\n");
  }
}

export const metrics = {
  httpRequests: new Counter("nexus_http_requests_total", "HTTP requests by route and status class"),
  httpDuration: new Histogram("nexus_http_request_duration_seconds", "HTTP request latency", [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5]),
  jobRuns: new Counter("nexus_job_runs_total", "Background job runs by kind and result"),
  jobDuration: new Histogram("nexus_job_duration_seconds", "Background job duration", [0.01, 0.05, 0.1, 0.5, 1, 5, 15, 60]),
};

/** Renders every metric plus point-in-time gauges supplied by the caller (e.g. queue depth). */
export function renderMetrics(gauges: { name: string; help: string; values: [Labels, number][] }[] = []) {
  const parts = Object.values(metrics).map((m) => m.render());
  for (const g of gauges) {
    parts.push([`# HELP ${g.name} ${g.help}`, `# TYPE ${g.name} gauge`, ...g.values.map(([l, v]) => `${g.name}${Object.keys(l).length ? `{${key(l)}}` : ""} ${v}`)].join("\n"));
  }
  parts.push(`# HELP nexus_process_uptime_seconds Seconds since the process started\n# TYPE nexus_process_uptime_seconds gauge\nnexus_process_uptime_seconds ${Math.round(process.uptime())}`);
  return parts.join("\n") + "\n";
}
