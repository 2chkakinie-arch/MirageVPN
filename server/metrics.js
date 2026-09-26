/**
 * 軽量メトリクス (req/s・レイテンシ・転送量・モード別内訳)
 * UI のダッシュボードと /mirage/api/metrics 両方から読む。
 * @module metrics
 */

const WINDOW = 60; // 秒

export class Metrics {
  constructor() {
    this.buckets = []; // [{t, req, bytes, err, ms[]}]
    this.total = { requests: 0, bytes: 0, errors: 0, blocked: 0, stripped: 0, rewrites: 0, cacheHits: 0, byMode: {}, byStatus: {}, byEgress: {} };
    this.lat = { p50: 0, p95: 0, avg: 0, max: 0, n: 0 };
    this.samples = [];
    this.startedAt = Date.now();
  }

  #bucket() {
    const t = Math.floor(Date.now() / 1000);
    let b = this.buckets[this.buckets.length - 1];
    if (!b || b.t !== t) {
      b = { t, req: 0, bytes: 0, err: 0, ms: 0 };
      this.buckets.push(b);
      while (this.buckets.length > WINDOW) this.buckets.shift();
    }
    return b;
  }

  record({ ms = 0, bytes = 0, error = false, status = 0, mode = 'uv', cache = false, blocked = 0, stripped = 0, egress = 'direct' } = {}) {
    const b = this.#bucket();
    b.req++;
    b.bytes += bytes;
    if (error) b.err++;
    this.total.requests++;
    this.total.bytes += bytes;
    if (error) this.total.errors++;
    if (blocked) this.total.blocked += blocked;
    if (stripped) this.total.stripped += stripped;
    if (cache) this.total.cacheHits++;
    this.total.byMode[mode] = (this.total.byMode[mode] || 0) + 1;
    const cls = status ? `${Math.floor(status / 100)}xx` : 'err';
    this.total.byStatus[cls] = (this.total.byStatus[cls] || 0) + 1;
    this.total.byEgress[egress] = (this.total.byEgress[egress] || 0) + 1;
    this.samples.push(ms);
    if (this.samples.length > 2000) this.samples.splice(0, 1000);
  }

  histogram() {
    return this.buckets.map((b) => ({ t: b.t, req: b.req, kb: Math.round(b.bytes / 1024), err: b.err }));
  }

  percentiles() {
    if (!this.samples.length) return { p50: 0, p95: 0, avg: 0, max: 0 };
    const s = [...this.samples].sort((a, b) => a - b);
    const at = (q) => s[Math.min(s.length - 1, Math.floor(s.length * q))];
    return {
      p50: Math.round(at(0.5)),
      p95: Math.round(at(0.95)),
      avg: Math.round(s.reduce((a, b) => a + b, 0) / s.length),
      max: Math.round(s[s.length - 1]),
    };
  }

  rate() {
    const recent = this.buckets.slice(-10);
    const req = recent.reduce((a, b) => a + b.req, 0);
    const bytes = recent.reduce((a, b) => a + b.bytes, 0);
    const secs = Math.max(1, recent.length);
    return { reqPerSec: Math.round((req / secs) * 100) / 100, kbPerSec: Math.round(bytes / 1024 / secs) };
  }

  summary() {
    const up = Date.now() - this.startedAt;
    return {
      uptimeMs: up,
      ...this.total,
      latency: this.percentiles(),
      rate: this.rate(),
      series: this.histogram(),
      windowSec: WINDOW,
    };
  }
}

export default Metrics;
