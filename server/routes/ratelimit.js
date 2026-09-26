/**
 * レート制限 / 同時実行制限 (メモリ内スライディングウィンドウ)
 * ---------------------------------------------------------------
 * Vercel のような serverless ではインスタンス単位でしか効かない (共有状態が無い) ため、
 * 「効く環境では効く、効かない環境ではコストだけ払う」設計にする:
 *  ・キー = clientId → 無ければ IP
 *  ・分単位の回数 + 分単位のバイト + 同時実行数
 *  ・超過時は 429 + Retry-After (SW / core.js はこれを見て自動リトライ間隔を延ばす)
 * @module routes/ratelimit
 */

import { LRU } from '../util.js';

export class RateLimiter {
  constructor({ windowMs = 60000, reqPerMin = 900, bytesPerMin = 220 * 1024 * 1024, maxConcurrent = 24, enabled = true } = {}) {
    this.windowMs = windowMs;
    this.reqPerMin = reqPerMin;
    this.bytesPerMin = bytesPerMin;
    this.maxConcurrent = maxConcurrent;
    this.enabled = enabled;
    this.buckets = new LRU(4000, windowMs * 5);
    this.concurrent = new Map();
    this.stats = { allowed: 0, deniedRequests: 0, deniedBytes: 0, deniedConcurrent: 0 };
  }

  bucket(key) {
    let b = this.buckets.get(key);
    const now = Date.now();
    if (!b || now - b.at > this.windowMs) {
      b = { at: now, reqs: 0, bytes: 0 };
      this.buckets.set(key, b);
    }
    return b;
  }

  /** @returns {{ok:boolean, retryAfterMs?:number, reason?:string, left:number}} */
  take(key, { bytes = 0, weight = 1 } = {}) {
    if (!this.enabled) return { ok: true, left: Infinity };
    const b = this.bucket(key);
    if (b.reqs + weight > this.reqPerMin) {
      this.stats.deniedRequests++;
      return { ok: false, reason: 'requests', retryAfterMs: Math.max(200, this.windowMs - (Date.now() - b.at)), left: 0 };
    }
    if (b.bytes + bytes > this.bytesPerMin) {
      this.stats.deniedBytes++;
      return { ok: false, reason: 'bytes', retryAfterMs: Math.max(500, this.windowMs - (Date.now() - b.at)), left: 0 };
    }
    b.reqs += weight;
    b.bytes += bytes;
    this.stats.allowed++;
    return { ok: true, left: Math.max(0, this.reqPerMin - b.reqs) };
  }

  addBytes(key, bytes) {
    if (!this.enabled) return;
    const b = this.bucket(key);
    b.bytes += bytes;
  }

  enter(key) {
    if (!this.enabled) return () => {};
    const n = (this.concurrent.get(key) || 0) + 1;
    this.concurrent.set(key, n);
    if (n > this.maxConcurrent) {
      this.stats.deniedConcurrent++;
      this.leave(key);
      return null;
    }
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.leave(key);
    };
  }

  leave(key) {
    const n = (this.concurrent.get(key) || 1) - 1;
    if (n <= 0) this.concurrent.delete(key);
    else this.concurrent.set(key, n);
  }

  summary() {
    return { ...this.stats, active: this.concurrent.size, tracked: this.buckets.size, windowMs: this.windowMs, reqPerMin: this.reqPerMin, maxConcurrent: this.maxConcurrent };
  }
}

/** express middleware */
export function rateLimitMiddleware(ctx) {
  const limiter = ctx.limiter;
  return (req, res, next) => {
    const proxied = (req.path || '').startsWith(ctx.config.url.prefix);
    if (!proxied && !(req.path || '').startsWith(ctx.config.url.apiPrefix)) return next();
    const key = req.mirage?.clientId || req.ip || 'anon';
    const declared = Number(req.headers['content-length']) || 0;
    if (proxied) {
      const gate = limiter.enter(key);
      if (!gate) {
        res.setHeader('retry-after', '2');
        res.setHeader('x-mirage-limit', 'concurrent');
        return res.status(429).type('text/plain; charset=utf-8').end('MirageVPN: このタブの同時リクエストが多すぎます (上限 ' + limiter.maxConcurrent + ')。少し待ってもう一度。');
      }
      res.on('finish', () => {
        gate();
        const sent = Number(res.getHeader('content-length')) || res.bytesWritten || 0;
        if (sent) limiter.addBytes(key, sent);
      });
    }
    const v = limiter.take(key, { bytes: declared, weight: proxied ? 1 : 2 });
    if (!v.ok) {
      res.setHeader('retry-after', String(Math.max(1, Math.ceil((v.retryAfterMs || 1000) / 1000))));
      res.setHeader('x-mirage-limit', v.reason);
      return res.status(429).json({ error: 'rate_limited', reason: v.reason, retryAfterMs: v.retryAfterMs, note: 'MirageVPN: リクエスト過多です。自動で間隔を空けて再試行します。' });
    }
    if (v.left < 100) res.setHeader('x-mirage-limit-left', String(v.left));
    return next();
  };
}

export default RateLimiter;
