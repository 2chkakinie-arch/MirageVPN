/**
 * MirageVPN — AI Mode 用の予算 (quota) とクールダウン
 * ---------------------------------------------------------------
 * Google AI Mode は「1 IP あたりの累積予算」で弾く (公開計測では約 40 問/時、
 * ブロックされると回復に数時間)。だから自前の API として切り出す側で
 * 同じ性質の guard を掛ける:
 *
 *   - perHour / perDay の問い合わせ上限 (累積)
 *   - 最小問い合わせ間隔 (バースト防止)
 *   - CAPTCHA を踏んだら cooldownMs の間そのまま止める
 *   - 連続失敗が続いたら自動で longer cooldown
 *
 * 状態はプロセス内 (インメモリ)。再起動でリセットされるのは意図的
 * (永続化すると「昨日ブロックされた IP」を引きずって回復が遅れる)。
 *
 * @module aimode/quota
 */

export class AiModeQuota {
  /**
   * @param {{perHour:number, perDay:number, minIntervalMs:number, cooldownMs:number, maxCooldownMs?:number}} [opts]
   */
  constructor(opts = {}) {
    this.perHour = Number(opts.perHour) > 0 ? Number(opts.perHour) : 0;
    this.perDay = Number(opts.perDay) > 0 ? Number(opts.perDay) : 0;
    this.minIntervalMs = Number(opts.minIntervalMs) > 0 ? Number(opts.minIntervalMs) : 0;
    this.cooldownMs = Number(opts.cooldownMs) > 0 ? Number(opts.cooldownMs) : 0;
    this.maxCooldownMs = Number(opts.maxCooldownMs) > 0 ? Number(opts.maxCooldownMs) : Math.max(this.cooldownMs * 8, 3600_000);
    /** @type {number[]} 直近の問い合わせ時刻 (ms) */
    this.hits = [];
    /** @type {number[]} 日次 */
    this.dayHits = [];
    this.lastAt = 0;
    this.cooldownUntil = 0;
    this.cooldownLevel = 0;
    this.blocks = 0;
    this.errors = 0;
    this.allowed = 0;
  }

  /** 今すぐ投げられるか。`{ok, reason, retryAfterMs}` */
  check(now = Date.now()) {
    if (this.cooldownUntil > now) {
      return { ok: false, reason: 'cooldown', retryAfterMs: this.cooldownUntil - now };
    }
    if (this.minIntervalMs && now - this.lastAt < this.minIntervalMs) {
      return { ok: false, reason: 'min_interval', retryAfterMs: this.minIntervalMs - (now - this.lastAt) };
    }
    this.#prune(now);
    if (this.perHour && this.hits.length >= this.perHour) {
      return { ok: false, reason: 'per_hour', retryAfterMs: this.hits[0] + 3600_000 - now };
    }
    if (this.perDay && this.dayHits.length >= this.perDay) {
      return { ok: false, reason: 'per_day', retryAfterMs: this.dayHits[0] + 86_400_000 - now };
    }
    return { ok: true };
  }

  /** 許可された1件を記録 */
  note(now = Date.now()) {
    this.hits.push(now);
    this.dayHits.push(now);
    this.lastAt = now;
    this.allowed++;
  }

  /** CAPTCHA / ブロックを踏んだ → クールダウン (階段的に延びる) */
  noteBlocked(now = Date.now()) {
    this.blocks++;
    this.cooldownLevel = Math.min(this.cooldownLevel + 1, 8);
    const ms = Math.min(this.cooldownMs * 2 ** (this.cooldownLevel - 1), this.maxCooldownMs);
    this.cooldownUntil = now + ms;
    return ms;
  }

  /** 通常エラー (弾かれたわけではない) */
  noteError() {
    this.errors++;
  }

  /** 成功したらクールダウン階級を戻す */
  noteSuccess() {
    this.cooldownLevel = Math.max(0, this.cooldownLevel - 1);
  }

  #prune(now) {
    const hCut = now - 3600_000;
    const dCut = now - 86_400_000;
    while (this.hits.length && this.hits[0] < hCut) this.hits.shift();
    while (this.dayHits.length && this.dayHits[0] < dCut) this.dayHits.shift();
  }

  stats(now = Date.now()) {
    this.#prune(now);
    return {
      perHour: this.perHour,
      perDay: this.perDay,
      usedLastHour: this.hits.length,
      usedToday: this.dayHits.length,
      minIntervalMs: this.minIntervalMs,
      cooldownUntil: this.cooldownUntil > now ? this.cooldownUntil : null,
      cooldownRemainingMs: this.cooldownUntil > now ? this.cooldownUntil - now : 0,
      cooldownLevel: this.cooldownLevel,
      blocks: this.blocks,
      errors: this.errors,
      allowed: this.allowed,
    };
  }
}

export default AiModeQuota;
