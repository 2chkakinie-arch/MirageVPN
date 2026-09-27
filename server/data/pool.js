/**
 * プロキシプール — 出口 IP の選択・健康診断・国籍ピン留め・自動追放
 * ---------------------------------------------------------------
 * 「リストを全自動で取得 → 国籍を自動判別 → 自分の IP を好きな国に偽装」を実現する中核。
 *
 *  - record には「リストが言う国籍(list)」と「実測で確認した国籍(exit)」を持つ。
 *    両者が食い違うリストは平然とあるので、スコアリングで exit を優遇する。
 *  - 失敗を連続で重ねたプロキシは cooldown へ自動退避 (= リアルタイム自己治癒)。
 *  - select() はスコア上位 K 件から重み付きランダム。同一タブは sticky にして
 *    セッション途中で出口国籍がフラフラするのを防ぐ。
 * @module data/pool
 */

import { readFile } from 'node:fs/promises';
import { LRU, ema, mapLimit } from '../util.js';
import { log } from '../log.js';
import { fetchSourceText, loadBundledSeeds, parseProxies, resolveSources, saveSnapshot, SourceStats } from './sources.js';
import { COUNTRIES, GeoResolver, normalizeCountry } from './geo.js';

const ns = log.child('pool');

const DEFAULT_PROBE = [
  // 出口 IP + 国が一緒に取れるもの。到達できなければ geo ソロで判定。
  { url: 'http://ip-api.com/line/?fields=status,country,countryCode,query', kind: 'text' },
  { url: 'http://httpbin.org/ip', kind: 'json' },
  { url: 'http://ifconfig.me/ip', kind: 'text' },
];

export class ProxyPool {
  /**
   * @param {import('../config.js').Config} config
   */
  constructor(config) {
    this.config = config;
    /** @type {Map<string, ProxyRecord>} */
    this.records = new Map();
    this.byCountry = new Map(); // CC → Set<key>
    this.byProtoCountry = new Map(); // `${proto}|${CC}` → Set<key>
    this.geo = new GeoResolver({
      seed: new Map(),
      offline: !!config.state.dir, // 有象無象の API を叩き過ぎないための簡易フラグではなく、単に初期化用
      timeoutMs: 5000,
    });
    this.geo.offline = false;
    this.stats = new SourceStats();
    this.lastRefresh = 0;
    this.lastError = null;
    this.refreshing = null;
    this.sticky = new LRU(2000, 1000 * 60 * 45); // sid → key
    this.listeners = new Set();
    this.counters = { selected: 0, success: 0, failure: 0, banned: 0, recovered: 0, blockedByPool: 0 };
    this.healthCursor = 0;
    this.inflight = 0;
    this.probes = DEFAULT_PROBE;
  }

  /* ---------------------------- 登録 ---------------------------- */

  /** @param {Array<{protocol:string,host:string,port:number,country?:string,city?:string}>} entries */
  ingest(entries, { sourceId = 'seed', weight = 1 } = {}) {
    let added = 0;
    for (const e of entries) {
      if (!e?.host || !e.port) continue;
      if (!/^\d+(\.\d+){3}$/.test(e.host) && !e.host.includes(':') && !/^[a-zA-Z0-9.-]+$/.test(e.host)) continue;
      const key = `${e.protocol}|${e.host}:${e.port}`;
      const cc = normalizeCountry(e.country) || 'XX';
      let rec = this.records.get(key);
      if (rec) {
        rec.sources.add(sourceId);
        if (rec.country === 'XX' && cc !== 'XX') {
          rec.country = cc;
          this.#indexCountry(rec, cc);
        }
        rec.lastSeen = Date.now();
        continue;
      }
      rec = {
        key,
        protocol: e.protocol,
        host: e.host,
        port: e.port,
        username: e.username,
        password: e.password,
        country: cc,
        exitCountry: null,
        city: e.city,
        anon: !!e.anon,
        sources: new Set([sourceId]),
        score: 50 + 12 * weight,
        latencyMs: null,
        latencyEma: null,
        ok: 0,
        fails: 0,
        consecutiveFails: 0,
        bannedUntil: 0,
        lastCheck: 0,
        lastSeen: Date.now(),
        httpsOk: false,
        tlsCapable: e.protocol === 'https',
        checked: false,
        bytes: 0,
        inFlight: 0,
      };
      this.records.set(key, rec);
      this.#indexCountry(rec, cc);
      if (e.country && e.country !== 'XX') this.geo.putSeed(e.host, { country: cc, city: e.city });
      added++;
    }
    this.#trim();
    if (added) this.emit('ingest', { added, total: this.records.size });
    return added;
  }

  #indexCountry(rec, cc) {
    if (!this.byCountry.has(cc)) this.byCountry.set(cc, new Set());
    this.byCountry.get(cc).add(rec.key);
    const pk = `${rec.protocol}|${cc}`;
    if (!this.byProtoCountry.has(pk)) this.byProtoCountry.set(pk, new Set());
    this.byProtoCountry.get(pk).add(rec.key);
  }

  #unindex(rec) {
    for (const set of [this.byCountry.get(rec.country), this.byProtoCountry.get(`${rec.protocol}|${rec.country}`)]) {
      set?.delete(rec.key);
    }
  }

  /**
   * プール上限への間引き。プロキシ種別でラウンドロビンに拾うので、
   * 件数の多い http 系に枠を占領されて socks5/https が全滅することを防ぐ。
   */
  #trim() {
    const max = this.config.egress.maxPoolSize;
    if (this.records.size <= max) return;
    const now = Date.now();
    const byProto = new Map();
    for (const rec of this.records.values()) {
      const arr = byProto.get(rec.protocol) || [];
      arr.push(rec);
      byProto.set(rec.protocol, arr);
    }
    for (const arr of byProto.values()) arr.sort((a, b) => effectiveScore(b, now) - effectiveScore(a, now));
    const queues = [...byProto.values()];
    const keep = new Set();
    let guard = 0;
    while (keep.size < max && guard++ < max * 4) {
      for (const q of queues) {
        const next = q.shift();
        if (next) {
          keep.add(next.key);
          if (keep.size >= max) break;
        }
      }
      if (queues.every((q) => !q.length)) break;
    }
    for (const rec of this.records.values()) {
      if (keep.has(rec.key) || rec.inFlight) continue;
      this.#unindex(rec);
      this.records.delete(rec.key);
    }
    this.__allKeys = null;
  }

  /** 古い (long time unseen) レコードを掃除。リスト側で消えた IP を残さない。 */
  /** select() 後に report() が呼ばれなかった場合の inFlight リークを回収 */
  sweepInflight() {
    let n = 0;
    for (const rec of this.records.values()) {
      if (rec.inFlight > 0 && Date.now() - (rec.lastSeen || 0) > 60000) {
        rec.inFlight = 0;
        n++;
      }
    }
    return n;
  }

  prune({ maxAgeMs = 1000 * 60 * 90 } = {}) {
    const now = Date.now();
    let removed = 0;
    for (const [key, rec] of this.records) {
      if (rec.inFlight) continue;
      const stale = now - rec.lastSeen > maxAgeMs;
      const dead = rec.consecutiveFails >= this.config.egress.failThreshold * 3 && now - rec.bannedUntil > this.config.egress.cooldownMs * 4;
      if (stale || dead) {
        this.#unindex(rec);
        this.records.delete(key);
        removed++;
      }
    }
    if (removed) this.emit('prune', { removed });
    return removed;
  }

  /* ---------------------------- 選択 ---------------------------- */

  /**
   * @param {{country?:string, protocols?:string[], stickyKey?:string, sid?:string, httpsTarget?:boolean, exclude?:Set<string>, requireHealthy?:boolean}} [opts]
   * @returns {ProxyRecord|null}
   */
  select(opts = {}) {
    const cfg = this.config.egress;
    const cc = normalizeCountry(opts.country ?? cfg.country) || null;
    const protocols = (opts.protocols || cfg.protocols).filter(Boolean);
    const exclude = opts.exclude || new Set();
    const now = Date.now();

    // 1) sticky: 前回このタブが使った出口が生きていれば維持する (タブ途中で国籍が揺れないように)
    if (opts.sid) {
      const prevKey = this.sticky.get(`sid:${opts.sid}`);
      const prev = prevKey ? this.records.get(prevKey) : null;
      const matchesCountry = !cc || cc === 'AUTO' || prev?.country === cc || prev?.exitCountry === cc;
      if (
        prev &&
        matchesCountry &&
        this.#usable(prev, { now, exclude, httpsTarget: opts.httpsTarget, requireHealthy: opts.requireHealthy, protocols })
      ) {
        return this.#pick(prev);
      }
    }

    // 2) 国籍指定あり → その国の候補から
    const candidateKeys = [];
    const pushFromIndex = (list) => {
      for (const set of list) for (const k of set) candidateKeys.push(k);
    };
    if (cc && cc !== 'AUTO') {
      pushFromIndex(protocols.map((p) => this.byProtoCountry.get(`${p}|${cc}`)).filter(Boolean));
    } else {
      pushFromIndex(protocols.map((p) => this.countrySetFor(p, null)).filter(Boolean));
    }

    let candidates = [];
    const seen = new Set();
    for (const key of candidateKeys) {
      if (seen.has(key)) continue;
      seen.add(key);
      const rec = this.records.get(key);
      if (!rec) continue;
      if (!this.#usable(rec, { now, exclude, httpsTarget: opts.httpsTarget, requireHealthy: opts.requireHealthy, protocols })) continue;
      candidates.push(rec);
    }

    // 国籍ピン留めで見つからず、allowFallback のときだけ他国へ (UI の「代替も許可」)
    if (!candidates.length && cc && cc !== 'AUTO' && opts.allowFallback) {
      for (const rec of this.records.values()) {
        if (seen.has(rec.key)) continue;
        if (!this.#usable(rec, { now, exclude, httpsTarget: opts.httpsTarget, requireHealthy: opts.requireHealthy, protocols })) continue;
        candidates.push(rec);
      }
    }
    if (!candidates.length) return null;

    // 3) スコア上位から重み付きランダム (上位 12 件)
    candidates.sort((a, b) => effectiveScore(b, now) - effectiveScore(a, now));
    const top = candidates.slice(0, Math.min(12, candidates.length));
    const total = top.reduce((s, r) => s + Math.max(1, effectiveScore(r, now)), 0);
    let r = Math.random() * total;
    for (const rec of top) {
      r -= Math.max(1, effectiveScore(rec, now));
      if (r <= 0) return this.#pick(rec);
    }
    return this.#pick(top[0]);
  }

  #pick(rec) {
    this.counters.selected++;
    if (rec) rec.inFlight++;
    return rec;
  }

  #usable(rec, { now, exclude, httpsTarget, requireHealthy, protocols }) {
    if (!rec) return false;
    if (exclude.has(rec.key)) return false;
    if (protocols && protocols.length && !protocols.includes(rec.protocol)) return false;
    if (rec.bannedUntil > now) return false;
    if (requireHealthy && (!rec.checked || rec.consecutiveFails >= this.config.egress.failThreshold)) return false;
    if (httpsTarget && !rec.tlsCapable && rec.protocol !== 'https' && rec.protocol !== 'socks5' && rec.protocol !== 'socks4' && rec.protocol !== 'socks4a') {
      // http プロキシでも CONNECT が通れば https 可。実績 (httpsOk) が無いものは避ける傾向にする
      if (rec.checked && !rec.httpsOk) return false;
    }
    const maxLat = this.config.egress.maxLatencyMs;
    if (maxLat > 0 && rec.latencyEma && rec.latencyEma > maxLat) return false;
    return true;
  }

  countrySetFor(protocol, cc) {
    if (cc) return this.byProtoCountry.get(`${protocol}|${cc}`);
    // 全 protocol 横断 Set を作るのは高いので、byCountry のUnion を使う
    return this.allKeys;
  }

  get allKeys() {
    if (!this.__allKeys || this.__allKeysVersion !== this.records.size) {
      this.__allKeys = new Set(this.records.keys());
      this.__allKeysVersion = this.records.size;
      // byProtoCountry に protocol 横断版を持たせる
      this.__byProto = new Map();
      for (const rec of this.records.values()) {
        const k = rec.protocol;
        if (!this.__byProto.has(k)) this.__byProto.set(k, new Set());
        this.__byProto.get(k).add(rec.key);
      }
      for (const [p, set] of this.__byProto) this.byProtoCountry.set(`${p}|null`, set);
    }
    return this.__allKeys;
  }

  /** プロキシ単位の使用完了報告 */
  report(rec, { ok, latencyMs, bytes, error, exitInfo } = {}) {
    if (!rec) return;
    rec.inFlight = Math.max(0, (rec.inFlight || 0) - 1);
    if (ok) {
      this.counters.success++;
      rec.checked = true; // 実トラフィックの成功は synthetic probe より強い健全性シグナル
      rec.ok++;
      rec.consecutiveFails = 0;
      rec.bannedUntil = 0;
      if (latencyMs) {
        rec.latencyMs = latencyMs;
        rec.latencyEma = ema(rec.latencyEma, latencyMs, 0.3);
      }
      rec.bytes += bytes || 0;
      rec.score = clampScore(rec.score + 3);
      if (exitInfo?.country) {
        rec.exitCountry = exitInfo.country;
        if (exitInfo.city) rec.city = exitInfo.city;
        if (exitInfo.ip) this.geo.putSeed(exitInfo.ip, { country: exitInfo.country });
      }
      return;
    }
    this.counters.failure++;
    rec.fails++;
    rec.checked = true;
    rec.consecutiveFails++;
    rec.score = clampScore(rec.score - 14);
    rec.lastError = error ? String(error).slice(0, 200) : 'unknown';
    if (rec.consecutiveFails >= this.config.egress.failThreshold) {
      rec.bannedUntil = Date.now() + this.config.egress.cooldownMs;
      this.counters.banned++;
      this.emit('ban', { key: rec.key, country: rec.country, fails: rec.consecutiveFails });
    }
  }

  /* ---------------------------- 更新 ---------------------------- */

  /**
   * 全ソースから取得してプールを更新。1 回しか走らないように promise を共有する。
   * @param {{clear?:boolean, probe?:boolean}} [opts]
   */
  async refresh({ clear = false, probe = false } = {}) {
    if (this.refreshing) return this.refreshing;
    this.refreshing = this.#refresh(clear, probe)
      .finally(() => {
        this.refreshing = null;
      })
      .catch((err) => {
        this.lastError = err.message;
        ns.warn(`リスト更新に失敗: ${err.message}`);
        return { ok: false, error: err.message };
      });
    return this.refreshing;
  }

  async #refresh(clear, probe) {
    const cfg = this.config;
    const t0 = Date.now();
    if (clear) {
      this.records.clear();
      this.byCountry.clear();
      this.byProtoCountry.clear();
      this.__allKeys = null;
    }
    const sources = resolveSources(cfg);
    const results = await mapLimit(sources, 4, async (source) => {
      const started = Date.now();
      const got = await fetchSourceText(source, {
        timeoutMs: cfg.lists.fetchTimeoutMs,
        order: cfg.lists.mirrorOrder,
      });
      if (!got) {
        let snap = null;
        if (cfg.state.dir) {
          try {
            snap = await readFile(`${cfg.state.dir}/lists/${source.id}.snapshot`, 'utf8');
          } catch {
            snap = null;
          }
        }
        return { source, text: snap, via: snap ? 'disk-snapshot' : 'unreachable', ms: Date.now() - started };
      }
      if (cfg.state.dir) {
        await saveSnapshot(`${cfg.state.dir}/lists`, source.id, got.text).catch(() => {});
      }
      return { source, text: got.text, via: got.via, bytes: got.bytes, ms: Date.now() - started };
    });

    let total = 0;
    let addedTotal = 0;
    let fromNetwork = 0;
    let errors = 0;
    let successfulSources = 0;
    // mapLimit は {ok,value,error} の envelope を返す。ここを直接 destructure すると
    // source が undefined になり、全ソース取得後に `reading 'id'` で更新全体が落ちる。
    for (let index = 0; index < sources.length; index++) {
      const source = sources[index];
      const row = results[index];
      const item = row?.ok ? row.value : null;
      if (!item) {
        errors++;
        this.stats.record(source.id, { ok: false, error: row?.error?.message || 'unreachable', via: 'error', ms: Date.now() - t0 });
        continue;
      }
      const { text, via, bytes, ms } = item;
      if (!text) {
        errors++;
        this.stats.record(source.id, { ok: false, error: 'unreachable', via, ms });
        continue;
      }
      const entries = parseProxies(text, source.format || 'ip:port', source.protocol || 'http');
      const added = this.ingest(entries, { sourceId: source.id, weight: source.weight ?? 1 });
      const network = via !== 'disk-snapshot';
      this.stats.record(source.id, {
        ok: network,
        count: entries.length,
        bytes: bytes || Buffer.byteLength(text),
        via,
        ms,
        error: network ? undefined : 'network unavailable; snapshot used',
      });
      total += entries.length;
      addedTotal += added;
      if (network) {
        fromNetwork += entries.length;
        successfulSources++;
      } else {
        errors++;
      }
      ns.info(`source ${source.id}: ${entries.length} proxies (+${added}) via ${via}`);
    }

    if (!total && cfg.lists.useBundledSeed) {
      const seeded = loadBundledSeeds();
      const seededAdded = this.ingest(seeded, { sourceId: 'bundled-seed', weight: 0.8 });
      total = seeded.length;
      addedTotal += seededAdded;
      ns.info(`ネットワークから取得できなかったため同梱シードを使用 (${seededAdded})`);
    }

    this.#trim();
    this.lastRefresh = Date.now();
    this.__allKeys = null;
    if (probe) await this.healthCheck({ limit: 120 });
    const elapsed = Date.now() - t0;
    this.emit('refresh', { total, added: addedTotal, ms: elapsed, fromNetwork });
    return {
      ok: fromNetwork > 0 || total > 0,
      total,
      added: addedTotal,
      fromNetwork,
      successfulSources,
      errors,
      size: this.records.size,
      countries: this.byCountry.size,
      ms: elapsed,
    };
  }

  /** 同梱シードのみで起動させる (オフライン環境 / Vercel コールドスタート対策) */
  bootstrapFromSeed() {
    if (!this.config.lists.useBundledSeed) return 0;
    const seeded = loadBundledSeeds();
    const n = this.ingest(seeded, { sourceId: 'bundled-seed', weight: 0.8 });
    this.#trim();
    this.__allKeys = null;
    return n;
  }

  /* ---------------------------- ヘルスチェック ---------------------------- */

  /**
   * 実際の接続で生死と latency、そして「そのプロキシから出た時の国籍」を測る。
   * @param {{limit?:number, only?:ProxyRecord[], concurrency?:number}} [opts]
   */
  async healthCheck({ limit = 100, only, concurrency } = {}) {
    const { request } = await import('../net/http1.js');
    const cfg = this.config.egress;
    const list =
      only ||
      [...this.records.values()]
        .filter((r) => !r.bannedUntil || r.bannedUntil < Date.now() || r.consecutiveFails < cfg.failThreshold)
        .sort((a, b) => a.lastCheck - b.lastCheck)
        .slice(0, limit);
    const probeUrl = this.probes[0].url;
    const t0 = Date.now();
    let alive = 0;
    let verified = 0;
    await mapLimit(list, concurrency || cfg.healthcheckConcurrency, async (rec) => {
      const start = Date.now();
      try {
        const res = await request({
          url: probeUrl,
          method: 'GET',
          proxy: { protocol: rec.protocol, host: rec.host, port: rec.port, username: rec.username, password: rec.password },
          connectTimeoutMs: cfg.healthcheckTimeoutMs,
          headTimeoutMs: cfg.healthcheckTimeoutMs,
          idleTimeoutMs: cfg.healthcheckTimeoutMs,
          maxBodyBytes: 20000,
          headers: new Map([['user-agent', 'MirageVPN/1.0 (healthcheck)'], ['accept', '*/*'], ['connection', 'close']]),
        });
        const chunks = [];
        for await (const c of res.stream) chunks.push(c);
        const text = Buffer.concat(chunks).toString('utf8');
        const ms = Date.now() - start;
        if (res.statusCode >= 200 && res.statusCode < 400) {
          alive++;
          let exitInfo = null;
          const code = /\b([A-Z]{2})\b/.exec(text || '');
          const ipm = /(\d{1,3}(?:\.\d{1,3}){3})/.exec(text || '');
          if (ipm) {
            const geoRec = await this.geo.resolve(ipm[1]);
            exitInfo = { country: geoRec.country, city: geoRec.city, ip: ipm[1] };
            if (exitInfo.country && exitInfo.country !== 'XX') verified++;
          } else if (code && COUNTRIES_OK.has(code[1])) {
            exitInfo = { country: code[1] };
          }
          this.report(rec, {
            ok: true,
            latencyMs: ms,
            exitInfo,
            bytes: text.length,
          });
          rec.checked = true;
          rec.lastCheck = Date.now();
          rec.httpsOk = rec.protocol === 'https' || rec.httpsOk;
        } else {
          this.report(rec, { ok: false, error: `probe HTTP ${res.statusCode}` });
          rec.checked = true;
          rec.lastCheck = Date.now();
        }
      } catch (err) {
        this.report(rec, { ok: false, error: err.message });
        rec.checked = true;
        rec.lastCheck = Date.now();
        rec.latencyEma = rec.latencyEma == null ? cfg.maxLatencyMs + 1 : rec.latencyEma;
      }
    });
    this.lastHealth = { at: Date.now(), tested: list.length, alive, verified, ms: Date.now() - t0 };
    this.emit('health', this.lastHealth);
    return this.lastHealth;
  }

  /** HTTPS ターゲットでも使えそうか (CONNECT が通る実績を作る) */
  async probeTls(rec, targetUrl = 'https://example.com/') {
    const { dial } = await import('../net/http1.js');
    try {
      const u = new URL(targetUrl);
      const { socket } = await dial({
        host: u.hostname,
        port: 443,
        secure: true,
        proxy: { protocol: rec.protocol, host: rec.host, port: rec.port, username: rec.username, password: rec.password },
        timeoutMs: 8000,
      });
      socket.destroy();
      rec.httpsOk = true;
      rec.tlsCapable = true;
      rec.score = clampScore(rec.score + 8);
      return true;
    } catch (err) {
      rec.httpsOk = false;
      rec.score = clampScore(rec.score - 6);
      return false;
    }
  }

  /* ---------------------------- 集計 / UI ---------------------------- */

  byCountryCounts() {
    const out = [];
    for (const [cc, set] of this.byCountry) {
      if (!set.size) continue;
      let alive = 0;
      let lat = 0;
      let latN = 0;
      const protocols = {};
      for (const key of set) {
        const rec = this.records.get(key);
        if (!rec) continue;
        protocols[rec.protocol] = (protocols[rec.protocol] || 0) + 1;
        if (rec.checked && rec.consecutiveFails < this.config.egress.failThreshold) alive++;
        if (rec.latencyEma) {
          lat += rec.latencyEma;
          latN++;
        }
      }
      out.push({
        country: cc,
        total: set.size,
        alive,
        avgLatencyMs: latN ? Math.round(lat / latN) : null,
        protocols,
      });
    }
    return out.sort((a, b) => b.total - a.total);
  }

  countries({ min = 1 } = {}) {
    return this.byCountryCounts()
      .filter((c) => c.total >= min)
      .map((c) => ({
        country: c.country,
        total: c.total,
        alive: c.alive,
        avgLatencyMs: c.avgLatencyMs,
      }));
  }

  top({ country, limit = 20, protocol } = {}) {
    const cc = normalizeCountry(country);
    const set = cc ? this.byCountry.get(cc) : new Set(this.records.keys());
    const now = Date.now();
    return [...(set || [])]
      .map((k) => this.records.get(k))
      .filter(Boolean)
      .filter((r) => !protocol || r.protocol === protocol)
      .sort((a, b) => effectiveScore(b, now) - effectiveScore(a, now))
      .slice(0, limit)
      .map((r) => this.public(r));
  }

  public(rec) {
    const now = Date.now();
    return {
      key: rec.key,
      protocol: rec.protocol,
      host: rec.host,
      port: rec.port,
      country: rec.country,
      exitCountry: rec.exitCountry,
      countryMatch: rec.exitCountry ? rec.exitCountry === rec.country : null,
      city: rec.city,
      score: Math.round(effectiveScore(rec, now)),
      latencyMs: rec.latencyEma ? Math.round(rec.latencyEma) : null,
      ok: rec.ok,
      fails: rec.fails,
      consecutiveFails: rec.consecutiveFails,
      banned: rec.bannedUntil > now ? Math.round((rec.bannedUntil - now) / 1000) : 0,
      checked: rec.checked,
      httpsOk: rec.httpsOk,
      auth: !!(rec.username || rec.password),
      sources: [...rec.sources],
      lastError: rec.lastError || null,
      lastCheck: rec.lastCheck || 0,
      bytes: rec.bytes || 0,
      inFlight: rec.inFlight || 0,
    };
  }

  list({ country, protocol, limit = 200, offset = 0, sort = 'score' } = {}) {
    const cc = normalizeCountry(country);
    let arr = cc ? [...(this.byCountry.get(cc) || [])].map((k) => this.records.get(k)) : [...this.records.values()];
    arr = arr.filter(Boolean);
    if (protocol) arr = arr.filter((r) => r.protocol === protocol);
    const now = Date.now();
    arr.sort((a, b) => {
      if (sort === 'latency') return (a.latencyEma ?? 1e9) - (b.latencyEma ?? 1e9);
      if (sort === 'country') return a.country.localeCompare(b.country) || effectiveScore(b, now) - effectiveScore(a, now);
      if (sort === 'recent') return b.lastSeen - a.lastSeen;
      return effectiveScore(b, now) - effectiveScore(a, now);
    });
    const total = arr.length;
    return {
      total,
      offset,
      items: arr.slice(offset, offset + limit).map((r) => this.public(r)),
    };
  }

  size() {
    return this.records.size;
  }

  summary() {
    const now = Date.now();
    let healthy = 0;
    let banned = 0;
    let latSum = 0;
    let latN = 0;
    const protoCounts = {};
    for (const rec of this.records.values()) {
      if (rec.bannedUntil > now) banned++;
      else if (rec.checked && rec.consecutiveFails < this.config.egress.failThreshold) healthy++;
      if (rec.latencyEma) {
        latSum += rec.latencyEma;
        latN++;
      }
      protoCounts[rec.protocol] = (protoCounts[rec.protocol] || 0) + 1;
    }
    return {
      size: this.records.size,
      healthy,
      banned,
      unchecked: [...this.records.values()].filter((r) => !r.checked).length,
      healthyPct: this.records.size ? Math.round((healthy / this.records.size) * 100) : 0,
      avgLatencyMs: latN ? Math.round(latSum / latN) : null,
      protocols: protoCounts,
      countries: this.byCountry.size,
      lastRefresh: this.lastRefresh,
      lastHealth: this.lastHealth || null,
      counters: { ...this.counters },
      refreshing: !!this.refreshing,
      lastError: this.lastError,
      geo: this.geo.stats(),
      sources: this.stats.list().map((s) => ({ ...s, id: s.id })),
    };
  }

  /* ---------------------------- 永続化 ---------------------------- */

  snapshot() {
    return {
      savedAt: Date.now(),
      records: [...this.records.values()].slice(0, 4000).map((r) => ({
        key: r.key,
        protocol: r.protocol,
        host: r.host,
        port: r.port,
        username: r.username,
        password: r.password,
        country: r.country,
        exitCountry: r.exitCountry,
        city: r.city,
        score: r.score,
        latencyEma: r.latencyEma,
        ok: r.ok,
        fails: r.fails,
        checked: r.checked,
        httpsOk: r.httpsOk,
        sources: [...r.sources],
      })),
    };
  }

  restore(snap) {
    if (!snap?.records) return 0;
    let n = 0;
    for (const r of snap.records) {
      if (!r?.host || !r.port) continue;
      this.ingest([r], { sourceId: r.sources?.[0] || 'restored', weight: 1 });
      const rec = this.records.get(`${r.protocol}|${r.host}:${r.port}`);
      if (rec) {
        Object.assign(rec, {
          score: r.score ?? rec.score,
          latencyEma: r.latencyEma ?? null,
          ok: r.ok || 0,
          fails: r.fails || 0,
          checked: !!r.checked,
          httpsOk: !!r.httpsOk,
          exitCountry: r.exitCountry || null,
        });
        n++;
      }
    }
    return n;
  }

  on(event, fn) {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  emit(event, payload) {
    for (const fn of this.listeners) {
      try {
        fn(event, payload);
      } catch (err) {
        ns.debug(() => `listener error: ${err.message}`);
      }
    }
  }

  clearSticky(sid) {
    this.sticky.delete(`sid:${sid}`);
  }

  setSticky(sid, key) {
    if (sid && key) this.sticky.set(`sid:${sid}`, key);
  }
}

function effectiveScore(rec, now) {
  let s = rec.score || 0;
  if (rec.bannedUntil > now) s -= 60;
  if (rec.latencyEma) s -= Math.min(30, rec.latencyEma / 150);
  if (rec.consecutiveFails > 0) s -= rec.consecutiveFails * 8;
  if (rec.inFlight > 2) s -= (rec.inFlight - 2) * 4;
  if (rec.exitCountry && rec.exitCountry === rec.country) s += 15; // 実測で国籍一致 = 良い出口
  return Math.max(1, Math.round(s));
}

const clampScore = (n) => Math.max(1, Math.min(200, n));

const COUNTRIES_OK = new Set(Object.keys(COUNTRIES));

export default ProxyPool;
