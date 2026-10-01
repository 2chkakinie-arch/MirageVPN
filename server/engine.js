/**
 * エンジン組立 (依存性注入の唯一の場所)
 * ---------------------------------------------------------------
 * 各レイヤーはここでお互いを受け取るだけで、singleton を持たない。
 * これにより (a) Vercel のように 1 リクエスト＝1 プロセス でも再構築が安く、
 * (b) テストで本物のパイプラインをそのまま組み立てられる。
 * @module engine
 */

import { readFile } from 'node:fs/promises';
import { loadConfig } from './config.js';
import { UrlMap } from './proxy/urlmap.js';
import { Rewriter } from './proxy/rewrite.js';
import { Pipeline } from './proxy/pipeline.js';
import { CookieStore } from './proxy/cookies.js';
import { TargetGuard } from './security/ssrf.js';
import { Shields } from './security/shields.js';
import { ThreatEngine } from './security/threats.js';
import { ProxyPool } from './data/pool.js';
import { GeoResolver } from './data/geo.js';
import { BUILTIN_AD_LISTS, fetchSourceText } from './data/sources.js';
import { StateStore } from './state/store.js';
import { Metrics } from './metrics.js';
import { Http1Pool } from './net/http1.js';
import { startScheduler } from './data/scheduler.js';
import { AiModeClient } from './aimode/client.js';
import { log } from './log.js';

const ns = log.child('engine');

let cached = null;

/** @param {object} [config] */
export async function createEngine(config = loadConfig(process.env)) {
  const guard = new TargetGuard(config);
  const urlmap = new UrlMap(config);
  const rewriter = new Rewriter({ config, urlmap });
  const geo = new GeoResolver({ timeoutMs: 4500 });
  const pool = new ProxyPool(config);
  pool.geo = geo; // 解決した IP→国 をエンジン側でも共有する
  const shields = new Shields(config);
  const threats = new ThreatEngine(config, { shields });
  const cookies = new CookieStore({ maxSessions: 400 });
  const store = new StateStore(config);
  const metrics = new Metrics();
  const httpPool = new Http1Pool({ maxIdlePerKey: config.transport.keepAlive ? 6 : 0, idleTimeoutMs: 15000 });
  const pipeline = new Pipeline({
    config,
    urlmap,
    rewriter,
    shields,
    threats,
    cookies,
    pool,
    guard,
    metrics,
    store,
    httpPool,
  });

  const engine = {
    config,
    guard,
    urlmap,
    rewriter,
    geo,
    pool,
    shields,
    threats,
    cookies,
    store,
    metrics,
    httpPool,
    pipeline,
    /** Google AI Mode を API として叩くクライアント (無効なら no-op) */
    aimode: new AiModeClient({ config, engine: null }),
    lastListRefresh: 0,
    lastAdRefresh: 0,
    bootedAt: Date.now(),
    booted: false,
    bootErrors: [],

    /** 重い初期化 (シード読込・初回リスト取得)。サーバ起動時に 1 回、serverless では遅延実行 */
    async boot({ firstFetch = true } = {}) {
      if (engine.booted) return engine;
      const tasks = [];
      tasks.push(
        (async () => {
          try {
            await store.init();
          } catch (err) {
            engine.bootErrors.push(`store: ${err.message}`);
          }
        })(),
      );
      tasks.push(
        (async () => {
          const seeded = pool.bootstrapFromSeed();
          ns.info(`プール初期化: ${seeded} 件 (bundled seed)`);
        })(),
      );
      tasks.push(
        (async () => {
          try {
            await shields.loadSeed();
          } catch (err) {
            engine.bootErrors.push(`shields: ${err.message}`);
            ns.warn(`シールドのシード読み込みに失敗: ${err.message}`);
          }
        })(),
      );
      tasks.push(
        (async () => {
          // 既知 badware ホスト (同梱スナップショット) — 実行時は shields の badware.txt 更新に同期して入る
          const files = (config.threats.badHostsFiles || ['data/adblock/threat-domains.seed.txt', 'data/adblock/threat-list.seed.txt']).filter(Boolean);
          for (const f of files) {
            try {
              const text = await readFileOrNull(f);
              if (text) threats.loadBadHosts(text);
            } catch (err) {
              ns.debug(() => `badHosts ${f}: ${err.message}`);
            }
          }
        })(),
      );
      await Promise.all(tasks);

      if (firstFetch && config.lists.enabled) {
        // ブートは待たせない: 1 回目は即キック、以降はスケジューラ
        engine.updateLists({ probe: false }).catch((err) => ns.debug(() => `initial list fetch: ${err.message}`));
      }
      // 永続設定が存在しない初回のみ、環境変数 (config) を global 設定として種火にする。
      // これで UI 表示とエンジン状態がズレない (MIRAGE_ADBLOCK=0 なら UI も OFF から始まる)。
      if (!store.persisted) {
        store.seedGlobal({
          mode: config.transport.defaultMode,
          egress: {
            strategy: config.egress.defaultStrategy,
            country: config.egress.country || 'AUTO',
            protocols: config.egress.protocols,
          },
          shields: {
            enabled: config.shields.enabled,
            level: config.shields.privacyLevel,
            cosmetic: config.shields.cosmetic,
          },
          threats: {
            enabled: config.threats.enabled,
            autoDelete: config.threats.autoDelete,
            blockScore: config.threats.blockScore,
            sanitizeScore: config.threats.sanitizeScore,
            credentialGuard: config.threats.credentialLeakGuard,
            blockDangerousDownloads: config.threats.blockDangerousDownloads,
          },
        });
        ns.info('設定ファイル未検出 — 環境変数を初期設定として適用しました');
      }
      const g = store.global;
      if (g?.shields?.enabled === false) shields.setEnabled(false);
      if (g?.shields?.enabled === true) shields.setEnabled(true);
      if (g?.shields?.level) shields.setLevel(g.shields.level);
      if (g?.threats?.enabled === false) threats.setEnabled(false);
      if (g?.threats?.enabled === true) threats.setEnabled(true);
      if (g?.threats?.autoDelete === false) threats.setAutoDelete(false);
      if (g?.threats?.autoDelete === true) threats.setAutoDelete(true);

      engine.booted = true;
      engine.scheduler = config.isServerless ? null : startScheduler(engine);
      ns.info(
        `エンジン起動完了 — pool=${pool.summary().size} rules=${shields.summary().rules} threats=${threats.stats().enabled ? 'on' : 'off'} mode=${config.transport.defaultMode}${config.wisp.enabled ? '+wisp' : ''}`,
      );
      return engine;
    },

    /** GitHub の無料プロキシリストを再取得 → プール差し替え */
    async updateLists({ probe = false, clear = false } = {}) {
      const out = await pool.refresh({ clear, probe });
      engine.lastListRefresh = Date.now();
      return out;
    },

    /** uBlock Origin 系のフィルタを GitHub から取り直してシールドを更新 */
    async updateAdLists() {
      const lists = [...BUILTIN_AD_LISTS, ...(config.shields.customLists || []).map((u, i) => ({ id: `custom-ad-${i}`, url: u, direct: true, kind: 'abp' }))];
      const results = [];
      let added = 0;
      let blocked = 0;
      await Promise.all(
        lists.map(async (list) => {
          try {
            const got = await fetchSourceText(list, { timeoutMs: config.lists.fetchTimeoutMs, order: config.lists.mirrorOrder });
            if (!got?.text) {
              results.push({ id: list.id, ok: false, error: '全ミラーから取得できず' });
              return;
            }
            const r = shields.parse(got.text, { source: list.id });
            added += r.rules;
            blocked += r.cosmetic;
            results.push({ id: list.id, ok: true, rules: r.rules, cosmetic: r.cosmetic, bytes: got.bytes, via: got.via });
          } catch (err) {
            results.push({ id: list.id, ok: false, error: err.message });
          }
        }),
      );
      engine.lastAdRefresh = Date.now();
      shields.stats.lastUpdate = Date.now();
      ns.info(`シールド更新: +${added} rules / +${blocked} cosmetic (${results.filter((r) => r.ok).length}/${results.length} sources)`);
      return { ok: results.some((r) => r.ok), rules: added, cosmetic: blocked, results };
    },

    /** UI 用のプロキシ URL 生成 */
    /**
     * @param {string} abs
     * @param {string} sid
     * @param {{keepHash?:boolean}} [opts] keepHash はアドレスバー入力など「ページ遷移」だけ
     */
    buildProxiedUrl(abs, sid, opts = {}) {
      try {
        return urlmap.proxify(abs, sid, { kind: 'document', ...opts });
      } catch (err) {
        return null;
      }
    },

    snapshot() {
      return {
        pool: pool.summary(),
        shields: shields.summary(),
        threats: threats.stats(),
        pipeline: pipeline.stats(),
        store: store.info(),
        geo: geo.stats(),
        lastListRefresh: engine.lastListRefresh,
        lastAdRefresh: engine.lastAdRefresh,
        bootErrors: engine.bootErrors,
        uptimeMs: Date.now() - engine.bootedAt,
      };
    },

    close() {
      engine.scheduler?.stop();
      httpPool.close();
    },
  };

  // aimode は pipeline/pool/cookies を後から必要とする (循環しないようここで差し込む)
  engine.aimode.engine = engine;

  return engine;
}

/** 同一プロセス内でエンジンを共有する (Dev サーバ用。serverless では createEngine を毎回使う) */
export async function sharedEngine(config = loadConfig(process.env)) {
  if (cached) return cached;
  cached = await createEngine(config);
  await cached.boot();
  return cached;
}

async function readFileOrNull(rel) {
  if (!rel) return null;
  try {
    return await readFile(new URL(`../${rel}`, import.meta.url), 'utf8');
  } catch {
    return null;
  }
}

export default createEngine;
