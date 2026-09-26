/**
 * 自動スケジュール (リスト更新 / ヘルスチェック / クリーンアップ)
 * ---------------------------------------------------------------
 * 「GitHub の無料プロキシリストを全自動で最新に保つ」要求の心臓部。
 *  ・間隔 + ジッタ → 全インスタンスが同時に同じ raw.githubusercontent を叩かない
 *  ・指数バックオフ → 失敗が続くと大人しくなる (連投でブロックされないため)
 *  ・serverless では実行しない (コンテナ寿命が短く、リクエスト毎にやり直した方がマシ)
 *  ・unref() するのでこのタイマーのせいでプロセスは終了できない、ということがない
 * @module data/scheduler
 */

import { log } from '../log.js';

const ns = log.child('sched');

/** @param {ReturnType<import('../engine.js').createEngine>} engine */
export function startScheduler(engine) {
  const config = engine.config;
  const st = {
    running: false,
    stopped: false,
    ticks: 0,
    lists: { runs: 0, ok: 0, fail: 0, last: null, next: 0, backoff: 0 },
    health: { runs: 0, ok: 0, fail: 0, last: null, next: 0, backoff: 0 },
    ad: { runs: 0, ok: 0, fail: 0, last: null, next: 0, backoff: 0 },
    gc: { runs: 0, last: null },
    timers: new Set(),
  };

  const jitter = (base) => Math.round(base * (0.85 + Math.random() * 0.3));
  const at = (ms) => Date.now() + Math.max(1000, ms);

  const later = (key, ms, fn) => {
    if (st.stopped) return;
    const delay = ms > 2 ** 31 - 1 ? 2 ** 31 - 2 : ms; // serverless 周りで overflow させない
    const t = setTimeout(() => {
      st.timers.delete(t);
      Promise.resolve()
        .then(fn)
        .catch((err) => {
          st[key].fail++;
          st[key].backoff = Math.min(6, st[key].backoff + 1);
          st[key].last = { at: Date.now(), ok: false, error: err.message };
          ns.warn(`${key} 実行エラー (${err.message}) → ${Math.round(delay / 1000)}s 後に再試行`);
          schedule(key);
        });
    }, delay);
    t.unref?.();
    st.timers.add(t);
    st[key].next = at(delay);
  };

  const runList = async () => {
    st.lists.runs++;
    const out = await engine.updateLists({ probe: false });
    st.lists.ok++;
    st.lists.backoff = 0;
    st.lists.last = { at: Date.now(), ok: true, ...summarize(out, engine) };
    ns.info(`リスト更新: +${st.lists.last.added} / pool=${st.lists.last.size} (国数 ${st.lists.last.countries})`);
    schedule('lists');
  };
  const runHealth = async () => {
    st.health.runs++;
    const out = await engine.pool.healthCheck({ limit: healthLimit(engine) });
    st.health.ok++;
    st.health.backoff = 0;
    st.health.last = { at: Date.now(), ok: true, ...out };
    schedule('health');
  };
  const runAd = async () => {
    st.ad.runs++;
    const out = await engine.updateAdLists();
    st.ad.ok++;
    st.ad.backoff = 0;
    st.ad.last = { at: Date.now(), ...out };
    if (config.shields.refreshMs > 0) schedule('ad');
  };
  const runGc = () => {
    st.gc.runs++;
    st.gc.last = Date.now();
    try {
      engine.pipeline.clearStaleSessions?.();
      engine.store.flush?.({ force: true });
    } catch (err) {
      ns.debug(() => `gc: ${err.message}`);
    }
    later('gc', jitter(60_000), runGc);
  };

  function schedule(key) {
    const base =
      key === 'lists' ? config.lists.refreshMs : key === 'health' ? config.egress.healthcheckMs : key === 'ad' ? config.shields.refreshMs : 60_000;
    if (!base || base <= 0) return;
    const backoff = 2 ** st[key].backoff;
    later(key, jitter(base * backoff), key === 'lists' ? runList : key === 'health' ? runHealth : key === 'ad' ? runAd : runGc);
  }

  // --- kick off ---
  if (config.lists.enabled && config.lists.refreshMs > 0) later('lists', jitter(Math.min(45_000, config.lists.refreshMs)), runList);
  if (config.egress.healthcheckMs > 0) later('health', jitter(90_000), runHealth);
  if (config.shields.refreshMs > 0) later('ad', jitter(20_000), runAd);
  st.gc.next = at(60_000);
  later('gc', jitter(60_000), runGc);
  st.running = true;

  return {
    state: st,
    nextRun: () => ({ lists: st.lists.next, health: st.health.next, ad: st.ad.next }),
    async runNow(what = 'lists') {
      if (what === 'lists') return runList();
      if (what === 'health') return runHealth();
      if (what === 'ad') return runAd();
      return runGc();
    },
    stop() {
      st.stopped = true;
      st.running = false;
      for (const t of st.timers) clearTimeout(t);
      st.timers.clear();
    },
    info() {
      return {
        running: st.running,
        ticks: st.ticks,
        lists: st.lists,
        health: st.health,
        ad: st.ad,
        gc: st.gc,
      };
    },
  };
}

function summarize(out, engine) {
  const s = engine.pool.summary();
  return {
    ok: out?.ok !== false,
    added: out?.added ?? 0,
    fetched: out?.fetched ?? 0,
    sources: out?.sources ?? 0,
    errors: out?.errors ?? 0,
    size: s.size,
    healthy: s.healthy,
    countries: s.countries,
  };
}

/** プール規模に応じてヘルスチェック量を絞る (無料リストは 1 万件超えると全数検査が無理) */
function healthLimit(engine) {
  const size = engine.pool.records.size;
  const cfg = engine.config.egress;
  if (size <= 600) return size;
  return Math.max(120, Math.min(600, Math.round(size * 0.18)));
}

export default startScheduler;
