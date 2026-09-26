/**
 * 状態管理 — 設定・ライブタブ・レポート永続化
 * ---------------------------------------------------------------
 * Vercel のような serverless ではディスクもメモリも永続しない。よって
 *   「正 (source of truth) はブラウザ側の localStorage + URL/サーバの設定」
 * にし、サーバ側は (a) env 由来のデフォルト、(b) 書ける環境なら JSON スナップショット、
 * の 2 層だけを持つ。書き込みは debounce + 容量上限付き。
 * @module state/store
 */

import { readFile, writeFile, mkdir, rename } from 'node:fs/promises';
import path from 'node:path';
import { LRU, deepMerge, now, stableStringify } from '../util.js';
import { log } from '../log.js';

const ns = log.child('store');

/** クライアント設定の既定値 (UI の「設定」パネルと 1:1) */
export const DEFAULT_SETTINGS = {
  version: 1,
  mode: 'uv', // uv | wisp | auto
  egress: {
    strategy: 'auto', // direct | pool | auto
    country: 'AUTO',
    allowFallback: true,
    rotate: 'per-tab', // per-request | per-tab | sticky-session
    pinExit: true,
    sendSpoofHeaders: true,
    protocols: ['http', 'https', 'socks5', 'socks4'],
  },
  shields: {
    enabled: true,
    level: 'standard', // standard | aggressive | off
    cosmetic: true,
    unbreakable: true,
    allowList: [],
  },
  threats: {
    enabled: true,
    autoDelete: true,
    sanitizeScore: 40,
    blockScore: 80,
    credentialGuard: true,
    blockDangerousDownloads: true,
  },
  privacy: {
    isolateStorage: true,
    containTop: true,
    blockNotifications: true,
    blockGeolocation: false,
    stripCredentials: true,
    blockServiceWorker: true,
    doNotSell: true,
  },
  ui: {
    theme: 'aurora',
    lang: 'ja',
    showThreatTicker: true,
    homePage: '',
    searchEngine: 'duckduckgo',
    tabsPerRow: 0,
  },
  advanced: {
    urlEncoding: 'token',
    maxBodyBytes: 24 * 1024 * 1024,
    timeoutMs: 35000,
    cache: true,
    logLevel: 'info',
  },
};

export class StateStore {
  /** @param {import('../config.js').Config} config */
  constructor(config) {
    this.config = config;
    this.dir = config.state.dir ? path.resolve(config.state.dir) : null;
    this.persist = config.state.persist && !!this.dir;
    this.settings = new LRU(500, 1000 * 60 * 60 * 12);
    this.sessions = new LRU(2000, 1000 * 60 * 60 * 6);
    this.global = structuredCloneSafe(DEFAULT_SETTINGS);
    this.report = { events: 0, quarantined: 0, updatedAt: 0, topHosts: [] };
    this.dirty = new Set();
    this.saveTimer = null;
    this.loaded = false;
    this.stats = { writes: 0, reads: 0, errors: 0 };
    this.persisted = false;
  }

  async init() {
    if (!this.persist) {
      this.loaded = true;
      return { persisted: false };
    }
    try {
      await mkdir(this.dir, { recursive: true });
      const raw = await readFile(path.join(this.dir, this.config.state.settingsFile), 'utf8');
      const json = JSON.parse(raw);
      if (json.global) this.global = deepMerge(structuredCloneSafe(DEFAULT_SETTINGS), json.global);
      if (json.sessions) for (const [k, v] of Object.entries(json.sessions)) this.sessions.set(k, v);
      this.loaded = true;
      this.persisted = true;
      ns.info(`設定を復元しました (${this.dir})`);
      return { persisted: true, dir: this.dir };
    } catch (err) {
      this.loaded = true;
      if (err.code !== 'ENOENT') ns.debug(() => `load skipped: ${err.message}`);
      return { persisted: false, error: err.message };
    }
  }

  /** @returns {object} 設定 (defaults ⊂ global ⊂ client) */
  settingsFor(clientId) {
    const client = clientId ? this.settings.get(clientId) : null;
    return deepMerge(structuredCloneSafe(DEFAULT_SETTINGS), this.global, client || {});
  }

  async update(clientId, patch, { global = false } = {}) {
    if (global) {
      this.global = deepMerge(structuredCloneSafe(this.global), patch);
      this.#markDirty();
      return this.global;
    }
    const cur = this.settings.get(clientId) || {};
    const next = deepMerge(structuredCloneSafe(cur), patch);
    this.settings.set(clientId, next);
    this.#markDirty();
    return next;
  }

  /** ブート時に一度だけ: 環境変数由来の初期値を global 層へ流し込む (永続設定があればそれを尊重) */
  seedGlobal(patch) {
    if (this.persisted) return this.global;
    this.global = deepMerge(structuredCloneSafe(DEFAULT_SETTINGS), patch || {});
    return this.global;
  }

  resetClient(clientId) {
    this.settings.delete(clientId);
    this.#markDirty();
  }

  /** ライブタブ状態 */
  touchSession(sid, patch = {}) {
    const cur = this.sessions.get(sid) || { sid, openedAt: now(), events: 0 };
    const next = { ...cur, ...patch, sid, lastSeen: now() };
    this.sessions.set(sid, next);
    return next;
  }
  session(sid) {
    return this.sessions.get(sid) || null;
  }
  listSessions({ limit = 50 } = {}) {
    const items = [...this.sessions.values()]
      .filter((s) => now() - (s.lastSeen || 0) < 1000 * 60 * 30)
      .sort((a, b) => b.lastSeen - a.lastSeen);
    return items.slice(0, limit);
  }
  dropSession(sid) {
    this.sessions.delete(sid);
  }

  reportPatch(patch) {
    this.report = { ...this.report, ...patch, updatedAt: now() };
    this.#markDirty();
  }

  #markDirty() {
    if (!this.persist) return;
    clearTimeout(this.saveTimer);
    this.saveTimer = setTimeout(() => this.flush().catch(() => {}), 2500);
    if (this.saveTimer.unref) this.saveTimer.unref();
  }

  async flush() {
    if (!this.persist) return false;
    try {
      const payload = {
        savedAt: now(),
        global: this.global,
        sessions: Object.fromEntries([...this.sessions.values()].slice(-200).map((s) => [s.sid, s])),
        report: this.report,
      };
      const text = stableStringify(payload);
      if (Buffer.byteLength(text) > this.config.state.maxPersistBytes) return false;
      const file = path.join(this.dir, this.config.state.settingsFile);
      await writeFile(`${file}.tmp`, text, 'utf8');
      await rename(`${file}.tmp`, file);
      this.stats.writes++;
      return true;
    } catch (err) {
      this.stats.errors++;
      ns.debug(() => `flush failed: ${err.message}`);
      return false;
    }
  }

  info() {
    return {
      persist: this.persist,
      dir: this.dir,
      loaded: this.loaded,
      sessions: this.sessions.size,
      clients: this.settings.size,
      writes: this.stats.writes,
      errors: this.stats.errors,
    };
  }
}

function structuredCloneSafe(o) {
  return JSON.parse(JSON.stringify(o));
}

export default StateStore;
