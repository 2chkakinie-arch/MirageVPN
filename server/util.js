/**
 * MirageVPN 共通ユーティリティ
 * @module server/util
 */

import { createHash } from 'node:crypto';
import { Buffer } from 'node:buffer';

export const encoder = new TextEncoder();
export const decoder = new TextDecoder();

/* ---------------- base64url (UTF-8 safe) ---------------- */

export function b64u(str) {
  return Buffer.from(String(str), 'utf8').toString('base64url');
}

export function unb64u(s) {
  try {
    return Buffer.from(String(s), 'base64url').toString('utf8');
  } catch {
    return null;
  }
}

/* ---------------- ids / hashing ---------------- */

export function uid(len = 12) {
  const a = new Uint8Array(len);
  crypto.getRandomValues(a);
  return [...a].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export const sha1 = (s) => createHash('sha1').update(String(s)).digest('hex');
export const sha256 = (s) => createHash('sha256').update(String(s)).digest('hex');

/* ---------------- misc ---------------- */

export const clamp = (n, a, b) => (n < a ? a : n > b ? b : n);

export const now = () => Date.now();
/**
 * 再帰的にマージ (配列は置換、オブジェクトは結合、undefined は無視)。
 * 設定の `defaults ⊂ global ⊂ client` のような階層合成用。元オブジェクトは変更しない。
 */
export function deepMerge(base = {}, ...sources) {
  const out = Array.isArray(base) ? [...base] : { ...base };
  for (const src of sources) {
    if (!src || typeof src !== 'object') continue;
    for (const [k, v] of Object.entries(src)) {
      if (v === undefined) continue;
      const cur = out[k];
      if (v && typeof v === 'object' && !Array.isArray(v) && cur && typeof cur === 'object' && !Array.isArray(cur)) {
        out[k] = deepMerge(cur, v);
      } else if (v && typeof v === 'object' && !Array.isArray(v)) {
        out[k] = deepMerge({}, v);
      } else {
        out[k] = v;
      }
    }
  }
  return out;
}

/** キーをソートしてシリアライズ (ハッシュ・差分検出・永続化用。循環参照は打ち切る) */
export function stableStringify(value, { space = 0, maxDepth = 12 } = {}) {
  const seen = new WeakSet();
  const walk = (v, depth) => {
    if (v === null || typeof v !== 'object') return typeof v === 'bigint' ? String(v) : v;
    if (depth > maxDepth) return '[deep]';
    if (seen.has(v)) return '[circular]';
    seen.add(v);
    if (Array.isArray(v)) return v.map((x) => walk(x, depth + 1));
    const out = {};
    for (const k of Object.keys(v).sort()) {
      if (v[k] === undefined || typeof v[k] === 'function') continue;
      out[k] = walk(v[k], depth + 1);
    }
    return out;
  };
  try {
    return JSON.stringify(walk(value, 0), null, space);
  } catch {
    return '{}';
  }
}


export function fmtBytes(n = 0) {
  const u = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  let v = Math.max(0, Number(n) || 0);
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v >= 10 || i === 0 ? Math.round(v) : v.toFixed(1)}${u[i]}`;
}

export function fmtMs(n = 0) {
  const v = Math.max(0, Number(n) || 0);
  if (v < 1000) return `${Math.round(v)}ms`;
  return `${(v / 1000).toFixed(v < 10000 ? 2 : 1)}s`;
}

export function relTime(ts) {
  const d = Date.now() - ts;
  if (d < 1500) return '今';
  if (d < 60000) return `${Math.round(d / 1000)}秒前`;
  if (d < 3600000) return `${Math.floor(d / 60000)}分前`;
  if (d < 86400000) return `${Math.floor(d / 3600000)}時間前`;
  return `${Math.floor(d / 86400000)}日前`;
}

export function escapeHtml(s = '') {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export const escapeRe = (s = '') => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** 指数的移動平均 */
export function ema(prev, next, alpha = 0.25) {
  const p = Number(prev);
  if (!Number.isFinite(p)) return Number(next) || 0;
  return p + alpha * ((Number(next) || 0) - p);
}

/** 文字列のエントロピー (bits/char) — 難読化判定に使う */
export function entropy(s = '') {
  if (!s) return 0;
  const f = Object.create(null);
  let n = 0;
  for (const ch of s) {
    f[ch] = (f[ch] || 0) + 1;
    n++;
  }
  let e = 0;
  for (const k in f) {
    const p = f[k] / n;
    e -= p * Math.log2(p);
  }
  return e;
}

/** Levenshtein (タイポスキッティング検知用, 軽い実装) */
export function lev(a, b, max = 4) {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = cur;
  }
  return prev[b.length];
}

/* ---------------- LRU ---------------- */

export class LRU {
  constructor(max = 500, ttl = 0) {
    this.max = max;
    this.ttl = ttl;
    this.map = new Map();
  }
  get(k) {
    const e = this.map.get(k);
    if (!e) return undefined;
    if (this.ttl && Date.now() - e.t > this.ttl) {
      this.map.delete(k);
      return undefined;
    }
    this.map.delete(k);
    this.map.set(k, e);
    return e.v;
  }
  set(k, v) {
    if (this.map.size >= this.max) {
      const first = this.map.keys().next().value;
      this.map.delete(first);
    }
    this.map.set(k, { v, t: Date.now() });
    return v;
  }
  get size() {
    return this.map.size;
  }
  delete(k) {
    return this.map.delete(k);
  }
  clear() {
    this.map.clear();
  }
  /** キャッシュミス時のみ compute() を実行して保持 */
  async wrap(k, compute) {
    const hit = this.get(k);
    if (hit !== undefined) return hit;
    const v = await compute();
    if (v !== undefined) this.set(k, v);
    return v;
  }
  stats() {
    return { size: this.map.size, max: this.max, ttl: this.ttl };
  }
  *values() {
    for (const e of this.map.values()) yield e.v;
  }
}

/** 単純な固定長リングバッファ (脅威イベント/メトリクス用) */
export class Ring {
  constructor(max = 500) {
    this.max = max;
    this.arr = [];
    this.total = 0;
  }
  push(v) {
    this.total++;
    this.arr.push(v);
    if (this.arr.length > this.max) this.arr.shift();
    return v;
  }
  list({ limit = 200, filter } = {}) {
    const out = [];
    for (let i = this.arr.length - 1; i >= 0 && out.length < limit; i--) {
      const v = this.arr[i];
      if (!filter || filter(v)) out.push(v);
    }
    return out;
  }
  get all() {
    return this.arr;
  }
  get length() {
    return this.arr.length;
  }
  removeWhere(fn) {
    const before = this.arr.length;
    this.arr = this.arr.filter((v) => !fn(v));
    return before - this.arr.length;
  }
  clear() {
    this.arr = [];
  }
}

/** キューによる同時実行制限 */
export async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let i = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    while (true) {
      const idx = i++;
      if (idx >= items.length) return;
      try {
        out[idx] = { ok: true, value: await fn(items[idx], idx) };
      } catch (err) {
        out[idx] = { ok: false, error: err };
      }
    }
  });
  await Promise.all(workers);
  return out;
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** 連続失敗などの状態をまとめて保持するヘルパ */
export function counter(map, key, delta = 1) {
  map.set(key, (map.get(key) || 0) + delta);
  return map.get(key);
}

/** レジストドメイン相当の簡易判定 (PSL なしで動かすための実用的近似) */
const TWO_LEVEL = new Set([
  'co', 'com', 'net', 'org', 'go', 'or', 'ac', 'ne', 'ad', 'ed', 'lg', 'mi', 're', 'sch',
]);
export function registrableDomain(hostname = '') {
  const host = String(hostname).toLowerCase().replace(/\.$/, '');
  if (/^\d+(\.\d+){3}$/.test(host) || host.includes(':')) return host;
  const parts = host.split('.');
  if (parts.length <= 2) return host;
  const second = parts[parts.length - 2];
  const tld = parts[parts.length - 1];
  const need = TWO_LEVEL.has(second) && tld.length === 2 ? 3 : 2;
  return parts.slice(-need).join('.');
}

export function isIpLiteral(host = '') {
  const h = host.replace(/^\[|\]$/g, '');
  return /^\d+(\.\d+){3}$/.test(h) || /^[0-9a-fA-F:]*:[0-9a-fA-F:]*$/.test(h) && h.includes(':');
}

/** 範囲内整数の乱数 */
export const randInt = (a, b) => a + Math.floor(Math.random() * (b - a + 1));

/** 安全 JSON parse */
export function parseJson(s, fallback = null) {
  try {
    return JSON.parse(s);
  } catch {
    return fallback;
  }
}

/** ヘッダ名の正規化 (小文字 / 無効文字除去) */
export function cleanHeaderName(s = '') {
  return String(s).toLowerCase().replace(/[^a-z0-9-]/g, '').slice(0, 60);
}

export function cleanHeaderValue(s = '') {
  return String(s).replace(/[\r\n\0]/g, ' ').slice(0, 8000);
}

/** 値を上限付きで保持 */
export function cap(n, max) {
  return Math.min(Math.max(0, Math.round(n || 0)), max);
}
