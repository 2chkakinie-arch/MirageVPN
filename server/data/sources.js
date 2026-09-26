/**
 * GitHub フリープロキシリスト・レジストリ + 取得/解析
 * ---------------------------------------------------------------
 * 「全自動で最新を取得」のための層。設計ポイント:
 *  - 複数の一次ソース (GitHub repo) を並列取得し、片方のリポジトリが死んでも機能継続
 *  - raw.githubusercontent.com が塞がれた環境 (社内ネット/一部 PaaS) 用に
 *    jsdelivr / api.github.com / githack へ自動フォールバック
 *  - リストによっては国コードが付いてくる (proxifly) ので、それを GeoIP シードとして使う
 * @module data/sources
 */

import { readFileSync } from 'node:fs';
import { writeFile, readFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { LRU, parseJson } from '../util.js';
import { log } from '../log.js';
import { normalizeCountry } from './geo.js';

const ns = log.child('lists');
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

/** @typedef {'http'|'https'|'socks4'|'socks5'} ProxyProtocol */

/**
 * 組み込みソース定義。`path` はブランチ基準。`format`:
 *  - `ip:port`     … 1 行 1 プロキシ (user:pass@ip:port にも対応)
 *  - `csv:3`       … `url,country,city` (proxifly 形式。先頭に scheme 付き)
 *  - `csv-fields`  … カンマ区切りでヘッダ無し `ip,port,country...`
 * @type {Array<object>}
 */
export const BUILTIN_SOURCES = [
  {
    id: 'proxifly-http',
    repo: 'proxifly/free-proxy-list',
    branch: 'main',
    path: 'proxies/protocols/http/data.csv',
    protocol: 'http',
    format: 'proxifly-csv',
    label: 'proxifly (HTTP)',
    weight: 1.0,
  },
  {
    id: 'proxifly-https',
    repo: 'proxifly/free-proxy-list',
    branch: 'main',
    path: 'proxies/protocols/https/data.csv',
    protocol: 'https',
    format: 'proxifly-csv',
    label: 'proxifly (HTTPS)',
    weight: 1.15,
  },
  {
    id: 'proxifly-socks5',
    repo: 'proxifly/free-proxy-list',
    branch: 'main',
    path: 'proxies/protocols/socks5/data.csv',
    protocol: 'socks5',
    format: 'proxifly-csv',
    label: 'proxifly (SOCKS5)',
    weight: 1.1,
  },
  {
    id: 'thespeedx-http',
    repo: 'TheSpeedX/PROXY-List',
    branch: 'master',
    path: 'http.txt',
    protocol: 'http',
    format: 'ip:port',
    label: 'TheSpeedX (HTTP)',
    weight: 0.9,
  },
  {
    id: 'thespeedx-socks5',
    repo: 'TheSpeedX/PROXY-List',
    branch: 'master',
    path: 'socks5.txt',
    protocol: 'socks5',
    format: 'ip:port',
    label: 'TheSpeedX (SOCKS5)',
    weight: 0.9,
  },
  {
    id: 'thespeedx-socks4',
    repo: 'TheSpeedX/PROXY-List',
    branch: 'master',
    path: 'socks4.txt',
    protocol: 'socks4',
    format: 'ip:port',
    label: 'TheSpeedX (SOCKS4)',
    weight: 0.75,
  },
];

export const BUILTIN_AD_LISTS = [
  {
    id: 'ublock-filters',
    repo: 'uBlockOrigin/uAssets',
    branch: 'master',
    path: 'filters/filters.txt',
    label: 'uBlock Origin – filters',
    kind: 'abp',
  },
  {
    id: 'ublock-privacy',
    repo: 'uBlockOrigin/uAssets',
    branch: 'master',
    path: 'filters/privacy.txt',
    label: 'uBlock Origin – privacy',
    kind: 'abp',
  },
  {
    id: 'ublock-badware',
    repo: 'uBlockOrigin/uAssets',
    branch: 'master',
    path: 'filters/badware.txt',
    label: 'uBlock Origin – badware',
    kind: 'abp',
  },
  // EasyList は「本体 1 ファイル」ではなく構成要素を置いていない (モジュラー化済み)。
  // ここでは (a) ホスト単位の広告サーバ一覧 と (b) $third-party 系 を読む。
  // どちらも `||host^` が大半なので本実装の高速経路 (blockHosts) にそのまま乗る。
  {
    id: 'easylist-adservers',
    repo: 'easylist/easylist',
    branch: 'master',
    path: 'easylist/easylist_adservers.txt',
    label: 'EasyList – ad servers',
    kind: 'abp',
  },
  {
    id: 'easylist-thirdparty',
    repo: 'easylist/easylist',
    branch: 'master',
    path: 'easylist/easylist_thirdparty.txt',
    label: 'EasyList – third-party',
    kind: 'abp',
  },
];

/* ------------------------------------------------------------------ */
/* URL 生成 / ミラー                                                   */
/* ------------------------------------------------------------------ */

export function mirrorUrls({ repo, branch = 'master', path: p }, order = ['raw', 'github-api', 'jsdelivr', 'githack']) {
  const clean = p.replace(/^\/+/, '');
  const map = {
    raw: `https://raw.githubusercontent.com/${repo}/${branch}/${clean}`,
    'github-api': `https://api.github.com/repos/${repo}/contents/${clean}?ref=${branch}`,
    jsdelivr: `https://cdn.jsdelivr.net/gh/${repo}@${branch}/${clean}`,
    githack: `https://rawcdn.githack.com/${repo}/${branch}/${clean}`,
    statically: `https://cdn.statically.io/gh/${repo}/${branch}/${clean}`,
  };
  return order.map((k) => map[k]).filter(Boolean);
}

/**
 * 1 つのソースを「どれかのミラーで」取得する。
 * @returns {Promise<{text:string, via:string, bytes:number}|null>}
 */
export async function fetchText(source, { timeoutMs = 20000, order, fetchImpl = globalThis.fetch } = {}) {
  const urls = mirrorUrls(source, order);
  let lastErr = null;
  for (const url of urls) {
    try {
      if (url.includes('api.github.com')) {
        const res = await fetchImpl(url, {
          signal: AbortSignal.timeout(timeoutMs),
          headers: { accept: 'application/vnd.github.raw+json', 'user-agent': 'MirageVPN/1.0' },
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const text = await res.text();
        // API が JSON を返してきた場合 (accept 無視環境) は base64 をほどく
        if (text.trimStart().startsWith('{')) {
          const j = parseJson(text, null);
          if (j?.content) return { text: Buffer.from(j.content, 'base64').toString('utf8'), via: 'github-api', bytes: j.size || 0 };
        }
        return { text, via: 'github-api', bytes: Buffer.byteLength(text) };
      }
      const res = await fetchImpl(url, {
        signal: AbortSignal.timeout(timeoutMs),
        headers: { 'user-agent': 'MirageVPN/1.0 (list updater)', accept: 'text/plain,*/*' },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const text = await res.text();
      if (text.length < 2) throw new Error('empty response');
      return { text, via: new URL(url).hostname, bytes: Buffer.byteLength(text) };
    } catch (err) {
      lastErr = err;
    }
  }
  ns.debug(() => `fetch failed for ${source.id}: ${lastErr?.message}`);
  return null;
}

/* ------------------------------------------------------------------ */
/* 解析                                                                */
/* ------------------------------------------------------------------ */

const PROXY_LINE =
  /^(?:(?<proto>https?|socks[45]a?|socks5h):\/\/)?(?:(?<user>[^:@\s/]+):(?<pass>[^@\s/]*)@)?(?<host>\[[0-9a-fA-F:.]+\]|[\w.-]+):(?<port>\d{2,5})(?<rest>.*)$/;

/**
 * `1.2.3.4:8080` / `http://1.2.3.4:8080` / `socks5://user:pass@ip:port` などを解析
 * @returns {{protocol:ProxyProtocol,host:string,port:number,username?:string,password?:string,country?:string,city?:string,anon?:boolean,schemeUrl:string}|null}
 */
export function parseProxyLine(line, fallbackProtocol = 'http') {
  const raw = String(line).trim();
  if (!raw || raw.startsWith('#') || raw.startsWith('//') || raw.startsWith('!')) return null;
  let m = PROXY_LINE.exec(raw);
  if (!m) {
    // `ip:port user:pass` や `ip:port:user:pass` 形式
    const sp = raw.split(/\s+/);
    const base = sp[0];
    if (base?.includes(':')) {
      const [host, port, u, p] = base.split(':');
      if (u && p) {
        m = { groups: { proto: sp[1] || fallbackProtocol, host, port, user: u, pass: p } };
      }
    }
    if (!m) return null;
  }
  const g = m.groups || {};
  const host = (g.host || '').replace(/^\[|\]$/g, '');
  const port = Number(g.port);
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) return null;
  // 数値でない host は除外 (リストのゴミ行対策)
  if (!/^\d+(\.\d+){3}$/.test(host) && !/:/.test(host) && !/^[a-z0-9.-]+$/i.test(host)) return null;
  const proto = String(g.proto || fallbackProtocol)
    .toLowerCase()
    .replace(/5h$/, '5');
  const protocol = ['http', 'https', 'socks4', 'socks4a', 'socks5'].includes(proto) ? proto : fallbackProtocol;
  const rest = g.rest || '';
  const countryFromTail = /\[?([A-Z]{2})\]?\s*$/.exec(rest.split(/[\s|]/).filter(Boolean).slice(-1)[0] || '');
  return {
    protocol,
    host,
    port,
    username: g.user || undefined,
    password: g.pass || undefined,
    country: normalizeCountry(g.country) || normalizeCountry(countryFromTail?.[1]) || undefined,
    anon: /elite|anonymous/i.test(rest) || undefined,
    schemeUrl: `${protocol}://${host}:${port}`,
  };
}

/**
 * proxifly 形式の CSV: `http://1.2.3.4:8080,JP,Tokyo`
 */
export function parseProxiflyCsv(text, fallbackProtocol = 'http') {
  const out = [];
  const seen = new Set();
  for (const line of String(text).split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('!') || trimmed.startsWith('#')) continue;
    const cols = trimmed.split(',');
    const first = cols[0].trim();
    const proxy = parseProxyLine(first, fallbackProtocol);
    if (!proxy) continue;
    proxy.country = normalizeCountry(cols[1]) || proxy.country;
    proxy.city = (cols[2] || '').trim() || undefined;
    const key = `${proxy.protocol}|${proxy.host}:${proxy.port}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(proxy);
  }
  return out;
}

/** `ip:port` 形式 (1 行 1 エントリ) */
export function parseIpPortList(text, fallbackProtocol = 'http') {
  const out = [];
  const seen = new Set();
  for (const line of String(text).split(/\r?\n/)) {
    const proxy = parseProxyLine(line, fallbackProtocol);
    if (!proxy) continue;
    const key = `${proxy.protocol}|${proxy.host}:${proxy.port}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(proxy);
  }
  return out;
}

/** `ip,port,country` カンマ区切り形式 (gitlab / monosource 系) */
export function parseCsvFields(text, fallbackProtocol = 'http') {
  const out = [];
  const seen = new Set();
  for (const line of String(text).split(/\r?\n/)) {
    const cols = line.trim().split(/[,;\t]/);
    if (cols.length < 2) continue;
    const proxy = parseProxyLine(`${cols[0].trim()}:${cols[1].trim()}`, fallbackProtocol);
    if (!proxy) continue;
    proxy.country = normalizeCountry(cols[2]) || undefined;
    proxy.city = (cols[3] || '').trim() || undefined;
    const key = `${proxy.protocol}|${proxy.host}:${proxy.port}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(proxy);
  }
  return out;
}

export function parseProxies(text, format = 'ip:port', fallbackProtocol = 'http') {
  if (format === 'proxifly-csv' || format === 'csv-country') return parseProxiflyCsv(text, fallbackProtocol);
  if (format === 'csv-fields' || format === 'csv') return parseCsvFields(text, fallbackProtocol);
  if (format === 'json') {
    const j = parseJson(text, []);
    const arr = Array.isArray(j) ? j : j?.proxies || j?.data || [];
    const out = [];
    for (const item of arr) {
      if (!item) continue;
      const host = item.ip || item.host || item.address;
      const port = item.port;
      if (!host || !port) continue;
      const p = parseProxyLine(`${host}:${port}`, item.anonymous === true || item.secure ? 'https' : fallbackProtocol);
      if (p) {
        p.country = normalizeCountry(item.country_code || item.countryCode || item.country) || undefined;
        p.city = item.city || item.location || undefined;
        out.push(p);
      }
    }
    return out;
  }
  return parseIpPortList(text, fallbackProtocol);
}

/* ------------------------------------------------------------------ */
/* キャッシュ / シード                                                 */
/* ------------------------------------------------------------------ */

/** 生テキストを disk に保存 (次回 boot 時、ネットワーク不可でもリストを復元) */
export async function saveSnapshot(dir, sourceId, text) {
  if (!dir) return false;
  try {
    await mkdir(dir, { recursive: true });
    await writeFile(path.join(dir, `${sourceId}.snapshot`), text, 'utf8');
    return true;
  } catch (err) {
    ns.debug(() => `snapshot save failed: ${err.message}`);
    return false;
  }
}

export async function loadSnapshot(dir, sourceId) {
  if (!dir) return null;
  try {
    return await readFile(path.join(dir, `${sourceId}.snapshot`), 'utf8');
  } catch {
    return null;
  }
}

export function bundledSeedFile(rel) {
  try {
    return readFileSync(path.join(ROOT, rel), 'utf8');
  } catch {
    return null;
  }
}

/** data/seeds に同梱されたシードを読み込んで正規化レコード配列にする */
export function loadBundledSeeds() {
  const out = [];
  const seen = new Set();
  const files = [
    { f: 'data/seeds/proxifly-http.csv', format: 'proxifly-csv', proto: 'http' },
    { f: 'data/seeds/proxifly-https.csv', format: 'proxifly-csv', proto: 'https' },
    { f: 'data/seeds/proxifly-socks5.csv', format: 'proxifly-csv', proto: 'socks5' },
    { f: 'data/seeds/thespeedx-http.txt', format: 'ip:port', proto: 'http' },
    { f: 'data/seeds/thespeedx-socks5.txt', format: 'ip:port', proto: 'socks5' },
  ];
  for (const { f, format, proto } of files) {
    const text = bundledSeedFile(f);
    if (!text) continue;
    for (const p of parseProxies(text, format, proto)) {
      const key = `${p.protocol}|${p.host}:${p.port}`;
      if (seen.has(key)) continue;
      seen.add(key);
      p.seed = f;
      out.push(p);
    }
  }
  return out;
}

/** 監視対象ソース = 組み込み + 環境変数で足したもの */
export function resolveSources(cfg) {
  const extra = (cfg.lists.extra || []).map((spec, i) => {
    // 書式: repo(オーナー/名前)#[branch]#[path]#[proto]#[format]
    const [repo, branch = 'main', p, proto = 'http', format = 'ip:port'] = String(spec).split('#');
    if (repo.startsWith('http')) {
      return { id: `custom-${i}`, url: repo, protocol: proto, format, label: `custom ${i}`, direct: true };
    }
    return { id: `custom-${i}`, repo, branch, path: p || 'proxy.txt', protocol: proto, format, label: `custom:${repo}` };
  });
  const builtin = BUILTIN_SOURCES.filter((s) => (cfg.egress.protocols || []).includes(s.protocol));
  return [...builtin, ...extra];
}

/** direct URL ソースにも対応した取得ラッパ */
export async function fetchSourceText(source, opts = {}) {
  if (source.direct) {
    try {
      const res = await (opts.fetchImpl || globalThis.fetch)(source.url, {
        signal: AbortSignal.timeout(opts.timeoutMs || 20000),
        headers: { 'user-agent': 'MirageVPN/1.0 (list updater)' },
      });
      if (!res.ok) return null;
      const text = await res.text();
      return { text, via: new URL(source.url).hostname, bytes: Buffer.byteLength(text) };
    } catch {
      return null;
    }
  }
  return fetchText(source, opts);
}

export class SourceStats {
  constructor() {
    this.byId = new Map();
  }
  record(id, { ok, count, bytes, via, ms, error }) {
    const prev = this.byId.get(id) || { id, ok: 0, fail: 0, count: 0, bytes: 0, last: null };
    if (ok) prev.ok++;
    else prev.fail++;
    prev.count = count || 0;
    prev.bytes = bytes || 0;
    prev.last = { at: Date.now(), via, ms, error };
    this.byId.set(id, prev);
    return prev;
  }
  list() {
    return [...this.byId.values()].sort((a, b) => b.count - a.count);
  }
}

export default { BUILTIN_SOURCES, parseProxies, parseProxyLine, loadBundledSeeds, resolveSources, fetchSourceText, mirrorUrls };
