/**
 * 外向き「管理系」HTTP クライアント — リスト取得 / Geo / 検証プローブ用
 * ---------------------------------------------------------------
 * `globalThis.fetch` (undici) を使わない理由:
 *  1. undici は Node 同梱 CA しか信頼しない → 社内プロキシ/フィルタ環境で
 *     `UNABLE_TO_VERIFY_LEAF_SIGNATURE` になり、GitHub リストだけが全滅する (実害あり)
 *  2. エラーが `TypeError: fetch failed` に潰れて **理由が UI に出せない**
 *     (利用者は「取得できない」しか分からず、対処できない)
 *  3. 送信プロキシ (HTTPS_PROXY) や keep-alive を自前ポリシーで制御できない
 *
 *  そこで既存の `net/http1.js` (素の socket) を使い、
 *  「厳格 TLS + OS 信頼ストア」「リダイレクト追従」「解凍」「詳細なエラー分類」
 *  「送信プロキシ対応」をまとめて提供する。依存は増えない。
 * @module net/outbound
 */

import zlib from 'node:zlib';
import { Buffer } from 'node:buffer';
import { request as http1Request, Http1Pool, HttpError } from './http1.js';
import { classifyNetError, trustOptions } from './trust.js';

/** 管理系リクエスト専用の keep-alive プール (プロセス内で 1 つ) */
export const outboundPool = new Http1Pool({ maxIdlePerKey: 4, idleTimeoutMs: 20000 });

/**
 * 環境変数の送信プロキシ (HTTPS_PROXY / HTTP_PROXY / ALL_PROXY) を読む。
 * `NO_PROXY` に合うホストは direct。
 * @returns {import('./http1.js').ProxyDef|null}
 */
export function envProxyFor(targetUrl, env = process.env) {
  const u = typeof targetUrl === 'string' ? safeUrl(targetUrl) : targetUrl;
  if (!u) return null;
  const noProxy = String(env.NO_PROXY || env.no_proxy || '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  const host = u.hostname.toLowerCase();
  if (noProxy.includes('*')) return null;
  for (const entry of noProxy) {
    const bare = entry.replace(/^\./, '');
    if (host === bare || host.endsWith(`.${bare}`)) return null;
  }
  const raw = (u.protocol === 'https:' ? env.HTTPS_PROXY || env.https_proxy : env.HTTP_PROXY || env.http_proxy) || env.ALL_PROXY || env.all_proxy;
  if (!raw) return null;
  const p = safeUrl(/^https?:\/\//i.test(raw) ? raw : `http://${raw}`);
  if (!p) return null;
  return {
    protocol: p.protocol === 'https:' ? 'https' : 'http',
    host: p.hostname,
    port: Number(p.port) || (p.protocol === 'https:' ? 443 : 80),
    username: p.username ? decodeURIComponent(p.username) : undefined,
    password: p.password ? decodeURIComponent(p.password) : undefined,
  };
}

/**
 * @typedef {object} OutResponse
 * @property {boolean} ok            2xx/3xx かつ本文あり
 * @property {number} status
 * @property {string} statusText
 * @property {Map<string,string>} headers
 * @property {string} text           解凍済みの本文 (utf8)
 * @property {number} bytes          解凍後のバイト数
 * @property {number} ms             所要時間
 * @property {string} finalUrl       リダイレクト後の最終 URL
 * @property {string} via            実際につながった経路 (hostname / proxy)
 */

/**
 * テキストを取得する。失敗は例外 (code + hint 付き) で返すので、呼び出し側は理由を表示できる。
 * @param {string} url
 * @param {{
 *   method?:string, headers?:Record<string,string>|Map<string,string>, timeoutMs?:number,
 *   connectTimeoutMs?:number, maxBytes?:number, redirects?:number, proxy?:object|null,
 *   strictTls?:boolean, insecure?:boolean, useEnvProxy?:boolean, pool?:object|null, signal?:AbortSignal,
 *   accept?:string
 * }} [opts]
 * @returns {Promise<OutResponse>}
 */
export async function fetchOut(url, opts = {}) {
  const {
    method: initialMethod = 'GET',
    headers = {},
    timeoutMs = 20000,
    connectTimeoutMs = Math.min(10000, timeoutMs),
    maxBytes = 24 * 1024 * 1024,
    redirects = 3,
    proxy,
    strictTls = true,
    insecure = false,
    useEnvProxy = true,
    pool = outboundPool,
    signal = null,
    accept = 'text/plain,application/json;q=0.9,*/*;q=0.5',
  } = opts;

  const t0 = Date.now();
  let method = String(initialMethod).toUpperCase();
  let current = String(url);
  let hop = 0;
  const tlsOpts = trustOptions({ strict: strictTls, insecure });
  const deadline = t0 + timeoutMs;

  while (true) {
    const target = safeUrl(current);
    if (!target) throw outboundError(new Error(`URL を解釈できません: ${current.slice(0, 120)}`), { code: 'bad_url', url: current });
    if (!/^https?:$/.test(target.protocol)) throw outboundError(new Error(`未対応のプロトコル: ${target.protocol}`), { code: 'bad_protocol', url: current });

    const hdrs = new Map();
    for (const [k, v] of headers instanceof Map ? headers : Object.entries(headers)) {
      if (v == null) continue;
      hdrs.set(String(k).toLowerCase(), String(v));
    }
    if (!hdrs.has('accept')) hdrs.set('accept', accept);
    if (!hdrs.has('user-agent')) hdrs.set('user-agent', 'MirageVPN/1.0 (+https://github.com/2chkakinie-arch/MirageVPN)');
    hdrs.set('connection', 'keep-alive');

    const remaining = Math.max(1500, deadline - Date.now());
    const useProxy = proxy !== undefined && proxy !== null ? proxy : useEnvProxy ? envProxyFor(target) : null;

    let res;
    try {
      res = await http1Request({
        url: target.href,
        method,
        headers: hdrs,
        proxy: useProxy,
        tls: tlsOpts,
        connectTimeoutMs: Math.min(connectTimeoutMs, remaining),
        headTimeoutMs: remaining,
        idleTimeoutMs: remaining,
        maxBodyBytes: maxBytes,
        pool,
        signal,
      });
    } catch (err) {
      throw outboundError(err, { url: target.href, via: useProxy ? `${useProxy.host}:${useProxy.port}` : target.hostname });
    }

    const loc = res.headers.get('location');
    if ([301, 302, 303, 307, 308].includes(res.statusCode) && loc && hop < redirects) {
      const next = safeUrl(loc, target.href);
      drainAndRelease(res);
      if (!next) throw outboundError(new Error('Location が不正です'), { code: 'bad_location', url: target.href });
      if (Date.now() > deadline) throw outboundError(new Error('リダイレクト追従中にタイムアウトしました'), { code: 'timeout', url: next.href });
      current = next.href;
      hop++;
      if ([301, 302, 303].includes(res.statusCode)) method = 'GET';
      continue;
    }

    const buf = await readAndDecode(res, { maxBytes });
    const ms = Date.now() - t0;
    return {
      ok: res.statusCode >= 200 && res.statusCode < 300,
      status: res.statusCode,
      statusText: res.statusText,
      headers: res.headers,
      text: buf.toString('utf8'),
      body: buf,
      bytes: buf.length,
      ms,
      finalUrl: target.href,
      via: useProxy ? `proxy ${useProxy.host}:${useProxy.port}` : target.hostname,
      hops: hop,
    };
  }
}

/** JSON を取得してパースする (失敗は理由付きで throw) */
export async function fetchJson(url, opts = {}) {
  const res = await fetchOut(url, { ...opts, accept: 'application/json' });
  if (!res.ok) throw outboundError(new Error(`HTTP ${res.status}`), { code: `http_${res.status}`, url: res.finalUrl, status: res.status });
  try {
    return JSON.parse(res.text);
  } catch (err) {
    throw outboundError(err, { code: 'bad_json', url: res.finalUrl });
  }
}

function drainAndRelease(res) {
  try {
    res.stream?.resume();
    res.stream?.on('error', () => {});
  } catch {
    /* ignore */
  }
}

async function readAndDecode(res, { maxBytes }) {
  const chunks = [];
  let len = 0;
  try {
    for await (const c of res.stream) {
      chunks.push(c);
      len += c.length;
      if (maxBytes && len > maxBytes) {
        res.stream.destroy?.();
        throw new HttpError(`応答が大きすぎます (${len} bytes > ${maxBytes})`, { code: 'body_too_large' });
      }
    }
  } catch (err) {
    throw outboundError(err, { url: res.finalUrl });
  }
  const raw = Buffer.concat(chunks, len);
  const enc = String(res.headers.get('content-encoding') || '').toLowerCase().split(',').pop().trim();
  if (!enc || enc === 'identity') return raw;
  try {
    if (enc === 'gzip' || enc === 'x-gzip') return zlib.gunzipSync(raw);
    if (enc === 'br') return zlib.brotliDecompressSync(raw);
    if (enc === 'deflate') {
      try {
        return zlib.inflateRawSync(raw);
      } catch {
        return zlib.inflateSync(raw);
      }
    }
  } catch {
    return raw; // 解凍できなければ生のまま (呼び出し側で判定できる)
  }
  return raw;
}

/** 理由・対処付きのエラーに正規化する (UI に出すため) */
export function outboundError(err, { url, via, code, status } = {}) {
  const info = classifyNetError(err);
  const e = new Error(info.message);
  e.code = code || info.code;
  e.kind = info.kind;
  e.hint = info.hint;
  e.url = url;
  e.via = via;
  e.status = status;
  e.cause = err;
  return e;
}

function safeUrl(s, base) {
  try {
    return new URL(s, base);
  } catch {
    return null;
  }
}

export default { fetchOut, fetchJson, envProxyFor, outboundPool, outboundError };
