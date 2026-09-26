/**
 * MirageVPN Service Worker — トランスポートの入口
 * ---------------------------------------------------------------
 * 役割は 3 つ:
 *  1. rewrite を潜り抜けた「取りこぼし」を救う。
 *     - root-relative URL (`/assets/a.css`) は当オリジンに逃げる → Referer から上流 base を復元して proxify
 *     - rewrite されない動的 URL (fetch('https://x/y') 等) も proxify (= リーク阻止)
 *  2. すでに proxied なリクエスト (/mirage/t/<sid>/…) をそのままサーバに流すか、
 *     モードが wisp/auto のとき WISP トンネルへ差し替える。
 *  3. 上流へ渡してはいけないヘッダを落とす (x-mirage-* は our origin 内なので安全)。
 *
 * 注意: core.js が仕込む x-mirage-* メタはこの SW 経由でも付いたまま流れる。
 */
/* global self, Response, Request, URL, clients, importScripts */
'use strict';

const PREFIX = self.__MIRAGE_PREFIX || '/mirage/t';
const API = '/mirage/api';
const INTERNAL = ['/mirage/api', '/mirage/core.js', '/mirage/sw.js', '/mirage/wisp-client.js', '/mirage/static', '/assets', '/icons', '/manifest'];
const modeOverrides = new Map(); // sid → 'uv' | 'wisp' | 'auto'

try {
  importScripts('/mirage/wisp-client.js');
} catch (e) {
  // WISP クライアントが無い環境 (serverless など) では UV のみ
}

self.addEventListener('install', (e) => {
  e.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', (e) => {
  e.waitUntil(clients.claim());
});

self.addEventListener('message', (ev) => {
  const d = ev.data || {};
  if (d.type === 'mirage:mode' && d.sid) modeOverrides.set(d.sid, d.mode);
  if (d.type === 'mirage:forget' && d.sid) modeOverrides.delete(d.sid);
  if (d.type === 'mirage:reload-all') {
    clients.matchAll({ type: 'window' }).then((list) => {
      list.forEach((c) => {
        try { c.postMessage({ type: 'mirage:reload' }); } catch (e) {}
      });
    });
  }
});

function ownOrigin(u) {
  return u.origin === self.location.origin;
}
function isInternal(pathname) {
  for (const p of INTERNAL) if (pathname.startsWith(p)) return true;
  return false;
}
function defaultMode() {
  try {
    return localStorage.getItem('mirage.mode') || 'uv';
  } catch (e) {
    return 'uv';
  }
}

/** `/mirage/t/<sid>/h.<token>/path` をパース (サーバ側の UrlMap と同じロジック) */
function parseProxied(pathname) {
  if (!pathname.startsWith(PREFIX + '/')) return null;
  const tail = pathname.slice(PREFIX.length + 1);
  const parts = tail.split('/');
  const sid = parts.shift();
  const marker = parts.shift() || '';
  if (!sid) return null;
  return { sid, marker, rest: '/' + parts.join('/') };
}
function decodeHost(seg) {
  try {
    if (seg.indexOf('h.') === 0) return unb64url(seg.slice(2));
    if (seg.indexOf('u.') === 0) return decodeURIComponent(seg.slice(2));
  } catch (e) {}
  return null;
}
function unb64url(b64) {
  let p = b64.replace(/-/g, '+').replace(/_/g, '/');
  while (p.length % 4) p += '=';
  const bin = atob(p);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}
function encodeHost(origin) {
  const bytes = new TextEncoder().encode(origin);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return 'h.' + btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** 上流 URL → proxied path (core.js と同一) */
function proxify(absHref, sid) {
  try {
    const u = new URL(absHref);
    if (!/^https?:$/.test(u.protocol)) return null;
    const port = u.port ? (u.protocol === 'http:' && u.port === '80' ? '' : u.protocol === 'https:' && u.port === '443' ? '' : ':' + u.port) : '';
    const origin = u.protocol + '//' + u.hostname + port;
    return `${PREFIX}/${sid}/${encodeHost(origin)}${u.pathname || '/'}${u.search || ''}`;
  } catch (e) {
    return null;
  }
}

/** proxied path → 上流 URL */
function deproxify(pathname) {
  const p = parseProxied(pathname);
  if (!p) return null;
  const origin = decodeHost(p.marker);
  if (!origin) return null;
  try {
    return { sid: p.sid, url: new URL(origin + p.rest) };
  } catch (e) {
    return null;
  }
}

/**
 * リクエストの「誰が起動したか」を復元する。
 * proxied ページからの root-relative / cross-origin リークはここで吸収する。
 */
function contextOf(request) {
  const ref = request.referrer;
  if (ref) {
    const u = new URL(ref);
    if (ownOrigin(u)) {
      const d = deproxify(u.pathname);
      if (d) return { sid: d.sid, base: d.url, proxiedReferrer: true };
    }
  }
  const sid = request.headers.get('x-mirage-sid');
  if (sid) return { sid, base: null, proxiedReferrer: true };
  return null;
}

self.addEventListener('fetch', (ev) => {
  const req = ev.request;
  const url = new URL(req.url);
  if (req.method === 'OPTIONS') return;

  // --- proxied リクエスト ---
  if (ownOrigin(url) && url.pathname.startsWith(PREFIX + '/')) {
    const parsed = parseProxied(url.pathname);
    const mode = (parsed && modeOverrides.get(parsed.sid)) || defaultMode();
    if (shouldUseWisp(mode, req, url)) {
      ev.respondWith(wispRequest(req, url).catch(() => passthrough(req)));
      return;
    }
    return; // 素通し (サーバ側が処理する)
  }

  // --- 当オリジンの内部資産は触らない ---
  if (ownOrigin(url) && (isInternal(url.pathname) || !contextOf(req))) return;

  const ctx = contextOf(req);
  if (!ctx) return;

  // --- rewrite を潜り抜けた URL を proxify して救済 ---
  let target = null;
  if (!ownOrigin(url)) {
    target = url.href; // 上流ドメインへ直接向かった → リーク、プロキシへ引き戻す
  } else if (ctx.base) {
    try {
      target = new URL(url.pathname + url.search, ctx.base.href).href;
    } catch (e) {
      target = null;
    }
  }
  if (!target) return;
  const proxied = proxify(target, ctx.sid);
  if (!proxied) return;
  const headers = new Headers(req.headers);
  headers.set('x-mirage-sid', ctx.sid);
  headers.set('x-mirage-recovered', '1');
  const mode = modeOverrides.get(ctx.sid) || defaultMode();
  if (shouldUseWisp(mode, req, new URL(target))) {
    ev.respondWith(wispFetch(req, target).catch(() => passthrough(req)));
    return;
  }
  ev.respondWith(passthrough(new Request(new URL(proxied, self.location.origin).href, {
    method: req.method,
    headers,
    body: ['GET', 'HEAD'].includes(req.method) ? null : req.body,
    credentials: 'omit',
    mode: 'cors',
    cache: 'no-cache',
    redirect: 'manual',
    duplex: 'half',
  })));
});

function passthrough(req) {
  return fetch(req);
}

function shouldUseWisp(mode, req, url) {
  if (mode !== 'wisp' && mode !== 'auto') return false;
  if (!self.__mrgWisp) return false;
  if (req.mode === 'navigate') return false; // ドキュメントは UV (ストリーミング表示が速い)
  if (!/^https?:$/.test(url.protocol)) return false;
  if (!['GET', 'HEAD', 'POST'].includes(req.method)) return false;
  // 大きな/バイナリのダウンロードは素の HTTP の方が有利
  const path = (url.pathname || '').toLowerCase();
  if (/\.(zip|gz|tar|mp4|webm|mkv|iso|dmg|exe|apk|woff2?|ttf|otf|png|jpe?g|webp|avif|mp3|ogg)$/.test(path)) return false;
  return true;
}

/** proxied URL を WISP トンネル経由で実行して Response に変換 */
async function wispRequest(req, url) {
  const parsed = deproxify(url.pathname);
  if (!parsed) throw new Error('unparsed');
  const abs = new URL(parsed.url.href);
  if (url.search) abs.search = url.search;
  return wispFetch(req, abs.href);
}

async function wispFetch(req, absHref) {
  const headers = {};
  req.headers.forEach((v, k) => {
    if (!['host', 'origin', 'referer', 'cookie', 'connection', 'content-length'].includes(k)) headers[k] = v;
  });
  const body = ['GET', 'HEAD'].includes(req.method) ? null : await req.arrayBuffer();
  const r = await self.__mrgWisp.request(req.method, absHref, headers, body, { sid: (parseProxifySid(req) || undefined) });
  return new Response(r.body, {
    status: r.status,
    statusText: r.statusText,
    headers: r.headers,
  });
}

function parseProxifySid(req) {
  const sid = req.headers.get('x-mirage-sid');
  if (sid) return sid;
  const ref = req.referrer ? new URL(req.referrer) : null;
  if (ref && ownOrigin(ref)) {
    const p = parseProxied(ref.pathname);
    if (p) return p.sid;
  }
  return null;
}
