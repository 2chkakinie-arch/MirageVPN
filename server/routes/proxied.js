/**
 * プロキシトランスポート (UV モード) — /mirage/t/<sid>/h.<origin>/<path>?<query>
 * ---------------------------------------------------------------
 * Service Worker が発火させる「素の HTTP リクエスト」をここで上流へ中継する。
 * URL は encode された origin + verbatim path/query なので、相対解決はブラウザが
 * そのままできる (base は消費済み / 絶対パスは sw.js が救出する)。
 * @module routes/proxied
 */

import { Buffer } from 'node:buffer';
import { safeUrl } from '../proxy/urlmap.js';
import { log } from '../log.js';

const ns = log.child('http');

const NO_BODY = new Set(['GET', 'HEAD']);

/**
 * @param {ReturnType<import('../app.js').createApp>} ctx
 * @returns {(req:any,res:any,next:any)=>Promise<void>}
 */
export function createProxiedHandler(ctx) {
  const { config, engine } = ctx;
  const { urlmap, pipeline } = engine;

  return async function proxied(req, res, next) {
    const started = Date.now();
    const raw = req.originalUrl || req.url || '/';
    const qIdx = raw.indexOf('?');
    const pathname = qIdx === -1 ? raw : raw.slice(0, qIdx);
    const search = qIdx === -1 ? '' : raw.slice(qIdx);
    // urlmap は basePath を含む完全な内部パスでトークンを解決する。
    // ここで前置きを落とすと、サブパス配信時だけ全ページが 404 になる。
    const proxyPath = `${config.basePath}${config.url.prefix}`;
    if (!pathname.startsWith(`${proxyPath}/`)) return next();

    let parsed = null;
    try {
      parsed = urlmap.deproxify(pathname, search);
    } catch (err) {
      ns.debug(() => `deproxify threw: ${err.message}`);
    }
    // デバッグ用フォールバック: /mirage/t/<sid>/abs/<encodeURIComponent(絶対URL)>
    if (!parsed) {
      try {
        const a = urlmap.parseAbs(pathname);
        if (a) parsed = { sid: a.sid, url: a.url, ws: a.url.protocol === 'ws:' || a.url.protocol === 'wss:' };
      } catch (err) {
        /* noop */
      }
    }
    if (!parsed) return notFound(req, res, ctx);

    if (!NO_BODY.has(req.method)) {
      try {
        req.mirageBody = await readRawBody(req, config.transport.maxBodyBytes);
      } catch (err) {
        return writeResult(
          res,
          { status: err.status || 413, statusText: 'Payload Too Large', headers: new Map([['content-type', 'text/plain; charset=utf-8']]), body: Buffer.from(String(err.message)), info: {} },
          req,
        );
      }
    }

    const refererRaw = req.headers.referer || req.headers.referrer || '';
    const referrer = refererRaw ? deproxifyAbs(String(refererRaw), ctx) : null;

    const dest = String(req.headers['sec-fetch-dest'] || '').toLowerCase();
    const acceptsHtml = /text\/html/.test(String(req.headers.accept || ''));
    const isDocument = ['document', 'iframe', 'frame', ''].includes(dest) && acceptsHtml;

    const out = await pipeline.execute({
      sid: parsed.sid,
      clientId: req.mirage.clientId,
      settings: req.mirage.settings,
      method: req.method,
      url: parsed.url.href,
      headers: incomingHeaders(req),
      body: NO_BODY.has(req.method) ? null : req.mirageBody,
      mode: req.mirage.mode || 'uv',
      kind: isDocument ? 'document' : 'asset',
      dest: dest || (isDocument ? 'document' : 'fetch'),
      referrer,
      spoofIp: req.headers['x-mirage-spoof-ip'] || undefined,
      headersOnly: req.method === 'HEAD',
    });

    writeResult(res, out, req);
    ns.debug(() => `${req.method} ${parsed.url.href} → ${out.status} (${Date.now() - started}ms, ${out.info?.bytes || 0}B)`);
    return undefined;
  };
}

/** 上流に渡してよいヘッダだけを Map にする (host/connection/content-length は pipeline 側で作り直す) */
const DROP_REQUEST = new Set([
  'host',
  'connection',
  'content-length',
  'keep-alive',
  'proxy-connection',
  'transfer-encoding',
  'upgrade',
  'te',
  'cookie', // 当方のジャーマーから入れる
  'x-forwarded-for',
  'x-forwarded-proto',
  'x-forwarded-host',
  'forwarded',
  'via',
  'x-real-ip',
  'sec-websocket-extensions',
  'sec-websocket-key',
  'sec-websocket-version',
  'sec-fetch-store',
]);
function incomingHeaders(req) {
  const h = new Map();
  for (const [k, v] of Object.entries(req.headers || {})) {
    const name = k.toLowerCase();
    if (DROP_REQUEST.has(name) || name.startsWith('sec-ch-ua') || name.startsWith('x-mirage-')) continue;
    if (v == null) continue;
    h.set(name, Array.isArray(v) ? v.join(', ') : String(v));
  }
  // core.js が送ってきたヒント (上流には送らないが pipeline は読む)
  if (req.headers['x-mirage-base']) h.set('x-mirage-base', String(req.headers['x-mirage-base']));
  return h;
}

export function writeResult(res, out, req) {
  if (res.headersSent) return;
  const status = out.status || 502;
  const headers = new Map(out.headers || []);
  const body = out.body;
  const isHead = req.method === 'HEAD';

  if (Buffer.isBuffer(body) || typeof body === 'string') {
    const buf = typeof body === 'string' ? Buffer.from(body) : body;
    headers.set('content-length', String(isHead ? 0 : buf.length));
  }
  res.statusCode = status;
  if (res.setStatusMessage && out.statusText) {
    try {
      res.setStatusMessage(out.statusText);
    } catch (e) {}
  }
  for (const [k, v] of headers) {
    if (v === undefined || v === null) continue;
    try {
      res.setHeader(k, v);
    } catch (err) {
      ns.debug(() => `setHeader(${k}) failed: ${err.message}`);
    }
  }
  if (isHead) return res.end();
  if (Buffer.isBuffer(body) || typeof body === 'string') return res.end(body);
  if (body && typeof body.pipe === 'function') {
    // 未改写のストリーム (動画など) はそのまま中継
    try {
      body.pipe(res);
      body.on('error', () => {
        try { res.destroy(); } catch (e) {}
      });
      res.on('close', () => {
        try { body.destroy(); } catch (e) {}
      });
    } catch (err) {
      res.end();
    }
    return undefined;
  }
  return res.end();
}

/** our-origin の referer → 上流の URL (いなければ null) */
function deproxifyAbs(href, ctx) {
  try {
    const u = new URL(href);
    const proxyPath = `${ctx.config.basePath}${ctx.config.url.prefix}`;
    if (!u.pathname.startsWith(`${proxyPath}/`)) return null;
    const parsed = ctx.engine.urlmap.deproxify(u.pathname, u.search);
    return parsed ? parsed.url.href : null;
  } catch (err) {
    return null;
  }
}

export function readRawBody(req, limitBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > limitBytes) {
        reject(Object.assign(new Error(`リクエストボディが大きすぎます (上限 ${Math.round(limitBytes / 1048576)}MB)`), { code: 'payload_too_large', status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
    // Vercel 等で body が先にパースされてしまっていた場合の救済
    if (req.body !== undefined && !req.readable) {
      const b = req.body;
      if (b == null) return resolve(Buffer.alloc(0));
      if (Buffer.isBuffer(b)) return resolve(b);
      if (typeof b === 'string') return resolve(Buffer.from(b));
      try {
        return resolve(Buffer.from(JSON.stringify(b)));
      } catch (e) {
        return resolve(Buffer.alloc(0));
      }
    }
    return undefined;
  });
}

function notFound(req, res, ctx) {
  const target = ctx.engine.urlmap.parseSession((req.originalUrl || '').replace(/^\/?/, ''));
  res.statusCode = 404;
  res.setHeader('content-type', 'text/plain; charset=utf-8');
  res.end(
    target
      ? `MirageVPN: URL を解釈できませんでした。マーカー (h./u.) が不足しています。\npath=${req.originalUrl}`
      : `MirageVPN: 不明なプロキシパスです。\npath=${req.originalUrl}\nform=<prefix>/<sid>/h.<b64(origin)>/<path>`,
  );
}

export default createProxiedHandler;
