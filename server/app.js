/**
 * MirageVPN — アプリ本体 (Express)
 * ---------------------------------------------------------------
 * ルーティングの全体像:
 *
 *   /                     … ダッシュボード (public/index.html)
 *   /mirage/app/*         … 同じ UI の別パス (フレーム内 embed 用)
 *   /mirage/core.js       … 注入されるクライアントコア (設定は各ドキュメントに埋め込み)
 *   /mirage/sw.js         … Service Worker (先頭に当方の設定を注入して配る)
 *   /mirage/worker.js     … Worker 用シム
 *   /mirage/wisp-client.js… WISP クライアント (SW 内 & ページ内)
 *   /mirage/api/*         … 状態・設定・レポート JSON API
 *   /mirage/t/<sid>/…     … プロキシトラフィック (UV)
 *   /mirage/wisp          … WISP WebSocket (Upgrade)
 *   /mirage/t/<sid>/ws/…  … WebSocket 中継 (UV)
 *
 * セキュリティヘッダは自作 (helmet 非依存)。proxied なレスポンスには当方のヘッダを
 * 付けない (上流の挙動を壊さない) ので注意。
 * @module app
 */

import express from 'express';
import path from 'node:path';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { randomUUID, createHmac } from 'node:crypto';
import { loadConfig } from './config.js';
import { createEngine } from './engine.js';
import { createApiRouter } from './routes/api.js';
import { createProxiedHandler } from './routes/proxied.js';
import { rateLimitMiddleware, RateLimiter } from './routes/ratelimit.js';
import { attachWsProxy } from './routes/ws-proxy.js';
import { WispServer } from './wisp/server.js';
import { log } from './log.js';
import { uid } from './util.js';

const ns = log.child('app');
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const PUBLIC = path.join(ROOT, 'public');

/** express4 でも async ハンドラの reject を error ハンドラに流す */
function promisifyRouter(router) {
  for (const layer of router.stack || []) {
    if (!layer.route) continue;
    for (const h of layer.route.stack) {
      const fn = h.handle;
      if (fn.__mirageWrapped || fn.length > 3) continue;
      const wrapped = (req, res, next) => {
        try {
          const r = fn(req, res, next);
          if (r && typeof r.then === 'function') r.catch(next);
        } catch (err) {
          next(err);
        }
      };
      wrapped.__mirageWrapped = true;
      h.handle = wrapped;
    }
  }
  return router;
}

/**
 * @param {{config?:object, engine?:object, boot?:boolean}} [opts]
 */
export async function createApp(opts = {}) {
  const config = opts.config || loadConfig(process.env);
  const engine = opts.engine || (await createEngine(config));
  if (opts.boot !== false && !engine.booted) await engine.boot({ firstFetch: !config.isServerless });
  if (config.isServerless && !engine.listsWarmed) {
    // serverless: ブートに含めて一度だけ短時間で取りに行く (コンテナ寿命内に終わる分だけ)
    engine.listsWarmed = true;
    await Promise.race([engine.updateLists().catch(() => {}), sleep(2600)]);
  }

  /** @type {{config:object, engine:object, limiter:RateLimiter, wisp?:WispServer, ws?:object}} */
  const ctx = {
    config,
    engine,
    limiter: new RateLimiter({
      windowMs: config.limits.windowMs,
      reqPerMin: config.limits.reqPerMin,
      bytesPerMin: config.limits.bytesPerMin,
      maxConcurrent: config.limits.maxConcurrent,
      enabled: config.limits.reqPerMin > 0,
    }),
    startedAt: Date.now(),
  };

  const app = express();
  app.disable('x-powered-by');
  app.disable('etag');
  if (config.trustProxy) app.set('trust proxy', 1);

  /* ---------------- 共通: client 識別 + ヘッダ ---------------- */
  app.use(clientIdentity(config));
  app.use(securityHeaders(config));
  app.use((req, res, next) => {
    req.mirage.settings = engine.store.settingsFor(req.mirage.clientId);
    req.mirage.mode = String(req.headers['x-mirage-mode'] || req.query.mmode || req.mirage.settings.mode || config.transport.defaultMode);
    return next();
  });
  app.use(rateLimitMiddleware(ctx));

  /* ---------------- クライアントアセット ---------------- */
  app.use(mirageAssets(ctx));

  /* ---------------- API ---------------- */
  app.use(`${config.basePath}${config.url.apiPrefix}`, express.json({ limit: '512kb' }), promisifyRouter(createApiRouter(ctx)));

  /* ---------------- プロキシ本体 ---------------- */
  const proxied = createProxiedHandler(ctx);
  app.use(config.basePath || '/', (req, res, next) => {
    const p = req.path;
    if (!p.startsWith(config.url.prefix)) return next();
    return proxied(req, res, next);
  });

  /* ---------------- UI ---------------- */
  app.use(
    `${config.basePath}/mirage/app`,
    express.static(PUBLIC, { index: 'index.html', extensions: ['html'], maxAge: config.env === 'production' ? '1h' : 0, etag: false, fallthrough: true }),
  );
  app.use(
    express.static(PUBLIC, {
      index: false,
      maxAge: config.env === 'production' ? '30m' : 0,
      etag: false,
      setHeaders: (res, fp) => {
        if (fp.endsWith('.html')) res.setHeader('cache-control', 'no-cache');
        if (fp.includes(`${path.sep}mirage${path.sep}`)) res.setHeader('cache-control', config.env === 'production' ? 'public, max-age=3600' : 'no-cache');
      },
    }),
  );
  app.get([`${config.basePath}/`, `${config.basePath}/index.html`], async (req, res) => sendIndex(res, config));
  app.get(`${config.basePath}/app`, (req, res) => res.redirect(302, `${config.basePath}/mirage/app/`));

  /* ---------------- 404 / error ---------------- */
  app.use((req, res) => {
    if ((req.path || '').startsWith(config.url.apiPrefix)) return res.status(404).json({ error: 'not_found', path: req.path });
    return res.status(404).type('html').send(NotFoundHtml(config));
  });
  app.use(errorHandler(config));

  ctx.app = app;
  ctx.sendIndex = (res) => sendIndex(res, config);

  /* ---------------- アタッチ (WS / WISP) ---------------- */
  ctx.attach = (httpServer) => {
    ctx.ws = attachWsProxy(httpServer, ctx);
    if (config.wisp.enabled && !config.isServerless) {
      ctx.wisp = new WispServer({ config, pipeline: engine.pipeline, store: engine.store, guard: engine.guard });
      ctx.wisp.attach(httpServer);
      ns.info(`WISP 準備完了: ${config.wisp.path}`);
    } else {
      ns.info(`WISP は無効 (${config.isServerless ? 'serverless では WebSocket 非対応のため UV のみ' : '設定'}) — UV トランスポートで動作します`);
    }
    return ctx;
  };
  ctx.close = async () => {
    ctx.wisp?.close();
    await ctx.ws?.close();
    engine.close();
  };

  return { app, ctx, engine, config };
}

/* ------------------------------------------------------------------ */
/* middleware                                                          */
/* ------------------------------------------------------------------ */

function clientIdentity(config) {
  const key = 'mirage_client';
  const secret = config.secret;
  const sign = (v) => `${v}.${createHmac('sha256', secret).update(String(v)).digest('base64').replace(/=+$/, '').slice(0, 22)}`;
  const verify = (raw) => {
    const i = String(raw || '').lastIndexOf('.');
    if (i < 1) return null;
    const v = raw.slice(0, i);
    const mac = raw.slice(i + 1);
    const want = sign(v).split('.')[1];
    return mac === want ? v : null;
  };
  return (req, res, next) => {
    let clientId = null;
    const cookie = req.headers.cookie;
    if (cookie) {
      for (const part of cookie.split(/;\s*/)) {
        const eq = part.indexOf('=');
        if (eq > 0 && part.slice(0, eq) === key) {
          clientId = verify(decodeURIComponent(part.slice(eq + 1)));
          break;
        }
      }
    }
    if (!clientId) {
      clientId = uid(12);
      res.setHeader('set-cookie', `${key}=${encodeURIComponent(sign(clientId))}; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax${config.env === 'production' ? '; Secure' : ''}`);
    }
    const sidFromQuery = req.query.sid ? String(req.query.sid).slice(0, 64) : null;
    const sidFromHeader = req.headers['x-mirage-sid'] ? String(req.headers['x-mirage-sid']).slice(0, 64) : null;
    req.mirage = { clientId, sid: sidFromQuery || sidFromHeader || null, ip: req.ip };
    req.mirageId = randomUUID().slice(0, 8);
    return next();
  };
}

/** 当方オリジンのレスポンスにだけかけるセキュリティヘッダ (proxied には付けられない) */
function securityHeaders(config) {
  const panic = (config.safety.panicKeys || []).join(',');
  return (req, res, next) => {
    const h = res.setHeader.bind(res);
    h('x-content-type-options', 'nosniff');
    h('referrer-policy', 'no-referrer');
    h('permissions-policy', 'geolocation=(), camera=(), microphone=(), display-capture=(), interest-cohort=(), browsing-topics=()');
    h('cross-origin-opener-policy', 'same-origin');
    h('x-dns-prefetch-control', 'off');
    h('x-mirage-app', `${config.meta.name}/${config.meta.version}`);
    if (panic) h('x-mirage-panic', panic);
    // frame-ancestors は敢えて設定しない: 埋め込みプレビュー/自己_iframe 利用を壊さないため。
    //  proxied ドキュメントには rewriter が frame-ancestors を付与する。
    if ((req.path || '').startsWith(config.url.apiPrefix)) h('content-security-policy', "default-src 'none'; frame-ancestors *; style-src 'unsafe-inline'");
    return next();
  };
}

/** core.js / sw.js / wisp-client.js などを「設定を埋め込んで」配る */
function mirageAssets(ctx) {
  const { config, engine } = ctx;
  const cache = new Map(); // file → {text, at}
  const readAsset = async (rel) => {
    const hit = cache.get(rel);
    const now = Date.now();
    if (hit && (config.env === 'production' || now - hit.at < 1500)) return hit.text;
    const text = await readFile(path.join(PUBLIC, rel), 'utf8');
    cache.set(rel, { text, at: now });
    return text;
  };
  const r = express.Router();

  r.get(`${config.basePath}${config.url.corePath}`, async (req, res, next) => {
    try {
      const src = await readAsset('mirage/core.js');
      res.setHeader('content-type', 'text/javascript; charset=utf-8');
      res.setHeader('cache-control', config.env === 'production' ? 'public, max-age=3600' : 'no-cache');
      res.send(src);
    } catch (err) {
      next(err);
    }
  });

  r.get(`${config.basePath}${config.url.swPath}`, async (req, res, next) => {
    try {
      const src = await readAsset('mirage/sw.js');
      const cfg = {
        prefix: config.url.prefix,
        apiPrefix: config.url.apiPrefix,
        corePath: config.url.corePath,
        wispUrl: config.wisp.enabled && !config.isServerless ? `${config.basePath}${config.wisp.path}` : null,
        defaultMode: config.transport.defaultMode,
        retries: 2,
        connectTimeoutMs: 3500,
        highWaterMarkBytes: config.wisp.highWaterMarkBytes,
        keepaliveMs: config.wisp.keepaliveMs,
        logLevel: config.telemetry.logLevel,
        appOrigin: req.protocol + '://' + req.get('host'),
        injectAt: Date.now(),
      };
      res.setHeader('content-type', 'text/javascript; charset=utf-8');
      res.setHeader('cache-control', 'no-cache, no-store, must-revalidate');
      res.setHeader('service-worker-allowed', config.url.swScope || '/');
      res.send(`/* MirageVPN SW config (injected) */\nself.__MIRAGE_PREFIX=${JSON.stringify(cfg.prefix)};\nself.__MIRAGE_SW_CFG=${JSON.stringify(cfg)};\n${src}`);
    } catch (err) {
      next(err);
    }
  });

  r.get(`${config.basePath}/mirage/wisp-client.js`, async (req, res, next) => {
    try {
      res.setHeader('content-type', 'text/javascript; charset=utf-8');
      res.setHeader('cache-control', config.env === 'production' ? 'public, max-age=3600' : 'no-cache');
      res.send(await readAsset('mirage/wisp-client.js'));
    } catch (err) {
      next(err);
    }
  });

  r.get(`${config.basePath}/mirage/client-config`, async (req, res) => {
    res.json({
      prefix: config.url.prefix,
      apiPrefix: config.url.apiPrefix,
      corePath: config.url.corePath,
      swPath: config.url.swPath,
      swScope: config.url.swScope || '/',
      encoding: config.url.encoding,
      basePath: config.basePath,
      mode: config.transport.defaultMode,
      wisp: { enabled: config.wisp.enabled && !config.isServerless, path: config.wisp.path },
      serverless: config.isServerless,
    });
  });

  return r;
}

function errorHandler(config) {
  return (err, req, res, _next) => {
    const proxied = (req.path || '').startsWith(config.url.prefix);
    const status = Number(err?.status || err?.statusCode) || 500;
    ns.error(`${req.method} ${req.originalUrl} → ${status}: ${err?.message || err}${err?.code ? ` [${err.code}]` : ''}`);
    if (res.headersSent) {
      try { res.end(); } catch (e) {}
      return undefined;
    }
    if (proxied || !((req.path || '').startsWith(config.url.apiPrefix) || (req.path || '').startsWith(config.basePath + '/mirage/app'))) {
      res
        .status(status >= 400 && status < 600 ? status : 500)
        .type('html')
        .send(ErrorHtml(req, err, status, config));
      return undefined;
    }
    res.status(status).json({ error: err?.code || 'internal', message: String(err?.message || err).slice(0, 400) });
    return undefined;
  };
}

/* ------------------------------------------------------------------ */

const indexCache = { html: null, at: 0 };
async function sendIndex(res, config) {
  const fresh = indexCache.html && Date.now() - indexCache.at < (config.env === 'production' ? 600000 : 1000);
  let html = fresh ? indexCache.html : null;
  if (!html) {
    try {
      html = await readFile(path.join(PUBLIC, 'index.html'), 'utf8');
      indexCache.html = html;
      indexCache.at = Date.now();
    } catch (err) {
      html = `<pre>MirageVPN: public/index.html がありません (${err.message})</pre>`;
    }
  }
  res.setHeader('content-type', 'text/html; charset=utf-8');
  res.setHeader('cache-control', 'no-cache');
  res.send(html);
  return undefined;
}

function shell(title, body, config) {
  return `<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title><style>
 body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(1200px 600px at 20% -10%,#1b2350 0%,#0b0e1c 55%,#070912 100%);color:#e8ecff;font:14px/1.7 ui-sans-serif,system-ui,"Hiragino Sans","Noto Sans JP",sans-serif}
 .box{max-width:660px;padding:28px 30px;background:rgba(18,22,40,.72);border:1px solid rgba(140,160,255,.18);border-radius:18px;backdrop-filter:blur(12px);box-shadow:0 30px 90px -40px #000}
 h1{margin:0 0 6px;font-size:19px;letter-spacing:.01em} code{background:#1b2140;padding:2px 6px;border-radius:6px;font-size:12px}
 a{color:#8fb6ff} .dim{color:#9aa6d0;font-size:12.5px}
 pre{white-space:pre-wrap;word-break:break-word;background:#141a33;border:1px solid rgba(140,160,255,.14);padding:12px 14px;border-radius:12px;font-size:12px;max-height:34vh;overflow:auto}
 .btn{display:inline-block;margin-top:14px;padding:9px 16px;border-radius:11px;background:linear-gradient(135deg,#4d6bff,#8a5cff);color:#fff;text-decoration:none;font-weight:700}
</style></head><body><div class="box">${body}<div class="dim" style="margin-top:16px">${config.meta.name} v${config.meta.version} ・ ${config.meta.codename}</div></div></body></html>`;
}

function NotFoundHtml(config) {
  return shell(
    'MirageVPN',
    `<h1>そのページはここにはありません</h1>
     <div class="dim">ダッシュボードからサイトを開くと、URL は <code>${config.url.prefix}/&lt;sid&gt;/…</code> の形でプロキシされます。</div>
     <a class="btn" href="${config.basePath}/">ダッシュボードへ</a>`,
    config,
  );
}

function ErrorHtml(req, err, status, config) {
  const safe = String(err?.message || err || '').slice(0, 500);
  return shell(
    'MirageVPN — エラー',
    `<h1>プロキシ処理でエラーが出ました <span class="dim">(${status})</span></h1>
     <pre>${escape(safe)}\n${escape(err?.code || '')}</pre>
     <div class="dim">プロキシ先の一時的な障害や、出口プロキシの応答タイムアウトがほとんどです。少し待って再読み込みしてください。</div>
     <a class="btn" href="${config.basePath}/">戻る</a>`,
    config,
  );
}

function escape(s) {
  return String(s || '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

export default createApp;
