/**
 * /mirage/api/* — ダッシュボード & 制御 API
 * ---------------------------------------------------------------
 * すべて JSON。`GET /api/*` は読み取り、`POST` は設定変更 (client 単位)。
 * 認証は「単一ユーザーのセルフホスト」前提なので既定なし。公開デプロイでは
 * MIRAGE_BASIC_AUTH または MIRAGE_SECRET を必ず設定すること (app.js で helmet 相当のheaders)。
 * @module routes/api
 */

import express from 'express';
import { Buffer } from 'node:buffer';
import { request as http1Request } from '../net/http1.js';
import { loadBundledSeeds, fetchSourceText, resolveSources } from '../data/sources.js';
import { COUNTRIES, clientCountry, flagOf, countryLabel } from '../data/geo.js';
import { escapeHtml, fmtBytes, fmtMs, relTime, uid } from '../util.js';
import { log } from '../log.js';

const ns = log.child('api');

const EXIT_PROBES = [
  { name: 'ip-api', url: 'http://ip-api.com/line/?fields=query,country,countryCode,city,isp,as' },
  { name: 'httpbin', url: 'http://httpbin.org/ip' },
  { name: 'ifconfig', url: 'http://ifconfig.me/all' },
];

/** @param {ReturnType<import('../app.js').createContext>} ctx */
export function createApiRouter(ctx) {
  const r = express.Router();
  const { config, engine } = ctx;
  const { store, pool, shields, threats, metrics, cookies } = engine;

  /* ---------------- 常時 ---------------- */

  r.get('/health', (req, res) => {
    res.json({
      ok: true,
      app: config.meta.name,
      version: config.meta.version,
      codename: config.meta.codename,
      uptimeSec: Math.round(process.uptime()),
      serverless: config.isServerless,
      wisp: !!ctx.wisp?.enabled,
      time: Date.now(),
    });
  });

  r.get('/status', async (req, res) => {
    const settings = store.settingsFor(req.mirage.clientId);
    const client = await clientCountry(req, engine.geo);
    res.json({
      app: config.meta,
      time: Date.now(),
      serverless: config.isServerless,
      capabilities: {
        wisp: config.wisp.enabled && !config.isServerless,
        ws: !config.isServerless,
        persist: store.persist,
        fs: !!config.state.dir,
      },
      transport: {
        mode: settings.mode || config.transport.defaultMode,
        default: config.transport.defaultMode,
        encoding: config.url.encoding,
        prefix: config.url.prefix,
        apiPrefix: config.url.apiPrefix,
        swPath: config.url.swPath,
        corePath: config.url.corePath,
        cache: engine.pipeline.cacheStats(),
        timeouts: {
          connect: config.transport.connectTimeoutMs,
          response: config.transport.responseTimeoutMs,
        },
      },
      egress: {
        strategy: settings.egress?.strategy || config.egress.defaultStrategy,
        country: settings.egress?.country || config.egress.country,
        protocols: config.egress.protocols,
        spoof: config.egress.spoofForwardedHeaders,
        clientCountry: client,
        pool: pool.summary(),
      },
      shields: shields.summary(),
      threats: { ...threats.stats(), sessions: threats.allSessions().slice(0, 12) },
      pipeline: engine.pipeline.stats(),
      sessions: store.listSessions({ limit: 20 }).map((s) => ({ ...s, flag: flagOf(s.country) })),
      wisp: ctx.wisp?.summary?.() || { enabled: false },
      cookies: cookies.stats(),
      geo: engine.geo.stats(),
      metrics: config.telemetry.exposeMetrics ? metrics.summary() : { hidden: true },
      lists: {
        refreshMs: config.lists.refreshMs,
        nextRefreshInMs: Math.max(0, engine.lastListRefresh + config.lists.refreshMs - Date.now()),
        sources: pool.stats.list(),
        enabled: config.lists.enabled,
      },
      limits: config.limits,
    });
  });

  /* ---------------- プロキシプール / 国籍 ---------------- */

  r.get('/countries', (req, res) => {
    const list = pool.countries({ min: Number(req.query.min || 1) }).map((c) => ({
      ...c,
      flag: flagOf(c.country),
      name: COUNTRIES[c.country]?.ja || (c.country === 'XX' ? '不明' : c.country),
      region: COUNTRIES[c.country]?.region || '-',
      label: countryLabel(c.country),
    }));
    res.json({ total: list.reduce((a, b) => a + b.total, 0), countries: list });
  });

  r.get('/pool', (req, res) => {
    const q = {
      country: req.query.country,
      protocol: req.query.protocol,
      limit: Math.min(500, Number(req.query.limit || 60)),
      offset: Number(req.query.offset || 0),
      sort: req.query.sort || 'score',
    };
    res.json(pool.list(q));
  });

  r.post('/pool/refresh', async (req, res) => {
    const out = await pool.refresh({ clear: !!req.body?.clear, probe: !!req.body?.probe });
    engine.lastListRefresh = Date.now();
    res.json({ ok: !!out.ok, ...out });
  });

  r.post('/pool/probe', async (req, res) => {
    const limit = Math.min(120, Number(req.body?.limit || 24));
    const only = req.body?.country ? pool.list({ country: req.body.country, limit }).items.map((p) => pool.records.get(p.key)).filter(Boolean) : undefined;
    const out = await pool.healthCheck({ limit, only });
    res.json(out);
  });

  r.post('/pool/country', async (req, res) => {
    const cc = String(req.body?.country || 'AUTO').toUpperCase();
    await store.update(req.mirage.clientId, { egress: { country: cc } });
    res.json({ ok: true, country: cc, label: cc === 'AUTO' ? '自動 (最適)' : countryLabel(cc) });
  });

  /** 「今の出口」を実際に検証する: プロキシ経由で自分の公開 IP を取りに行く */
  r.get('/egress/verify', async (req, res) => {
    const settings = store.settingsFor(req.mirage.clientId);
    const strategy = settings.egress?.strategy || config.egress.defaultStrategy;
    const country = settings.egress?.country && settings.egress.country !== 'AUTO' ? settings.egress.country : null;
    const results = [];
    const attempts = [];
    const proxy =
      strategy === 'direct'
        ? null
        : pool.select({ country: country || undefined, sid: req.query.sid || `verify-${uid(4)}`, allowFallback: strategy === 'auto', protocols: settings.egress?.protocols });
    attempts.push({ label: proxy ? `${proxy.protocol}://${proxy.host}:${proxy.port}` : 'direct', proxy });
    if (strategy === 'auto' && !proxy) attempts.push({ label: 'direct', proxy: null });

    for (const attempt of attempts) {
      for (const probe of EXIT_PROBES) {
        const t0 = Date.now();
        try {
          const res2 = await http1Request({
            url: probe.url,
            method: 'GET',
            proxy: attempt.proxy ? { protocol: attempt.proxy.protocol === 'https' ? 'http' : attempt.proxy.protocol, host: attempt.proxy.host, port: attempt.proxy.port, username: attempt.proxy.username, password: attempt.proxy.password } : null,
            connectTimeoutMs: 9000,
            headTimeoutMs: 9000,
            idleTimeoutMs: 9000,
            maxBodyBytes: 4096,
            headers: new Map([['user-agent', 'MirageVPN/1.0 (egress-verify)'], ['accept', '*/*'], ['connection', 'close']]),
            pool: engine.httpPool,
          });
          const chunks = [];
          for await (const c of res2.stream) chunks.push(c);
          const text = Buffer.concat(chunks).toString('utf8');
          if (res2.statusCode >= 200 && res2.statusCode < 400) {
            const parsed = parseExit(text);
            if (attempt.proxy) pool.report(attempt.proxy, { ok: true, latencyMs: Date.now() - t0, exitInfo: parsed, bytes: text.length });
            results.push({ via: attempt.label, probe: probe.name, ok: true, ms: Date.now() - t0, ...parsed });
            break;
          }
        } catch (err) {
          if (attempt.proxy) pool.report(attempt.proxy, { ok: false, error: err.message });
          results.push({ via: attempt.label, probe: probe.name, ok: false, error: `${err.code || ''} ${err.message}`.trim() });
        }
      }
      if (results.some((x) => x.ok)) break;
    }
    const ok = results.find((x) => x.ok);
    const spoofIps = config.egress.spoofForwardedHeaders ? [req.query.spoofIp || 'see headers'] : [];
    res.json({
      ok: !!ok,
      strategy,
      wantedCountry: country || 'AUTO',
      matched: ok?.country ? ok.country === country : country === null,
      attempts: results,
      note: ok
        ? 'この国 (AS/IP) から出ています。ブラウザ自身の IP は上流に見えていません。'
        : '出口を検証できませんでした。direct にフォールバックするか、別の国籍/プロトコルを試してください。',
      sentSpoofHeaders: spoofIps,
    });
  });

  r.get('/lists', (req, res) => {
    const sources = resolveSources(config);
    res.json({
      sources: sources.map((s) => ({ ...s, stats: pool.stats.byId.get(s.id) || null })),
      bundled: config.lists.useBundledSeed ? { note: 'data/seeds にオフライン用スナップショットを同梱' } : null,
      refreshMs: config.lists.refreshMs,
      enabled: config.lists.enabled,
    });
  });

  r.post('/lists/seed', (req, res) => {
    const n = pool.ingest(loadBundledSeeds(), { sourceId: 'manual-seed', weight: 0.8 });
    res.json({ ok: true, added: n });
  });

  /* ---------------- シールド ---------------- */

  r.get('/shields', (req, res) => res.json(shields.summary()));

  r.post('/shields', async (req, res) => {
    const patch = {};
    if (req.body?.enabled !== undefined) {
      patch.enabled = !!req.body.enabled;
      shields.setEnabled(patch.enabled);
    }
    if (req.body?.level) {
      patch.level = req.body.level;
      shields.setLevel(req.body.level);
    }
    if (req.body?.cosmetic !== undefined) patch.cosmetic = !!req.body.cosmetic;
    await store.update(req.mirage.clientId, { shields: patch });
    res.json({ ok: true, shields: shields.summary() });
  });

  r.post('/shields/domain', async (req, res) => {
    const domain = String(req.body?.domain || '').toLowerCase();
    const allow = req.body?.allow !== false;
    if (!domain) return res.status(400).json({ error: 'domain が必要です' });
    const settings = store.settingsFor(req.mirage.clientId);
    const list = new Set(settings.shields?.allowList || []);
    if (allow) {
      list.add(domain);
      shields.disableFor(domain);
    } else {
      list.delete(domain);
      shields.enableFor(domain);
    }
    await store.update(req.mirage.clientId, { shields: { allowList: [...list].slice(-200) } });
    res.json({ ok: true, allowList: [...list] });
  });

  r.post('/shields/unrelax', (req, res) => {
    shields.unrelax(String(req.body?.domain || ''));
    res.json({ ok: true, relaxed: shields.relaxState() });
  });

  r.post('/shields/update', async (req, res) => {
    const out = await engine.updateAdLists();
    res.json(out);
  });

  r.get('/shields/report', (req, res) => {
    const s = shields.summary();
    res.json({
      blocked: s.blocked,
      byCategory: s.byCategory,
      byType: s.byType,
      topHosts: s.topHosts,
      recent: [],
      relaxed: s.autoRelaxed,
      disabledFor: s.disabledFor,
    });
  });

  /* ---------------- 脅威 ---------------- */

  r.get('/threats', (req, res) => {
    res.json(threats.report({ sid: req.query.sid, limit: Math.min(500, Number(req.query.limit || 150)), minScore: Number(req.query.min || 0), code: req.query.code }));
  });

  r.get('/threats/report.html', (req, res) => {
    const rep = threats.report({ limit: 400 });
    res.type('html').send(renderReportHtml(rep, ctx, req));
  });

  r.get('/threats/report.json', (req, res) => {
    const rep = threats.report({ limit: 1000 });
    res.setHeader('content-disposition', `attachment; filename="mirage-threat-report-${new Date().toISOString().slice(0, 10)}.json"`);
    res.json(rep);
  });

  r.post('/threats', async (req, res) => {
    const patch = {};
    if (req.body?.enabled !== undefined) {
      patch.enabled = !!req.body.enabled;
      threats.setEnabled(patch.enabled);
    }
    if (req.body?.autoDelete !== undefined) {
      patch.autoDelete = !!req.body.autoDelete;
      threats.setAutoDelete(patch.autoDelete);
    }
    if (req.body?.sanitizeScore !== undefined || req.body?.blockScore !== undefined) {
      const t = threats.setThresholds({ sanitize: Number(req.body.sanitizeScore), block: Number(req.body.blockScore) });
      patch.sanitizeScore = t.sanitize;
      patch.blockScore = t.block;
    }
    if (req.body?.credentialGuard !== undefined) patch.credentialGuard = !!req.body.credentialGuard;
    await store.update(req.mirage.clientId, { threats: patch });
    res.json({ ok: true, threats: threats.stats() });
  });

  r.post('/threats/purge', async (req, res) => {
    const removed = threats.purge({
      sid: req.body?.sid,
      olderThanMs: req.body?.olderThanMs,
      codes: Array.isArray(req.body?.codes) ? req.body.codes : undefined,
    });
    res.json({ ok: true, removed, events: threats.stats().events });
  });

  /* ---------------- タブ / セッション ---------------- */

  r.get('/tabs', (req, res) => {
    res.json({ tabs: store.listSessions({ limit: Number(req.query.limit || 40) }) });
  });

  r.post('/tabs/open', async (req, res) => {
    const sid = String(req.body?.sid || uid(8));
    const s = store.touchSession(sid, { url: req.body?.url || '', title: req.body?.title || '新規タブ', openedAt: Date.now(), mode: req.body?.mode || config.transport.defaultMode });
    res.json({ ok: true, sid, session: s, proxiedPrefix: `${config.url.prefix}/${sid}` });
  });

  r.post('/tabs/close', (req, res) => {
    const sid = String(req.body?.sid || '');
    pool.clearSticky(sid);
    threats.clearSession(sid);
    cookies.clear(sid);
    store.dropSession(sid);
    res.json({ ok: true, sid });
  });

  r.post('/tabs/touch', (req, res) => {
    const sid = String(req.body?.sid || '');
    if (!sid) return res.status(400).json({ error: 'sid' });
    res.json({ ok: true, session: store.touchSession(sid, { url: req.body?.url, title: req.body?.title }) });
  });

  /* ---------------- イベント (core.js から) ---------------- */

  r.post('/events', express.json({ limit: '128kb' }), (req, res) => {
    const events = Array.isArray(req.body?.events) ? req.body.events.slice(0, 40) : [];
    for (const ev of events) {
      const sid = String(ev.sid || '').slice(0, 64);
      if (!sid) continue;
      if (ev.type === 'tab.state') {
        store.touchSession(sid, { url: String(ev.data?.url || '').slice(0, 500), title: String(ev.data?.title || '').slice(0, 120), lastSeen: Date.now() });
      } else if (ev.type === 'page.ready') {
        store.touchSession(sid, { readyAt: Date.now(), mode: ev.data?.mode, wisp: !!ev.data?.wisp });
      } else if (ev.type === 'shields.client_block') {
        store.touchSession(sid, { clientBlocked: (store.session(sid)?.clientBlocked || 0) + 1 });
      } else if (ev.type === 'cookie.set') {
        /* ジャー更新は /cookies 側で行う (ここでは統計のみ) */
      }
      ns.debug(() => `event ${ev.type} from ${sid}`);
    }
    res.json({ ok: true, accepted: events.length });
  });

  r.post('/cookies', express.json({ limit: '64kb' }), (req, res) => {
    const sid = String(req.body?.sid || '').slice(0, 64);
    const raw = String(req.body?.raw || '');
    const url = req.body?.url;
    if (!sid || !raw) return res.status(400).json({ error: 'sid/raw' });
    try {
      cookies.applySetCookies(sid, new URL(url || 'https://example.com/'), [raw]);
      res.json({ ok: true, jar: cookies.export(sid).length });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  r.get('/cookies', (req, res) => {
    const sid = String(req.query.sid || '');
    res.json({ sid, cookies: sid ? cookies.export(sid) : [], stats: cookies.stats() });
  });

  r.post('/cookies/clear', (req, res) => {
    const n = cookies.clear(String(req.body?.sid || ''), { domain: req.body?.domain });
    res.json({ ok: true, removed: n });
  });

  /* ---------------- 設定 ---------------- */

  r.get('/settings', (req, res) => {
    res.json({ settings: store.settingsFor(req.mirage.clientId), info: store.info(), defaults: config.env === 'production' ? undefined : undefined });
  });

  r.patch('/settings', async (req, res) => {
    const patch = req.body || {};
    // 即時反映すべき項目をここでエンジンへ流し込む
    if (patch.shields) {
      if (patch.shields.enabled !== undefined) shields.setEnabled(patch.shields.enabled);
      if (patch.shields.level) shields.setLevel(patch.shields.level);
    }
    if (patch.threats) {
      if (patch.threats.enabled !== undefined) threats.setEnabled(patch.threats.enabled);
      if (patch.threats.autoDelete !== undefined) threats.setAutoDelete(patch.threats.autoDelete);
      if (patch.threats.sanitizeScore !== undefined || patch.threats.blockScore !== undefined)
        threats.setThresholds({ sanitize: patch.threats.sanitizeScore, block: patch.threats.blockScore });
    }
    if (patch.advanced?.cache === false) engine.pipeline.clearCache();
    const next = await store.update(req.mirage.clientId, patch);
    res.json({ ok: true, settings: next });
  });

  r.post('/settings/reset', async (req, res) => {
    store.resetClient(req.mirage.clientId);
    res.json({ ok: true, settings: store.settingsFor(req.mirage.clientId) });
  });

  /* ---------------- 検索 / URL ビルダー ---------------- */

  r.post('/resolve', (req, res) => {
    const raw = String(req.body?.input || '').trim();
    const sid = String(req.body?.sid || uid(8));
    const out = resolveAddress(raw, sid, ctx, req);
    res.json(out);
  });

  r.get('/url', (req, res) => {
    const sid = String(req.query.sid || 'preview');
    res.json(resolveAddress(String(req.query.q || ''), sid, ctx, req));
  });

  /* ---------------- キャッシュ ---------------- */

  r.get('/cache', (req, res) => res.json(engine.pipeline.cacheStats()));
  r.post('/cache/clear', (req, res) => {
    engine.pipeline.clearCache();
    res.json({ ok: true });
  });

  /* ---------------- 計測 ---------------- */

  r.get('/metrics', (req, res) => {
    if (!config.telemetry.exposeMetrics) return res.status(404).json({ error: 'metrics hidden' });
    res.json({ ...metrics.summary(), pipeline: engine.pipeline.stats(), pool: pool.summary(), wisp: ctx.wisp?.summary?.(), store: store.info() });
  });

  /** 速度計測用: 指定 KB のデータを返す (圧縮なし・チャンク配信) */
  r.get('/speedtest', (req, res) => {
    const kb = Math.max(16, Math.min(8192, Number(req.query.kb || 1024)));
    const total = kb * 1024;
    res.setHeader('content-type', 'application/octet-stream');
    res.setHeader('content-length', String(total));
    res.setHeader('cache-control', 'no-store');
    const chunk = Buffer.alloc(64 * 1024, 0x58);
    let sent = 0;
    const pump = () => {
      while (sent < total) {
        const take = Math.min(chunk.length, total - sent);
        sent += take;
        if (!res.write(chunk.subarray(0, take))) return res.once('drain', pump);
      }
      res.end();
      return undefined;
    };
    pump();
  });

  r.get('/docs', (req, res) => {
    res.json({
      endpoints: [
        ['GET', '/mirage/api/health', '生存確認'],
        ['GET', '/mirage/api/status', '全エンジンの状態 (UI が 1s ごとに読む)'],
        ['GET', '/mirage/api/countries', 'プール内の国籍一覧'],
        ['GET', '/mirage/api/pool?country=&limit=', 'プロキシ一覧'],
        ['POST', '/mirage/api/pool/refresh', 'リストを再取得'],
        ['POST', '/mirage/api/pool/probe', 'ヘルスチェック実行'],
        ['POST', '/mirage/api/pool/country', '出口国籍を固定'],
        ['GET', '/mirage/api/egress/verify', '実際の出口 IP/国を検証'],
        ['GET', '/mirage/api/shields', 'シールド統計'],
        ['POST', '/mirage/api/shields', 'ON/OFF・レベル'],
        ['POST', '/mirage/api/shields/domain', 'サイト別 ON/OFF'],
        ['GET', '/mirage/api/threats', '脅威レポート (JSON)'],
        ['GET', '/mirage/api/threats/report.html', '印刷できるレポート'],
        ['POST', '/mirage/api/threats', '検知設定'],
        ['POST', '/mirage/api/threats/purge', 'レポートの自動削除'],
        ['GET/PATCH', '/mirage/api/settings', 'クライアント設定'],
        ['POST', '/mirage/api/resolve', 'アドレスバー入力を URL/検索に変換'],
      ],
    });
  });

  return r;
}

/* ------------------------------------------------------------------ */

function parseExit(text) {
  const out = { exitIp: null, country: null, countryName: null, city: null, isp: null };
  const ip = /(\d{1,3}(?:\.\d{1,3}){3})/.exec(text);
  if (ip) out.exitIp = ip[1];
  const lines = text.split(/\r?\n/).map((l) => l.trim());
  if (lines.length >= 2 && /^\d+\.\d+\.\d+\.\d+$/.test(lines[0])) {
    out.countryName = lines[1];
    if (/^[A-Z]{2}$/.test(lines[1] || '')) {
      out.country = lines[1];
      out.city = lines[2];
      out.isp = lines[3];
    } else {
      const code = /\(([A-Z]{2})\)/.exec(text);
      if (code) out.country = code[1];
    }
  } else {
    const code = /"country[_A-Za-z]*"\s*:\s*"([A-Z]{2})"/.exec(text) || /\b([A-Z]{2})\b/.exec(text);
    if (code) out.country = code[1];
    const j = /"origin"|"ip"\s*:\s*"(\d+\.\d+\.\d+\.\d+)"/.exec(text);
    if (j) void j;
  }
  if (out.country) out.countryName = COUNTRIES[out.country]?.ja || out.countryName || out.country;
  return out;
}

/** アドレスバー入力 → {type, url, proxied} */
export function resolveAddress(raw, sid, ctx, req) {
  const { config, engine } = ctx;
  const input = String(raw || '').trim();
  if (!input) return { type: 'empty' };
  const engines = { ...config.search.engines, ...SEARCH_ALIASES };

  // 検索クエリ (スキームもドメインらしさも無い文字列)
  const looksHost = /^[\w-]+([.,][\w-]+)*\.(?:[a-z]{2,}|\d{1,3})(?::\d+)?([/?#].*)?$/i.test(input) || /^[\w-]+:\d+(?:[/?#].*)?$/.test(input);
  if (!/^https?:\/\//i.test(input) && !looksHost) {
    let q = input;
    let engineName = req?.body?.engine || req?.query?.engine || config.search.engine;
    const bang = /^!(\w+)\s+(.*)$/s.exec(input);
    if (bang && engines[bang[1].toLowerCase()]) {
      engineName = bang[1].toLowerCase();
      q = bang[2];
    }
    const tpl = engines[engineName] || engines.duckduckgo;
    const abs = tpl.replace('{q}', encodeURIComponent(q));
    return { type: 'search', engine: engineName, url: abs, proxied: engine.buildProxiedUrl(abs, sid), sid };
  }

  let url = input;
  if (/^https?:\/\//i.test(url) === false) {
    // スキーム省略時: IP:port / localhost は http、それ以外は https に寄せる (平文で最初に叩かないほうが安全)
    const bare = /^(?:localhost|\[[0-9a-f:]+\]|\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?(?:[/?#].*)?$/i.test(url);
    url = `${bare ? 'http' : 'https'}://${url}`;
  } else if (/^http:\/\//i.test(url)) {
    // よく「http で入れてしまう」巨大サイトは https へ上げる (mixed content と平文漏れを減らす)
    url = url.replace(/^http:\/\/((?:[^/]*\.)?(?:google|youtube|github|wikipedia|duckduckgo|twitter|x)\.[^/]*)/i, 'https://$1');
  }
  const proxied = engine.buildProxiedUrl(url, sid, { keepHash: true });
  if (!proxied) {
    return { type: 'url', url: null, proxied: null, sid, error: 'URL を解釈できませんでした (スキームかホストが不適切です)。http:// か https:// を付けてください。' };
  }
  const hint = privateHostHint(url);
  return { type: 'url', url, proxied, sid, blocked: hint || null };
}

/** DNS を引かずに「これは明らかにローカルだ」と分かるものだけ先に警告する (実遮断は pipeline の SSRF ガード) */
function privateHostHint(absUrl) {
  try {
    const host = new URL(absUrl).hostname.replace(/^\[|\]$/g, '').toLowerCase();
    if (!host) return null;
    if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal') || host === 'metadata.google.internal') {
      return 'ローカル/内部ホストはブロック対象です';
    }
    if (/^0\.0\.0\.0$/.test(host)) return 'ローカル/内部ホストはブロック対象です';
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
    if (m) {
      const [a, b] = [Number(m[1]), Number(m[2])];
      if (a === 10 || a === 127 || a === 0 || a >= 224) return 'ローカル/内部ホストはブロック対象です';
      if (a === 192 && b === 168) return 'ローカル/内部ホストはブロック対象です';
      if (a === 172 && b >= 16 && b <= 31) return 'ローカル/内部ホストはブロック対象です';
      if (a === 169 && b === 254) return 'ローカル/内部ホストはブロック対象です';
    }
  } catch {
    /* ignore */
  }
  return null;
}

const SEARCH_ALIASES = {
  wiki: 'https://ja.wikipedia.org/w/index.php?search={q}',
  ddg: 'https://html.duckduckgo.com/html/?q={q}',
  sp: 'https://www.startpage.com/sp/search?query={q}',
  gh: 'https://github.com/search?q={q}',
  yt: 'https://www.youtube.com/results?search_query={q}',
  amz: 'https://www.amazon.co.jp/s?k={q}',
};

/* ------------------------------------------------------------------ */
/* 印刷用レポート                                                       */
/* ------------------------------------------------------------------ */

function renderReportHtml(rep, ctx, req) {
  const { config, engine } = ctx;
  const pool = engine.pool;
  const shields = engine.shields;
  const rows = (rep.events || [])
    .map(
      (e) => `<tr>
    <td class="t">${new Date(e.at).toLocaleString('ja-JP')}</td>
    <td><span class="b b-${e.color}">${escapeHtml(e.label || e.code)}</span></td>
    <td class="num">${e.score}</td>
    <td>${escapeHtml(e.host || '')}</td>
    <td class="ev">${escapeHtml(String(e.evidence || '').slice(0, 180))}</td>
    <td>${escapeHtml(e.action || '-')}</td>
    <td class="sid">${escapeHtml(e.sid || '-')}</td>
  </tr>`,
    )
    .join('');
  const summary = pool.summary();
  const sh = shields.summary();
  return `<!doctype html><html lang="ja"><head><meta charset="utf-8">
<title>MirageVPN — セキュリティレポート</title>
<style>
 :root{color-scheme:light}
 body{margin:0;padding:32px;background:#f6f7fb;color:#12172b;font:13px/1.65 ui-sans-serif,system-ui,"Hiragino Sans","Noto Sans JP",sans-serif}
 h1{font-size:22px;margin:0 0 2px} h2{font-size:14px;margin:26px 0 8px}
 .sub{color:#5b6480;font-size:12px}
 .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin-top:14px}
 .card{background:#fff;border:1px solid #e3e6f0;border-radius:12px;padding:12px 14px}
 .k{font-size:11px;color:#6b7392;text-transform:uppercase;letter-spacing:.06em}
 .v{font-size:19px;font-weight:700;margin-top:3px}
 table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e3e6f0;border-radius:12px;overflow:hidden}
 th,td{padding:7px 9px;text-align:left;border-bottom:1px solid #eef0f7;vertical-align:top}
 th{background:#f2f4fb;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:#5b6480}
 .num{text-align:right;font-variant-numeric:tabular-nums} .t,.sid{white-space:nowrap;color:#6b7392;font-size:11px}
 .ev{max-width:420px;word-break:break-word}
 .b{padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700}
 .b-danger{background:#ffe9e9;color:#a3161f} .b-warn{background:#fff3d9;color:#8a5a00} .b-info{background:#e7f0ff;color:#2456a6}
 .b-good{background:#e4f8ec;color:#116b39}
 footer{margin-top:26px;color:#8890aa;font-size:11px}
 @media print{body{background:#fff;padding:0}.card,table{border-color:#ccc}}
</style></head><body>
<h1>MirageVPN セキュリティレポート</h1>
<div class="sub">生成 ${new Date(rep.generatedAt).toLocaleString('ja-JP')} ・ 検知エンジン ${rep.enabled ? 'ON' : 'OFF'} ・ 自動削除 ${rep.autoDelete ? 'ON' : 'OFF'} ・ 閾値 sanitize ${rep.thresholds.sanitize} / block ${rep.thresholds.block}</div>
<div class="grid">
  <div class="card"><div class="k">検知イベント</div><div class="v">${rep.totals.events}</div></div>
  <div class="card"><div class="k">自動除去した要素</div><div class="v">${rep.totals.stripped}</div></div>
  <div class="card"><div class="k">遮断</div><div class="v">${rep.totals.blocked}</div></div>
  <div class="card"><div class="k">強化 (rel/referrer 等)</div><div class="v">${rep.totals.hardened}</div></div>
  <div class="card"><div class="k">シールド ブロック</div><div class="v">${sh.blocked}</div></div>
  <div class="card"><div class="k">プール / 健全</div><div class="v">${summary.size} / ${summary.healthy}</div></div>
  <div class="card"><div class="k">カバレッジ</div><div class="v">${summary.healthyPct}%</div></div>
  <div class="card"><div class="k">平均応答</div><div class="v">${summary.avgLatencyMs ? summary.avgLatencyMs + 'ms' : '-'}</div></div>
</div>
<h2>検知履歴 (${(rep.events || []).length} 件)</h2>
<table><thead><tr><th>時刻</th><th>カテゴリ</th><th>score</th><th>host</th><th>根拠</th><th>実施した処置</th><th>tab</th></tr></thead>
<tbody>${rows || '<tr><td colspan="7">検知はありませんでした 🎉</td></tr>'}</tbody></table>
<h2>ルール別ヒット</h2>
<table><thead><tr><th>ルール</th><th class="num">ヒット</th></tr></thead><tbody>
${(rep.topRules || []).map((x) => `<tr><td>${escapeHtml(x.rule)}</td><td class="num">${x.hits}</td></tr>`).join('') || '<tr><td colspan="2">-</td></tr>'}
</tbody></table>
<footer>MirageVPN v${config.meta.version} (${config.meta.codename}) ・ トランスポート ${config.transport.defaultMode.toUpperCase()} + ${config.wisp.enabled ? 'WISP' : 'WISP off'} ・ 出口 ${config.egress.defaultStrategy} ・ このレポートにページ本文は含まれません (メタのみ)。</footer>
</body></html>`;
}

export default createApiRouter;
