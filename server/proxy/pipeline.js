/**
 * MirageVPN パイプライン — 1 リクエストの生命周期
 * ---------------------------------------------------------------
 *   guard → egress 選択 (国籍ピン/ローテ) → shields → fetch (redirect 追従・解凍)
 *   → threats (検知と自動除去) → rewrite (html/css/js/headers) → cache → 応答
 *
 * HTTP トランスポート (UV 高速モード) と WISP トンネルの両方がここを呼ぶ。
 * 「どの経路でも同じ安全・同じ改写」が成立するように、経路差分はここ に閉じた。
 * @module proxy/pipeline
 */

import { Buffer } from 'node:buffer';
import zlib from 'node:zlib';
import { LRU, escapeHtml, fmtBytes } from '../util.js';
import { log } from '../log.js';
import { request as http1Request } from '../net/http1.js';
import { cookieHeader } from './cookies.js';
import { splitSetCookie } from './rewrite.js';

const ns = log.child('pipeline');

const REWRITEABLE = {
  'text/html': 'html',
  'application/xhtml+xml': 'html',
  'text/javascript': 'js',
  'application/javascript': 'js',
  'application/x-javascript': 'js',
  'module': 'js',
  'text/css': 'css',
  'application/xml': 'xml',
  'text/xml': 'xml',
  'image/svg+xml': 'svg',
};

const ALWAYS_BUFFER = new Set(['html', 'js', 'css', 'svg', 'xml']);
/**
 * キャッシュ対象。html を入れないこと:
 * 応答は Cookie/セッションに依存して変わり、sid を埋め込んだ改写を共有すると別タブの情報になるため。
 * (改写前は raw を持つので、html を cache に入れても結局 per-sid で改写し直す = 得をしない)
 */
const CACHEABLE = new Set(['js', 'css', 'svg', 'xml']);

export class Pipeline {
  /**
   * @param {{
   *  config:object, urlmap:object, rewriter:object, shields:object, threats:object,
   *  cookies:object, pool:object, guard:object, metrics?:object, store?:object
   * }} deps
   */
  constructor(deps) {
    this.config = deps.config;
    this.urlmap = deps.urlmap;
    this.rewriter = deps.rewriter;
    this.shields = deps.shields;
    this.threats = deps.threats;
    this.cookies = deps.cookies;
    this.pool = deps.pool;
    this.guard = deps.guard;
    this.metrics = deps.metrics;
    this.store = deps.store;
    this.httpPool = deps.httpPool;
    this.cache = new LRU(3000, this.config.transport.cache.ttlMs);
    this.cacheBytes = 0;
    this.cacheMaxBytes = this.config.transport.cache.maxBytes;
    this.cacheMaxEntry = this.config.transport.cache.maxEntryBytes;
    this.cacheEnabled = this.config.transport.cache.enabled;
    this.counters = { requests: 0, errors: 0, blocked: 0, quarantined: 0, stripped: 0, poolUsed: 0, direct: 0, redirects: 0 };
  }

  /**
   * @param {{
   *   sid:string, clientId?:string, method:string, url:string, headers:Map, body?:Buffer,
   *   mode?:string, dest?:string, kind?:string, referrer?:string, settings?:object,
   *   stream?:boolean, spoofIp?:string
   * }} req
   * @returns {Promise<{status:number,statusText:string,headers:Map,body:Buffer|import('node:stream').Readable,info:object}>}
   */
  async execute(req) {
    const t0 = Date.now();
    this.counters.requests++;
    const settings = req.settings || this.store?.settingsFor(req.clientId) || {};
    const url = safeUrl(req.url);
    if (!url) return this.#error(400, '不正な URL です', req);

    // ---------- 1. 安全ガード ----------
    const guard = this.guard.check(url, { resolve: true });
    if (!guard.ok) {
      this.counters.blocked++;
      return this.#error(403, `MirageVPN: ${guard.reason}`, req, { code: guard.code, url: url.href });
    }

    // ---------- 2. 脅威: URL 段 ----------
    const urlVerdict = this.threats?.enabled
      ? this.threats.inspectUrl(url.href, { sid: req.sid, kind: req.kind || 'asset', referrer: req.referrer })
      : { score: 0, findings: [], block: false };
    if (urlVerdict.block) {
      this.counters.quarantined++;
      return this.#quarantine(url, urlVerdict, req);
    }

    // ---------- 3. シールド: リクエスト段 ----------
    const typeHint = shieldTypeFor(req.dest, req.kind);
    const shieldHit = this.shields?.enabled
      ? this.shields.match(url.href, { type: typeHint, sourceUrl: req.referrer, sid: req.sid, method: req.method, documentUrl: req.referrer })
      : { blocked: false };
    if (shieldHit.blocked) {
      this.counters.blocked++;
      if (req.referrer) this.shields.noteBlocked(req.sid, req.referrer);
      return this.#blocked(url, shieldHit, req, typeHint);
    }

    // ---------- 4. 出口 (egress) 選択 ----------
    const egress = this.#pickEgress(req, settings, url);

    // ---------- 5. キャッシュ ----------
    const cacheKey = `${url.href}|${egress.info.egressCountry || 'self'}|${egress.info.egressStrategy}`;
    if (this.cacheEnabled && (req.method === 'GET' || req.method === 'HEAD')) {
      const hit = this.cache.get(cacheKey);
      if (hit && hit.status < 400) {
        this.metrics?.record({ ms: Date.now() - t0, bytes: hit.bytes, cache: true, mode: req.mode || 'uv', status: hit.status, egress: egress.label });
        return this.#fromCache(hit, req, url, egress, t0, urlVerdict);
      }
    }

    // ---------- 6. 上流リクエスト ----------
    let upstream = null;
    let lastErr = null;
    if (!egress.chain.length) {
      return this.#error(
        503,
        `利用可能な出口プロキシがありません (国籍 ${egress.info.egressCountry || 'AUTO'} / プロトコル ${this.config.egress.protocols.join(',')})。リスト更新を待つか、出口戦略を auto/direct にしてください。`,
        req,
        { code: 'no_egress', url: url.href, pool: this.pool.summary() },
      );
    }
    const attempts = egress.chain.length;
    for (let i = 0; i < attempts; i++) {
      const hop = egress.chain[i];
      try {
        upstream = await this.#fetchWithRedirects({ ...req, url, reqHeaders: egress.reqHeaders, egress: hop });
        if (hop.proxy) this.pool.report(hop.proxy, { ok: true, latencyMs: upstream.timing.ms, bytes: upstream.bytes });
        if (i > 0) ns.debug(() => `egress retry #${i} succeeded via ${hop.label}`);
        break;
      } catch (err) {
        lastErr = err;
        if (hop.proxy) {
          this.pool.report(hop.proxy, { ok: false, error: `${err.code || ''} ${err.message}`.trim() });
          this.counters.errors++;
        }
        if (i + 1 < attempts) {
          ns.debug(() => `egress ${hop.label} failed (${err.message}) → 次の出口へ`);
          upstream = null;
          continue;
        }
      }
    }
    if (!upstream) return this.#upstreamError(url, lastErr, req, egress, t0);

    const contentType = (upstream.headers.get('content-type') || '').toLowerCase();
    const kind = classify(upstream, url, contentType, req);
    if (upstream.decodeFailed) {
      ns.debug(() => `decompress failed (${upstream.headers.get('content-encoding') || '?'}): 改写をスキップします`);
      upstream.noRewrite = true;
    }

    // ---------- 7. ダウンロード検査 (閲覧扱い / attachment のときだけ) ----------
    const attachment = /attachment/i.test(String(upstream.headers.get('content-disposition') || ''));
    const navLike = ['document', 'iframe', 'frame', 'empty', ''].includes(String(req.dest || '').toLowerCase());
    if (kind !== 'html' && navLike && (attachment || kind === 'download') && this.threats?.enabled) {
      const dl = this.threats.inspectDownload({
        url: upstream.finalUrl.href,
        headers: upstream.headers,
        contentType,
      });
      if (dl.block) {
        this.counters.blocked++;
        return this.#error(451, '危険なファイル形式のためダウンロードは中止されました', req, {
          code: 'dangerous_file',
          detail: dl.findings.map((f) => f.evidence).join(' / '),
          url: upstream.finalUrl.href,
        });
      }
    }

    // ---------- 8. 改写 ----------
    const out = await this.#transform({ req, url, upstream, kind, urlVerdict, egress });
    if (this.cacheEnabled && CACHEABLE.has(kind) && upstream.status === 200 && !upstream.headers.get('set-cookie') && upstream.body?.length <= this.cacheMaxEntry) {
      const sanitized = new Map();
      for (const [k, v] of upstream.headers) {
        if (['content-length', 'content-encoding', 'transfer-encoding', 'vary', 'set-cookie', 'connection'].includes(k)) continue;
        sanitized.set(k, v);
      }
      this.cache.set(cacheKey, {
        status: upstream.status,
        statusText: upstream.statusText,
        headers: sanitized,
        body: upstream.body,
        kind,
        finalUrl: upstream.finalUrl.href,
        bytes: upstream.body.length,
      });
      this.cacheBytes += upstream.body.length;
    }

    // ---------- 9. ヘッダ ----------
    const { headers: outHeaders } = this.rewriter.responseHeaders(upstream.headers, {
      sid: req.sid,
      url: upstream.finalUrl,
      cookieStore: this.cookies,
      setCookies: upstream.setCookies,
      isDocument: kind === 'html' && req.kind === 'document',
    });
    if (out.info.cosmeticCount) outHeaders.set('x-mirage-cosmetic', String(out.info.cosmeticCount));
    const bodyBuffer = Buffer.isBuffer(out.body);
    if (bodyBuffer) outHeaders.set('content-length', String(out.body.length));
    else if (upstream.headers.get('content-length') && !out.rewritten) outHeaders.set('content-length', upstream.headers.get('content-length'));
    if (!outHeaders.get('content-type')) outHeaders.set('content-type', 'application/octet-stream');
    outHeaders.set('cache-control', 'no-store');
    // 上流の CSP / X-Frame-Options は落としたので、額縁制限は こちらで付け直す:
    // 「このゲートウェイのオリジンだけを額縁に許す」= 別サイトからの UI-redress / クリックジャッキングを塞ぐ。
    // 'self' なので自アプリのタブ (same-origin iframe) は今まで通り表示できる。
    if (kind === 'html') {
      outHeaders.set('content-security-policy', "frame-ancestors 'self'");
      outHeaders.set('x-frame-options', 'SAMEORIGIN');
    }
    outHeaders.set('x-mirage-egress', egress.label);

    const bytes = bodyBuffer ? out.body.length : out.contentLength || 0;
    const info = {
      ...out.info,
      ...egress.info,
      status: upstream.status,
      ms: Date.now() - t0,
      bytes,
      upstreamMs: upstream.timing.ms,
      connectMs: upstream.timing.connectMs,
      redirects: upstream.hops,
      cacheHit: false,
      mode: req.mode || 'uv',
      contentType,
      kind,
    };
    this.metrics?.record({
      ms: info.ms,
      bytes,
      status: upstream.status,
      mode: info.mode,
      blocked: out.blocked,
      stripped: out.stripped,
      egress: egress.label,
    });
    if (this.store && req.sid) {
      this.store.touchSession(req.sid, {
        url: upstream.finalUrl.href,
        host: upstream.finalUrl.hostname,
        title: out.info.title || upstream.finalUrl.hostname,
        egress: egress.info.egressLabel || 'direct',
        country: egress.info.egressCountry || 'XX',
        threat: out.info.threatScore || 0,
        blocked: out.blocked || 0,
        bytes,
        lastReq: Date.now(),
      });
    }
    outHeaders.set('x-mirage-info', encodeInfo(info));
    outHeaders.set('x-mirage-final-url', encodeURIComponent(upstream.finalUrl.href));
    return { status: upstream.status, statusText: upstream.statusText, headers: outHeaders, body: out.body, info };
  }

  /* ------------------------------------------------------------------ */
  /* WISP 用: 応答を「生の HTTP バイト」として返す                        */
  /* ------------------------------------------------------------------ */

  /**
   * @param {{sid:string, method:string, url:string, headers:object, body?:Buffer, clientId?:string, settings?:object}} req
   * @returns {Promise<Buffer>}
   */
  async wispExecute(req) {
    const headers = new Map(Object.entries(req.headers || {}).map(([k, v]) => [String(k).toLowerCase(), String(v)]));
    const res = await this.execute({
      sid: req.sid,
      clientId: req.clientId,
      settings: req.settings,
      method: req.method || 'GET',
      url: req.url,
      headers,
      body: req.body ? Buffer.from(req.body) : null,
      mode: 'wisp',
      dest: 'fetch',
      kind: 'asset',
      referrer: req.referrer,
    });
    const lines = [`HTTP/1.1 ${res.status} ${res.statusText || 'OK'}`];
    for (const [k, v] of res.headers) lines.push(`${k}: ${v}`);
    const body = Buffer.isBuffer(res.body) ? res.body : Buffer.alloc(0);
    lines.push(`content-length: ${body.length}`);
    return Buffer.concat([Buffer.from(`${lines.join('\r\n')}\r\n\r\n`, 'latin1'), body]);
  }

  /* ------------------------------------------------------------------ */
  /* 内部                                                                */
  /* ------------------------------------------------------------------ */

  #pickEgress(req, settings, url) {
    const cfg = this.config;
    const s = settings.egress || {};
    const strategy = s.strategy || cfg.egress.defaultStrategy;
    const httpsTarget = url.protocol === 'https:';
    const country = (s.country && s.country !== 'AUTO' ? s.country : cfg.egress.country) || 'AUTO';
    const rotate = s.rotate || 'per-tab';
    const chain = [];
    const label0 = strategy === 'direct' ? 'direct' : country !== 'AUTO' && country !== 'XX' ? `pool:${country}` : 'pool:auto';

    if (strategy !== 'direct') {
      const wantProxy = {
        country: country === 'AUTO' ? undefined : country,
        protocols: s.protocols || cfg.egress.protocols,
        httpsTarget,
        sid: rotate === 'per-request' ? undefined : req.sid,
        allowFallback: s.allowFallback !== false && country !== 'AUTO',
        // auto は未検査の無料プロキシをいきなり踏まず、まず direct でページを開く。
        // ヘルスチェックで生存確認できた出口だけ、次回以降の auto 候補にする。
        requireHealthy: strategy === 'auto',
      };
      const picks = [];
      const first = this.pool.select(wantProxy);
      if (first) picks.push(first);
      if (strategy === 'auto' || strategy === 'pool') {
        for (let i = 0; i < Math.max(0, cfg.egress.retries); i++) {
          const extra = this.pool.select({ ...wantProxy, exclude: new Set(picks.map((p) => p.key)) });
          if (extra) picks.push(extra);
        }
      }
      for (const proxy of picks) {
        chain.push({
          proxy,
          label: `${proxy.protocol}://${proxy.country}:${proxy.port}`,
          profile: `p:${proxy.key}`,
          to: { protocol: proxy.protocol, host: proxy.host, port: proxy.port, username: proxy.username, password: proxy.password },
        });
        this.counters.poolUsed++;
      }
    }
    // auto/direct では最終手段として自前 IP で出す (プロキシ死しててもブラウザは動く)
    if (strategy !== 'pool') {
      chain.push({ proxy: null, label: 'direct', profile: `d:${url.origin}`, to: null });
      if (chain.length === 1) this.counters.direct++;
    }
    const usedProxy = chain.length > 0 && chain[0].proxy;
    if (usedProxy) this.counters.poolUsed = this.counters.poolUsed;

    const spoofIps = cfg.egress.spoofForwardedHeaders && s.sendSpoofHeaders !== false ? [req.spoofIp || randomSpoofIp(country)] : undefined;
    const reqHeaders = this.rewriter.requestHeaders({
      url,
      sid: req.sid,
      method: req.method,
      mode: req.mode || 'navigate',
      dest: req.dest,
      clientHeaders: req.headers,
      referrer: req.referrer,
      body: req.body,
      spoofIps,
      egress: { country: usedProxy ? usedProxy.country : null },
      cookie: this.cookies ? cookieHeader(this.cookies.jar(req.sid), url) : '',
    });
    const info = {
      egressStrategy: strategy,
      egressLabel: usedProxy ? chain[0].label : 'direct',
      egressCountry: usedProxy ? usedProxy.country : 'SELF',
      egressProxy: usedProxy ? `${usedProxy.host}:${usedProxy.port}` : null,
      egressLatencyMs: usedProxy ? Math.round(usedProxy.latencyEma || 0) : 0,
      spoofIp: spoofIps ? spoofIps[0] : null,
    };
    return { chain, profile: chain.map((c) => c.profile).join('+') || 'direct', label: label0, info, reqHeaders };
  }

  async #fetchWithRedirects(o) {
    const cfg = this.config.transport;
    const pool = this.httpPool;
    let url = o.url;
    let method = o.method || 'GET';
    let body = o.body;
    let hops = 0;
    let proxyChainIndex = o.egress ? 0 : 0;
    const t0 = Date.now();
    let connectMs = 0;
    let last = null;

    while (true) {
      const proxyDef = o.egress ? { ...o.egress.to } : null;
      // 試行/リダイレクトごとに複製 (referer/body を書き換えるので共有しない)
      const headers = new Map(o.reqHeaders || []);
      if (hops > 0) {
        // リダイレクト後は referer を更新、body を落とす
        headers.set('referer', url.origin + url.pathname);
        if ([301, 302, 303].includes(last?.status) && method !== 'HEAD') {
          method = 'GET';
          body = null;
          headers.delete('content-length');
          headers.delete('content-type');
        }
      }
      const tReq = Date.now();
      const res = await http1Request({
        url: url.href,
        method,
        headers: new Map(headers),
        body,
        proxy: proxyDef,
        connectTimeoutMs: cfg.connectTimeoutMs,
        headTimeoutMs: cfg.responseTimeoutMs,
        idleTimeoutMs: cfg.streamIdleTimeoutMs,
        maxBodyBytes: 0,
        pool,
      });
      const status = res.statusCode;
      const headers2 = res.headers;
      let setCookies = [];
      const rawSet = headers2.get('set-cookie');
      if (rawSet) setCookies = splitSetCookie(rawSet);
      const loc = headers2.get('location');
      const isRedirect = [301, 302, 303, 307, 308].includes(status) && loc;
      const shouldFollow = isRedirect && hops < cfg.maxRedirects && (req_wants_follow(o));
      if (!shouldFollow) {
        const buf = await readBody(res, {
          decompress: cfg.decompress,
          maxBytes: this.config.transport.maxBodyBytes,
          bufferAlways: ALWAYS_BUFFER.has(classify({ headers: headers2 }, url, headers2.get('content-type') || '', o)),
          contentType: headers2.get('content-type') || '',
        });
        return {
          status,
          statusText: res.statusText,
          headers: headers2,
          setCookies,
          body: buf.body,
          stream: buf.stream,
          decoded: !!buf.decoded,
          decodeFailed: !!buf.decodeFailed,
          contentLength: buf.length,
          bytes: buf.length,
          finalUrl: url,
          hops,
          timing: { ms: Date.now() - t0, connectMs },
          location: loc || null,
        };
      }
      this.counters.redirects++;
      const next = safeUrl(loc, url.href);
      if (!next) throw Object.assign(new Error('Location ヘッダが不正です'), { code: 'bad_location' });
      const g = this.guard.check(next, { resolve: true });
      if (!g.ok) throw Object.assign(new Error(`リダイレクト先が許可されていません: ${g.reason}`), { code: 'redirect_blocked' });
      url = next;
      hops++;
      last = { status };
    }
  }

  async #transform({ req, url, upstream, kind, urlVerdict, egress }) {
    const info = { threatScore: urlVerdict?.score || 0, threatFindings: (urlVerdict?.findings || []).length, blocked: 0, stripped: 0, rewritten: 0, cosmeticCount: 0, title: null };
    const isBuffer = Buffer.isBuffer(upstream.body);
    if (!ALWAYS_BUFFER.has(kind) || !isBuffer) {
      // ストリーミング配信 (動画/大容量) は改写しない — レンジ指定も壊さない
      info.rewriteSkipped = true;
      return { body: upstream.stream || upstream.body, info, blocked: 0, stripped: 0, contentLength: upstream.contentLength, rewritten: false };
    }

    const decoded = upstream.body;
    const text = decoded.toString('utf8');
    if (upstream.noRewrite) {
      return { body: upstream.body, info, blocked: 0, stripped: 0, contentLength: upstream.body.length, rewritten: false };
    }

    const sid = req.sid;
    const ctx = {
      sid,
      base: new URL(upstream.finalUrl.href),
      kind: req.kind || (kind === 'html' ? 'document' : 'asset'),
      documentUrl: upstream.finalUrl.href,
      coreUrl: `${this.config.basePath}${this.config.url.corePath}`,
      blockedUrls: [],
      config: this.#clientConfig(req, upstream, info),
      proxify: (u) => this.urlmap.proxify(u, sid),
      cosmeticCss: this.shields?.enabled && this.config.shields.cosmetic ? this.shields.cosmeticCss(upstream.finalUrl.href).css : '',
    };
    if (ctx.cosmeticCss) info.cosmeticCount = this.shields.cosmeticCss(upstream.finalUrl.href).count;

    let body;
    let stripped = 0;
    if (kind === 'html') {
      // 脅威: ドキュメント内容スキャン (自動削除 = strip 指示)
      let verdict = { score: 0, findings: [], strips: [] };
      if (this.threats?.enabled) {
        verdict = this.threats.inspectDocument(text, { sid, url: upstream.finalUrl.href, baseUrl: ctx.base, kind: 'document' });
        if (verdict.block) {
          this.counters.quarantined++;
          const q = this.#quarantine(upstream.finalUrl, verdict, req);
          q.info = { ...q.info, threatScore: verdict.score };
          return { ...q, blocked: 1, stripped: 0, info: { ...q.info, ...info } };
        }
        const cred = this.threats.credentialFormCheck({ html: text, baseUrl: ctx.base, sid });
        if (cred.length) {
          info.credentialGuard = cred.length;
          stripped += cred.length;
        }
      }
      const r = this.rewriter.html(text, ctx);
      body = Buffer.from(r.body, 'utf8');
      info.title = r.meta.title;
      info.rewritten = r.counters.rewritten;
      info.stripped = r.counters.stripped + stripped;
      info.hardened = r.counters.hardened;
      info.blockedByShields = r.counters.blocked;
      this.counters.stripped += r.counters.stripped + stripped;
    } else if (kind === 'css') {
      const r = this.rewriter.css(text, ctx);
      body = Buffer.from(r, 'utf8');
      info.rewritten = 1;
    } else if (kind === 'js') {
      let drop = false;
      if (this.threats?.enabled) {
        const v = this.threats.inspectAsset(text, { url: upstream.finalUrl.href, kind: 'script', sid });
        drop = v.drop;
        if (drop) info.threatFindings += v.findings.length;
      }
      if (drop) {
        this.counters.stripped++;
        body = Buffer.from(`/* MirageVPN: このスクリプトは脅威検知により自動除去されました */`, 'utf8');
        info.stripped = 1;
        info.rewritten = 0;
      } else {
        const r = this.rewriter.js(text, ctx, { rewritten: 0 });
        body = Buffer.from(r, 'utf8');
        info.rewritten = 1;
      }
    } else if (kind === 'svg' || kind === 'xml') {
      const r = this.rewriter.html(text, { ...ctx, kind: 'asset' });
      body = Buffer.from(r.body.replace(/<meta charset="utf-8">/, ''), 'utf8');
      info.rewritten = r.counters.rewritten;
    } else {
      body = upstream.body;
    }

    return {
      body,
      info,
      blocked: this.shields?.enabled ? ctx.blockedUrls.length : 0,
      stripped: info.stripped || 0,
      contentLength: body.length,
      rewritten: (info.rewritten || 0) > 0,
    };
  }

  #fromCache(hit, req, url, egress, t0, urlVerdict) {
    const ctx = {
      sid: req.sid,
      base: new URL(hit.finalUrl),
      kind: req.kind || 'asset',
      documentUrl: hit.finalUrl,
      coreUrl: `${this.config.basePath}${this.config.url.corePath}`,
      blockedUrls: [],
      config: { ...this.#clientConfig(req, { finalUrl: new URL(hit.finalUrl) }, {}), cache: true },
      proxify: (u) => this.urlmap.proxify(u, req.sid),
      cosmeticCss: this.shields?.enabled && this.config.shields.cosmetic ? this.shields.cosmeticCss(hit.finalUrl).css : '',
    };
    let body = hit.body;
    const headers = new Map(hit.headers);
    if (hit.kind === 'html') {
      const r = this.rewriter.html(body.toString('utf8'), ctx);
      body = Buffer.from(r.body, 'utf8');
    } else if (hit.kind === 'js') {
      body = Buffer.from(this.rewriter.js(body.toString('utf8'), ctx, { rewritten: 0 }), 'utf8');
    } else if (hit.kind === 'css') {
      body = Buffer.from(this.rewriter.css(body.toString('utf8'), ctx), 'utf8');
    }
    const outHeaders = new Map();
    for (const [k, v] of headers) outHeaders.set(k, v);
    outHeaders.set('content-length', String(body.length));
    outHeaders.set('x-mirage-info', encodeInfo({
      cacheHit: true,
      finalUrl: hit.finalUrl,
      bytes: body.length,
      ms: Date.now() - t0,
      mode: req.mode || 'uv',
      kind: hit.kind,
      egressLabel: 'cache',
      threatScore: urlVerdict?.score || 0,
    }));
    outHeaders.set('cache-control', 'no-store');
    if (hit.kind === 'html') {
      outHeaders.set('content-security-policy', "frame-ancestors 'self'");
      outHeaders.set('x-frame-options', 'SAMEORIGIN');
    }
    return { status: hit.status, statusText: hit.statusText, headers: outHeaders, body, info: { cacheHit: true, bytes: body.length, ms: Date.now() - t0, kind: hit.kind, finalUrl: hit.finalUrl } };
  }

  #clientConfig(req, upstream, info) {
    const cfg = this.config;
    const settings = req.settings || this.store?.settingsFor(req.clientId) || {};
    const blockedHosts = this.shields?.topBlockedHosts ? this.shields.topBlockedHosts(150) : [];
    return {
      sid: req.sid,
      encoding: cfg.url.encoding,
      prefix: this.urlmap.sessionPrefix(req.sid),
      apiBase: `${cfg.basePath}${cfg.url.apiPrefix}`,
      corePath: `${cfg.basePath}${cfg.url.corePath}`,
      base: upstream.finalUrl ? upstream.finalUrl.href : req.url,
      finalUrl: info?.redirectedTo || undefined,
      mode: req.mode || cfg.transport.defaultMode,
      wispAvailable: cfg.wisp.enabled && !cfg.isServerless,
      wispUrl: cfg.wisp.enabled && !cfg.isServerless ? `${cfg.basePath}${cfg.wisp.path}?sid=${encodeURIComponent(req.sid)}` : null,
      wispClientUrl: cfg.wisp.enabled && !cfg.isServerless ? `${cfg.basePath}/mirage/wisp-client.js` : null,
      wispConnectTimeoutMs: 3500,
      wispRetries: 2,
      swPath: `${cfg.basePath}${cfg.url.swPath}`,
      shieldsOn: !!(settings.shields && settings.shields.enabled !== false),
      blockedHosts,
      blockedSuffixes: this.shields?.topSuffixes ? this.shields.topSuffixes(120) : [],
      containTop: settings.privacy?.containTop !== false,
      isolateStorage: settings.privacy?.isolateStorage !== false,
      blockNotifications: settings.privacy?.blockNotifications !== false,
      blockServiceWorker: settings.privacy?.blockServiceWorker !== false,
      blockGeolocation: !!settings.privacy?.blockGeolocation,
      stripCredentials: settings.privacy?.stripCredentials !== false,
      cookies: this.cookies ? this.cookies.clientStringFor(req.sid, safeUrl(req.url) || new URL('https://x/')) : '',
      reportTabs: true,
    };
  }

  /* ---------------- 特殊応答 ---------------- */

  #blocked(url, hit, req, typeHint) {
    const headers = new Map([['content-type', 'text/plain; charset=utf-8'], ['x-mirage-blocked', String(hit.category || 'blocked').slice(0, 24)]]);
    if (typeHint === 'document' && req.kind === 'document') {
      return this.#error(
        451,
        'このアドレスはシールド (広告/トラッカー ブロック) により遮断されました',
        req,
        { code: 'shields', detail: hit.rule, url: url.href },
      );
    }
    if (typeHint === 'image') {
      const gif = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
      headers.set('content-type', 'image/gif');
      headers.set('content-length', String(gif.length));
      return { status: 200, statusText: 'OK (blocked)', headers, body: gif, info: { blocked: true, rule: hit.rule, category: hit.category } };
    }
    if (typeHint === 'script' || typeHint === 'xhr' || typeHint === 'stylesheet') {
      headers.set('content-type', typeHint === 'script' ? 'application/javascript' : 'text/css');
      const stub = Buffer.from(typeHint === 'script' ? '/* MirageVPN: blocked by shields */' : '/* MirageVPN: blocked */');
      headers.set('content-length', String(stub.length));
      return { status: 204, statusText: 'No Content (blocked)', headers, body: stub, info: { blocked: true, rule: hit.rule, category: hit.category } };
    }
    headers.set('content-length', '0');
    return { status: 204, statusText: 'No Content (blocked)', headers, body: Buffer.alloc(0), info: { blocked: true, rule: hit.rule } };
  }

  #quarantine(url, verdict, req) {
    this.counters.quarantined++;
    const html = quarantinePage(url, verdict, req);
    const body = Buffer.from(html, 'utf8');
    return {
      status: 451,
      statusText: 'Quarantined',
      headers: new Map([
        ['content-type', 'text/html; charset=utf-8'],
        ['content-length', String(body.length)],
        ['x-mirage-threat', String(verdict.score)],
      ]),
      body,
      info: { quarantine: true, threatScore: verdict.score, findings: verdict.findings.map((f) => f.code) },
    };
  }

  #error(status, message, req, extra = {}) {
    const accept = String(req.headers?.get?.('accept') || '');
    const wantsHtml = status >= 400 && (req.kind === 'document' || /text\/html/.test(accept));
    const body = wantsHtml
      ? Buffer.from(errorPage(message, extra), 'utf8')
      : Buffer.from(JSON.stringify({ error: message, ...extra }), 'utf8');
    const headers = new Map([
      ['content-type', wantsHtml ? 'text/html; charset=utf-8' : 'application/json; charset=utf-8'],
      ['content-length', String(body.length)],
    ]);
    this.metrics?.record({ ms: 0, bytes: body.length, error: true, status, mode: req.mode || 'uv' });
    return { status, statusText: 'Mirage', headers, body, info: { error: message, ...extra } };
  }

  #upstreamError(url, err, req, egress, t0) {
    this.counters.errors++;
    const code = err?.code || 'fetch_failed';
    const tips = [];
    if (egress.chain.some((c) => c.proxy)) tips.push('プロキシ経由の接続が失敗しました。別の出口 (他国/直接) を試すか、シールド/タイムアウトを設定してください。');
    if (code === 'head_timeout' || code === 'idle_timeout' || code === 'connect_failed') tips.push('このサイトはプロキシからのアクセスを拒否している可能性があります (直接接続なら開けるかもしれません)。');
    if (code === 'tls_failed') tips.push('TLS ハンドシェイクに失敗しました (自己署名証明書/プロキシの干渉)。');
    const message = `上流に接続できませんでした: ${err?.message || code}`;
    const out = this.#error(502, message, req, {
      code,
      url: url.href,
      egress: egress.info,
      tips,
      ms: Date.now() - t0,
    });
    this.metrics?.record({ ms: Date.now() - t0, error: true, status: 0, mode: req.mode || 'uv', egress: egress.label });
    if (this.store && req.sid) {
      this.store.touchSession(req.sid, { lastError: `${code}: ${err?.message || ''}`.slice(0, 200), lastSeen: Date.now() });
    }
    return out;
  }

  /* ---------------- キャッシュ管理 ---------------- */

  cacheStats() {
    return { size: this.cache.size, bytes: this.cacheBytes, maxBytes: this.cacheMaxBytes, enabled: this.cacheEnabled };
  }
  clearCache() {
    this.cache.clear();
    this.cacheBytes = 0;
    return true;
  }

  stats() {
    return { ...this.counters, cache: this.cacheStats(), upstreamPool: this.httpPool ? this.httpPool.size() : 0 };
  }
}

/* ------------------------------------------------------------------ */

function safeUrl(s, base) {
  try {
    return new URL(s, base);
  } catch {
    return null;
  }
}

function classify(upstream, url, contentType, req) {
  const ct = (contentType || '').split(';')[0].trim();
  if (REWRITEABLE[ct]) return REWRITEABLE[ct];
  if (req.kind === 'document' && (ct === '' || ct === 'text/html' || ct === 'application/xhtml+xml')) return 'html';
  const ext = (url.pathname.split('/').pop() || '').split('.').pop()?.toLowerCase();
  if (['js', 'mjs'].includes(ext)) return 'js';
  if (ext === 'css') return 'css';
  if (['html', 'htm'].includes(ext)) return 'html';
  if (ext === 'svg') return 'svg';
  return 'other';
}

function shieldTypeFor(dest, kind) {
  const map = {
    document: 'document',
    script: 'script',
    style: 'stylesheet',
    image: 'image',
    font: 'font',
    video: 'media',
    audio: 'media',
    track: 'other',
    embed: 'object',
    object: 'object',
    fetch: 'xhr',
    xhr: 'xhr',
    beacon: 'ping',
    report: 'other',
    ping: 'ping',
    manifest: 'other',
    worker: 'script',
    frame: 'subdocument',
    iframe: 'subdocument',
    nested: 'subdocument',
  };
  if (map[dest]) return map[dest];
  if (kind === 'document') return 'document';
  return 'other';
}

async function readBody(res, { decompress, contentType = '', maxBytes, bufferAlways = false }) {
  const enc = (res.headers.get('content-encoding') || '').toLowerCase();
  const isText = /text|javascript|json|xml|html|css|svg/.test(contentType);
  const clearEncoded = () => {
    // 平文にしたのでヘッダは必ず合わせる (ブラウザが二度解こうとして壊れるのを防ぐ)
    res.headers.delete('content-encoding');
    res.headers.delete('content-length');
  };
  const encoded = !!enc && enc !== 'identity';
  const willDecode = decompress && encoded && (isText || bufferAlways);
  if (!willDecode) {
    // 改写しないタイプはストリームのまま (圧縮が掛かっていればそのままで渡す = 上流と同じ挙動)
    if (bufferAlways || isText || contentType.includes('json')) {
      const buf = await collect(res.stream, maxBytes);
      return { body: buf, stream: null, length: buf.length };
    }
    return { body: null, stream: res.stream, length: Number(res.headers.get('content-length')) || 0 };
  }
  const buf = await collect(res.stream, maxBytes);
  const done = (out) => {
    clearEncoded();
    return { body: out, stream: null, length: out.length, decoded: true };
  };
  const failed = () => ({ body: buf, stream: null, length: buf.length, decodeFailed: true });
  if (enc === 'gzip' || enc === 'x-gzip') {
    try {
      return done(zlib.gunzipSync(buf));
    } catch {
      return failed();
    }
  }
  if (enc === 'br') {
    try {
      return done(zlib.brotliDecompressSync(buf));
    } catch {
      return failed();
    }
  }
  if (enc === 'deflate') {
    try {
      return done(zlib.inflateRawSync(buf));
    } catch {
      try {
        return done(zlib.inflateSync(buf));
      } catch {
        return failed();
      }
    }
  }
  if (enc === 'zstd' && typeof zlib.zstdDecompressSync === 'function') {
    try {
      return done(zlib.zstdDecompressSync(buf));
    } catch {
      return failed();
    }
  }
  return failed(); // 未知の encoding → 改写しない (生で返す)
}

async function collect(stream, maxBytes) {
  const chunks = [];
  let len = 0;
  for await (const c of stream) {
    chunks.push(c);
    len += c.length;
    if (maxBytes && len > maxBytes) {
      stream.destroy?.();
      throw Object.assign(new Error(`応答が大きすぎます (${fmtBytes(len)})`), { code: 'body_too_large' });
    }
  }
  return Buffer.concat(chunks, len);
}

function decompressBuffer(buf, enc) {
  if (enc === 'gzip' || enc === 'x-gzip') return zlib.gunzipSync(buf);
  if (enc === 'br') return zlib.brotliDecompressSync(buf);
  if (enc === 'deflate') {
    try {
      return zlib.inflateRawSync(buf);
    } catch {
      return zlib.inflateSync(buf);
    }
  }
  return buf;
}

function req_wants_follow(o) {
  // 上流がリダイレクトを隠すと SPA/SPA 認証が壊れるので基本は追う。
  // ただし XHR で 同一 SPA の API リダイレクトは 1 回までなど、細かな調整余地はここ。
  return o.followRedirects !== false;
}

function encodeInfo(info) {
  try {
    return encodeURIComponent(JSON.stringify(info)).slice(0, 1800);
  } catch {
    return '';
  }
}

function randomSpoofIp(country) {
  // 国がわかっていれば「その国らしい」レンジ、未知ならグローバルレンジ
  return randomPublicIpFor(country);
}

function randomPublicIpFor(_country) {
  const bytes = new Uint8Array(4);
  crypto.getRandomValues(bytes);
  // プライベート/リザーブドに当たらないよう 1..223 に寄せる
  bytes[0] = 1 + (bytes[0] % 223);
  if (bytes[0] === 10 || bytes[0] === 127 || bytes[0] === 0) bytes[0] = 203;
  if (bytes[0] === 100) bytes[0] = 104;
  if (bytes[0] === 169) bytes[0] = 193;
  if (bytes[0] === 172 && bytes[1] < 32) bytes[1] = 44;
  if (bytes[0] === 192 && bytes[1] === 168) bytes[1] = 31;
  return `${bytes[0]}.${bytes[1]}.${bytes[2]}.${1 + bytes[3] % 253}`;
}

function errorPage(message, extra = {}) {
  const tips = (extra.tips || []).map((t) => `<li>${escapeHtml(t)}</li>`).join('');
  return `<!doctype html><html lang="ja"><head><meta charset="utf-8"><title>MirageVPN — 接続エラー</title>
<style>
  body{margin:0;min-height:100vh;display:grid;place-items:center;background:#070b17;color:#e6ecff;font:15px/1.7 ui-sans-serif,system-ui,"Hiragino Sans","Noto Sans JP",sans-serif}
  .c{max-width:640px;padding:34px 34px 28px;border:1px solid #ffffff1f;border-radius:18px;background:linear-gradient(160deg,#111a33ee,#0a1024ee);box-shadow:0 30px 80px #0009}
  h1{margin:0 0 6px;font-size:19px;letter-spacing:.02em}
  .m{opacity:.85} code{background:#ffffff14;padding:1px 6px;border-radius:6px}
  ul{margin:14px 0 0;padding-left:18px;opacity:.8}
  .btn{margin-top:18px;display:inline-flex;gap:10px}
  a,button{color:#9fd0ff;text-decoration:none;border:1px solid #ffffff22;background:#ffffff0d;padding:7px 12px;border-radius:10px;font:inherit;cursor:pointer}
</style></head><body><div class="c">
<h1>⚠️ MirageVPN</h1><div class="m">${escapeHtml(message)}</div>
${extra.url ? `<div class="m" style="margin-top:8px;font-size:13px"><code>${escapeHtml(String(extra.url).slice(0, 160))}</code></div>` : ''}
${tips ? `<ul>${tips}</ul>` : ''}
<div class="btn"><button onclick="history.back()">戻る</button><button onclick="location.reload()">再試行</button></div>
</div></body></html>`;
}

function quarantinePage(url, verdict, req) {
  const items = (verdict.findings || [])
    .map(
      (f) =>
        `<li><b>${escapeHtml(f.label || f.code)}</b> <span class="s">score ${f.score}</span><div class="e">${escapeHtml(String(f.evidence || '').slice(0, 220))}</div></li>`,
    )
    .join('');
  return `<!doctype html><html lang="ja"><head><meta charset="utf-8"><title>隔離しました — MirageVPN</title>
<style>
  body{margin:0;min-height:100vh;display:grid;place-items:center;background:#080c18;color:#f2f6ff;font:15px/1.7 ui-sans-serif,system-ui,"Hiragino Sans","Noto Sans JP",sans-serif}
  .c{max-width:720px;padding:34px;border:1px solid #ff5d5d55;border-radius:20px;background:radial-gradient(120% 140% at 0% 0%,#2a1020ee,#0b0f1cee);box-shadow:0 30px 90px #000a}
  h1{margin:0 0 4px;font-size:22px}
  .u{font-size:12px;opacity:.7;word-break:break-all}
  .score{display:inline-flex;align-items:center;gap:8px;margin:16px 0 0;padding:6px 12px;border-radius:999px;background:#ff5d5d22;border:1px solid #ff5d5d55;font-weight:700}
  ul{margin:16px 0 0;padding-left:18px}
  li{margin:8px 0}
  .s{opacity:.7;font-size:12px;margin-left:6px}
  .e{font-size:12px;opacity:.72}
  .btn{margin-top:22px;display:flex;gap:10px;flex-wrap:wrap}
  button{color:#ffd0d0;border:1px solid #ff5d5d55;background:#ff5d5d1a;padding:8px 14px;border-radius:11px;font:inherit;cursor:pointer}
  button.ghost{color:#cfe0ff;border-color:#ffffff22;background:#ffffff0a}
</style></head><body><div class="c">
  <h1>🛡️ このページは隔離されました</h1>
  <div class="u">${escapeHtml(url.href)}</div>
  <div class="score">脅威スコア ${verdict.score} / 閾値 ${req.settings?.threats?.blockScore ?? 80}</div>
  <ul>${items || '<li>総合スコアが閾値を超えました。</li>'}</ul>
  <div class="btn">
    <button onclick="parent.postMessage({type:'mirage:unblock',sid:'${escapeHtml(req.sid || '')}',url:'${escapeHtml(url.href)}'},'*')">リスクを理解した上で許可する</button>
    <button class="ghost" onclick="parent.postMessage({type:'mirage:report',sid:'${escapeHtml(req.sid || '')}'},'*')">レポートを開く</button>
    <button class="ghost" onclick="history.back()">戻る</button>
  </div>
</div></body></html>`;
}

export default Pipeline;
