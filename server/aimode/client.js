/**
 * MirageVPN — Google AI Mode クライアント (プロバイダ抽象)
 * ---------------------------------------------------------------
 * Google AI Mode に公式 API は無い。この module は「AI Mode を API として
 * 叩く」ための差し替え可能なプロバイダを 3 つ持つ:
 *
 *   serp    … 自前。`/search?q=...&udm=50` をパイプライン経由 (出口は US 固定)
 *             で取り、aimc コンテナを抽出する。依存ゼロ・無料・壊れやすい。
 *   relay   … 外部リレー (Playwright 常駐ブラウザや自前の FastAPI 等) に
 *             POST する。堅いが別プロセスが必要。
 *   serpapi … 有料 SERP API (SerpApi の engine=google_ai_mode)。
 *             安定・多ターン対応・課金。
 *
 * どのプロバイダでも戻り値を同じ形に正規化する:
 *   { ok, provider, answer, text, citations[], sources[], followUps[],
 *     confidence, warnings[], usage?, meta{ ms, egress, cache, ... } }
 *
 * @module aimode/client
 */

import { Buffer } from 'node:buffer';
import { extractAiMode, DEFAULT_CONTAINERS, DEFAULT_DISCLAIMER_RE, DEFAULT_SOURCES_LABEL_RE, DEFAULT_GOOGLE_HOSTS } from './extract.js';
import { AiModeQuota } from './quota.js';
import { log } from '../log.js';

const ns = log.child('aimode');

export class AiModeClient {
  /**
   * @param {{config:object, engine:object}} deps
   */
  constructor({ config, engine }) {
    this.config = config;
    /** @type {object|null} engine は組立後に差し込まれる (循環参照を避けるため) */
    this.engine = engine;
    this.cfg = config.aimode;
    this.quota = new AiModeQuota({
      perHour: this.cfg.perHour,
      perDay: this.cfg.perDay,
      minIntervalMs: this.cfg.minIntervalMs,
      cooldownMs: this.cfg.cooldownMs,
    });
    /** @type {Map<string,{at:number,value:object}>} */
    this.cache = new Map();
    this.lastError = null;
    this.lastOk = null;
    this.counters = { ok: 0, fail: 0, cacheHit: 0, captcha: 0 };
  }

  get enabled() {
    return !!this.cfg?.enabled;
  }

  /** engine 後付けなので getter で解決する */
  get pipeline() {
    return this.engine?.pipeline;
  }

  get pool() {
    return this.engine?.pool;
  }

  get cookies() {
    return this.engine?.cookies;
  }

  /** 抽出オプション (環境変数で上書き可能) */
  extractOptions() {
    const c = this.cfg || {};
    return {
      containers: c.containers?.length ? c.containers : DEFAULT_CONTAINERS,
      disclaimerRe: c.disclaimerRe || DEFAULT_DISCLAIMER_RE,
      sourcesLabelRe: c.sourcesLabelRe || DEFAULT_SOURCES_LABEL_RE,
      googleHosts: c.googleHosts?.length ? c.googleHosts : DEFAULT_GOOGLE_HOSTS,
    };
  }

  /* ---------------------------------------------------------------- */
  /* メイン                                                            */
  /* ---------------------------------------------------------------- */

  /**
   * @param {{q:string, lang?:string, country?:string, provider?:string,
   *          sid?:string, clientId?:string, settings?:object,
   *          resolveCitations?:boolean, messages?:Array, system?:string}} req
   * @returns {Promise<object>}
   */
  async ask(req = {}) {
    if (!this.enabled) return { ok: false, reason: 'disabled', error: 'AI Mode 連携は無効です (MIRAGE_AIMODE=1)' };
    const q = String(req.q || '').trim();
    if (!q) return { ok: false, reason: 'empty_query', error: 'q が必要です' };

    const provider = req.provider || this.cfg.provider || 'serp';
    const lang = req.lang || this.cfg.lang || 'en';
    const country = (req.country || this.cfg.country || 'US').toUpperCase();

    // relay は別ホストで geo を解決するので country/lang は送るだけ
    const gate = this.quota.check();
    if (!gate.ok) {
      this.counters.fail++;
      return {
        ok: false,
        reason: `quota:${gate.reason}`,
        error: 'AI Mode の問い合わせ予算を使い切りました (Google にブロックされないための自制)',
        retryAfterMs: gate.retryAfterMs,
        quota: this.quota.stats(),
      };
    }

    const cacheKey = `${provider}|${country}|${lang}|${q}`;
    const cached = this.#cacheGet(cacheKey);
    if (cached) {
      this.counters.cacheHit++;
      return { ...cached, meta: { ...cached.meta, cache: true } };
    }

    const t0 = Date.now();
    this.quota.note();
    let out;
    try {
      const dispatch = () =>
        provider === 'relay'
          ? this.#relayAsk({ q, lang, country, req })
          : provider === 'serpapi'
            ? this.#serpApiAsk({ q, lang, country, req })
            : this.#serpAsk({ q, lang, country, req });
      out = await dispatch();
      // CAPTCHA / 上流エラーは出口を変えて 1 回だけリトライ (quota は 1 回分)
      const retryable = (r) => r && !r.ok && (r.reason === 'captcha' || String(r.reason).startsWith('upstream_'));
      for (let i = 0; i < this.cfg.retries && retryable(out); i++) {
        ns.debug(() => `${provider} リトライ ${i + 1}: ${out.reason}`);
        const again = await dispatch();
        if (again.ok || !retryable(again)) {
          out = again;
          break;
        }
      }
    } catch (err) {
      this.quota.noteError();
      this.counters.fail++;
      this.lastError = { at: Date.now(), message: String(err?.message || err) };
      ns.warn(() => `${provider} 失敗: ${err?.message || err}`);
      return { ok: false, reason: 'exception', error: String(err?.message || err).slice(0, 300), provider };
    }

    if (!out.ok) {
      this.counters.fail++;
      if (out.reason === 'captcha') {
        this.counters.captcha++;
        const cd = this.quota.noteBlocked();
        out.cooldownMs = cd;
      } else {
        this.quota.noteError();
      }
      this.lastError = { at: Date.now(), reason: out.reason, message: out.error || out.warnings?.join(' ') || '' };
      return { ...out, meta: { ms: Date.now() - t0, provider, cache: false } };
    }

    // 引用の `/goto?url=` 包装を解決 (serp プロバイダのみ)
    const wantResolve = req.resolveCitations ?? this.cfg.resolveWrapped;
    if (wantResolve && out.citations?.some((c) => c.wrapped)) {
      const resolved = await this.#resolveCitations(out.citations, { q, lang, country, req });
      out = { ...out, citations: resolved.citations, warnings: [...(out.warnings || []), ...resolved.warnings] };
    }

    const value = {
      ...out,
      meta: { ...(out.meta || {}), ms: Date.now() - t0, provider, cache: false, at: Date.now() },
    };
    this.quota.noteSuccess();
    this.counters.ok++;
    this.lastOk = { at: Date.now(), q, provider };
    this.#cacheSet(cacheKey, value);
    return value;
  }

  /* ---------------------------------------------------------------- */
  /* provider: serp (自前・パイプライン経由)                            */
  /* ---------------------------------------------------------------- */

  /** AI Mode の接続先 origin (既定 www.google.com)。テストでは local origin を指せる */
  get baseUrl() {
    try {
      return new URL(this.cfg.baseUrl || 'https://www.google.com').origin;
    } catch {
      return 'https://www.google.com';
    }
  }

  async #serpAsk({ q, lang, country, req }) {
    const url = new URL(`${this.baseUrl}/search`);
    url.searchParams.set('q', q);
    url.searchParams.set('udm', '50'); // AI Mode
    if (lang) url.searchParams.set('hl', lang);
    if (country) url.searchParams.set('gl', country.toLowerCase());

    // 出口は問い合わせごとにローテーション (同じ IP の予算を浪費しない)
    const sid = `aimode:${req.sid || req.clientId || 'anon'}:${Date.now().toString(36)}`;
    const base = req.settings || this.engine?.store?.settingsFor(req.clientId) || {};
    const settings = {
      ...base,
      egress: {
        ...(base.egress || {}),
        // 既定は pool = US の出口だけを使う (AI Mode は geo 制限があるので国は譲らない)。
        // 自ホストが US にあるなら auto/direct にすると proxy 不要で高速。
        strategy: this.cfg.egressStrategy,
        country,
        allowFallback: this.cfg.egressAllowFallback,
        protocols: this.config.egress.protocols,
        rotate: 'per-request',
      },
    };

    // 同意ページを避ける SOCS クッキーをジャーへ
    if (this.cfg.consentCookie && this.cookies) {
      try {
        this.cookies.applySetCookies(sid, new URL(`${this.baseUrl}/`), [`${this.cfg.consentCookie}; Path=/; Secure`]);
      } catch {
        /* ジャー注入に失敗しても続行 (同意ページは reason で判別できる) */
      }
    }

    const headers = new Map([
      ['accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'],
      ['accept-language', `${lang},en;q=0.8`],
      ['cache-control', 'no-cache'],
      ['upgrade-insecure-requests', '1'],
    ]);

    const res = await this.pipeline.execute({
      sid,
      clientId: req.clientId,
      settings,
      method: 'GET',
      url: url.href,
      headers,
      mode: 'aimode',
      dest: 'document',
      kind: 'document',
      raw: true, // 改写せず生 HTML が欲しい
    });

    const html = Buffer.isBuffer(res.body) ? res.body.toString('utf8') : '';
    const info = res.info || {};
    if (res.status >= 400) {
      // パイプライン自身のエラーページ (出口枯渇 etc.) — aimc はないので理由を汲む
      return {
        ok: false,
        reason: `upstream_${res.status}`,
        error: upstreamErrorText(html),
        meta: { status: res.status, egress: info.egressLabel || 'direct', egressCountry: info.egressCountry || null },
      };
    }
    const finalUrl = res.headers?.get?.('x-mirage-final-url');
    const parsed = extractAiMode(html, this.extractOptions());
    return {
      ...parsed,
      ...(req.debug ? { __html: html.slice(0, 2_000_000) } : {}),
      meta: {
        status: res.status,
        egress: info.egressLabel || 'direct',
        egressCountry: info.egressCountry || null,
        egressProxy: info.egressProxy || null,
        upstreamMs: info.upstreamMs ?? null,
        url: url.href,
        finalUrl: finalUrl ? decodeURIComponent(finalUrl) : null,
      },
    };
  }

  /* ---------------------------------------------------------------- */
  /* provider: relay (外部ブラウザリレー)                               */
  /* ---------------------------------------------------------------- */

  async #relayAsk({ q, lang, country, req }) {
    const base = String(this.cfg.relayUrl || '').replace(/\/+$/, '');
    if (!base) return { ok: false, reason: 'relay_not_configured', error: 'MIRAGE_AIMODE_RELAY_URL が未設定です' };
    const headers = { 'content-type': 'application/json' };
    if (this.cfg.relayKey) headers.authorization = `Bearer ${this.cfg.relayKey}`;
    const timeout = this.cfg.relayTimeoutMs;

    // 1) リッチな契約: POST {base}/v1/query → {answer, citations[], sources[], follow_ups[]}
    //    (当方の thin contract。TurkerYakup/google-ai-mode-api 等がこの形)
    try {
      const res = await fetch(`${base}/v1/query`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ q, prompt: q, lang, country, include_html: false }),
        signal: AbortSignal.timeout(timeout),
      });
      if (res.status !== 404 && res.status !== 405) {
        const text = await res.text();
        let json = null;
        try {
          json = JSON.parse(text);
        } catch {
          return { ok: false, reason: 'relay_bad_response', error: `relay が JSON を返しませんでした (${res.status})`, raw: text.slice(0, 300) };
        }
        if (!res.ok || json.ok === false) {
          return { ok: false, reason: json.reason || `relay_http_${res.status}`, error: json.error || json.detail || text.slice(0, 300) };
        }
        return normalizeProviderResult(json, 'relay');
      }
    } catch (err) {
      if (err?.name !== 'AbortError' && err?.name !== 'TimeoutError') {
        ns.debug(() => `relay /v1/query 失敗: ${err.message}`);
      }
    }

    // 2) OpenAI 互換にフォールバック: POST {base}/v1/chat/completions
    //    (引用は取れないので warnings に残す)
    try {
      const res = await fetch(`${base}/v1/chat/completions`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          model: 'google-ai-mode',
          messages: [{ role: 'user', content: q }],
          stream: false,
        }),
        signal: AbortSignal.timeout(timeout),
      });
      const json = await res.json().catch(() => null);
      if (!res.ok || !json) {
        return { ok: false, reason: `relay_http_${res.status}`, error: json?.error?.message || 'relay が失敗しました' };
      }
      const content = json?.choices?.[0]?.message?.content;
      if (!content) return { ok: false, reason: 'no_answer', error: 'relay が回答を返しませんでした' };
      const out = normalizeProviderResult({ answer: String(content), confidence: 0.7 }, 'relay');
      out.warnings.push('relay は OpenAI 互換で応答したため citations/sources は空です (/v1/query に対応した relay だと richer)');
      return out;
    } catch (err) {
      return { ok: false, reason: 'relay_unreachable', error: String(err?.message || err).slice(0, 300) };
    }
  }

  /* ---------------------------------------------------------------- */
  /* provider: serpapi (有料)                                          */
  /* ---------------------------------------------------------------- */

  async #serpApiAsk({ q, lang, country, req }) {
    const key = this.cfg.serpApiKey;
    if (!key) return { ok: false, reason: 'serpapi_not_configured', error: 'MIRAGE_SERPAPI_KEY が未設定です' };
    const url = new URL('https://serpapi.com/search.json');
    url.searchParams.set('engine', 'google_ai_mode');
    url.searchParams.set('q', q);
    url.searchParams.set('api_key', key);
    url.searchParams.set('hl', lang || 'en');
    url.searchParams.set('gl', (country || 'us').toLowerCase());
    const res = await fetch(url.href, { signal: AbortSignal.timeout(this.cfg.relayTimeoutMs) });
    const json = await res.json().catch(() => null);
    if (!res.ok || !json) {
      return { ok: false, reason: `serpapi_http_${res.status}`, error: json?.error || 'SerpApi が失敗しました' };
    }
    return normalizeProviderResult(json, 'serpapi');
  }

  /* ---------------------------------------------------------------- */
  /* /goto?url= の解決                                                 */
  /* ---------------------------------------------------------------- */

  async #resolveCitations(citations, { country, req }) {
    const warnings = [];
    const out = [];
    const todo = citations.filter((c) => c.wrapped && c.rawHref);
    const limit = Math.min(todo.length, this.cfg.maxResolveCitations);
    for (let i = 0; i < limit; i++) {
      const c = todo[i];
      try {
        const sid = `aimode:resolve:${Date.now().toString(36)}:${i}`;
        const settings = {
          ...(req.settings || {}),
          egress: { strategy: 'pool', country, allowFallback: true, protocols: this.config.egress.protocols, rotate: 'per-request' },
        };
        const res = await this.pipeline.execute({
          sid,
          settings,
          method: 'GET',
          url: new URL(c.rawHref, `${this.baseUrl}/`).href,
          headers: new Map([['accept', '*/*']]),
          mode: 'aimode',
          dest: 'empty',
          kind: 'asset',
          raw: true,
        });
        const finalUrl = res.headers?.get?.('x-mirage-final-url');
        const href = finalUrl ? decodeURIComponent(finalUrl) : null;
        if (href && /^https?:\/\//.test(href) && !/^https?:\/\/(www\.)?google\./.test(href)) {
          const host = new URL(href).hostname;
          out.push({ ...c, url: href, host, domain: host.replace(/^www\./, ''), wrapped: false });
          continue;
        }
        warnings.push(`引用 ${i + 1} は解決できませんでした (Google の署名付きリダイレクト)`);
        out.push(c);
      } catch (err) {
        warnings.push(`引用 ${i + 1} の解決でエラー: ${String(err?.message || err).slice(0, 80)}`);
        out.push(c);
      }
    }
    // 解決しなかった残りも順番を保って戻す
    const rest = citations.filter((c) => !todo.includes(c));
    const merged = [...rest, ...out];
    return { citations: merged.map((c, i) => ({ index: i + 1, ...c })), warnings };
  }

  /* ---------------------------------------------------------------- */
  /* cache / status                                                    */
  /* ---------------------------------------------------------------- */

  #cacheKey(q) {
    return q;
  }

  #cacheGet(key) {
    const hit = this.cache.get(key);
    if (!hit) return null;
    if (Date.now() - hit.at > this.cfg.cacheTtlMs) {
      this.cache.delete(key);
      return null;
    }
    return hit.value;
  }

  #cacheSet(key, value) {
    if (this.cfg.cacheTtlMs <= 0) return;
    this.cache.set(key, { at: Date.now(), value });
    while (this.cache.size > this.cfg.cacheMax) {
      const first = this.cache.keys().next().value;
      this.cache.delete(first);
    }
  }

  clearCache() {
    const n = this.cache.size;
    this.cache.clear();
    return n;
  }

  status() {
    return {
      enabled: this.enabled,
      provider: this.cfg.provider,
      country: this.cfg.country,
      lang: this.cfg.lang,
      relayConfigured: !!this.cfg.relayUrl,
      serpApiConfigured: !!this.cfg.serpApiKey,
      quota: this.quota.stats(),
      cache: { size: this.cache.size, ttlMs: this.cfg.cacheTtlMs },
      counters: this.counters,
      lastOk: this.lastOk,
      lastError: this.lastError,
    };
  }
}

/**
 * 外部プロバイダ (relay / SerpApi) の JSON を共通形に正規化する。
 * SerpApi の google_ai_mode は text_blocks / references / related_questions、
 * 参考リレーは answer / citations / sources / follow_ups を返す。
 */
export function normalizeProviderResult(json, provider) {
  const warnings = [];
  let answer = '';
  const citations = [];
  const sources = [];
  const followUps = [];

  if (typeof json.answer === 'string' && json.answer.trim()) {
    answer = json.answer.trim();
  } else if (Array.isArray(json.text_blocks)) {
    // SerpApi: [{type:'paragraph'|'list'|'heading', text/snippet, reference_indexes[]}]
    for (const b of json.text_blocks) {
      if (!b) continue;
      const t = String(b.text || b.snippet || '').trim();
      if (!t) continue;
      if (b.type === 'heading') answer += `${answer ? '\n\n' : ''}## ${t}`;
      else if (b.type === 'list') answer += `${answer ? '\n\n' : ''}- ${t}`;
      else answer += `${answer ? '\n\n' : ''}${t}`;
    }
  } else if (typeof json.text === 'string') {
    answer = json.text.trim();
  } else if (typeof json.markdown === 'string') {
    answer = json.markdown.trim();
  }

  for (const r of Array.isArray(json.references) ? json.references : Array.isArray(json.citations) ? json.citations : []) {
    if (!r) continue;
    const url = r.link || r.url || r.href;
    if (!url) continue;
    let host = null;
    try {
      host = new URL(url).hostname;
    } catch {
      continue;
    }
    citations.push({ url, host, domain: host.replace(/^www\./, ''), title: String(r.title || r.snippet || '').slice(0, 300), wrapped: false });
  }
  for (const s of Array.isArray(json.sources) ? json.sources : []) {
    if (!s?.url) continue;
    sources.push({
      url: s.url,
      domain: s.domain || (() => {
        try {
          return new URL(s.url).hostname.replace(/^www\./, '');
        } catch {
          return null;
        }
      })(),
      title: String(s.title || '').slice(0, 300),
      source: String(s.source || '').slice(0, 120),
      date: String(s.date || '').slice(0, 40),
      snippet: String(s.snippet || '').slice(0, 600),
    });
  }
  for (const f of Array.isArray(json.related_questions) ? json.related_questions : Array.isArray(json.follow_ups) ? json.follow_ups : []) {
    const t = typeof f === 'string' ? f : f?.question || f?.text;
    if (t && String(t).trim()) followUps.push(String(t).trim().slice(0, 160));
  }

  if (!answer) {
    return { ok: false, reason: 'no_answer', error: 'プロバイダが回答を返しませんでした', warnings, provider };
  }
  if (provider === 'relay' && json.confidence == null) warnings.push('relay が confidence を返しませんでした');
  return {
    ok: true,
    answer,
    text: answer.replace(/^#+\s*/gm, '').replace(/^[-*]\s*/gm, '').replace(/\[([^\]]+)\]\([^)]*\)/g, '$1'),
    citations: citations.map((c, i) => ({ index: i + 1, ...c })),
    sources,
    followUps,
    confidence: typeof json.confidence === 'number' ? json.confidence : 0.7,
    warnings,
    provider,
    usage: json.usage || null,
  };
}

/** パイプラインのエラーページから人間向けの 1 行を抜く */
function upstreamErrorText(html) {
  const src = String(html || '');
  const m = /<div class="m"[^>]*>([\s\S]*?)<\/div>/i.exec(src);
  const raw = m ? m[1] : src.slice(0, 400);
  return raw
    .replace(/<[^>]+>/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 240) || '上流エラー';
}

export default AiModeClient;
