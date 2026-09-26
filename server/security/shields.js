/**
 * MirageVPN シールド (Brave 風の広告/トラッカー ブロッカー)
 * ---------------------------------------------------------------
 * Adblock Plus / EasyList 構文の部分実装をサーバ側に持つ。
 *  - ネットワーク規則: `||host^`, `||host/path$script,domain=x.com`, `@@例外`, `$important`
 *  - 高速経路: プレーンなホスト規則は「ドメイン suffix を辿って Set  lookup」だけ (正規表現不使用)
 *  - カSMETIC 規則: `##.ad` 等は「ネイティブ CSS 文字列」としてページに注入 (`:has()` はブラウザが処理)
 *  - 起動は同梱シード、以降は GitHub から自動更新 (uBlockOrigin/uAssets 等)
 *  - 「サイトごと OFF」「自動で緩める (unbreakable)」を内蔵 → ブロックしすぎて壊れる事故対策
 * @module security/shields
 */

import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { LRU, escapeRe, registrableDomain } from '../util.js';
import { log } from '../log.js';

const ns = log.child('shields');
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

const TYPES = new Map([
  ['script', 'script'],
  ['image', 'image'],
  ['css', 'stylesheet'],
  ['stylesheet', 'stylesheet'],
  ['font', 'font'],
  ['media', 'media'],
  ['xhr', 'xhr'],
  ['xmlhttprequest', 'xhr'],
  ['frame', 'subdocument'],
  ['subdocument', 'subdocument'],
  ['iframe', 'subdocument'],
  ['doc', 'document'],
  ['document', 'document'],
  ['ping', 'ping'],
  ['beacon', 'ping'],
  ['websocket', 'websocket'],
  ['object', 'object'],
  ['other', 'other'],
  ['elemhide', 'elemhide'],
  ['hiding', 'hiding'],
  ['inline-script', 'inlinescript'],
  ['popunder', 'popunder'],
  ['popup', 'popup'],
]);

const OPTION_ALIAS = new Map([
  ['3p', 'third-party'],
  ['third-party', 'third-party'],
  ['1p', 'first-party'],
  ['first-party', 'first-party'],
  ['strict1p', 'first-party'],
  ['match-case', 'match-case'],
  ['important', 'important'],
  ['badfilter', 'badfilter'],
  ['all', 'all'],
  ['~third-party', '~third-party'],
  ['~first-party', '~first-party'],
  ['~script', '~script'],
  ['generichide', 'generichide'],
  ['specifichide', 'specifichide'],
  ['elemhide', 'elemhide'],
  ['image', 'image'],
  ['other', 'other'],
  ['permissions', 'ignore'],
  ['queryfilter', 'ignore'],
  ['removeparam', 'ignore'],
  ['domain', 'domain'],
  ['denyallow', 'denyallow'],
  ['redirect', 'redirect'],
  ['redirect-rule', 'redirect'],
  ['csp', 'ignore'],
  ['replace', 'replace'],
  ['method', 'method'],
  ['to', 'ignore'],
  ['from', 'ignore'],
  ['urlbase64', 'ignore'],
  ['bag', 'ignore'],
  ['name', 'ignore'],
  ['type', 'type'],
]);

/** カテゴリー分類 (UI の内訳表示用) */
const CATEGORY_PATTERNS = [
  [/(^|\.)doubleclick\.net$|googlesyndication|googleadservices|adsystem|adservice|adnxs|taboola|outbrain|criteo|openx|rubiconproject|pubmatic|contextweb|smartadserver|amazon-adsystem/i, 'ads'],
  [/google-analytics|googletagmanager|analytics|segment\.(io|com)|mixpanel|amplitude|matomo|piwik|hotjar|fullstory|crazyegg|chartbeat|scorecardresearch|quantserve/i, 'analytics'],
  [/facebook\.|fb\.com|twitter|x\.com|linkedin|instagram|tiktok|snapchat|pinterest|reddit\.com\/ads|disqus|addthis|sharethis|plus\.google/i, 'social'],
  [/scorecardresearch|bluekai|exelator|innovid|adsafeprotected|integralme|doubleverify|moatads|sizmek|flashtalking|teads/i, 'ads'],
  [/(phishing|malware|badware|fraud|scam|cryptonot|miner)/i, 'malware'],
  [/tpc|cookie|consent|onetrust|quantcast|didomi|cdn-cgi\/performance/i, 'privacy'],
];

export class Shields {
  /** @param {import('../config.js').Config} config */
  constructor(config) {
    this.config = config;
    this.enabled = config.shields.enabled;
    this.level = config.shields.privacyLevel;
    /** host → Rule[]  (ネットワーク規則の高速経路) */
    this.hostRules = new Map();
    /** 修飾子なしの単純ブロックホスト (最速 path) */
    this.blockHosts = new Set();
    /** 例外のみのホスト */
    this.allowHosts = new Set();
    /** 完全正規表現ルール */
    this.regexRules = [];
    /** キーワード (|| なし) ルール */
    this.keyRules = [];
    /** cosmetic: domain key → selector[] */
    this.cosmeticByDomain = new Map();
    this.cosmeticGeneric = [];
    this.cosmeticExceptions = new Set();
    this.cssCache = new LRU(4000, 10 * 60 * 1000);
    this.decisionCache = new LRU(20000, 2 * 60 * 1000);
    this.domains = new Set(); // ブロック対象ホスト (サマリ表示用)
    this.categoryOf = new Map();
    this.disabledFor = new Set();
    this.autoRelaxed = new Map(); // 実ドメイン → 期限
    this.stats = {
      rules: 0,
      parsed: 0,
      skipped: 0,
      cosmetic: 0,
      blocked: 0,
      allowed: 0,
      byCategory: { ads: 0, analytics: 0, social: 0, malware: 0, privacy: 0, other: 0 },
      byType: {},
      topHosts: new Map(),
      since: Date.now(),
      lastUpdate: 0,
      sources: [],
    };
    this.recentBlocks = []; // {at, sid, url, rule, type, category}
  }

  /* ------------------------------------------------------------------ */
  /* ロード                                                             */
  /* ------------------------------------------------------------------ */

  /**
   * 同梱シードをロードする。
   *  - `seedFile`  : uAssets + EasyList から生成した大きい方 (network + cosmetic)
   *  - `hostsSeed` : どのリストも引けないときのための hard-block 層 (||host^ のみ)
   * ファイルが無いほうは黙ってスキップする (デプロイで data/ を除外した場合も動く)。
   */
  async loadSeed() {
    const rels = [this.config.shields.seedFile, this.config.shields.hostsSeed].filter(Boolean);
    const total = { rules: 0, cosmetic: 0, files: 0 };
    for (const rel of rels) {
      const file = path.join(ROOT, rel);
      try {
        const text = await readFile(file, 'utf8');
        const r = this.parse(text, { source: `seed:${rel}` });
        total.rules += r.rules;
        total.cosmetic += r.cosmetic;
        total.files++;
        ns.info(`シード読込 ${rel}: rules=${r.rules} cosmetic=${r.cosmetic}`);
      } catch (err) {
        if (err?.code === 'ENOENT') continue;
        ns.warn(`シードが読み込めません (${rel}): ${err.message}`);
      }
    }
    if (!total.files) ns.warn('同梱シードが見つかりません — ブロックは既定リストなしで起動します');
    return total;
  }

  /**
   * テキスト (ABP リスト) をパースして索引を作る。
   * @param {string} text
   * @param {{source?:string, chunkSize?:number, awaitIdle?:boolean}} [opts]
   */
  parse(text, { source = 'inline', chunkSize = 4096 } = {}) {
    const t0 = Date.now();
    let rules = 0;
    let cosmetic = 0;
    let skipped = 0;
    const lines = String(text).split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line || line.startsWith('!') || line.startsWith('[')) continue;
      if (line.startsWith('#')) {
        // `##sel` / `#@#sel` / `#$#css` のように先頭が cosmetic マーカーの行は「注釈」ではない
        // (uAssets ではドメイン指定なしの汎用則が最頻出なので、ここで落とすと機能が半分以上死んだことになる)。
        if (!COSMETIC_LEADING.test(line) && !line.includes('##')) continue;
      }
      const res = this.#addLine(line, source);
      if (res === 'rule') rules++;
      else if (res === 'cosmetic') cosmetic++;
      else skipped++;
    }
    this.stats.rules += rules;
    this.stats.cosmetic += cosmetic;
    this.stats.skipped += skipped;
    this.stats.parsed += lines.length;
    this.stats.lastUpdate = Date.now();
    this.stats.sources.push({ source, at: Date.now(), rules, cosmetic, ms: Date.now() - t0 });
    this.decisionCache.clear();
    this.cssCache.clear();
    return { rules, cosmetic, skipped, ms: Date.now() - t0 };
  }

  /**
   * ホスト高速経路 (blockHosts/allowHosts) を上書きする「より具体的な規則」を探す。
   * @param {string} label
   * @param {URL} url
   * @param {{type:string, thirdParty:boolean, sourceUrl:URL|null, method?:string}} m
   * @param {{wantException:boolean, onlyImportant?:boolean}} want
   */
  #overrideRule(label, url, m, want) {
    const arr = this.hostRules.get(label);
    if (!arr || !arr.length) return null;
    const href = url.href.toLowerCase();
    for (const r of arr) {
      if (!!r.exception !== want.wantException) continue;
      if (want.onlyImportant && !r.important) continue;
      if (r.re && !r.re.test(url.href)) continue;
      if (!r.re && r.needle && !href.includes(r.needle)) continue;
      if (!this.#optionsMatch(r, m)) continue;
      return r;
    }
    return null;
  }

  #addLine(line, source) {
    // ---------------- cosmetic 規則 ----------------
    const markerMatch = /(#\$\$#|#@#\$\$#|#\+\$#|##\+js|##|#@#)/.exec(line);
    // index 0 もある (ドメイン指定なしの汎用則 `##.ad` は uAssets で最頻出)。
    // ただし `||x.com/##` のような网络則を食わないように、前段がドメインリストに見えるかだけ確認する。
    const domPartLooksHosty = (d) => d === '' || (/^[a-z0-9.,*^|\-_~]+$/i.test(d) && !d.includes('//'));
    if (markerMatch && domPartLooksHosty(line.slice(0, markerMatch.index))) {
      const marker = markerMatch[0];
      const domPart = line.slice(0, markerMatch.index);
      const sel = line.slice(markerMatch.index + marker.length).trim();
      if (!sel) return null;
      const isExcept = marker.includes('@');
      const isProceduralStyle = marker === '#$#' || marker === '#@#$#';
      const domains = domPart.split(',').map((d) => d.trim()).filter(Boolean);
      if (!domains.length) domains.push('*'); // 汎用則 (全ページ対象)
      let applied = 0;
      for (const d of domains) {
        const key = d
          .replace(/^\^/, '')
          .replace(/[^a-z0-9.\-*]/gi, '')
          .toLowerCase();
        if (!key) continue;
        if (isExcept) {
          this.cosmeticExceptions.add(`${key}|${sel}`);
          applied++;
          continue;
        }
        const arr = this.cosmeticByDomain.get(key) || [];
        arr.push({ selector: isProceduralStyle && !sel.startsWith(':') ? sel : sel, source });
        this.cosmeticByDomain.set(key, arr);
        applied++;
      }
      return applied ? 'cosmetic' : null;
    }

    // ---------------- network 規則 ----------------
    const dollar = findOptionsSeparator(line);
    const pattern = dollar === -1 ? line : line.slice(0, dollar);
    const optionStr = dollar === -1 ? '' : line.slice(dollar + 1);
    const exception = pattern.startsWith('@@');
    const pat = exception ? pattern.slice(2) : pattern;
    if (!pat || pat === '/' || pat.length < 3) return null;
    if (pat.startsWith('##') || pat.startsWith('#')) return null;

    const opts = parseOptions(optionStr);
    if (opts.badfilter || opts.ignoreOnly) return null;
    // uBO 系の「例外 + $redirect=」は、リダイレクトを実装しない本実装では例外として扱わない
    if (exception && opts.redirect) return null;
    const typeKeys = Object.keys(opts).filter((k) => TYPES.has(k) || k.startsWith('~'));
    const hasDomain = typeof opts.domain === 'string' && opts.domain.length > 0;

    // `||host` のリテラルを取り出してバケットに置く (uBlock と同じ発想。正規表現総当りを避ける)
    const hostLit = /\|\|([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)\.([a-z]{2,})/i.exec(pat);
    const bucketHost = hostLit ? hostLit[0].slice(2).toLowerCase() : null;
    const pureHost = bucketHost ? new RegExp(`^\\|\\|${escapeRe(bucketHost)}\\^?$`, 'i').test(pat) : false;

    // ホスト単位の高速経路に入れるのは「条件なしのホスト丸ごとブロック/例外」だけ。
    // $script や $domain が付いた規則をここに入れると、画像やドキュメントまで道連れにして
    // サイトを壊す (uBlock はここでも type/domain を評価する) ので、条件付きは一般経路に落とす。
    const ignorable = new Set(['name', 'tags', 'ext', 'csp']);
    const realOpts = Object.keys(opts).filter((k) => !ignorable.has(k));
    const unconditional = realOpts.length === 0 || (realOpts.length === 1 && realOpts[0] === 'important');
    if (pureHost && unconditional) {
      if (exception) this.allowHosts.add(bucketHost);
      else {
        this.blockHosts.add(bucketHost);
        this.domains.add(bucketHost);
        this.categoryOf.set(bucketHost, categorize(bucketHost));
      }
      return 'rule';
    }

    let rule = null;
    const needsRegex = /[*^\[\](){}+?|]/.test(pat);
    if (needsRegex) {
      rule = this.#compileRegex(pat, opts, exception, line, source);
    } else {
      const literal = pat.replace(/^\|/, '').replace(/\|$/, '');
      if (literal.length < 4) return null;
      rule = { needle: literal.toLowerCase(), anchoredStart: pat.startsWith('|') };
    }
    if (!rule) return null;

    Object.assign(rule, {
      raw: line,
      exception,
      options: opts,
      typeKeys,
      domains: hasDomain
        ? String(opts.domain)
            .split(',')
            .map((s) => s.trim().toLowerCase())
            .filter(Boolean)
        : null,
      important: !!opts.important,
      source,
      host: bucketHost || null,
    });

    if (bucketHost) {
      if (!exception) this.domains.add(bucketHost);
      this.categoryOf.set(bucketHost, categorize(bucketHost));
      const arr = this.hostRules.get(bucketHost) || [];
      arr.push(rule);
      this.hostRules.set(bucketHost, arr);
      return 'rule';
    }
    if (rule.needle && rule.needle.length >= 8) {
      this.keyRules.push(rule);
      return 'rule';
    }
    if (rule) this.regexRules.push(rule);
    return rule ? 'rule' : null;
  }

  #compileRegex(pattern, opts, exception, raw, source) {
    try {
      const re = new RegExp(abpToRegex(pattern), 'i');
      // 正規表現を回す前の安い前段フィルタ: pattern 先頭のリテラル部分
      const pre = literalPrefix(pattern);
      return {
        pre,
        raw,
        re,
        exception,
        options: opts,
        typeKeys: Object.keys(opts).filter((k) => TYPES.has(k)),
        domains: opts.domain ? String(opts.domain).split(',').map((s) => s.trim().toLowerCase()) : null,
        important: !!opts.important,
        source,
      };
    } catch {
      return null;
    }
  }

  /* ------------------------------------------------------------------ */
  /* マッチング                                                          */
  /* ------------------------------------------------------------------ */

  /**
   * @param {string} rawUrl
   * @param {{type?:string, sourceUrl?:string, sid?:string, method?:string, documentUrl?:string}} [ctx]
   * @returns {{blocked:boolean, reason?:string, rule?:string, category?:string}}
   */
  match(rawUrl, ctx = {}) {
    if (!this.enabled || this.level === 'off' || ctx.type === 'websocket-allow') return { blocked: false };
    let url;
    try {
      url = new URL(rawUrl);
    } catch {
      return { blocked: false };
    }
    const type = TYPES.get(ctx.type || 'other') || 'other';
    const sourceUrl = ctx.sourceUrl ? safeUrl(ctx.sourceUrl) : null;
    const thirdParty = sourceUrl ? registrableDomain(sourceUrl.hostname) !== registrableDomain(url.hostname) : false;
    const siteKey = registrableDomain(sourceUrl?.hostname || url.hostname);
    if (this.disabledFor.has(siteKey) || (this.autoRelaxed.get(siteKey) || 0) > Date.now()) return { blocked: false };

    const hrefLower = url.href.toLowerCase();
    const cacheKey = `${type}|${thirdParty ? 1 : 0}|${rawUrl}`;
    const cached = this.decisionCache.get(cacheKey);
    if (cached) {
      if (cached.blocked) this.#count(cached, ctx);
      return cached;
    }

    const host = url.hostname.toLowerCase();
    let decision = { blocked: false };
    let importantHit = null;

    // 1) 高速: ブロックホスト (subdomain 含む)
    for (const label of domainChain(host)) {
      if (this.allowHosts.has(label)) {
        // ホスト単位の例外より具体的な $important 規則があれば、それが勝つ (uBlock と同じ優先順位)
        const over = this.#overrideRule(label, url, { type, thirdParty, sourceUrl, method: ctx.method }, { wantException: false, onlyImportant: true });
        decision = over
          ? { blocked: true, rule: over.raw, category: this.categoryOf.get(label) || 'other', host: label }
          : { blocked: false, rule: `@@||${label}^`, fast: true };
        break;
      }
      if (this.blockHosts.has(label)) {
        // ホスト単体ブロックでも、パス付き例外規則 (@@||host/p) が合致すれば通す
        const over = this.#overrideRule(label, url, { type, thirdParty, sourceUrl, method: ctx.method }, { wantException: true });
        decision = over
          ? { blocked: false, rule: over.raw }
          : { blocked: true, rule: `||${label}^`, category: this.categoryOf.get(label) || 'other', host: label, fast: true };
        break;
      }
      const arr = this.hostRules.get(label);
      if (arr) {
        for (const r of arr) {
          if (r.re && !r.re.test(url.href)) continue;
          if (!r.re && r.needle && !url.href.toLowerCase().includes(r.needle)) continue;
          if (!this.#optionsMatch(r, { type, thirdParty, sourceUrl, url, method: ctx.method })) continue;
          if (r.exception) {
            decision = { blocked: false, rule: r.raw };
            importantHit = null;
            break;
          }
          const cand = { blocked: true, rule: r.raw, category: this.categoryOf.get(label) || 'other', host: label };
          if (r.important) {
            importantHit = cand;
            break;
          }
          if (!decision.blocked) decision = cand;
        }
        if (importantHit) break;
      }
      if (decision.blocked || decision.fast) break;
    }

    // 2) 正規表現 / キーワード (ドメイン単体ブロックで止められなかったときのみ)
    if (!decision.blocked) {
      const fullLower = hrefLower;
      for (const r of this.regexRules) {
        if (!r) continue;
        if (r.pre && !fullLower.includes(r.pre)) continue; // 安価な前置判定
        if (r.re ? !r.re.test(url.href) : !fullLower.includes(r.needle || '')) continue;
        if (!this.#optionsMatch(r, { type, thirdParty, sourceUrl, url, method: ctx.method })) continue;
        decision = r.exception
          ? { blocked: false, rule: r.raw }
          : { blocked: true, rule: r.raw, category: this.categoryOf.get(label) || categorize(host), host: registrableDomain(url.hostname) };
        if (!r.exception) break;
      }
    }
    if (!decision.blocked && this.keyRules.length) {
      const full = hrefLower;
      for (const r of this.keyRules) {
        if (!full.includes(r.needle)) continue;
        if (r.anchoredStart && !full.startsWith(r.needle)) continue; // `|` は URL 先頭 anchor
        if (!this.#optionsMatch(r, { type, thirdParty, sourceUrl, url, method: ctx.method })) continue;
        decision = r.exception
          ? { blocked: false, rule: r.raw }
          : { blocked: true, rule: r.raw, category: this.categoryOf.get(label) || categorize(host), host: registrableDomain(url.hostname) };
        if (!r.exception) break;
      }
    }

    // aggressive レベルでは、第 3者スクリプト/beacon をもう少し強めに止める
    if (!decision.blocked && this.level === 'aggressive' && thirdParty) {
      if ((type === 'ping' || (type === 'xhr' && /collect|beat|log|track|event/i.test(url.pathname))) && !ctx.allowThirdParty) {
        decision = { blocked: true, rule: 'mirage:aggressive-3p-beacon', category: 'privacy', host: registrableDomain(url.hostname) };
      }
    }

    this.decisionCache.set(cacheKey, decision);
    if (decision.blocked) this.#count(decision, ctx);
    return decision;
  }

  #count(decision, ctx) {
    this.stats.blocked++;
    const cat = decision.category || 'other';
    this.stats.byCategory[cat] = (this.stats.byCategory[cat] || 0) + 1;
    this.stats.byType[decision.type || 'unknown'] = (this.stats.byType[decision.type || 'unknown'] || 0) + 1;
    const host = decision.host || 'unknown';
    this.stats.topHosts.set(host, (this.stats.topHosts.get(host) || 0) + 1);
    if (this.stats.topHosts.size > 80) {
      const sorted = [...this.stats.topHosts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 40);
      this.stats.topHosts = new Map(sorted);
    }
    this.recentBlocks.push({ at: Date.now(), sid: ctx.sid, url: decision.host, rule: decision.rule, category: cat });
    if (this.recentBlocks.length > 300) this.recentBlocks.shift();
  }

  #optionsMatch(rule, { type, thirdParty, sourceUrl, url, method }) {
    const o = rule.options || {};
    if (rule.domains?.length) {
      const base = sourceUrl ? sourceUrl.hostname.toLowerCase() : '';
      const reg = registrableDomain(base) || '';
      let ok = false;
      for (const d of rule.domains) {
        if (d.startsWith('~')) {
          if (!base.endsWith(d.slice(1)) && reg !== d.slice(1)) ok = true;
        } else if (base === d || base.endsWith(`.${d}`) || reg === d) ok = true;
      }
      if (!ok) return false;
    }
    if (o['third-party'] && !thirdParty) return false;
    if (o['first-party'] && thirdParty) return false;
    if (o['~third-party'] && thirdParty) return false;
    if (o['~first-party'] && !thirdParty) return false;
    if (o.method && method) {
      const allowed = String(o.method).split(',').map((s) => s.trim().toUpperCase());
      if (allowed.length && !allowed.includes(method.toUpperCase())) return false;
    }
    if (o['denyallow']) return true; // 簡略化: 無視 (誤ブロック回避のため)
    const typeKeys = rule.typeKeys?.length ? rule.typeKeys : null;
    if (!typeKeys) return true;
    if (typeKeys.includes('all')) return true;
    const negations = typeKeys.filter((k) => k.startsWith('~')).map((k) => TYPES.get(k.slice(1)) || k.slice(1));
    const positives = typeKeys.filter((k) => !k.startsWith('~')).map((k) => TYPES.get(k)).filter(Boolean);
    if (negations.includes(type)) return false;
    if (!positives.length) return true;
    return positives.includes(type);
  }

  /* ------------------------------------------------------------------ */
  /* cosmetic                                                            */
  /* ------------------------------------------------------------------ */

  /**
   * ページに注入する CSS を返す (ドメインチェーン + 汎用則)
   * @param {string} documentUrl
   * @returns {{css:string, count:number, procedural:number}}
   */
  cosmeticCss(documentUrl) {
    if (!this.enabled || this.config.shields.cosmetic === false || this.level === 'off') return { css: '', count: 0, procedural: 0 };
    let url;
    try {
      url = new URL(documentUrl);
    } catch {
      return { css: '', count: 0, procedural: 0 };
    }
    const host = url.hostname.toLowerCase();
    const cacheKey = host;
    const cached = this.cssCache.get(cacheKey);
    if (cached) return cached;
    const parts = [];
    let count = 0;
    let procedural = 0;
    const generic = this.cosmeticByDomain.get('*');
    if (generic) {
      for (const r of generic) {
        const css = selectorToCss(r.selector);
        if (css === 'procedural') procedural++;
        else if (css) {
          parts.push(css);
          count++;
        }
      }
    }
    for (const label of domainChain(host)) {
      const arr = this.cosmeticByDomain.get(label);
      if (!arr) continue;
      for (const r of arr) {
        if (this.cosmeticExceptions.has(`${label}|${r.selector}`)) continue;
        const css = selectorToCss(r.selector);
        if (css === 'procedural') procedural++;
        else if (css) {
          parts.push(css);
          count++;
        }
      }
    }
    const out = {
      css: parts.length ? `${parts.join('\n')}` : '',
      count,
      procedural,
      injectedAt: Date.now(),
    };
    this.cssCache.set(cacheKey, out);
    return out;
  }

  /* ------------------------------------------------------------------ */
  /* 状態 / 制御                                                          */
  /* ------------------------------------------------------------------ */

  setEnabled(v) {
    this.enabled = !!v;
    this.stats.allowed = 0;
    this.decisionCache.clear();
    return this.enabled;
  }

  setLevel(l) {
    if (['standard', 'aggressive', 'off'].includes(l)) {
      this.level = l;
      if (l === 'off') this.enabled = false;
      else this.enabled = true;
      this.decisionCache.clear();
    }
    return this.level;
  }

  disableFor(domain) {
    this.disabledFor.add(String(domain).toLowerCase());
  }
  enableFor(domain) {
    this.disabledFor.delete(String(domain).toLowerCase());
  }

  /** ページが壊れかけたときの自動緩和 (Unbreakable) */
  noteBlocked(sid, documentUrl) {
    if (!this.config.shields.unbreakable) return false;
    const reg = registrableDomain(safeUrl(documentUrl)?.hostname || '');
    if (!reg) return false;
    const k = `${sid}|${reg}`;
    const cur = (this.__unbreak || (this.__unbreak = new Map())).get(k) || { n: 0, at: Date.now() };
    cur.n++;
    cur.at = Date.now();
    this.__unbreak.set(k, cur);
    if (cur.n >= 14) {
      this.autoRelaxed.set(reg, Date.now() + 1000 * 60 * 60); // 1h
      this.__unbreak.delete(k);
      return true;
    }
    return false;
  }

  relaxState() {
    const now = Date.now();
    for (const [k, until] of this.autoRelaxed) if (until <= now) this.autoRelaxed.delete(k);
    return [...this.autoRelaxed].map(([domain, until]) => ({ domain, until })).sort((a, b) => b.until - a.until);
  }

  unrelax(domain) {
    this.autoRelaxed.delete(String(domain).toLowerCase());
  }

  /* ------------------ クライアント側即止め用の小リスト ------------------ */

  /** 既知のトラッカー接尾辞 (core.js に渡してブラウザ側でも即ブロックするための優先順位付け) */
  static HOT_SUFFIXES = new Set([
    'doubleclick.net', 'googlesyndication.com', 'googleadservices.com', 'google-analytics.com',
    'adservice.google.com', 'googletagmanager.com', 'googletagservices.com', 'adnxs.com',
    'facebook.net', 'facebook.com', 'scorecardresearch.com', 'quantserve.com', 'amazon-adsystem.com',
    'criteo.com', 'criteo.net', 'outbrain.com', 'taboola.com', 'rubiconproject.com', 'pubmatic.com',
    'openx.net', 'casalemedia.com', 'indexww.com', 'moatads.com', 'adsafeprotected.com', 'chartbeat.com',
    'hotjar.com', 'mixpanel.com', 'segment.io', 'amplitude.com', 'fullstory.com', 'mouseflow.com',
    'doubleverify.com', 'adsrvr.org', 'invocacdn.com', 'nr-data.net', 'newrelic.com', 'branch.io',
    'appsflyer.com', 'adjust.com', 'app-measurement.com', 'firebase-settings.crashlytics.com',
  ]);

  /**
   * 「いまこのプロセスでよく止めているホスト」上位 n 件。
   * ヒット履歴が無い段階では既知トラッカー → 規則ホストの順で埋める (クライアントはこれで十分)。
   */
  topBlockedHosts(n = 300, { ttlMs = 60000 } = {}) {
    const now = Date.now();
    if (this.__topCache && this.__topCacheAt && now - this.__topCacheAt < ttlMs) return this.__topCache.slice(0, n);
    const counts = this.stats.topHosts;
    const seen = new Set();
    const out = [];
    for (const [host, c] of [...counts.entries()].sort((a, b) => b[1] - a[1])) {
      if (out.length >= n) break;
      if (seen.has(host)) continue;
      seen.add(host);
      out.push(host);
    }
    if (out.length < n) {
      for (const h of Shields.HOT_SUFFIXES) {
        if (out.length >= n) break;
        if (seen.has(h) || !this.blockHosts.has(h)) continue;
        seen.add(h);
        out.push(h);
      }
    }
    if (out.length < n) {
      for (const h of this.blockHosts) {
        if (out.length >= n * 2) break;
        if (seen.has(h)) continue;
        seen.add(h);
        out.push(h);
      }
    }
    this.__topCache = out;
    this.__topCacheAt = now;
    return out.slice(0, n);
  }

  /** ブロック規則を registrable domain 単位でまとめ、上位 n 件の接尾辞を返す (サブドメイン込みで効く) */
  topSuffixes(n = 160, { ttlMs = 300000 } = {}) {
    const now = Date.now();
    if (this.__sufCache && now - this.__sufCacheAt < ttlMs) return this.__sufCache.slice(0, n);
    const counts = new Map();
    for (const h of this.blockHosts) {
      const host = String(h).replace(/^\*\.?/, '').replace(/\^$/, '');
      if (!host || host.length > 253) continue;
      const parts = host.split('.');
      if (parts.length < 2) continue;
      const reg = parts.slice(-2).join('.');
      counts.set(reg, (counts.get(reg) || 0) + 1 + (Shields.HOT_SUFFIXES.has(reg) ? 1e6 : 0) + Math.min(50, (this.stats.topHosts.get(host) || 0)));
    }
    const out = [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .filter(([reg, c]) => c >= 2 || Shields.HOT_SUFFIXES.has(reg))
      .slice(0, n)
      .map(([reg]) => reg);
    this.__sufCache = out;
    this.__sufCacheAt = now;
    return out;
  }

  summary() {
    const top = [...this.stats.topHosts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 12)
      .map(([host, count]) => ({ host, count, category: this.categoryOf.get(host) || categorize(host) }));
    return {
      enabled: this.enabled,
      level: this.level,
      rules: this.stats.rules,
      cosmeticRules: this.stats.cosmetic,
      blocked: this.stats.blocked,
      byCategory: { ...this.stats.byCategory },
      byType: { ...this.stats.byType },
      topHosts: top,
      domains: this.domains.size,
      decisionCache: this.decisionCache.stats ? this.decisionCache.stats() : { size: this.decisionCache.size },
      lastUpdate: this.stats.lastUpdate,
      sources: this.stats.sources.slice(-8),
      disabledFor: [...this.disabledFor],
      autoRelaxed: this.relaxState(),
    };
  }

  reset() {
    this.stats.blocked = 0;
    this.stats.byCategory = { ads: 0, analytics: 0, social: 0, malware: 0, privacy: 0, other: 0 };
    this.stats.byType = {};
    this.stats.topHosts = new Map();
    this.recentBlocks = [];
  }
}

/* -------------------------------------------------------------------- */
/* helpers                                                              */
/* -------------------------------------------------------------------- */

/** 最初の `,` 区切り选项ブロック (`$`) を探す — `$` が pattern 内部に無い前提で十分正確 */
function findOptionsSeparator(line) {
  const i = line.indexOf('$');
  if (i <= 0) return -1;
  const rest = line.slice(i + 1);
  // 选项部は [a-z~] で始まるはず (`https://x/a$b` のような誤検出を避ける)
  if (!/^[a-z~]/i.test(rest)) return -1;
  return i;
}

/** `||host/*.gif` のような pattern から、URL に必ず含まれる先頭リテラルを取り出す */
function literalPrefix(pattern) {
  let p = pattern.replace(/^\|\|/, '').replace(/^\|/, '').replace(/^@@/, '');
  let out = '';
  for (const ch of p) {
    if ('*^|(){}[]+?'.includes(ch)) break;
    out += ch;
  }
  out = out.toLowerCase().replace(/\\/g, '');
  return out.length >= 6 ? out.slice(0, 24) : null;
}

function safeUrl(s) {
  try {
    return new URL(s);
  } catch {
    return null;
  }
}

function* domainChain(host) {
  const parts = host.split('.');
  for (let i = 0; i < parts.length - 1; i++) yield parts.slice(i).join('.');
}

function parseOptions(str) {
  const out = {};
  if (!str) return out;
  for (const raw of str.split(',')) {
    const part = raw.trim();
    if (!part) continue;
    const eq = part.indexOf('=');
    let key = eq === -1 ? part : part.slice(0, eq);
    const value = eq === -1 ? true : part.slice(eq + 1);
    const neg = key.startsWith('~');
    if (neg) key = key.slice(1);
    const mapped = OPTION_ALIAS.get(key.toLowerCase()) || TYPES.get(key.toLowerCase()) || key.toLowerCase();
    if (mapped === 'ignore') continue;
    if (mapped === 'badfilter') out.badfilter = true;
    else if (mapped === 'domain') out.domain = value;
    else if (mapped === 'denyallow') out.denyallow = value;
    else if (TYPES.has(key.toLowerCase())) out[mapped] = value;
    else if (mapped.startsWith('elemhide') || mapped === 'generichide' || mapped === 'specifichide' || mapped === 'hiding' || mapped === 'inlinescript' || mapped === 'popunder' || mapped === 'ignore') out[mapped] = true;
    else out[(neg ? '~' : '') + mapped] = value;
  }
  if (out.ignoreOnly) return out;
  // 修飾子がすべて理解不能 (removeparam 等) なら、そのルールは適用しない
  const known = ['third-party', 'first-party', 'important', 'domain', 'method', 'redirect', 'replace', 'denyallow', ...TYPES.keys(), 'ignore', 'elemhide', 'generichide', 'specifichide', 'hiding', 'inlinescript', 'popunder', '~third-party', '~first-party'];
  const keys = Object.keys(out).map((k) => k.replace(/^~/, ''));
  if (keys.length && !keys.some((k) => known.includes(k) || TYPES.has(k))) out.ignoreOnly = true;
  return out;
}

/** ABP の pattern を JS RegExp に変換 (* → .*, ^ → 分離子, | → anchor) */
// 先頭に現れうる cosmetic マーカー (ABP/uBO 構文)
const COSMETIC_LEADING = /^#(?:@#|\$\$#|@\$\$#|\+\$#|\?\$#|\+#|\?#|\$#|\+js|\?)/;

export function abpToRegex(pattern) {
  let src = pattern;
  let anchoredStart = false;
  let anchoredEnd = false;
  let domainAnchored = false;
  if (src.startsWith('||')) {
    src = src.slice(2);
    anchoredStart = true;
    domainAnchored = true; // サブドメイン可、ただしラベル境界 (`.` か先頭) で始める
  } else if (src.startsWith('|')) {
    anchoredStart = true;
    src = src.slice(1);
  }
  if (src.endsWith('|')) {
    anchoredEnd = true;
    src = src.slice(0, -1);
  }
  let out = '';
  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    if (ch === '*') {
      if (src[i + 1] === '*') {
        out += '.*';
        i++;
      } else out += '[^/]*?';
    } else if (ch === '^') {
      out += '(?:[/?#\\x00-\\x1f]|$|:)';
    } else if (ch === '.') out += '\\.';
    else if ('+?()[]{}$^\\|/'.includes(ch)) out += `\\${ch}`;
    else out += ch;
  }
  const prefix = anchoredStart
    ? domainAnchored
      ? '^https?:\\/\\/(?:[^/?#]*\\.)?'
      : '^'
    : '^(?:https?:)?\\/\\/[^/?#]*';
  return `${prefix}${out}${anchoredEnd ? '$' : ''}`;
}

function isRegexish(p) {
  return /[*^]|\\\d|\[|\(|\{/.test(p) && !/^\|\|[a-z0-9.\-*\[\]:]+$/i.test(p);
}

/** `##` / `#@#` / `#$#` / `##+js` などの区切りを探す (index of the cosmetic marker) */
function findCosmeticSeparator(line) {
  const m = /(##|#@#|#\$\$|#@#\$\$|#\+\$#|##\+js)/.exec(line);
  if (!m) return -1;
  // 例: `example.com##.ad`  → マーカーの直前がドメイン部
  if (m.index === 0) return -1; // 行頭 ## は無効
  return m.index;
}

/**
 * cosmetic rule を CSS に変換。
 *  - `selector:style(prop:value)` → `selector{prop:value}`
 *  - `:has(...)` はネイティブ CSS に委譲、`:upward()/if()/not()` は除去してカウント
 * @returns {string|'procedural'|''}
 */
export function selectorToCss(sel) {
  if (!sel) return '';
  if (sel.startsWith('#') || sel.startsWith('@')) return '';
  if (/^script:|^iframe:|^a\[(?:^|\s)href=/.test(sel)) {
    // 要素型フィルタは JS 側で対応 (ここでは CSS 化しない)
  }
  if (/:style\((.*)\)$/.test(sel)) {
    const m = /:style\((.*)\)$/.exec(sel);
    const base = sel.slice(0, m.index).trim();
    const body = m[1];
    if (!base) return '';
    // `:style()` の中身はそのまま CSS になるので、閉じ括弧・タグ抜け・危険関数は禁止
    if (/[{}<>;@]|expression\(|javascript:|url\(/i.test(body)) return '';
    const safeBase = safeSelector(base);
    if (!safeBase) return '';
    return `${safeBase}{${body}}`;
  }
  if (/:(upward|if|if-not|not|has-text|matches|remove|defsize|xpath|nth-ancestor|at-start|within)/.test(sel)) return 'procedural';
  if (sel.startsWith('+js') || sel.includes(':has()')) return 'procedural';
  // ABP の `~selector1, selector2` 形式は素朴に最初のセレクタだけ採用
  const first = sel.split(',')[0].trim();
  if (!first || /[{}]/.test(first)) return '';
  const safe = safeSelector(first);
  if (!safe) return '';
  return `${safe}{display:none !important}`;
}

function safeSelector(s) {
  // CSS インジェクション対策: `{`, `}`, `;`, `@import`, `expression(` を除外。
  // `<` は `</style>` によるタグ抜け (注入先が <style> 要素なので実害が出る) なので、これも落とす。
  // `##` が残っているのはパース失敗 (マーカー自体がセレクタに入っている) なので採用しない。
  if (/[{};@<]|##|expression\(|javascript:/i.test(s)) return '';
  return s.slice(0, 400);
}

function categorize(hostOrUrl = '') {
  for (const [re, cat] of CATEGORY_PATTERNS) if (re.test(hostOrUrl)) return cat;
  return 'other';
}

export default Shields;
