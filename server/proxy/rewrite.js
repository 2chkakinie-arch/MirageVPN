/**
 * Mirage Rewriter — Ultraviolet 系の「ページ改写層」に相当する自前実装
 * ---------------------------------------------------------------
 * 上流の HTML/CSS/JS/HTTP ヘッダを、当オリジン上で安全に再生産できる形へ書き換える。
 *
 * 設計判断:
 *  - URL は「相対解決をブラウザに任せても壊れない」よう、path を素で保った proxied path へ。
 *    (`<base>` 方式だと root-relative URL = /a/b.css が当オリジンへ逃げるため不採用。SW で救済)
 *  - `integrity` / `crossorigin` / `sandbox` / CSP / XFO は書き換え後に必ず壊れるので除去。
 *  - JS の構文改写は最小限: [Unforgeable] な `location` と、漏れると意味が無い
 *    「絶対 URL を持つ文字列リテラル」だけ。fetch / XHR / cookie / history / *.src は
 *    core.js のランタイムパッチで処理する (広く書き換えるとサイトを壊すため)。
 * @module proxy/rewrite
 */

import { escapeHtml } from '../util.js';
import { COUNTRIES } from '../data/geo.js';

const URL_ATTRS = new Set([
  'href',
  'src',
  'action',
  'formaction',
  'poster',
  'data',
  'cite',
  'background',
  'longdesc',
  'xlink:href',
  'manifest',
]);
const SRCSET_ATTRS = new Set(['srcset', 'imagesrcset']);
/** content を触るタグ (meta は特別扱い、他は通常書き換え) */
const SKIP_CONTENT_TAGS = new Set(['textarea', 'pre', 'code']);
const BLOCKED_PIXEL = 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';
const ENTITY_RE = /&(?:amp|lt|gt|quot|#39|#x27|apos|nbsp);/gi;
const ENTITIES = { '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&#39;': "'", '&#x27': "'", '&apos;': "'", '&nbsp;': ' ' };

export function decodeEntities(s = '') {
  return String(s).replace(ENTITY_RE, (m) => ENTITIES[m.toLowerCase()] ?? m);
}

export class Rewriter {
  /**
   * @param {{config:object, urlmap:object, shields?:object, threats?:object}} deps
   */
  constructor(deps) {
    this.config = deps.config;
    this.urlmap = deps.urlmap;
    this.shields = deps.shields || null;
    this.threats = deps.threats || null;
  }

  /* ================================ HTML ================================ */

  /**
   * @param {string} html
   * @param {{sid:string, base:URL, proxify:(u:string)=>string|null, kind?:string, documentUrl?:string, cosmeticCss?:string, coreUrl:string, config?:object, blockedUrls?:Array, counters?:object}} ctx
   * @returns {{body:string, counters:object, meta:object}}
   */
  html(html, ctx) {
    const counters = ctx.counters || { rewritten: 0, blocked: 0, stripped: 0, hardened: 0 };
    const meta = { title: null, hadHead: false, droppedCsp: false, baseChanged: false, charset: null };
    const out = [];
    const len = html.length;
    let i = 0;
    let text = '';
    let injected = false;

    const flush = () => {
      if (text) {
        out.push(text);
        text = '';
      }
    };
    const injectOnce = () => {
      if (injected) return '';
      injected = true;
      return this.#injectHead(ctx, counters);
    };

    while (i < len) {
      const lt = html.indexOf('<', i);
      if (lt === -1) {
        text += html.slice(i);
        break;
      }
      text += html.slice(i, lt);
      i = lt;

      if (html.startsWith('<!--', i)) {
        const end = html.indexOf('-->', i);
        const stop = end === -1 ? len : end + 3;
        flush();
        out.push(html.slice(i, stop));
        i = stop;
        continue;
      }
      if (html.startsWith('<!', i) || html.startsWith('<?', i)) {
        const end = html.indexOf('>', i);
        const stop = end === -1 ? len : end + 1;
        flush();
        out.push(html.slice(i, stop));
        i = stop;
        continue;
      }
      const closing = /^<\/([a-z][a-z0-9:-]*)[^>]*>/i.exec(html.slice(i, i + 96));
      if (closing) {
        flush();
        out.push(closing[0]);
        i += closing[0].length;
        continue;
      }
      const tag = matchTag(html, i);
      if (!tag) {
        flush();
        out.push('<');
        i++;
        continue;
      }
      const name = tag.tagName.toLowerCase();
      flush();

      if (name === 'head') {
        meta.hadHead = true;
        out.push(tag.raw);
        out.push(injectOnce());
        i = tag.end;
        continue;
      }
      if (name === 'html') {
        // <html> の直後に注入 (head が無い文書対策にもなる)
        out.push(tag.raw);
        i = tag.end;
        continue;
      }
      if (name === 'script') {
        const closeIdx = findClosing(html, tag.end, 'script');
        const closeTag = /^<\/script[^>]*>/i.exec(html.slice(closeIdx));
        const content = html.slice(tag.end, closeIdx);
        out.push(this.#scriptElement(tag, content, ctx, counters));
        i = closeTag ? closeIdx + closeTag[0].length : html.length;
        continue;
      }
      if (name === 'style') {
        const closeIdx = findClosing(html, tag.end, 'style');
        const closeTag = /^<\/style[^>]*>/i.exec(html.slice(closeIdx));
        const content = html.slice(tag.end, closeIdx);
        const attrs = this.#rewriteAttrs(tag, ctx, counters, meta);
        out.push(`<${tag.tagName}${attrsToString(attrs, tag.selfClosing)}>${this.css(content, ctx)}</style>`);
        i = closeTag ? closeIdx + closeTag[0].length : html.length;
        continue;
      }
      if (SKIP_CONTENT_TAGS.has(name)) {
        const closeIdx = findClosing(html, tag.end, name);
        const closeTag = new RegExp(`</${name}[^>]*>`, 'i').exec(html.slice(closeIdx));
        out.push(html.slice(i, closeIdx));
        i = closeTag ? closeIdx + closeTag[0].length : html.length;
        continue;
      }
      if (name === 'title') {
        const closeIdx = findClosing(html, tag.end, 'title');
        const closeTag = /^<\/title[^>]*>/i.exec(html.slice(closeIdx));
        meta.title = decodeEntities(html.slice(tag.end, closeIdx)).replace(/\s+/g, ' ').trim().slice(0, 160);
        out.push(html.slice(i, closeIdx) + (closeTag ? closeTag[0] : '</title>'));
        i = closeIdx + (closeTag ? closeTag[0].length : 8);
        continue;
      }

      const attrs = this.#rewriteAttrs(tag, ctx, counters, meta);
      if (attrs === null) {
        i = tag.end;
        continue;
      }
      out.push(`<${tag.tagName}${attrsToString(attrs, tag.selfClosing)}>`);
      i = tag.end;
    }
    flush();
    let body = out.join('');
    const head = injectOnce();
    if (head) body = head + body; // <head> が無かった場合
    return { body, counters, meta };
  }

  #injectHead(ctx, counters) {
    const cfg = ctx.config || {};
    const cosmetic = ctx.cosmeticCss
      ? `<style id="__mirage-cosmetic">${sanitizeCss(ctx.cosmeticCss)}</style>`
      : '';
    const json = JSON.stringify(cfg).replace(/[<>&]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
    return [
      '<meta charset="utf-8">',
      '<meta name="referrer" content="no-referrer">',
      `<script id="__mirage-config" type="application/json">${json}</script>`,
      '<script>window.__MIRAGE_CFG=JSON.parse(document.getElementById("__mirage-config").textContent);document.getElementById("__mirage-config").remove();</script>',
      cfg.wispClientUrl && cfg.mode && cfg.mode !== 'uv' ? `<script src="${cfg.wispClientUrl}"></script>` : '',
      `<script src="${ctx.coreUrl}"></script>`,
      cosmetic,
    ].join('');
  }

  /** <script> 要素 1 個を文字列として再生産 (除去の判定含む) */
  #scriptElement(tag, content, ctx, counters) {
    let attrs = tag.attrs;
    const type = (attrValue(attrs, 'type') || '').toLowerCase();
    const language = (attrValue(attrs, 'language') || '').toLowerCase();
    const isJs = !type || /javascript|ecmascript|module/.test(type) || /javascript|ecmascript/.test(language);
    const isModule = type === 'module';
    const src = attrValue(attrs, 'src');

    if (src != null) {
      const raw = decodeEntities(src);
      if (!raw.trim()) return '';
      const abs = absolutize(raw, ctx.base);
      if (!abs) return tag.raw; // data:/blob: などはそのまま (実行はブラウザ次第)
      const blocked = this.#subresourceBlocked(abs, ctx, 'script');
      if (blocked) {
        counters.blocked++;
        return `<script data-mirage-blocked="${escapeHtml(String(blocked.rule || '')).slice(0, 100)}"></script>`;
      }
      const proxied = ctx.proxify(abs.href);
      if (!proxied) return tag.raw;
      counters.rewritten++;
      attrs = replaceAttr(dropAttrs(attrs, ['integrity', 'crossorigin', 'nonce']), 'src', proxied);
      attrs = [...attrs, ['referrerpolicy', 'no-referrer']];
      counters.hardened++;
      return `<script${attrsToString(attrs, false)}></script>`;
    }

    if (!isJs || !content.trim()) return tag.raw;

    if (this.threats?.enabled) {
      const verdict = this.threats.inspectAsset(content, { url: ctx.documentUrl, kind: 'script', sid: ctx.sid });
      if (verdict.drop) {
        counters.stripped++;
        const why = escapeHtml(verdict.findings.map((f) => f.label).join(' / ')).slice(0, 140);
        return `<script type="text/plain" data-mirage-stripped="${verdict.score}" data-mirage-reason="${why}"></script>`;
      }
    }
    const rewrittenBody = this.js(content, { ...ctx, module: isModule }, counters);
    return `<script${attrsToString(attrs, false)}>${rewrittenBody}</script>`;
  }

  /**
   * 属性の書き換え。`null` を返したらタグごと除去。
   */
  #rewriteAttrs(tag, ctx, counters, meta = {}) {
    const name = tag.tagName.toLowerCase();
    let attrs = tag.attrs.slice();

    if (name === 'meta') {
      const httpEquiv = (attrValue(attrs, 'http-equiv') || '').toLowerCase().replace(/[^a-z0-9-]/g, '');
      if (attrNameExists(attrs, 'charset')) return null; // utf-8 に差し替えた
      if (httpEquiv === 'content-security-policy' || httpEquiv === 'x-frame-options' || httpEquiv === 'expect-ct') {
        meta.droppedCsp = true;
        return null;
      }
      if (httpEquiv === 'refresh') {
        const content = attrValue(attrs, 'content') || '';
        const m = /(\d+)\s*;\s*url\s*=\s*(.+)$/i.exec(content.trim());
        if (!m) return null;
        const target = absolutize(decodeEntities(m[2].trim().replace(/^['"]|['"]$/g, '')), ctx.base);
        if (!target) return null;
        const proxied = ctx.proxify(target.href);
        counters.rewritten++;
        return replaceAttr(attrs, 'content', `${m[1]};url=${proxied || target.href}`);
      }
      return attrs;
    }

    if (name === 'base') {
      const href = attrValue(attrs, 'href');
      if (href) {
        const abs = absolutize(decodeEntities(href), ctx.base);
        if (abs) {
          ctx.base = abs;
          meta.baseChanged = true;
        }
      }
      return null;
    }

    if (name === 'iframe' || name === 'frame' || name === 'object' || name === 'embed') {
      attrs = dropAttrs(attrs, ['sandbox']); // sandbox は我々の origin 制約と衝突する
    }

    for (let k = 0; k < attrs.length; k++) {
      const [key, value] = attrs[k];
      const lk = key.toLowerCase();
      if (lk === 'style' && value != null) {
        const res = this.css(value, ctx);
        if (res !== value) counters.rewritten++;
        attrs[k] = [key, res];
        continue;
      }
      if (SRCSET_ATTRS.has(lk)) {
        attrs[k] = [key, this.#srcset(value, ctx, counters)];
        continue;
      }
      if (!URL_ATTRS.has(lk) || value == null) continue;
      const raw = decodeEntities(value).trim();
      if (!raw) continue;
      if (/^(javascript|vbscript):/i.test(raw)) {
        attrs[k] = [key, '#'];
        attrs.push(['data-mirage-stripped', 'javascript-uri']);
        counters.stripped++;
        continue;
      }
      const abs = absolutize(raw, ctx.base);
      if (!abs) continue; // data:/blob:/mailto:/#anchor 等は何もしない
      const typeHint =
        name === 'script'
          ? 'script'
          : name === 'img' || name === 'source' || name === 'video' || name === 'audio'
            ? 'image'
            : name === 'link'
              ? linkType(attrs)
              : name === 'iframe' || name === 'frame'
                ? 'subdocument'
                : name === 'a' || name === 'area'
                  ? 'document'
                  : 'other';
      const blocked = this.#subresourceBlocked(abs, ctx, typeHint);
      if (blocked) {
        counters.blocked++;
        if (name === 'img' || name === 'source') attrs[k] = [key, BLOCKED_PIXEL];
        else if (name === 'a' || name === 'area') attrs[k] = [key, '#'];
        else if (name === 'link') return null;
        else attrs[k] = [key, ''];
        attrs.push(['data-mirage-blocked', String(blocked.category || 'blocked').slice(0, 24)]);
        continue;
      }
      const proxied = ctx.proxify(abs.href);
      if (proxied) {
        attrs[k] = [key, proxied];
        counters.rewritten++;
      }
    }

    if (['script', 'link', 'img', 'source', 'audio', 'video', 'iframe', 'embed', 'object'].includes(name)) {
      const before = attrs.length;
      attrs = dropAttrs(attrs, ['integrity', 'crossorigin', 'referrerpolicy']);
      if (attrs.length !== before) counters.hardened++;
      attrs = [...attrs, ['referrerpolicy', 'no-referrer']];
    }

    const targetAttr = attrValue(attrs, 'target');
    if (targetAttr && /_blank/i.test(targetAttr) && !/noopener/i.test(attrValue(attrs, 'rel') || '')) {
      const rel = attrValue(attrs, 'rel') || '';
      attrs = replaceAttr(attrs, 'rel', `${rel ? `${rel} ` : ''}noopener noreferrer`);
      counters.hardened++;
    }
    return attrs;
  }

  #srcset(value, ctx, counters) {
    if (!value) return value;
    return decodeEntities(value)
      .split(',')
      .map((candidate) => {
        const m = /^\s*(\S+)(\s+[\d.]+[wx])?\s*$/.exec(candidate);
        if (!m) return candidate;
        const abs = absolutize(m[1], ctx.base);
        if (!abs) return candidate;
        if (this.#subresourceBlocked(abs, ctx, 'image')) {
          counters.blocked++;
          return 'about:blank';
        }
        const proxied = ctx.proxify(abs.href);
        if (!proxied) return candidate;
        counters.rewritten++;
        return `${proxied}${m[2] || ''}`;
      })
      .join(', ');
  }

  #subresourceBlocked(absUrl, ctx, type) {
    if (!this.shields?.enabled) return null;
    if (ctx.kind === 'document' && type === 'document') return null;
    const d = this.shields.match(absUrl.href, {
      type,
      sourceUrl: ctx.base ? ctx.base.href : undefined,
      sid: ctx.sid,
      documentUrl: ctx.documentUrl,
    });
    if (!d.blocked) return null;
    if (ctx.documentUrl) this.shields.noteBlocked(ctx.sid, ctx.documentUrl);
    ctx.blockedUrls?.push({ url: absUrl.href, rule: d.rule, category: d.category, type });
    return d;
  }

  /* ================================ CSS ================================ */

  css(cssText, ctx) {
    const s = String(cssText ?? '');
    if (!s) return '';
    return s.replace(
      /url\(\s*(['"]?)([^'"\s)]+)\1\s*\)|@import\s+(['"])([^'"]+)\3/gi,
      (whole, _q1, u1, _q2, u2) => {
        const raw = decodeEntities((u1 || u2 || '').trim());
        if (!raw || /^(data|blob):/i.test(raw)) return whole;
        const abs = absolutize(raw, ctx.base);
        if (!abs) return whole;
        if (this.#subresourceBlocked(abs, ctx, 'stylesheet')) return 'url("")';
        const proxied = ctx.proxify(abs.href);
        if (!proxied) return whole;
        return whole.trimStart().startsWith('@import') ? `@import url("${proxied}")` : `url("${proxied}")`;
      },
    );
  }

  /* ================================ JS ================================ */

  /**
   * `location` と「絶対 URL 文字列リテラル」だけを触る最小改写。
   * 文字列・コメント・正規表現リテラルの中は書き換えない (置換で壊すリスクを避ける)。
   * @param {string} src
   * @param {{sid:string, base:URL, proxify:(u:string)=>string|null, module?:boolean}} ctx
   * @param {{rewritten?:number}} [counters]
   */
  js(src, ctx, counters = { rewritten: 0 }) {
    const code = String(src ?? '');
    if (!code) return code;
    let out = '';
    let i = 0;
    const n = code.length;
    let prevIdent = '';

    while (i < n) {
      const c = code[i];

      if (c === '/' && code[i + 1] === '/') {
        const end = code.indexOf('\n', i);
        const stop = end === -1 ? n : end;
        out += code.slice(i, stop);
        i = stop;
        continue;
      }
      if (c === '/' && code[i + 1] === '*') {
        const end = code.indexOf('*/', i);
        const stop = end === -1 ? n : end + 2;
        out += code.slice(i, stop);
        i = stop;
        continue;
      }
      if (c === '"' || c === "'" || c === '`') {
        const { end } = readStringLiteral(code, i);
        const literal = code.slice(i, end);
        out += ctx.module && false ? literal : rewriteStringLiteral(literal, ctx, counters);
        i = end;
        prevIdent = '';
        continue;
      }
      if (c === '/' && regexAllowedHere(out)) {
        const end = scanRegex(code, i);
        if (end > i) {
          out += code.slice(i, end);
          i = end;
          continue;
        }
      }
      if (/[A-Za-z_$]/.test(c)) {
        let j = i + 1;
        while (j < n && /[A-Za-z0-9_$]/.test(code[j])) j++;
        const ident = code.slice(i, j);
        if (ident === 'location') {
          const nextChar = peekNext(code, j);
          const prevChar = peekPrev(out);
          const precededByDot = prevChar === '.';
          // 触ってよいのは 裸の location / window|document|self|top|parent|.location。
          // 分割束縛 `{location}`、オブジェクトキー `{location: x}`、ラベル文 `x:` は触らない。
          const isKeyOrLabel = nextChar === ':' || prevChar === ':';
          const isDestructureShorthand = (prevChar === '{' || prevChar === ',') && (nextChar === '}' || nextChar === ',');
          const objIsGlobal = LOC_OWNER_RE.test(out);
          const safe = !isKeyOrLabel && !isDestructureShorthand && (!precededByDot || objIsGlobal);
          if (safe && precededByDot && objIsGlobal) {
            // `window.` 等の prefix を落として __mrg.loc に寄せる
            // (top/parent を素で書き換えると親フレーム = アプリ本体を操られてしまうため)
            out = out.replace(LOC_OWNER_RE, '');
          }
          out += safe ? '__mrg.loc' : ident;
          i = j;
          prevIdent = 'location';
          continue;
        }
        prevIdent = ident;
        out += ident;
        i = j;
        continue;
      }
      out += c;
      i++;
    }
    return out;
  }

  /* ============================== Headers ============================== */

  /**
   * 上流 → クライアント
   * @param {Map<string,string>} headers
   * @param {{sid:string, url:URL, cookieStore?:object, setCookies?:string[], isDocument:boolean}} ctx
   */
  responseHeaders(headers, ctx) {
    const out = new Map();
    const DROP = new Set([
      'content-security-policy',
      'content-security-policy-report-only',
      'x-frame-options',
      'cross-origin-opener-policy',
      'cross-origin-embedder-policy',
      'cross-origin-resource-policy',
      'report-to',
      'nel',
      'expect-ct',
      'strict-transport-security',
      'permissions-policy',
      'require-trusted-types-for',
      'trusted-types',
      'content-encoding',
      'content-length',
      'transfer-encoding',
      'vary',
      'set-cookie',
      'refresh',
      'x-webkit-csp',
      'access-control-allow-origin',
      'access-control-allow-credentials',
      'access-control-allow-methods',
      'access-control-allow-headers',
      'access-control-expose-headers',
      'access-control-max-age',
      'server',
      'via',
      'cf-ray',
      'x-real-ip',
      'x-forwarded-for',
    ]);
    for (const [k, v] of headers) {
      const key = k.toLowerCase();
      if (DROP.has(key)) continue;
      if (/^x-(?:cdn|cache|request-id|trace|amz|cf|edge|akamai|server)/.test(key)) {
        out.set(`x-upstream-${key}`, v);
        continue;
      }
      out.set(key, v);
    }
    const link = headers.get('link');
    if (link) {
      const rewritten = link
        .split(/,\s*(?=<)/)
        .map((part) => {
          const m = /^\s*<([^>]+)>(.*)$/.exec(part.trim());
          if (!m) return '';
          const abs = absolutize(m[1], ctx.url);
          if (!abs) return '';
          const proxied = ctx.sid ? this.urlmap.proxify(abs.href, ctx.sid) : abs.href;
          return `<${proxied || m[1]}>${m[2]}`;
        })
        .filter(Boolean);
      if (rewritten.length) out.set('link', rewritten.join(', '));
    }
    // Refresh ヘッダ
    const refresh = headers.get('refresh');
    if (refresh) {
      const m = /(\d+)\s*;\s*url\s*=\s*(.+)$/i.exec(refresh.trim());
      if (m) {
        const abs = absolutize(m[2].trim(), ctx.url);
        const proxied = abs ? this.urlmap.proxify(abs.href, ctx.sid) : null;
        if (proxied) out.set('refresh', `${m[1]};url=${proxied}`);
      }
    }
    // Set-Cookie → ジャー
    const lines = ctx.setCookies?.length ? ctx.setCookies : headers.get('set-cookie') ? [headers.get('set-cookie')] : [];
    const stored = [];
    for (const piece of lines) {
      for (const one of splitSetCookie(piece)) {
        if (ctx.cookieStore && ctx.sid) ctx.cookieStore.applySetCookies(ctx.sid, ctx.url, [one]);
        stored.push(one);
      }
    }
    out.set('access-control-allow-origin', '*');
    out.set('access-control-allow-headers', '*');
    out.set('access-control-expose-headers', 'x-mirage-final-url,x-mirage-info,x-mirage-blocked,x-mirage-cookies');
    out.set('x-content-type-options', 'nosniff');
    return { headers: out, setCookies: stored };
  }

  /**
   * クライアント → 上流のリクエストヘッダ。
   * クライアントの実環境が漏れるヘッダ (sec-ch-ua*, referer, origin, cookie) は作り直す。
   * @param {{url:URL, sid?:string, mode?:string, method?:string, dest?:string, egress?:object, clientHeaders?:Map, referrer?:string, body?:Buffer, spoofIps?:string[], cookie?:string}} o
   */
  requestHeaders(o) {
    const cfg = this.config;
    const h = new Map();
    const KEEP = new Set([
      'accept',
      'content-type',
      'range',
      'cache-control',
      'pragma',
      'if-none-match',
      'if-modified-since',
      'x-requested-with',
      'priority',
      'accept-datetime',
    ]);
    const src = o.clientHeaders || new Map();
    for (const [k, v] of src) {
      const key = k.toLowerCase();
      if (KEEP.has(key) && v != null) h.set(key, String(v).replace(/[\r\n]/g, ' ').slice(0, 2000));
    }
    h.set('host', o.url.host);
    h.set('user-agent', cfg.egress.userAgent);
    h.set(
      'accept',
      String(src.get('accept') || 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8').slice(0, 900),
    );
    const cc = o.egress?.country;
    if (cfg.egress.localizeHeaders && cc && COUNTRIES[cc]) h.set('accept-language', COUNTRIES[cc].lang);
    else h.set('accept-language', String(src.get('accept-language') || 'ja,en-US;q=0.9,en;q=0.8').slice(0, 300));
    if (cfg.egress.sendPrivacySignals) {
      h.set('dnt', '1');
      h.set('sec-gpc', '1');
    }
    if (o.referrer) {
      const r = safeUrl(o.referrer);
      if (r) h.set('referer', r.origin + (r.pathname === '/' ? '' : r.pathname + (r.search || '')));
    }
    if ((o.method === 'POST' || o.method === 'PUT' || o.method === 'PATCH') && o.mode === 'cors') h.set('origin', o.url.origin);
    h.set('sec-fetch-site', 'none');
    h.set('sec-fetch-mode', o.mode === 'cors' ? 'cors' : 'navigate');
    h.set('sec-fetch-dest', o.dest || 'document');
    h.set('upgrade-insecure-requests', '1');
    h.set('connection', 'keep-alive');
    h.set('accept-encoding', 'gzip, deflate, br');
    if (o.cookie) h.set('cookie', o.cookie);
    if (cfg.egress.spoofForwardedHeaders) {
      const ips = o.spoofIps?.length ? o.spoofIps : [randomPublicIp(cc)];
      h.set('x-forwarded-for', ips.join(', '));
      h.set('x-real-ip', ips[0]);
      h.set('client-ip', ips[0]);
      h.set('true-client-ip', ips[0]);
      h.set('cf-connecting-ip', ips[0]);
    }
    if (o.body?.length) h.set('content-length', String(o.body.length));
    h.delete('transfer-encoding');
    h.delete('proxy-authorization');
    return h;
  }
}

/* ------------------------------------------------------------------ */
/* scanning helpers                                                    */
/* ------------------------------------------------------------------ */

/** `<tag a="1" b=2 />` を 1 個拾う */
export function matchTag(html, start) {
  const m = /^<([a-zA-Z][a-zA-Z0-9:-]*)/.exec(html.slice(start, start + 96));
  if (!m) return null;
  const tagName = m[1];
  const len = html.length;
  let i = start + m[0].length;
  const attrs = [];
  let selfClosing = false;
  let quote = null;
  while (i < len) {
    const ch = html[i];
    if (quote) {
      if (ch === quote) quote = null;
      i++;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      i++;
      continue;
    }
    if (ch === '>') return { tagName, attrs, selfClosing, raw: html.slice(start, i + 1), end: i + 1 };
    if (ch === '/' && html[i + 1] === '>') {
      selfClosing = true;
      return { tagName, attrs, selfClosing, raw: html.slice(start, i + 2), end: i + 2 };
    }
    if (/\s/.test(ch)) {
      i++;
      continue;
    }
    const am = /^([a-zA-Z0-9_:.$-]{1,80})/.exec(html.slice(i, i + 90));
    if (!am) {
      i++;
      continue;
    }
    const name2 = am[1];
    let j = i + name2.length;
    while (j < len && /\s/.test(html[j])) j++;
    let value = null;
    if (html[j] === '=') {
      j++;
      while (j < len && /\s/.test(html[j])) j++;
      const q = html[j];
      if (q === '"' || q === "'") {
        const end = html.indexOf(q, j + 1);
        value = html.slice(j + 1, end === -1 ? len : end);
        j = end === -1 ? len : end + 1;
      } else {
        const end = findUnquotedEnd(html, j);
        value = html.slice(j, end);
        j = end;
      }
    }
    attrs.push([name2, value]);
    i = j;
  }
  return { tagName, attrs, selfClosing, raw: html.slice(start), end: len };
}

function findUnquotedEnd(html, from) {
  let i = from;
  while (i < html.length && !/[\s>]/.test(html[i])) i++;
  return i;
}

export function attrValue(attrs, name) {
  for (const [k, v] of attrs) if (k.toLowerCase() === name) return v;
  return null;
}

function attrNameExists(attrs, name) {
  return attrs.some(([k]) => k.toLowerCase() === name);
}

export function replaceAttr(attrs, name, value) {
  const out = attrs.map(([k, v]) => (k.toLowerCase() === name ? [k, value] : [k, v]));
  if (!out.some(([k]) => k.toLowerCase() === name)) out.push([name, value]);
  return out;
}

export function dropAttrs(attrs, names) {
  const set = new Set(names.map((n) => n.toLowerCase()));
  return attrs.filter(([k]) => !set.has(k.toLowerCase()));
}

function attrsToString(attrs, selfClosing) {
  if (!attrs) return selfClosing ? ' /' : '';
  return `${attrs.map(([k, v]) => (v === null ? ` ${k}` : ` ${k}="${escapeAttr(v)}"`)).join('')}${selfClosing ? ' /' : ''}`;
}

function escapeAttr(v) {
  return String(v).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
}

export function findClosing(html, from, tag) {
  const m = new RegExp(`</${tag}\\s*>`, 'i').exec(html.slice(from));
  return m ? from + m.index : html.length;
}

function linkType(attrs) {
  const rel = (attrValue(attrs, 'rel') || '').toLowerCase();
  if (/preload/.test(rel)) return PRELOAD_AS[(attrValue(attrs, 'as') || '').toLowerCase()] || 'other';
  if (/stylesheet/.test(rel)) return 'stylesheet';
  if (/icon/.test(rel)) return 'image';
  return 'other';
}
const PRELOAD_AS = { script: 'script', style: 'stylesheet', image: 'image', font: 'font', fetch: 'xhr', document: 'subdocument', video: 'media', audio: 'media', worker: 'script' };

/** 相対/絶対を吸収。data:/blob:/#anchor などは null (= 触らない) */
export function absolutize(raw, base) {
  const s = String(raw || '').trim();
  if (!s || s.startsWith('#')) return null;
  if (/^(data|blob|javascript|vbscript|mailto|tel|about|filesystem|file|chrome|chrome-extension|moz-extension|EXT|ws|wss):/i.test(s)) return null;
  try {
    if (s.startsWith('//')) return new URL(`${base?.protocol || 'https:'}${s}`);
    const u = new URL(s, base ? base.href : undefined);
    return /^https?:$/.test(u.protocol) ? u : null;
  } catch {
    return null;
  }
}

function safeUrl(s) {
  try {
    return new URL(s);
  } catch {
    return null;
  }
}

/** 文字列リテラル開始位置から終了位置まで */
export function readStringLiteral(code, start) {
  const quote = code[start];
  let i = start + 1;
  while (i < code.length) {
    const ch = code[i];
    if (ch === '\\') {
      i += 2;
      continue;
    }
    if (quote === '`' && ch === '$' && code[i + 1] === '{') {
      let depth = 1;
      i += 2;
      while (i < code.length && depth > 0) {
        if (code[i] === '{') depth++;
        else if (code[i] === '}') depth--;
        else if (code[i] === '"' || code[i] === "'" || code[i] === '`') {
          i = readStringLiteral(code, i).end;
          continue;
        }
        i++;
      }
      continue;
    }
    if (ch === quote) return { value: code.slice(start + 1, i), end: i + 1 };
    // 改行で文字列が切れた = 壊れたソース (あるいは正規表現内) → ここで打ち切り
    if (quote !== '`' && ch === '\n') return { value: code.slice(start + 1, i), end: i };
    i++;
  }
  return { value: code.slice(start + 1), end: code.length };
}

const ABS_URL_RE = /^(?:https?:\/\/|\/\/)[a-z0-9.\-:[\]]+[/?#].*$/i;

/** 絶対 URL の文字列リテラルだけを proxify する */
export function rewriteStringLiteral(literal, ctx, counters = { rewritten: 0 }) {
  const quote = literal[0];
  if (quote !== '"' && quote !== "'" && quote !== '`') return literal;
  const inner = literal.slice(1, -1);
  if (!inner || inner.length > 3000) return literal;
  if (inner.includes('\\') || inner.includes('${') || /["'`<>]/.test(inner)) return literal;
  if (!ABS_URL_RE.test(inner)) return literal;
  const abs = absolutize(inner, ctx.base);
  if (!abs) return literal;
  const proxied = ctx.proxify(abs.href);
  if (!proxied) return literal;
  counters.rewritten++;
  return `${quote}${proxied}${quote}`;
}

/** `window.` `document.` `self.` `top.` `parent.` `globalThis.` の直前か */
const LOC_OWNER_RE = /(window|document|self|top|parent|globalThis)\.\s*$/;

function peekPrev(out) {
  let i = out.length - 1;
  while (i >= 0 && /\s/.test(out[i])) i--;
  return out[i];
}

function peekNext(code, from) {
  let i = from;
  while (i < code.length && /\s/.test(code[i])) i++;
  return code[i];
}

/** この位置の `/` は正規リテラル開始とみなしてよい文脈か */
function regexAllowedHere(out) {
  const trimmed = out.replace(/\s+$/, '');
  if (!trimmed) return true;
  const last = trimmed[trimmed.length - 1];
  if ('(,=:[!&|?{};+-*%^~<>'.includes(last)) return true;
  return /(?:return|typeof|case|in|do|else|yield|await)$/.test(trimmed.slice(-6));
}

function scanRegex(code, start) {
  let i = start + 1;
  let inClass = false;
  while (i < code.length) {
    const c = code[i];
    if (c === '\\') {
      i += 2;
      continue;
    }
    if (c === '[') inClass = true;
    else if (c === ']') inClass = false;
    else if (c === '/' && !inClass) {
      i++;
      while (i < code.length && /[a-z]/i.test(code[i])) i++;
      return i;
    } else if (c === '\n') return start;
    i++;
  }
  return start;
}

function sanitizeCss(css = '') {
  return String(css).replace(/<\/style/gi, '<\\/style').slice(0, 300000);
}

/** Set-Cookie が 1 ヘッダに畳まれた状態を分離 (Expires の ", 09 Jun..." を壊さない) */
export function splitSetCookie(raw) {
  const out = [];
  let cur = '';
  const s = String(raw);
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    cur += c;
    if (c === ',') {
      const rest = s.slice(i + 1);
      // `, 09 Jun 2026` (日付の続き) でなく `, name=value` のときだけ切る
      if (/^\s*[a-z0-9_.-]+=(?:"[^"]*"|[^,;]*)/i.test(rest) && !/^\s*\d{1,2}\s/.test(rest)) {
        out.push(cur.slice(0, -1).trim());
        cur = '';
      }
    }
  }
  if (cur.trim()) out.push(cur.trim());
  return out.filter(Boolean);
}

/** 偽装 XFF 用: リークしにくい「もっともらしい」グローバル IP を生成 */
export function randomPublicIp(_country, rng = Math.random) {
  const firsts = [8, 23, 24, 31, 34, 35, 36, 39, 40, 42, 45, 49, 51, 52, 54, 58, 60, 61, 62, 63, 64, 66, 68, 70, 71, 72, 74, 75, 76, 77, 78, 80, 81, 82, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 128, 129, 130, 131, 132, 133, 134, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223];
  let a = firsts[Math.floor(rng() * firsts.length)];
  if (a >= 100 && a <= 127) {
    // プライベート/研究用範囲に偶発的に触れないよう外す
    const bad = (a === 100 && rng() < 0.3) || a === 127 || a === 10 || (a >= 172 && a <= 191 && rng() < 0.05);
    if (bad) a = 8;
  }
  const b = Math.floor(rng() * 256);
  const c = Math.floor(rng() * 256);
  const d = 1 + Math.floor(rng() * 253);
  return `${a}.${b}.${c}.${d}`;
}

export default Rewriter;
