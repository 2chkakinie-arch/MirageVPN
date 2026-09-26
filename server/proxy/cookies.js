/**
 * セッション別 Cookie ジャー
 * ---------------------------------------------------------------
 * プロキシ済みページは当オリジン上で動くため、上流の Cookie を素直に Set-Cookie すると
 * ドメイン衝突・Secure/SameSite 不整合で壊れる。そこで
 *   - 上流 Cookie は「セッション + 実効ドメイン」キーでサーバ側ジャーに保存し
 *   - クライアントには core.js 経由で JSON として配布 (document.cookie を override)
 * の両方を行う。Cookie 文字列はタブを閉じれば消える (設定で永続化も可)。
 * @module proxy/cookies
 */

import { LRU, registrableDomain } from '../util.js';

const ATTR_RE = /^([a-z0-9!#$%&'*+.^_`|~-]+)(?:=([^;]*))?/i;

export function parseSetCookie(line) {
  const parts = String(line).split(/;\s*/);
  const [nameValue, ...attrs] = parts;
  const eq = nameValue.indexOf('=');
  const name = (eq === -1 ? nameValue : nameValue.slice(0, eq)).trim();
  const value = eq === -1 ? '' : nameValue.slice(eq + 1).trim();
  if (!name) return null;
  const out = { name, value, attributes: {} };
  for (const a of attrs) {
    const m = ATTR_RE.exec(a);
    if (!m) continue;
    out.attributes[m[1].toLowerCase()] = m[2] === undefined ? true : m[2];
  }
  return out;
}

/** 上流 Set-Cookie をジャーに保存できる形へ正規化 */
export function toJarEntry(setCookie, requestUrl) {
  const parsed = parseSetCookie(setCookie);
  if (!parsed) return null;
  const attrs = parsed.attributes;
  const host = requestUrl.hostname.toLowerCase();
  let domain = typeof attrs.domain === 'string' ? attrs.domain.replace(/^\./, '').toLowerCase() : host;
  // 親ドメイン以外を指定されたら無視 (RFC 6265 の simplicity 準拠)
  if (host !== domain && !host.endsWith(`.${domain}`)) domain = host;
  let path = typeof attrs.path === 'string' && attrs.path.startsWith('/') ? attrs.path : '/';
  if (!path.endsWith('/')) path += '/';
  const maxAge = Number(attrs['max-age']);
  let expiresAt = null;
  if (Number.isFinite(maxAge)) {
    expiresAt = maxAge <= 0 ? 0 : Date.now() + maxAge * 1000;
  } else if (typeof attrs.expires === 'string') {
    const t = Date.parse(attrs.expires);
    expiresAt = Number.isNaN(t) ? null : t;
  }
  return {
    name: parsed.name,
    value: parsed.value,
    domain,
    path,
    secure: 'secure' in attrs,
    httpOnly: 'httponly' in attrs,
    sameSite: typeof attrs.samesite === 'string' ? String(attrs.samesite).toLowerCase() : 'lax',
    expiresAt,
    hostOnly: typeof attrs.domain !== 'string',
    creation: Date.now(),
  };
}

export function pathMatches(cookiePath, requestPath) {
  if (cookiePath === '/' || cookiePath === requestPath) return true;
  if (!requestPath.startsWith(cookiePath)) return false;
  return cookiePath.endsWith('/') || requestPath[cookiePath.length] === '/';
}

export function domainMatches(cookieDomain, host) {
  const h = host.toLowerCase();
  const d = String(cookieDomain || '').toLowerCase();
  if (!d) return false;
  return h === d || h.endsWith(`.${d}`);
}

/** RFC6265 風のマッチ (Secure は https 時のみ / httpOnly はクライアント配布から除外) */
export function selectCookies(jar, url, { forClient = false } = {}) {
  const now = Date.now();
  const out = [];
  for (const c of jar.values()) {
    if (c.expiresAt === 0) continue;
    if (c.expiresAt && c.expiresAt < now) {
      jar.delete(cookieKey(c));
      continue;
    }
    if (c.secure && url.protocol !== 'https:') continue;
    if (forClient && c.httpOnly) continue;
    if (!domainMatches(c.domain, url.hostname)) continue;
    if (!pathMatches(c.path, url.pathname)) continue;
    out.push(c);
  }
  // 長い path が先頭 (より具体的なのを優先) → 同一 name は最初の 1 つだけ採用
  out.sort((a, b) => b.path.length - a.path.length || b.creation - a.creation);
  const seen = new Set();
  const picked = [];
  for (const c of out) {
    if (seen.has(c.name)) continue;
    seen.add(c.name);
    picked.push(c);
  }
  return picked;
}

export const cookieKey = (c) => `${c.domain}|${c.path}|${c.name}`;

/** ヘッダに載せる Cookie 文字列 */
export function cookieHeader(jar, url) {
  const picked = selectCookies(jar, url);
  if (!picked.length) return '';
  return picked.map((c) => `${c.name}=${c.value}`).join('; ');
}

/** クライアント配信用 (document.cookie 復元用) */
export function cookieClientString(jar, url) {
  const picked = selectCookies(jar, url, { forClient: true });
  return picked.map((c) => `${c.name}=${c.value}`).join('; ');
}

/**
 * セッションごとのジャー管理。LRU で放置タブのメモリリークを防ぐ。
 */
export class CookieStore {
  constructor({ maxSessions = 500 } = {}) {
    this.sessions = new LRU(maxSessions, 1000 * 60 * 60 * 8); // 8h idle
  }

  jar(sid) {
    let j = this.sessions.get(sid);
    if (!j) {
      j = new Map();
      j.__count = 0;
      this.sessions.set(sid, j);
    }
    return j;
  }

  /** @returns {string[]} 破棄された (クライアントへ教える) cookie 名 */
  applySetCookies(sid, url, setCookieLines = []) {
    const jar = this.jar(sid);
    const cleared = [];
    for (const line of Array.isArray(setCookieLines) ? setCookieLines : [setCookieLines]) {
      const entry = toJarEntry(line, url);
      if (!entry) continue;
      const key = cookieKey(entry);
      if (entry.expiresAt === 0) {
        jar.delete(key);
        cleared.push(entry.name);
        continue;
      }
      jar.set(key, entry);
      if (jar.size > 200) {
        // 暴走防止: 先頭から捨てる
        const first = jar.keys().next().value;
        jar.delete(first);
      }
    }
    return cleared;
  }

  headerFor(sid, url) {
    return cookieHeader(this.jar(sid), url);
  }

  clientStringFor(sid, url) {
    return cookieClientString(this.jar(sid), url);
  }

  export(sid) {
    const jar = this.sessions.get(sid);
    if (!jar) return [];
    return [...jar.values()];
  }

  clear(sid, { domain } = {}) {
    const jar = this.sessions.get(sid);
    if (!jar) return 0;
    let n = 0;
    if (!domain) {
      n = jar.size;
      this.sessions.delete(sid);
      return n;
    }
    for (const [k, c] of jar) {
      if (domainMatches(domain, c.domain) || domainMatches(c.domain, domain)) {
        jar.delete(k);
        n++;
      }
    }
    return n;
  }

  stats() {
    let cookies = 0;
    for (const jar of this.sessions.values()) cookies += jar.size;
    return { sessions: this.sessions.size, cookies };
  }
}

export default CookieStore;

/** Set-Cookie を当オリジン安全な形に書き換えてクライアントへ渡す (ジャーとは別経路) */
export function rewriteSetCookie(line, { sid, url }) {
  const parsed = parseSetCookie(line);
  if (!parsed) return null;
  const attrs = { ...parsed.attributes };
  delete attrs.domain;
  delete attrs.secure;
  delete attrs.samesite;
  delete attrs.partitioned;
  attrs.path = `/${sid.slice(0, 4)}`.slice(0, 12);
  const domain = registrableDomain(url.hostname) || url.hostname;
  const attrStr = Object.entries(attrs)
    .map(([k, v]) => (v === true ? k : `${k}=${v}`))
    .join('; ');
  return `${parsed.name}=${parsed.value}; ${attrStr}${attrStr ? '; ' : ''}__mirage=${encodeURIComponent(domain)}`;
}
