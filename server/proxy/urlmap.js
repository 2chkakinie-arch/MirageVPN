/**
 * MirageVPN URL スキーム
 * ---------------------------------------------------------------
 * プロキシ済み URL は「authority だけをトークン化し、path/query は素で残す」方式。
 *
 *   /mirage/t/<sid>/h/<token>/a/b/c.html?x=1
 *        │       │    │         └ 上流の path はそのまま → ブラウザの相対解決が自然に効く
 *        │       │    └ scheme://host[:port] を base64url で難読化 (stateless, serverless 友好)
 *        │       └ セッション(タブ) ID → Cookie/Storage/脅威レポートの分離キー
 *        └ ルートprefix
 *
 * 利点:
 *  - `<base>` ハック不要。相対リンク `../x` がそのまま正しい上流 URL になる
 *  - サーバ側にマップを持たない (Vercel などのマルチインスタンスで動く)
 *  - root-relative URL (`/assets/a.css`) は SW が referrer から復元 (フォールバック: Referer リダイレクト)
 * @module proxy/urlmap
 */

import { b64u, unb64u } from '../util.js';

const DEFAULT_PORTS = { 'http:': '80', 'https:': '443' };

export const SEG_TOKEN = 'h'; // host トークン
export const SEG_PLAIN = 'u'; // host 平文
export const SEG_WS = 'w'; // WebSocket トンネル用 (info を query に)

export class UrlMap {
  /**
   * @param {import('../config.js').Config} config
   */
  constructor(config) {
    this.config = config;
    this.prefix = `${config.basePath}${config.url.prefix}`;
    this.appBase = config.basePath || '';
    this.encoding = config.url.encoding;
  }

  /** セッション単体の prefix (path 用) */
  sessionPrefix(sid) {
    return `${this.prefix}/${sid}`;
  }

  /** origin 文字列 (既定ポートは落とす) */
  static originOf(url) {
    const port = url.port ? (DEFAULT_PORTS[url.protocol] === url.port ? '' : `:${url.port}`) : '';
    return `${url.protocol}//${url.hostname}${port}`;
  }

  encodeHost(origin) {
    if (this.encoding === 'plain') return `${SEG_PLAIN}.${encodeURIComponent(origin)}`;
    return `${SEG_TOKEN}.${b64u(origin)}`;
  }

  decodeHost(seg) {
    if (seg.startsWith(`${SEG_TOKEN}.`)) {
      const raw = seg.slice(SEG_TOKEN.length + 1);
      if (!/^[A-Za-z0-9\-_]+$/.test(raw)) return null;
      const decoded = unb64u(raw);
      if (!decoded) return null;
      try {
        return assertHttp(decoded);
      } catch {
        return null;
      }
    }
    if (seg.startsWith(`${SEG_PLAIN}.`)) {
      const raw = seg.slice(SEG_PLAIN.length + 1);
      try {
        return assertHttp(decodeURIComponent(raw));
      } catch {
        return null;
      }
    }
    return null;
  }

  /**
   * 上流 URL → このオリジン上のプロキシ済み URL
   * @param {string|URL} target 絶対URL
   * @param {string} sid
   * @param {string|{kind?:string, relative?:boolean, full?:boolean, meta?:object, keepHash?:boolean}} [optsOrKind]
   *   keepHash: ドキュメント遷移用。フラグメントは上流に送らないが、プロキシ URL 側に残すと
   *   ブラウザのスクロールと `location.hash` が自然に動く (サブリソースには不要なので既定は off)。
   */
  proxify(target, sid, optsOrKind = {}) {
    const opts = typeof optsOrKind === 'string' ? { kind: optsOrKind } : optsOrKind;
    const url = typeof target === 'string' ? safeUrl(target) : target;
    if (!url || !/^https?:$/.test(url.protocol)) return null;
    const path = url.pathname || '/';
    const search = url.search || '';
    const hash = opts.keepHash && url.hash ? url.hash : '';
    const built = `${this.sessionPrefix(sid)}/${this.encodeHost(UrlMap.originOf(url))}${path}${search}${hash}`;
    if (opts.full) return `${this.originFromMeta(opts.meta)}${built}`;
    return built;
  }

  originFromMeta(meta = {}) {
    return meta.origin || '';
  }

  /**
   * プロキシ済み path を逆引き
   * @param {string} rawPathname 生 pathname (%2F を復元しない)
   * @param {string} [search]
   * @returns {{sid:string, url:URL, ws:boolean}|null}
   */
  deproxify(rawPathname, search = '') {
    const parsed = this.parseSession(rawPathname);
    if (!parsed) return null;
    const { sid, marker, rest } = parsed;
    const segMatch = /^(h|u)\.(.+)$/.exec(marker || '');
    if (!segMatch) return null;
    const origin = this.decodeHost(marker);
    if (!origin) return null;
    let url;
    try {
      url = new URL(origin + (rest || '/'));
    } catch {
      return null;
    }
    if (search) url.search = search.startsWith('?') ? search : `?${search}`;
    return { sid, url, ws: url.protocol === 'ws:' || url.protocol === 'wss:' };
  }

  /**
   * path の切り出し (ルーター用)
   * @returns {{sid:string, marker:string, rest:string}|null}
   */
  parseSession(pathname) {
    if (!pathname.startsWith(this.prefix + '/')) return null;
    const tail = pathname.slice(this.prefix.length + 1);
    const parts = tail.split('/');
    const sid = parts.shift();
    if (!sid || !isSid(sid)) return null;
    const first = parts.shift() || '';
    return { sid, marker: first, rest: '/' + parts.join('/') };
  }

  isProxiedPath(pathname) {
    return this.parseSession(pathname) !== null;
  }

  /**
   * リクエスト先が「上流の絶対URL」を含む形態 (plain モード等のフォールバック) にも対応する。
   * 例: /mirage/t/<sid>/abs/https://example.com/x
   */
  parseAbs(pathname) {
    const parsed = this.parseSession(pathname);
    if (!parsed || parsed.marker !== 'abs') return null;
    const raw = pathname.slice(this.prefix.length + 1 + parsed.sid.length + 1 + 4);
    const url = safeUrl(decodeURIComponent(raw));
    return url ? { sid: parsed.sid, url } : null;
  }

  /** プロキシ済み URL から「上流の階層」を復元 (相対解決の基準) */
  static dirOf(url) {
    const p = url.pathname || '/';
    if (p.endsWith('/')) return p;
    const i = p.lastIndexOf('/');
    return (i <= 0 ? '/' : p.slice(0, i + 1)) || '/';
  }

  /** 同一 origin 内での再prefix構築に使う */
  sameOriginToken(url) {
    return this.encodeHost(UrlMap.originOf(url));
  }
}

function assertHttp(origin) {
  const u = new URL(origin);
  if (!/^https?:$/.test(u.protocol)) throw new Error('bad protocol');
  if (u.username || u.password) throw new Error('userinfo forbidden');
  return `${u.protocol}//${u.host}`;
}

export function safeUrl(s) {
  try {
    return new URL(s);
  } catch {
    return null;
  }
}

const SID_RE = /^[A-Za-z0-9_.-]{6,64}$/;
export function isSid(s) {
  return SID_RE.test(s);
}

/** クライアント側と同じロジックで proxify するためのスニペット (文字列として注入) */
export function clientCodecSource() {
  return `
  const DEFAULT_PORTS = { 'http:': '80', 'https:': '443' };
  const b64url = (str) => {
    const bytes = new TextEncoder().encode(str);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
  };
  const unb64url = (b64) => {
    const p = b64.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(p + '='.repeat((4 - (p.length % 4)) % 4));
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder().decode(bytes);
  };
  return {
    encoding: ENC,
    originOf(u) {
      const port = u.port ? (DEFAULT_PORTS[u.protocol] === u.port ? '' : ':' + u.port) : '';
      return u.protocol + '//' + u.hostname + port;
    },
    encodeHost(origin) {
      return ENC === 'plain' ? 'u.' + encodeURIComponent(origin) : 'h.' + b64url(origin);
    },
    decodeHost(seg) {
      try {
        if (seg.startsWith('h.')) return unb64url(seg.slice(2));
        if (seg.startsWith('u.')) return decodeURIComponent(seg.slice(2));
      } catch {}
      return null;
    },
  };
  `
    .replace(/ENC/g, JSON.stringify(this.encoding))
    .trim();
}

export default UrlMap;
