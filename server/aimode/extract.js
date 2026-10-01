/**
 * MirageVPN — Google AI Mode 回答抽出 (pure Node / 依存ゼロ)
 * ---------------------------------------------------------------
 * `https://www.google.com/search?q=...&udm=50` の HTML から
 * AI Mode の回答ブロック (`div[data-subtree="aimc"]`) を抜き出し、
 * 「本文 (markdown) / 引用 (citations) / 出典カード (sources) / 追加質問
 * (followUps)」に分解する。
 *
 * なぜ自前か: この repo は依存を express と ws だけに保つ方針なので、
 * DOM ライブラリを入れずに「タグスキャナ + 軽量ツリー + ウォーカ」で組む。
 * Google の DOM は変わるので、セレクタと打ち切りマーカーは全部
 * DEFAULT_OPTIONS に集約し、環境変数 (MIRAGE_AIMODE_*) で上書きできる。
 *
 * 壊れ方を前提にした設計:
 *   - 回答が取れなければ `{ ok:false, reason }` を返す (推測で埋めない)
 *   - 取れた場合も `confidence` と `warnings` を必ず返す
 *   - CAPTCHA / 同意ページ / 地域未対応 / 回答なしを別 reason で区別する
 *
 * @module aimode/extract
 */

import { matchTag, attrValue, decodeEntities } from '../proxy/rewrite.js';

/* ------------------------------------------------------------------ */
/* 既定値                                                               */
/* ------------------------------------------------------------------ */

/** 回答コンテナの候補 (上から順に試す) */
export const DEFAULT_CONTAINERS = [
  'div[data-subtree="aimc"]',
  'div[data-async-context] div[data-subtree]',
  '#im-box',
  'div[jsname="txFAF"]',
];

/** 会話 UI の Chrome (共有ダイアログ/フィードバック/スナックバー) を落とす */
const DEFAULT_NOISE_TAGS = new Set([
  'script',
  'style',
  'noscript',
  'svg',
  'template',
  'button',
  'textarea',
  'input',
  'select',
  'option',
  'form',
  'nav',
  'iframe',
  'canvas',
  'video',
  'audio',
]);

/** 属性があれば子孫ごと除外 (UI chrome) */
const DEFAULT_NOISE_ROLES = new Set(['dialog', 'alert', 'progressbar', 'tooltip', 'menu', 'navigation', 'tablist', 'search', 'button']);

/** ブロック要素。ここで「段落」が切れる */
const BLOCK_TAGS = new Set([
  'p',
  'div',
  'li',
  'ul',
  'ol',
  'h1',
  'h2',
  'h3',
  'h4',
  'h5',
  'h6',
  'table',
  'thead',
  'tbody',
  'tr',
  'td',
  'th',
  'blockquote',
  'pre',
  'section',
  'article',
  'aside',
  'figure',
  'figcaption',
  'hr',
  'dl',
  'dt',
  'dd',
]);

const VOID_TAGS = new Set([
  'area',
  'base',
  'br',
  'col',
  'embed',
  'hr',
  'img',
  'input',
  'link',
  'meta',
  'param',
  'source',
  'track',
  'wbr',
]);

/**
 * 暗黙の close (HTML の end tag 省略)。`closes` に当たるまでスタックを辿り、
 * `stop` に当たったら諦める (親子を壊さないため)。
 * 例: `<td>` は前の `<td>` を閉じるが、親の `<tr>` は閉じない。
 */
const IMPLICIT_CLOSE = {
  li: { closes: ['p', 'li'], stop: ['ul', 'ol', 'menu', '#root'] },
  dt: { closes: ['p', 'dt', 'dd'], stop: ['dl', '#root'] },
  dd: { closes: ['p', 'dt', 'dd'], stop: ['dl', '#root'] },
  tr: { closes: ['p', 'tr'], stop: ['table', 'thead', 'tbody', 'tfoot', '#root'] },
  td: { closes: ['p', 'td', 'th'], stop: ['tr', '#root'] },
  th: { closes: ['p', 'td', 'th'], stop: ['tr', '#root'] },
  option: { closes: ['option'], stop: ['select', 'datalist', 'optgroup', '#root'] },
};
// その他のブロック要素は「開いたままの <p>」を閉じる (親子是関係は保つ)
for (const t of [
  'p',
  'div',
  'ul',
  'ol',
  'h1',
  'h2',
  'h3',
  'h4',
  'h5',
  'h6',
  'table',
  'blockquote',
  'pre',
  'section',
  'article',
  'aside',
  'figure',
  'figcaption',
  'dl',
  'form',
  'header',
  'footer',
  'nav',
  'main',
  'fieldset',
  'hr',
  'details',
  'address',
]) {
  if (!IMPLICIT_CLOSE[t]) IMPLICIT_CLOSE[t] = { closes: ['p'], stop: ['#root'] };
}

/**
 * 「AI は間違えることがある」注意書き。回答本文はここで終わる。
 * Google はこの文をロケールごとに差し替えるので主要ロケールを並べる。
 * (設定で上書き可能。ここに頼らない構造判定も後段で効く)
 */
export const DEFAULT_DISCLAIMER_RE =
  /(can make mistakes?|hata yapabildi|間違うことがあります|間違いがある場合|Fehler machen|faire des erreurs|cometer errores|cometer erros|può commettere errori|kan fouten maken|puede cometer|erreurs|kan göra misstag|może popełniać błędy|może mylić|may be inaccurate|double-?check)/i;

/** 出典トグルの aria-label ("9 site" / "12 sources" / "9 件") */
export const DEFAULT_SOURCES_LABEL_RE = /^\s*\d+\s*(site|sites|kaynak|kaynağı|source|sources|来源|サイト|件|출처)\s*$/i;

/** Google 自身のホスト (引用には数えない) */
export const DEFAULT_GOOGLE_HOSTS = [
  'google.com',
  'gstatic.com',
  'googleusercontent.com',
  'ggpht.com',
  'youtube.com',
  'youtu.be',
  'goo.gl',
];

/** 日付 ("21 Oca 2026 —" / "Jan 21, 2026" / "2026年1月21日") */
const DATE_RE = /(\d{1,2}\s+[A-Z][a-zÇĞİÖŞÜçğıöşü]{2,8}\.?\s+\d{4}|[A-Z][a-z]{2,8}\.?\s+\d{1,2},?\s+\d{4}|\d{4}\s*年\s*\d{1,2}\s*月\s*\d{1,2}\s*日)/;

/** Chrome 区間の判りにくい言語のための語彙 (フォールバック判定用) */
const CHROME_WORDS_RE =
  /(copy|kopyala|paylaş|paylas|share|teile|copiar|copier|コピー|共有|good response|bad response|iyi yanıt|kötü yanıt|thanks|teşekkür|danke|gracias|helpful|not helpful|faydalı|yardımcı|feedback|geri bildirim)/i;

/** 回答として出す最大ブロック数 (暴走防止) */
const MAX_BLOCKS = 600;

export const DEFAULT_OPTIONS = {
  containers: DEFAULT_CONTAINERS,
  noiseTags: DEFAULT_NOISE_TAGS,
  noiseRoles: DEFAULT_NOISE_ROLES,
  disclaimerRe: DEFAULT_DISCLAIMER_RE,
  sourcesLabelRe: DEFAULT_SOURCES_LABEL_RE,
  googleHosts: DEFAULT_GOOGLE_HOSTS,
};

/* ------------------------------------------------------------------ */
/* タグスキャナ                                                         */
/* ------------------------------------------------------------------ */

/**
 * HTML の断片 [from, to) を軽量ツリーに直す。
 * @returns {{tag:string, attrs:Array, children:Array, text?:string}[]}
 */
export function parseFragment(html, from = 0, to = html.length) {
  const root = { tag: '#root', attrs: [], children: [] };
  const stack = [root];
  let i = from;

  const top = () => stack[stack.length - 1];
  const push = (node) => top().children.push(node);

  while (i < to) {
    const lt = html.indexOf('<', i);
    if (lt < 0 || lt >= to) {
      const text = html.slice(i, to);
      if (text.trim()) push({ tag: '#text', attrs: [], children: [], text });
      break;
    }
    if (lt > i) {
      const text = html.slice(i, lt);
      if (text.trim()) push({ tag: '#text', attrs: [], children: [], text });
    }
    if (html.startsWith('<!--', lt)) {
      const end = html.indexOf('-->', lt + 4);
      i = end < 0 ? to : end + 3;
      continue;
    }
    if (html.startsWith('<!', lt) || html.startsWith('<?', lt)) {
      const end = html.indexOf('>', lt);
      i = end < 0 ? to : end + 1;
      continue;
    }
    // 終了タグ (matchTag は開始タグしか受けないので先に処理)
    if (html[lt + 1] === '/') {
      const cm = /^<\/([a-zA-Z][a-zA-Z0-9:-]*)\s*>/.exec(html.slice(lt, lt + 64));
      if (cm) {
        const cname = cm[1].toLowerCase();
        for (let k = stack.length - 1; k > 0; k--) {
          if (stack[k].tag === cname) {
            stack.length = k;
            break;
          }
        }
        i = lt + cm[0].length;
        continue;
      }
      i = lt + 1;
      continue;
    }
    const tag = matchTag(html, lt);
    if (!tag) {
      i = lt + 1;
      continue;
    }
    const name = tag.tagName.toLowerCase();
    // 暗黙の close (li/p/tr/td...) — closes に当たるまでだけ辿る
    const implied = IMPLICIT_CLOSE[name];
    if (implied) {
      for (let k = stack.length - 1; k > 0; k--) {
        const open = stack[k].tag;
        if (implied.closes.includes(open)) {
          stack.length = k;
          break;
        }
        if (implied.stop.includes(open)) break;
      }
    }
    const node = { tag: name, attrs: tag.attrs, children: [] };
    push(node);
    if (!VOID_TAGS.has(name) && !tag.selfClosing) stack.push(node);
    i = tag.end;
  }
  return root.children;
}

/** 属性値を取る (HTML エンティティは戻す) */
function attr(node, name) {
  const v = attrValue(node.attrs, name);
  return v === null || v === undefined ? null : decodeEntities(String(v));
}

function hasAttr(node, name) {
  return node.attrs.some(([k]) => k.toLowerCase() === name);
}

function classList(node) {
  return (attr(node, 'class') || '').split(/\s+/).filter(Boolean);
}

function styleOf(node) {
  return (attr(node, 'style') || '').toLowerCase();
}

/** 表示されていない要素 (display:none / hidden / visibility:hidden) */
function isHidden(node) {
  if (hasAttr(node, 'hidden')) return true;
  const s = styleOf(node);
  if (!s) return false;
  return /display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?!\.)/.test(s);
}

/** 子孫のテキストを連結 */
function textOf(node) {
  if (node.tag === '#text') return node.text || '';
  let out = '';
  for (const c of node.children) out += textOf(c);
  return out;
}

/** ツリー内の全要素 (自分を含む) を深さ優先で */
function* walk(node) {
  if (node.tag !== '#text') yield node;
  for (const c of node.children) yield* walk(c);
}

/** parent を張る (セレクタの祖先判定用) */
function linkParents(nodes, parent = null) {
  for (const n of nodes) {
    n.parent = parent;
    if (n.children?.length) linkParents(n.children, n);
  }
}

/* ------------------------------------------------------------------ */
/* セレクタ                                                             */
/* ------------------------------------------------------------------ */

/**
 * 超簡易セレクタ: `tag` / `#id` / `.class` / `[attr]` / `[attr="v"]` /
 * `tag[attr="v"]` / `A B` (子孫)。
 * @returns {(node:object)=>boolean|null}
 */
function compileSelector(sel) {
  const parts = String(sel).trim().split(/\s+/).filter(Boolean);
  const compiled = parts.map(compileSimple);
  if (compiled.some((c) => !c)) return null;
  return (node) => {
    if (!compiled[compiled.length - 1](node)) return false;
    let idx = compiled.length - 2;
    let p = node.parent;
    while (idx >= 0 && p) {
      if (compiled[idx](p)) idx--;
      p = p.parent;
    }
    return idx < 0;
  };
}

function compileSimple(part) {
  const tagM = /^[a-zA-Z][a-zA-Z0-9-]*/.exec(part);
  const tag = tagM ? tagM[0].toLowerCase() : '';
  const rest = part.slice(tag.length);
  const tests = [];
  if (tag) tests.push((n) => n.tag === tag);
  let i = 0;
  while (i < rest.length) {
    const ch = rest[i];
    if (ch === '#') {
      const m = /^#([^#.[]+)/.exec(rest.slice(i));
      if (!m) return null;
      tests.push((n) => attr(n, 'id') === m[1]);
      i += m[0].length;
    } else if (ch === '.') {
      const m = /^\.([^#.[]+)/.exec(rest.slice(i));
      if (!m) return null;
      tests.push((n) => classList(n).includes(m[1]));
      i += m[0].length;
    } else if (ch === '[') {
      const m = /^\[([a-zA-Z0-9_:.-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\]]*)))?\]/.exec(rest.slice(i));
      if (!m) return null;
      const name = m[1].toLowerCase();
      const val = m[2] !== undefined ? m[2] : m[3] !== undefined ? m[3] : m[4];
      if (val === undefined) tests.push((n) => hasAttr(n, name));
      else tests.push((n) => attr(n, name) === val);
      i += m[0].length;
    } else return null;
  }
  return (n) => tests.every((t) => t(n));
}

/* ------------------------------------------------------------------ */
/* Chrome 落とし                                                        */
/* ------------------------------------------------------------------ */

/** opts.skipRoots に含まれるサブツリーか (出典パネル等) */
function inSkipRoot(node, skipRoots) {
  if (!skipRoots?.length) return false;
  let p = node;
  while (p) {
    if (skipRoots.includes(p)) return true;
    p = p.parent;
  }
  return false;
}

/** UI chrome (ダイアログ/スナックバー/ボタン/非表示/出典パネル) か */
export function isNoise(node, opts) {
  if (opts.skipRoots && inSkipRoot(node, opts.skipRoots)) return true;
  if (opts.noiseTags.has(node.tag)) return true;
  const role = (attr(node, 'role') || '').toLowerCase();
  if (role && opts.noiseRoles.has(role)) return true;
  if (hasAttr(node, 'popover')) return true;
  if (hasAttr(node, 'aria-live')) return true;
  if ((attr(node, 'aria-hidden') || '').toLowerCase() === 'true') return true;
  if (isHidden(node)) return true;
  return false;
}

/* ------------------------------------------------------------------ */
/* ブロック化 (markdown)                                                */
/* ------------------------------------------------------------------ */

const HEADING_RE = /^h([1-6])$/;

/**
 * ツリーを「段落ブロック」の列に落とす。インラインは markdown に変換。
 * @returns {{kind:string, text:string, raw:string, node:object, level?:number}[]}
 */
export function toBlocks(nodes, opts, out = []) {
  let inline = '';
  let inlineNode = null;
  const flush = () => {
    const t = inline.trim();
    if (t) out.push({ kind: 'p', text: t, raw: t, node: inlineNode });
    inline = '';
    inlineNode = null;
  };

  for (const node of nodes) {
    if (node.tag === '#text') {
      inline += ' ' + collapse(node.text || '');
      if (!inlineNode) inlineNode = node;
      continue;
    }
    if (isNoise(node, opts)) continue;
    const tag = node.tag;
    if (BLOCK_TAGS.has(tag)) {
      flush();
      const h = HEADING_RE.exec(tag);
      if (h) {
        const t = collapse(textOf(node));
        if (t) out.push({ kind: 'heading', level: Number(h[1]), text: t, raw: t, node });
        continue;
      }
      if (tag === 'li') {
        const t = inlineOf(node, opts);
        if (t) out.push({ kind: 'li', text: t, raw: t, node });
        continue;
      }
      if (tag === 'hr') {
        out.push({ kind: 'hr', text: '', raw: '', node });
        continue;
      }
      if (tag === 'tr') {
        const cells = node.children.filter((c) => c.tag === 'td' || c.tag === 'th').map((c) => inlineOf(c, opts)).filter(Boolean);
        if (cells.length) out.push({ kind: 'row', text: cells.join(' | '), raw: cells.join(' | '), node });
        continue;
      }
      // ラッパ (div/section/ul/ol/table...) は中を再帰
      toBlocks(node.children, opts, out);
      continue;
    }
    // インライン
    const inner = inlineOf(node, opts);
    if (!inner) continue;
    if (tag === 'strong' || tag === 'b') inline += ` **${inner}**`;
    else if (tag === 'em' || tag === 'i') inline += ` _${inner}_`;
    else if (tag === 'code') inline += ` \`${inner}\``;
    else if (tag === 'a') {
      const href = attr(node, 'href');
      inline += href ? ` [${inner}](${href})` : ` ${inner}`;
    } else if (tag === 'br') inline += ' ';
    else inline += ` ${inner}`;
    if (!inlineNode) inlineNode = node;
  }
  flush();
  return out;
}

/** インライン要素の中身を markdown 化 (ブロックは改行扱い) */
function inlineOf(node, opts) {
  if (node.tag === '#text') return collapse(node.text || '');
  if (isNoise(node, opts)) return '';
  let out = '';
  for (const c of node.children) {
    if (c.tag === '#text') {
      out += ' ' + collapse(c.text || '');
      continue;
    }
    if (isNoise(c, opts)) continue;
    if (BLOCK_TAGS.has(c.tag)) {
      out += ' ' + inlineOf(c, opts) + ' ';
      continue;
    }
    const inner = inlineOf(c, opts);
    if (!inner) continue;
    if (c.tag === 'strong' || c.tag === 'b') out += ` **${inner}**`;
    else if (c.tag === 'em' || c.tag === 'i') out += ` _${inner}_`;
    else if (c.tag === 'code') out += ` \`${inner}\``;
    else if (c.tag === 'a') {
      const href = attr(c, 'href');
      out += href ? ` [${inner}](${href})` : ` ${inner}`;
    } else out += ` ${inner}`;
  }
  return collapse(out);
}

function collapse(s) {
  return decodeEntities(String(s || ''))
    .replace(/[\t\r\xa0]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/* ------------------------------------------------------------------ */
/* 引用 / 出典                                                          */
/* ------------------------------------------------------------------ */

/**
 * Google のリダイレクト包装 (`/url?q=` `/goto?url=`) を剥がす。
 * @returns {string|null|{wrapped:string}} 解決不能な包装は {wrapped}
 */
export function unwrapGoogleUrl(href) {
  if (!href) return null;
  const raw = String(href).trim();
  if (!raw) return null;
  try {
    const base = 'https://www.google.com';
    const u = new URL(raw, base);
    const q = u.searchParams.get('q') || u.searchParams.get('url');
    if ((u.pathname === '/url' || u.pathname === '/goto') && q) {
      // q が絶対 URL のときだけ剥がせる。署名ブロブ (/goto?url=CAES...) は
      // 相対パスとして解決できてしまうので、スキームを見て弾く。
      if (/^https?:\/\//i.test(q)) {
        const inner = new URL(q, base);
        if (/^https?:$/.test(inner.protocol)) return inner.href;
      }
      return { wrapped: raw };
    }
    if (/^https?:$/.test(u.protocol) && u.hostname !== 'www.google.com') return u.href;
    if (u.hostname === 'www.google.com' && (u.pathname === '/url' || u.pathname === '/goto')) return { wrapped: raw };
    return null;
  } catch {
    return null;
  }
}

function isGoogleHost(host, googleHosts) {
  const h = String(host || '').toLowerCase().replace(/^www\./, '');
  return googleHosts.some((g) => h === g || h.endsWith(`.${g}`));
}

/** aria-label に混ざる UI の文脈語を落とす */
const SECTION_SUFFIX_RE =
  /[\s.|·]*[–—-]?\s*([İI]lgili (sonu[çc]lar|videolar)|Related (results|videos)|関連する(結果|動画)|Resultados relacionados|Résultats associés|Ähnliche Ergebnisse|Gerelateerde resultaten)\s*\.?\s*$/i;
const NEWTAB_SUFFIX_RE =
  /[.\s|·]*(Yeni sekmede a[çc][ıi]l[ıi]r|Yeni sekmede a[çc][ıi]l[ıi]yor|Opens in new tab|Open in new tab|新しいタブで開く|Se abre en una nueva pestaña|S'ouvre dans un nouvel onglet|Wird in neuem Tab geöffnet|Opent in nieuw tabblad)\s*\.?\s*$/i;

/**
 * Google のリンクラベルを {title, site} に分解する。
 * 典型形: `"<site> - <page title> | <site name>. İlgili sonuçlar"`
 * @returns {{title:string, site:string}}
 */
export function parseLinkLabel(label) {
  let s = decodeEntities(String(label || ''))
    .replace(SECTION_SUFFIX_RE, '')
    .replace(NEWTAB_SUFFIX_RE, '')
    .replace(/\s{2,}/g, ' ')
    .trim();
  let site = '';
  const pipe = s.lastIndexOf(' | ');
  if (pipe > 0) {
    site = s.slice(pipe + 3).trim();
    s = s.slice(0, pipe).trim();
  }
  let title = s;
  const dash = s.indexOf(' - ');
  if (dash > 0 && dash < 60) {
    title = s.slice(dash + 3).trim();
    if (!site) site = s.slice(0, dash).trim();
  }
  return { title: title || s, site };
}

/**
 * コンテナ内の外部リンクを引用として集める (出現順・重複排除)
 * @returns {{url:string, domain:string, title:string, site:string, wrapped:boolean, rawHref:string}[]}
 */
function collectCitations(rootNodes, opts) {
  const seen = new Map();
  for (const node of rootNodes) {
    for (const el of walk(node)) {
      if (el.tag !== 'a') continue;
      const href = attr(el, 'href');
      if (!href) continue;
      const unwrapped = unwrapGoogleUrl(href);
      const wrapped = !!(unwrapped && typeof unwrapped === 'object' && unwrapped.wrapped);
      const url = typeof unwrapped === 'string' ? unwrapped : null;
      if (!url && !wrapped) continue; // Google 内部/相対リンクは引用ではない
      let host = null;
      if (url) {
        try {
          host = new URL(url).hostname;
        } catch {
          host = null;
        }
      }
      if (url && isGoogleHost(host, opts.googleHosts)) continue;
      const key = url ? url.replace(/#.*$/, '').replace(/\/$/, '') : `wrapped:${href}`;
      if (seen.has(key)) continue;
      const parsed = parseLinkLabel(attr(el, 'aria-label') || inlineOf(el, opts));
      seen.set(key, {
        url,
        domain: host ? host.replace(/^www\./, '') : null,
        host,
        title: (parsed.title || '').slice(0, 300),
        site: (parsed.site || '').slice(0, 120),
        wrapped,
        rawHref: href,
      });
    }
  }
  return [...seen.values()];
}

/**
 * 出典カード (タイトル/日付/出典名/スニペット) を復元する。
 * Google は「N site」トグル以降 (ダイアログ内) に `<li>` でカードを並べる。
 * 回答側の `<li>` (製品名の箇条書き) と混同しないため、
 * 「N site」トグルを含むサブツリーにだけ侵入する。
 */
function collectSources(root, citations, opts) {
  const byUrl = new Map(citations.map((c, i) => [c.url ? c.url.replace(/#.*$/, '').replace(/\/$/, '') : `wrapped:${c.rawHref}`, i]));
  const sources = [];
  for (const li of walk(root)) {
    if (li.tag !== 'li') continue;
    const anchors = [...walk(li)].filter((e) => e.tag === 'a' && attr(e, 'href'));
    if (!anchors.length) continue;
    const first = anchors[0];
    const url = unwrapGoogleUrl(attr(first, 'href'));
    if (typeof url !== 'string') continue;
    let host;
    try {
      host = new URL(url).hostname;
    } catch {
      continue;
    }
    if (isGoogleHost(host, opts.googleHosts)) continue;
    // カード内のテキスト断片
    const frags = [];
    const collect = (n) => {
      for (const c of n.children) {
        if (c.tag === '#text') {
          const t = collapse(c.text || '');
          if (t) frags.push(t);
        } else if (!isNoise(c, opts)) collect(c);
      }
    };
    collect(li);
    const parsed = parseLinkLabel(attr(first, 'aria-label') || '');
    const title = parsed.title || frags[0] || '';
    const date = frags.find((f) => DATE_RE.test(f)) || '';
    const domain = host.replace(/^www\./, '');
    const rest = frags.filter((f) => f !== title && f !== date && f !== parsed.site);
    const source =
      (parsed.site && parsed.site !== title ? parsed.site : '') ||
      rest.find((f) => f === domain) ||
      rest.find((f) => /^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/i.test(f)) ||
      rest
        .filter((f) => f.length <= 40 && /^[A-Za-z0-9 .ÇĞİÖŞÜçğıöşü&'’+-]+$/.test(f))
        .sort((a, b) => a.length - b.length)[0] ||
      domain;
    const snippet =
      frags
        .filter((f) => f !== title && f !== date && f !== source && f.length > 30)
        .sort((a, b) => b.length - a.length)[0] || '';
    const key = url.replace(/#.*$/, '').replace(/\/$/, '');
    const idx = byUrl.get(key);
    sources.push({
      url,
      domain,
      title: title.slice(0, 300),
      source: source.slice(0, 120),
      date: date.replace(/\s*[—-]\s*$/, '').slice(0, 40),
      snippet: snippet.slice(0, 600),
      citationIndex: idx === undefined ? null : idx,
    });
  }
  // 重複排除 (URL キー)
  const seen = new Set();
  return sources.filter((s) => {
    const k = s.url.replace(/#.*$/, '').replace(/\/$/, '');
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/**
 * 出典パネルの根を探す。「N site」トグル (aria-label) を持つ要素から
 * 祖先を辿り、外部アンカ付き `<li>` を 2 個以上含む最初の祖先を返す。
 */
function findSourcesRoot(rootNodes, opts) {
  let toggle = null;
  for (const node of rootNodes) {
    for (const el of walk(node)) {
      const label = attr(el, 'aria-label');
      if (label && opts.sourcesLabelRe.test(label)) {
        toggle = el;
        break;
      }
    }
    if (toggle) break;
  }
  const cardCount = (n) => {
    let count = 0;
    for (const li of walk(n)) {
      if (li.tag !== 'li') continue;
      const a = [...walk(li)].find((e) => e.tag === 'a' && attr(e, 'href') && typeof unwrapGoogleUrl(attr(e, 'href')) === 'string');
      if (a) count++;
    }
    return count;
  };
  if (toggle) {
    // ダイアログ境界までは昇らない (回答側の<ul>を巻き込まない)
    let p = toggle;
    for (let depth = 0; p && depth < 8; depth++) {
      const role = (attr(p, 'role') || '').toLowerCase();
      if (role === 'dialog' && cardCount(p) >= 2) return p;
      if (cardCount(p) >= 2) return p;
      p = p.parent;
    }
  }
  // フォールバック: ダイアログの中で最もカードが多いもの
  let best = null;
  let bestN = 0;
  for (const node of rootNodes) {
    for (const el of walk(node)) {
      if ((attr(el, 'role') || '').toLowerCase() !== 'dialog') continue;
      const n = cardCount(el);
      if (n > bestN) {
        bestN = n;
        best = el;
      }
    }
  }
  return best;
}

/* ------------------------------------------------------------------ */
/* メイン                                                               */
/* ------------------------------------------------------------------ */

/**
 * @param {string|Buffer} html `udm=50` のレスポンス HTML
 * @param {Partial<typeof DEFAULT_OPTIONS>} [options]
 * @returns {{
 *  ok:boolean, reason?:string, answer?:string, text?:string,
 *  blocks?:object[], citations?:object[], sources?:object[], followUps?:string[],
 *  confidence?:number, warnings?:string[], stats?:object, container?:string
 * }}
 */
export function extractAiMode(html, options = {}) {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  const src = Buffer.isBuffer(html) ? html.toString('utf8') : String(html || '');
  if (!src) return { ok: false, reason: 'empty_html', warnings: ['空のレスポンス'] };

  /* --- 0. ブロック/同意 --- */
  if (/(^|\W)(unusual traffic|systems have detected|recaptcha|not a robot)/i.test(src) || src.includes('/sorry/index')) {
    return { ok: false, reason: 'captcha', warnings: ['CAPTCHA / reCAPTCHA ページ — 出口 IP が枯れています'] };
  }
  if ((/consent\.google\.com|before you continue/i.test(src) || src.includes('/sorry/')) && !src.includes('data-subtree="aimc"')) {
    return { ok: false, reason: 'consent_required', warnings: ['Google の同意/ブロックページが返りました (SOCS クッキーと出口国を確認)'] };
  }

  /* --- 1. コンテナを抜く --- */
  let containerHtml = null;
  let containerSel = null;
  for (const sel of opts.containers) {
    const span = findElementSpan(src, sel);
    if (span) {
      containerHtml = src.slice(span.start, span.end);
      containerSel = sel;
      break;
    }
  }
  if (!containerHtml) {
    if (/id="im-box"|data-subtree="aimc"|role="heading"/.test(src)) {
      return { ok: false, reason: 'container_not_found', warnings: ['aimc コンテナが見つかりません (DOM 変更の可能性)'] };
    }
    return { ok: false, reason: 'no_answer', warnings: ['AI Mode の回答ブロックがありません (このクエリ/地域では非表示)'] };
  }

  /* --- 2. ツリー化 --- */
  const nodes = parseFragment(containerHtml);
  linkParents(nodes, null);
  if (!nodes.length) return { ok: false, reason: 'empty_container', warnings: ['コンテナは空です'] };

  /* --- 3. 出典パネルを特定し、回答側からは除外する --- */
  const sourcesRoot = findSourcesRoot(nodes, opts);
  const blockOpts = sourcesRoot ? { ...opts, skipRoots: [sourcesRoot] } : opts;

  /* --- 4. ブロック化 (Chrome は isNoise で除去済み) --- */
  let blocks = toBlocks(nodes, blockOpts).slice(0, MAX_BLOCKS);

  /* --- 5. 回答の終点を探す --- */
  const cut = findAnswerCut(blocks, opts);
  const warnings = [];
  if (cut.by === 'fallback') {
    warnings.push('注意書き/Chrome の境界が見つからなかったのでフォールバック境界で切断しました');
  }
  blocks = blocks.slice(0, cut.index);

  /* --- 6. 引用/出典/追加質問 --- */
  const citations = collectCitations(nodes, opts);
  const sources = sourcesRoot ? collectSources(sourcesRoot, citations, opts) : [];
  const followUps = collectFollowUps(nodes, blockOpts);

  const answer = blocksToMarkdown(blocks);
  const text = blocks.map((b) => b.text).join('\n\n').trim();
  if (!text) {
    return {
      ok: false,
      reason: 'empty_answer',
      container: containerSel,
      citations,
      sources,
      followUps,
      warnings: [...warnings, 'コンテナは取れたが本文テキストが空でした (JS ストリーミング未完の可能性)'],
      stats: { blocks: blocks.length, citations: citations.length, sources: sources.length },
    };
  }

  return {
    ok: true,
    answer,
    text,
    blocks: blocks.map((b) => ({ kind: b.kind, text: b.text, level: b.level })),
    citations: citations.map((c, i) => ({ index: i + 1, ...c })),
    sources,
    followUps,
    confidence: cut.by === 'disclaimer' ? 0.9 : cut.by === 'sources' ? 0.75 : 0.5,
    warnings,
    container: containerSel,
    stats: {
      blocks: blocks.length,
      citations: citations.length,
      sources: sources.length,
      wrappedCitations: citations.filter((c) => c.wrapped).length,
      chars: text.length,
    },
  };
}

/* ------------------------------------------------------------------ */
/* 境界判定                                                             */
/* ------------------------------------------------------------------ */

/**
 * 回答ブロックの終点を返す。優先順:
 *   1. 注意書き (「AI は間違えることがある」) — 最も信頼できる
 *   2. 出典トグル ("9 site") — 回答の後に出典パネルが来る
 *   3. フォールバック — 短文の Chrome 連鎖が始まる位置
 */
function findAnswerCut(blocks, opts) {
  for (let i = 0; i < blocks.length; i++) {
    const b = blocks[i];
    if (b.kind === 'p' && opts.disclaimerRe.test(b.text) && b.text.length < 400) {
      return { index: i, by: 'disclaimer' };
    }
    if (b.kind === 'p' && opts.sourcesLabelRe.test(b.text) && b.text.length < 60) {
      return { index: i, by: 'sources' };
    }
  }
  // フォールバック: 4 個以上の短文が連続し、その中に Chrome 語が 1 つでもあれば
  // そこで Chrome 区間が始まったとみなす (注意書きの文言が変わった時の逃げ道)
  for (let i = 1; i + 3 < blocks.length; i++) {
    const run = [blocks[i], blocks[i + 1], blocks[i + 2], blocks[i + 3]];
    if (!run.every((b) => b.kind === 'p' && b.text.split(/\s+/).length <= 4)) continue;
    if (run.some((b) => CHROME_WORDS_RE.test(b.text))) return { index: i, by: 'fallback' };
  }
  return { index: blocks.length, by: 'none' };
}

/** 追加質問 (フォローアップ) チップ。Chrome を避けて疑問文だけ拾う */
function collectFollowUps(rootNodes, opts) {
  const out = [];
  const seen = new Set();
  for (const node of rootNodes) {
    for (const el of walk(node)) {
      if (el.tag !== '#text' && el.tag !== 'li' && el.tag !== 'div' && el.tag !== 'span') continue;
      const t = collapse(ownText(el));
      if (!t || t.length < 12 || t.length > 160) continue;
      if (!/[?？]$/.test(t)) continue;
      if (opts.disclaimerRe.test(t)) continue;
      if (seen.has(t)) continue;
      seen.add(t);
      out.push(t);
    }
  }
  return out.slice(0, 8);
}

/** その要素直属のテキスト (子孫要素のテキストは除外) */
function ownText(node) {
  if (node.tag === '#text') return node.text || '';
  let out = '';
  for (const c of node.children) if (c.tag === '#text') out += ' ' + (c.text || '');
  return out;
}

function blocksToMarkdown(blocks) {
  const lines = [];
  for (const b of blocks) {
    if (b.kind === 'li') {
      lines.push(`- ${b.text}`);
      continue;
    }
    if (b.kind === 'heading') lines.push(`${'#'.repeat(Math.min(6, b.level || 2))} ${b.text}`);
    else if (b.kind === 'row') lines.push(b.text);
    else if (b.kind === 'hr') lines.push('---');
    else lines.push(b.text);
  }
  return lines.join('\n\n').trim();
}

/* ------------------------------------------------------------------ */
/* HTML 断片中の要素境界                                                */
/* ------------------------------------------------------------------ */

/**
 * セレクタに一致する最初の要素の [start, end) を HTML 文字列上で返す。
 * @returns {{start:number,end:number}|null}
 */
export function findElementSpan(html, selector) {
  const test = compileSelector(selector);
  if (!test) return null;
  const tagRe = /<(\/?)([a-zA-Z][a-zA-Z0-9:-]*)((?:[^>"']|"[^"]*"|'[^']*')*?)(\/?)>/g;
  const stack = [];
  let m;
  while ((m = tagRe.exec(html))) {
    const name = m[2].toLowerCase();
    if (m[1] === '/') {
      for (let k = stack.length - 1; k >= 0; k--) {
        if (stack[k].tag === name) {
          stack.length = k;
          break;
        }
      }
      continue;
    }
    const attrs = parseAttrString(m[3] || '');
    const node = { tag: name, attrs, children: [], parent: stack.length ? stack[stack.length - 1].node : null };
    if (test(node)) {
      const selfClosing = VOID_TAGS.has(name) || m[4] === '/';
      return { start: m.index, end: selfClosing ? m.index + m[0].length : findMatchingEnd(html, tagRe.lastIndex, name) };
    }
    if (!VOID_TAGS.has(name) && m[4] !== '/') stack.push({ tag: name, node });
  }
  return null;
}

/** name の対応する終了タグまで (同名の入れ子を数える) */
function findMatchingEnd(html, from, name) {
  const re = new RegExp(`<(/?)([a-zA-Z][a-zA-Z0-9:-]*)((?:[^>"']|"[^"]*"|'[^']*')*?)(/?)>`, 'g');
  re.lastIndex = from;
  let depth = 1;
  let m;
  while ((m = re.exec(html))) {
    if (m[2].toLowerCase() !== name) continue;
    if (m[1] === '/') {
      depth--;
      if (depth === 0) return m.index + m[0].length;
    } else if (m[4] !== '/' && !VOID_TAGS.has(name)) depth++;
  }
  return html.length;
}

/** 属性文字列を [name, value] の配列に (matchTag と同型) */
function parseAttrString(s) {
  const out = [];
  const re = /([a-zA-Z0-9_:.$-]{1,80})(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g;
  let m;
  while ((m = re.exec(s))) {
    const name = m[1].toLowerCase();
    if (!name || name === '/') continue;
    const value = m[3] !== undefined ? m[3] : m[4] !== undefined ? m[4] : m[2] !== undefined ? m[2] : null;
    out.push([name, value]);
  }
  return out;
}

export default extractAiMode;
