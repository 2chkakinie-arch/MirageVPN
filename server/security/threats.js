/**
 * MirageVPN 脅威エンジン — リアルタイム検知 + 自動削除 + レポート
 * ---------------------------------------------------------------
 * 「ページを表示する前に、ページ自身を疑う」層。
 *
 *  - inspectUrl()      … リクエスト先の実態 (タイポスキッティング / 短縮URL / 危険TLD / 既知 badware)
 *  - inspectDocument() … HTML/CSS/JS を構文レベルで検査し、危険な node・attr を「削除指示」付きで返す
 *  - inspectAsset()    … script / css / json の難読化・マイナー・キーロガー・外部送信を判定
 *  - inspectDownload() … 危険拡張子・MIME 偽装・二重拡張子を判定
 *
 * score は 0..100。`sanitizeScore` 以上で該当要素を自動除去、`blockScore` 以上で表示そのものを遮断。
 * すべての検知はレポート (リングバッファ + 任意で disk) に残り、UI と JSON エクスポートから確認できる。
 * @module security/threats
 */

import { Ring, entropy, lev, registrableDomain, isIpLiteral, sha1 } from '../util.js';
import { log } from '../log.js';

const ns = log.child('threats');

/** 短縮/転送サービス (リダイレクトで真の送信先が隠れる) */
const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'cutt.ly', 'rb.gy',
  'rebrand.ly', 'shorturl.at', 't.ly', 'urlz.fr', 'clck.ru', 'v.gd', 'soo.gd', 'lnkd.in', 'trib.al',
]);

/** 濫用されやすい TLD */
const RISKY_TLDS = new Set([
  'zip', 'mov', 'top', 'click', 'link', 'country', 'work', 'gq', 'tk', 'ml', 'cf', 'ga', 'sbs', 'cyou',
  'monster', 'quest', 'beauty', 'fit', 'loan', 'download', 'stream', 'download', 'date', 'racing', 'trade',
]);

/** 良く使われるドメインの偽装候補 (タイポスキッティング) */
const PROTECTED = [
  'google.com', 'youtube.com', 'gmail.com', 'amazon.com', 'apple.com', 'microsoft.com', 'netflix.com',
  'facebook.com', 'instagram.com', 'twitter.com', 'x.com', 'paypal.com', 'github.com', 'line.me',
  'yahoo.co.jp', 'rakuten.co.jp', 'docomo.ne.jp', 'softbank.ne.jp', 'au.com', 'mp.go.jp', 'ntt.com',
  'co.jp', 'g.jp', 'meti.go.jp', 'nicovideo.jp', 'pixiv.net', 'mercari.com', 'yahoo.com', 'icbc.com.cn',
];

const MINER_TOKENS = [
  'coinhive', 'coin-hive', 'coinimp', 'cryptoloot', 'cryptonight', 'jsecoin', 'minero', 'webminepool',
  'supportxmr', 'monero', 'mineris', 'nicehash', 'crypto-loot', 'happycookie', 'projectpork', 'deepminer',
];

const KEYLOGGER_TOKENS = [
  'keylogger', 'keydown-all', 'k3yl0g', 'recordkeys', 'spykeys', 'klog', 'hwks', 'logkeys',
];

// 「ブラウザで踏んだら怪しい」に絞る。.js / .json / .css は普通に見るのでここに入れない
// (入れてると <script> が全部止まって_web-proxy として使えなくなる)。
const DANGEROUS_EXT = [
  '.exe', '.scr', '.pif', '.vbs', '.vbe', '.wsf', '.wsh', '.msi', '.msp', '.msix',
  '.jar', '.bat', '.cmd', '.com', '.ps1', '.psm1', '.lnk', '.hta', '.cpl', '.chm',
  '.iso', '.img', '.scpt', '.command', '.apk', '.dex', '.gadget', '.reg', '.application',
];
const DANGEROUS_MIME = new Set([
  'application/x-msdownload',
  'application/x-msdos-program',
  'application/x-win-lnk',
  'application/x-msi',
  'application/vnd.microsoft.portable-executable',
  'application/x-ms-application',
  'application/x-ms-xbap',
  'application/bat',
  'application/x-sh',
]);

const OBFUSCATION_HINTS = [
  { re: /_0x[0-9a-f]{4,}/gi, name: 'javascript-obfuscator 変数名', weight: 22 },
  { re: /\bString\.fromCharCode\s*\(\s*(?:\d{1,3}\s*,\s*){8,}/gi, name: 'fromCharCode による文字列生成', weight: 26 },
  { re: /\batob\s*\(\s*['"][A-Za-z0-9+/=]{40,}['"]\s*\)/g, name: 'base64 デコードで読み込まれるスクリプト', weight: 24 },
  { re: /\beval\s*\(\s*(?:atob|unescape|decodeURIComponent|Function)/gi, name: '難読化文字列の eval 実行', weight: 34 },
  { re: /\bFunction\s*\(\s*(?:atob|unescape|['"]return)/gi, name: '動的 Function コンストラクタ', weight: 22 },
  { re: /\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/gi, name: '_hex エスケープの連鎖', weight: 14 },
  { re: /\bunescape\s*\(\s*['"]%u/i, name: "unescape('%u…') 難読化", weight: 28 },
  { re: /\/\*\*\s*\d+\s*\*\//g, name: 'パッカーのマーキング', weight: 12 },
  { re: /\b(p\.a\.c\.k\.e\.d|packed by|p,a,c,k,e,d)/i, name: 'Dean Edwards パッカー', weight: 18 },
  { re: /\bdocument\.write\s*\(\s*unescape/gi, name: 'document.write(unescape(...))', weight: 24 },
  { re: /https?:\/\/[^/'"\s]+\/[^\s'"]*\?(?:[^'"\s]*)(?:cmd|shell|exec|base64_decode|eval)\b/i, name: 'リモートコマンド実行Looks', weight: 20 },
];

export const CATEGORIES = {
  KNOWN_BAD: { key: 'known_bad', label: '既知の悪性ホスト', score: 100, color: 'danger' },
  PHISHING: { key: 'phishing', label: 'フィッシング疑い', score: 78, color: 'danger' },
  SPOOF: { key: 'lookalike', label: 'なりすまし (タイポスキット)', score: 72, color: 'danger' },
  HOMOGlyph: { key: 'homoglyph', label: '同形文字/ punycode', score: 66, color: 'danger' },
  CRED_EXFIL: { key: 'cred_exfil', label: '認証情報の外部送信', score: 88, color: 'danger' },
  KEYLOGGER: { key: 'keylogger', label: 'キーロガー挙動', score: 82, color: 'danger' },
  MINER: { key: 'miner', label: '暗号資産マイニング', score: 74, color: 'danger' },
  OBFUSCATION: { key: 'obfuscation', label: 'スクリプト難読化', score: 52, color: 'warn' },
  DRIVE_BY: { key: 'drive_by', label: '自動実行/ドライブバイ', score: 70, color: 'danger' },
  DANGEROUS_FILE: { key: 'dangerous_file', label: '危険なファイル形式', score: 62, color: 'warn' },
  SHORTENER: { key: 'shortener', label: 'URL 短縮による隠蔽', score: 30, color: 'warn' },
  RISKY_TLD: { key: 'risky_tld', label: '濫用されやすい TLD', score: 22, color: 'info' },
  IP_HOST: { key: 'ip_host', label: 'IP リテラル指定', score: 20, color: 'info' },
  INSECURE: { key: 'insecure', label: '通信が保護されていない', score: 26, color: 'warn' },
  MIXED: { key: 'mixed', label: 'Mixed Content', score: 18, color: 'info' },
  CLICKJACK: { key: 'clickjacking', label: 'クリックジャッキング対策なし', score: 12, color: 'info' },
  OPENER: { key: 'opener', label: 'tabnabbing (rel=noopener 欠落)', score: 8, color: 'info' },
  REDIRECT: { key: 'unexpected_redirect', label: '予期しない別ドメインへの転送', score: 34, color: 'warn' },
  DATA_URI: { key: 'data_uri', label: 'data: URI 実行', score: 44, color: 'warn' },
  TRACKER: { key: 'tracker', label: 'トラッカー (広告/解析)', score: 6, color: 'info' },
  PRIVACY: { key: 'privacy', label: 'プライバシー配慮の自動強化', score: 0, color: 'good' },
  RELAX: { key: 'auto_relax', label: '自動でシールドを緩めた', score: 0, color: 'good' },
};

export class ThreatEngine {
  /**
   * @param {import('../config.js').Config} config
   * @param {{shields?: object}} [deps]
   */
  constructor(config, deps = {}) {
    this.config = config;
    this.shields = deps.shields || null;
    this.events = new Ring(config.threats.maxReportEvents);
    this.bySid = new Map(); // sid → {score, counts, blocked}
    this.badHosts = new Set();
    this.actionCounters = { stripped: 0, blocked: 0, hardened: 0, quarantined: 0, warned: 0 };
    this.ruleHits = new Map();
    this.enabled = config.threats.enabled;
    this.autoDelete = config.threats.autoDelete;
    this.scanBytes = config.threats.scanBytes;
    this.blockScore = config.threats.blockScore;
    this.sanitizeScore = config.threats.sanitizeScore;
    this.startedAt = Date.now();
  }

  /* --------------------------- 設定 --------------------------- */

  loadBadHosts(text) {
    let n = 0;
    for (const line of String(text).split(/\r?\n/)) {
      const t = line.trim();
      if (!t || t.startsWith('!') || t.startsWith('#') || t.startsWith('[')) continue;
      // 対応形式: `||host^...` (ABP) / `host/path` (uBO 風) / `<ip> <host>` (hosts ファイル)
      let host = t;
      if (t.startsWith('||')) host = t.slice(2).split('^')[0].split('$')[0];
      else if (/^(?:0\.0\.0\.0|127(?:\.0\.0\.1)?|255\.255\.255\.255|::1|[0-9a-f:.]+)\s+\S+$/i.test(t)) host = t.split(/\s+/)[1];
      else if (t.includes('/')) host = t.split('/')[0];
      host = host.trim().replace(/\.$/, '');
      if (/^[a-z0-9.\-*]+$/i.test(host) && host.includes('.')) {
        this.badHosts.add(host.toLowerCase());
        n++;
      }
    }
    ns.info(`既知 badware ホストを読み込み: ${n}`);
    return n;
  }

  isBadHost(host) {
    const h = String(host || '').toLowerCase();
    for (const label of chainUp(h)) if (this.badHosts.has(label) || this.badHosts.has(`*.${label}`)) return true;
    return false;
  }

  /* --------------------------- API --------------------------- */

  /**
   * @param {string|URL} rawUrl
   * @param {{sid?:string, kind?:string, referrer?:string}} [ctx]
   * @returns {{score:number, findings:Finding[], block:boolean}}
   */
  inspectUrl(rawUrl, ctx = {}) {
    const findings = [];
    if (!this.enabled) return { score: 0, findings, block: false };
    let url;
    try {
      url = typeof rawUrl === 'string' ? new URL(rawUrl) : rawUrl;
    } catch {
      return { score: 0, findings, block: false };
    }
    const host = url.hostname.toLowerCase();
    const reg = registrableDomain(host) || host;

    if (this.isBadHost(host)) {
      findings.push(f('KNOWN_BAD', url.href, { evidence: `ブロックリスト一致: ${reg}`, action: 'block' }));
    }
    if (host.startsWith('xn--') || /(^|\.)xn--/i.test(host)) {
      findings.push(f('HOMOGlyph', url.href, { evidence: 'punycode (国際化) ホスト名 — 同形文字攻撃の可能性があります' }));
    }
    if (SHORTENERS.has(reg)) {
      findings.push(f('SHORTENER', url.href, { evidence: `短縮サービス: ${reg}` }));
    }
    const tld = host.includes(':') ? null : host.split('.').pop();
    if (tld && RISKY_TLDS.has(tld) && !PROTECTED.includes(reg)) {
      findings.push(f('RISKY_TLD', url.href, { evidence: `.${tld} TLD` }));
    }
    if (isIpLiteral(host)) {
      findings.push(f('IP_HOST', url.href, { evidence: `host がドメインでなく IP: ${host}` }));
    }
    if (host.split('.').length > 5) {
      findings.push(f('PHISHING', url.href, { evidence: 'ラベル数が多い過剰なサブドメイン構造', weightDelta: -20 }));
    }
    if (url.username || url.password) {
      findings.push(f('CRED_EXFIL', url.href, { evidence: 'URL に資格情報を含む', action: 'block' }));
    }
    // 正規ドメインと編集距離 2 以内の偽ドメイン (例: g00gle.com)
    if (!PROTECTED.includes(reg) && reg.includes('.')) {
      for (const p of PROTECTED) {
        const d = lev(reg, p, 2);
        if (d > 0 && d <= 2 && reg.length >= p.length - 2) {
          findings.push(
            f('SPOOF', url.href, {
              evidence: `"${reg}" は "${p}" と類似 (編集距離 ${d})`,
              action: 'block',
            }),
          );
          break;
        }
      }
      // 正規ドメインを「サブドメインとして騙る」手口: paypal.com.verify-secure.top
      for (const p of PROTECTED) {
        if (reg !== p && url.href.toLowerCase().includes(`${p.split('.')[0]}.`) && !host.endsWith(`.${p}`)) {
          const suspicious = /(?:verify|secure|login|account|update|confirm|bank|billing|password)/i.test(host);
          if (suspicious) {
            findings.push(f('PHISHING', url.href, { evidence: `ブランド名 "${p}" をパス/ホストに埋め込み + 認証系キーワード`, action: 'block' }));
          } else {
            findings.push(f('PHISHING', url.href, { evidence: `ブランド名 "${p}" をホストに含める (正規ドメインではない)`, weightDelta: -26 }));
          }
          break;
        }
      }
    }
    if (url.protocol === 'http:' && ctx.kind === 'document') {
      findings.push(f('INSECURE', url.href, { evidence: '平文 HTTP (閲覧内容が漏れます) — Mirage は強制的に https を試行しません' }));
    }
    if (/\/$/u.test(url.pathname) === false && /\.(php|aspx|jsp|cgi)(\b|$)/i.test(url.pathname) && ctx.kind === 'document') {
      // 参考情報 (スコアにしない)
      findings.push(f('PRIVACY', url.href, { infoOnly: true, evidence: 'レガシーサーバースクリプト検出' }));
    }
    return this.#finalize(findings, ctx, url);
  }

  /**
   * HTML ドキュメントの検査。除去指示 (strips) を返す。
   * @param {string} html
   * @param {{sid?:string, url:string, baseUrl:URL, kind:string}} ctx
   */
  inspectDocument(html, ctx) {
    if (!this.enabled) return { score: 0, findings: [], strips: [] };
    const findings = [];
    const strips = [];
    const text = html.length > this.scanBytes ? html.slice(0, this.scanBytes) : html;
    const lower = text.toLowerCase();
    const pageHost = ctx.baseUrl?.hostname || '';
    const pageReg = registrableDomain(pageHost);

    // --- 1. 危険な <script src> / <iframe src> / <a href=download> を機械抽出 (rewriter 側が call する) ---
    // 以下はドキュメント全体のヒューリスティック
    const evalHits = countMatches(text, /\beval\s*\(/g);
    const fnHits = countMatches(text, /\bnew\s+Function\s*\(/g);
    const atobHits = countMatches(text, /\b(?:atob|unescape)\s*\(/g);
    if (evalHits + fnHits >= 12) {
      findings.push(
        f('OBFUSCATION', ctx.url, {
          evidence: `ページ全体に eval/new Function が ${evalHits + fnHits} 箇所`,
          weightDelta: 10,
        }),
      );
    }
    for (const token of MINER_TOKENS) {
      if (lower.includes(token)) {
        findings.push(f('MINER', ctx.url, { evidence: `キーワード "${token}"`, action: 'block' }));
        break;
      }
    }
    for (const token of KEYLOGGER_TOKENS) {
      if (lower.includes(token)) {
        findings.push(f('KEYLOGGER', ctx.url, { evidence: `キーワード "${token}"`, action: 'block' }));
        break;
      }
    }
    // キー入力を別ドメインへ送る combo
    const keyHandler = /addEventListener\s*\(\s*['"]key(down|press|up)['"]/i.test(text);
    const exfil = /sendBeacon\s*\(|XMLHttpRequest|fetch\s*\(/i.test(text);
    if (keyHandler && exfil) {
      const foreign = foreignScriptHosts(text, pageReg);
      if (foreign.length) {
        findings.push(
          f('KEYLOGGER', ctx.url, {
            evidence: `キー入力ハンドラ + 別ドメイン(${foreign[0]})への送信`,
            action: 'block',
          }),
        );
      }
    }
    // meta refresh による即座の別ドメイン遷移
    const metaRefresh = /<meta[^>]+http-equiv=["']?refresh["']?[^>]+content=["']?\s*0\s*;\s*url=([^"'>\s]+)/i.exec(text);
    if (metaRefresh) {
      let target = null;
      try {
        target = new URL(decodeEntities(metaRefresh[1]), ctx.baseUrl || undefined);
      } catch {}
      if (target && registrableDomain(target.hostname) !== pageReg) {
        findings.push(
          f('REDIRECT', ctx.url, {
            evidence: `<meta http-equiv=refresh> → ${target.origin}${target.pathname.slice(0, 40)} (別ドメインへ即時転送)`,
            action: 'strip-meta-refresh',
          }),
        );
        strips.push({ reason: 'meta-refresh-redirect', selector: 'meta[http-equiv]', action: 'strip' });
      }
    }
    // ドライブバイ: サイズ 0 の iframe/embed + 危険拡張子
    if (/(?:width|height)\s*=\s*["']?0["']?[^>]*>[\s\S]{0,80}?<iframe|<iframe[^>]{0,300}?\.(exe|scr|jar|vbs|hta)\b/i.test(text)) {
      findings.push(f('DRIVE_BY', ctx.url, { evidence: '非表示 iframe + 実行可能ファイル', action: 'block' }));
    }
    // data: URI 実行
    if (/<(?:script|iframe|object|embed)[^>]{0,200}src=["']data:\s*(?:text\/html|application\/javascript|javascript)/i.test(text)) {
      findings.push(
        f('DATA_URI', ctx.url, {
          evidence: 'data: URI からのスクリプト/ドキュメント実行',
          action: 'strip-data-uri',
        }),
      );
      strips.push({ reason: 'data-uri-exec', action: 'strip' });
    }
    // クリックジャッキング (ページ自身がフレーム内表示を制限していない)
    if (ctx.kind === 'document' && !/X-Frame-Options|frame-ancestors/i.test(text)) {
      findings.push(f('CLICKJACK', ctx.url, { infoOnly: true, evidence: '親フレーム制限なし → Mirage 側で sandbox を付与しました', harden: 'iframe-sandbox' }));
    }
    // 難読化パターン (heavy)
    let obfScore = 0;
    const obfHits = [];
    for (const hint of OBFUSCATION_HINTS) {
      const m = text.match(hint.re);
      if (m && m.length) {
        obfScore += Math.min(hint.weight, 6 + m.length);
        obfHits.push(hint.name);
      }
    }
    const inline = extractInlineScripts(text);
    if (inline.length) {
      const avgEnt = inline.reduce((s, code) => s + entropy(code), 0) / inline.length;
      if (avgEnt > 5.4 && inline.some((c) => c.length > 400)) {
        obfScore += 18;
        obfHits.push(`インラインスクリプトのエントロピー ${avgEnt.toFixed(2)} bits/char`);
      }
    }
    if (obfScore > 0) {
      findings.push(
        f('OBFUSCATION', ctx.url, {
          evidence: obfHits.slice(0, 4).join(' / '),
          weightDelta: Math.min(34, obfScore) - CATEGORIES.OBFUSCATION.score,
        }),
      );
    }
    if (atobHits > 6) {
      findings.push(f('OBFUSCATION', ctx.url, { evidence: `atob/unescape が ${atobHits} 箇所`, weightDelta: -30 }));
    }

    const out = this.#finalize(findings, ctx, safeUrl(ctx.url));
    out.strips = strips;
    return out;
  }

  /**
   * リソース (script/css/json) の検査。rewriter が 1 要素ずつ呼ぶ。
   * @param {string} code
   * @param {{sid?:string,url:string,kind:string,baseUrl?:URL}} ctx
   */
  inspectAsset(code, ctx) {
    if (!this.enabled || ctx.kind !== 'script') return { score: 0, findings: [], drop: false };
    const findings = [];
    let score = 0;
    const lower = code.toLowerCase();
    for (const token of MINER_TOKENS) {
      if (lower.includes(token)) {
        findings.push(f('MINER', ctx.url, { evidence: `スクリプト内に "${token}"`, action: 'block' }));
        break;
      }
    }
    for (const hint of OBFUSCATION_HINTS.slice(0, 9)) {
      if (hint.re.test(code)) {
        score += hint.weight;
        findings.push(f('OBFUSCATION', ctx.url, { evidence: hint.name, weightDelta: -CATEGORIES.OBFUSCATION.score + hint.weight, host: ctx.url }));
      }
    }
    const ent = entropy(code);
    if (ent > 5.6 && code.length > 900) {
      score += 16;
      findings.push(f('OBFUSCATION', ctx.url, { evidence: `エントロピー ${ent.toFixed(2)} bits/char (${code.length} bytes)`, weightDelta: -20 }));
    }
    if (score === 0) return { score: 0, findings: [], drop: false };
    const out = this.#finalize(findings, ctx, safeUrl(ctx.url));
    out.drop = out.score >= this.sanitizeScore && this.autoDelete;
    return out;
  }

  /** ダウンロード/Content-Disposition 検査 */
  inspectDownload({ url, headers, contentType }) {
    if (!this.enabled) return { block: false, findings: [] };
    const findings = [];
    let u = safeUrl(url);
    const pathName = (u?.pathname || '').toLowerCase();
    const disp = headers?.get?.('content-disposition') || '';
    const fileName = /filename\*?="?([^";]+)/i.exec(disp)?.[1];
    const target = (fileName || pathName).toLowerCase();
    const ext = (target.match(/\.[a-z0-9]{1,6}$/) || [''])[0];
    const mime = String(contentType || '').toLowerCase();
    if (DANGEROUS_EXT.includes(ext)) {
      findings.push(
        f('DANGEROUS_FILE', url, {
          evidence: `拡張子 ${ext}${fileName ? ` (ファイル名: ${fileName.slice(0, 40)})` : ''}`,
          action: this.config.threats.blockDangerousDownloads ? 'block' : 'warn',
        }),
      );
    }
    if (DANGEROUS_MIME.has(mime.split(';')[0])) {
      findings.push(f('DANGEROUS_FILE', url, { evidence: `MIME ${mime}`, action: 'block', weightDelta: -20 }));
    }
    if (/\.(exe|js|vbs|bat)\.(pdf|png|jpg|txt|zip)$/i.test(target) || /(?:pdf|png|jpe?g)\.(exe|scr|js)$/i.test(target)) {
      findings.push(f('DANGEROUS_FILE', url, { evidence: '二重拡張子による偽装の可能性', action: 'block', weightDelta: -14 }));
    }
    if (findings.length) {
      const out = this.#finalize(findings, { url }, u);
      out.block = out.score >= this.sanitizeScore && this.config.threats.blockDangerousDownloads;
      return out;
    }
    return { block: false, findings: [], score: 0 };
  }

  /** クレデンシャル送信ガード: ページにパスワード入力があり、フォームの送信先が別登録ドメインなら遮断 */
  credentialFormCheck({ html, baseUrl, sid }) {
    if (!this.config.threats.credentialLeakGuard) return [];
    const out = [];
    const formRe = /<form\b[^>]*\baction=["']([^"']+)["'][^>]*>/gi;
    let m;
    const hasPassword = /<input[^>]+type=["']?password/i.test(html);
    if (!hasPassword) return out;
    while ((m = formRe.exec(html))) {
      let action = null;
      try {
        action = new URL(decodeEntities(m[1]), baseUrl);
      } catch {
        continue;
      }
      const reg = registrableDomain(action.hostname);
      const pageReg = registrableDomain(baseUrl.hostname);
      if (reg && pageReg && reg !== pageReg) {
        out.push(
          f('CRED_EXFIL', action.href, {
            evidence: `パスワード入力付きフォームの送信先が別登録ドメイン (${pageReg} → ${reg})`,
            action: 'strip-form-action',
            sid,
          }),
        );
      }
      if (action.protocol === 'http:') {
        out.push(
          f('INSECURE', action.href, {
            evidence: '認証フォームが平文 HTTP に送信されます — https へ昇格しました',
            action: 'upgrade-https',
            sid,
          }),
        );
      }
    }
    if (!out.length) return out;
    const agg = this.#finalize(out, { url: baseUrl.href, sid }, baseUrl);
    return agg.findings;
  }

  /* --------------------------- 内部 --------------------------- */

  #finalize(findings, ctx, url) {
    let score = 0;
    const out = [];
    for (const finding of findings) {
      if (!finding) continue;
      const cat = CATEGORIES[finding.code];
      if (!cat) continue;
      if (finding.infoOnly) {
        out.push({
          ...finding,
          score: 0,
          infoOnly: true,
          label: cat.label,
          key: cat.key,
          color: cat.color,
          at: Date.now(),
          sid: ctx.sid,
          host: url?.hostname || '',
          id: sha1(`info|${cat.key}|${url?.href || ''}`.slice(0, 400)).slice(0, 12),
        });
        continue;
      }
      const s = Math.max(0, Math.min(100, cat.score + (finding.weightDelta || 0)));
      const ev = {
        ...finding,
        score: s,
        label: cat.label,
        key: cat.key,
        color: cat.color,
        at: Date.now(),
        sid: ctx.sid,
        host: url?.hostname || finding.host || '',
        id: sha1(`${ctx.sid}|${cat.key}|${url?.href || ''}|${finding.evidence}`.slice(0, 400)).slice(0, 12),
      };
      score = Math.max(score, s);
      // 複数要因は加算効かせつつ飽和させる
      score = Math.min(100, score + Math.round(s * 0.12));
      out.push(ev);
      this.#record(ev);
    }
    const block = score >= this.blockScore;
    const sanitize = score >= this.sanitizeScore;
    if (out.length) {
      const agg = { score, findings: out, block, sanitize };
      this.#noteSession(ctx.sid, agg);
      return agg;
    }
    return { score: 0, findings: [], block: false, sanitize: false };
  }

  #record(ev) {
    this.events.push(ev);
    this.ruleHits.set(`${ev.code}:${ev.host || '-'}`, (this.ruleHits.get(`${ev.code}:${ev.host || '-'}`) || 0) + 1);
    if (ev.action === 'block') this.actionCounters.blocked++;
    else if (ev.action?.startsWith('strip') || ev.action === 'drop-asset') this.actionCounters.stripped++;
    else if (ev.action?.startsWith('upgrade') || ev.action?.startsWith('harden')) this.actionCounters.hardened++;
    else this.actionCounters.warned++;
    if (this.config.telemetry.logLevel !== 'silent' && ev.score >= 60) {
      ns.warn(`${ev.score} ${ev.label} @ ${ev.host}`);
    }
  }

  #noteSession(sid, agg) {
    if (!sid) return;
    const cur = this.bySid.get(sid) || { score: 0, counts: {}, actions: [], blocked: 0, updatedAt: 0 };
    cur.score = Math.max(cur.score, agg.score);
    for (const fd of agg.findings) {
      cur.counts[fd.code] = (cur.counts[fd.code] || 0) + 1;
      if (fd.action) cur.actions.unshift({ at: fd.at, action: fd.action, label: fd.label, score: fd.score });
      if (fd.action === 'block') cur.blocked++;
      if (cur.score >= this.blockScore) cur.quarantined = true;
    }
    cur.actions = cur.actions.slice(0, 40);
    cur.updatedAt = Date.now();
    this.bySid.set(sid, cur);
    if (this.bySid.size > 400) {
      const oldest = [...this.bySid.entries()].sort((a, b) => a[1].updatedAt - b[1].updatedAt)[0];
      if (oldest) this.bySid.delete(oldest[0]);
    }
  }

  /* --------------------------- レポート --------------------------- */

  /** @param {{sid?:string, limit?:number, minScore?:number, code?:string}} [q] */
  report(q = {}) {
    const { sid, limit = 120, minScore = 0, code } = q;
    const list = this.events.list({
      limit,
      filter: (e) =>
        (!sid || e.sid === sid) &&
        e.score >= minScore &&
        (!code || e.code === code || e.key === code),
    });
    const byCode = {};
    for (const e of this.events.all) byCode[e.code] = (byCode[e.code] || 0) + 1;
    return {
      generatedAt: Date.now(),
      enabled: this.enabled,
      autoDelete: this.autoDelete,
      thresholds: { sanitize: this.sanitizeScore, block: this.blockScore },
      totals: {
        events: this.events.total,
        ...this.actionCounters,
      },
      session: sid ? this.sessionSummary(sid) : undefined,
      byCode,
      topRules: [...this.ruleHits.entries()].sort((a, b) => b[1] - a[1]).slice(0, 12).map(([k, n]) => ({ rule: k, hits: n })),
      events: list,
    };
  }

  sessionSummary(sid) {
    const s = this.bySid.get(sid);
    if (!s) return { sid, score: 0, level: 'safe', counts: {}, actions: [], blocked: 0 };
    const level = s.score >= this.blockScore ? 'danger' : s.score >= this.sanitizeScore ? 'warn' : s.score > 0 ? 'info' : 'safe';
    return { sid, ...s, level };
  }

  allSessions() {
    return [...this.bySid.entries()].map(([sid, s]) => this.sessionSummary(sid));
  }

  /** 検知済みイベントの「自動削除」= レポートからの除去 (ユーザーの被写体情報の保持時間管理) */
  purge({ sid, olderThanMs, codes } = {}) {
    let n = 0;
    const cutoff = olderThanMs ? Date.now() - olderThanMs : Infinity;
    n += this.events.removeWhere((e) => (sid ? e.sid === sid : true) && e.at < cutoff && (!codes || codes.includes(e.code)));
    if (sid) this.bySid.delete(sid);
    else if (olderThanMs) for (const [k, v] of this.bySid) if (v.updatedAt < cutoff) this.bySid.delete(k);
    return n;
  }

  clearSession(sid) {
    this.bySid.delete(sid);
    const removed = this.events.removeWhere((e) => e.sid === sid);
    return removed;
  }

  stats() {
    const counts = { danger: 0, warn: 0, info: 0 };
    for (const e of this.events.all) counts[e.color in counts ? e.color : 'info']++;
    return {
      enabled: this.enabled,
      autoDelete: this.autoDelete,
      badHosts: this.badHosts.size,
      events: this.events.length,
      totalEvents: this.events.total,
      byAction: { ...this.actionCounters },
      bySeverity: counts,
      sessions: this.bySid.size,
      thresholds: { sanitize: this.sanitizeScore, block: this.blockScore },
      uptimeMs: Date.now() - this.startedAt,
    };
  }

  setEnabled(v) {
    this.enabled = !!v;
    return this.enabled;
  }
  setAutoDelete(v) {
    this.autoDelete = !!v;
    return this.autoDelete;
  }
  setThresholds({ sanitize, block } = {}) {
    if (Number.isFinite(sanitize)) this.sanitizeScore = Math.max(1, Math.min(100, sanitize | 0));
    if (Number.isFinite(block)) this.blockScore = Math.max(this.sanitizeScore, Math.min(100, block | 0));
    return { sanitize: this.sanitizeScore, block: this.blockScore };
  }
}

/* ------------------------------------------------------------------ */

function f(code, url, extra = {}) {
  return { code, url: typeof url === 'string' ? url.slice(0, 500) : url?.href, ...extra };
}

function* chainUp(host) {
  const parts = host.split('.');
  for (let i = 0; i < parts.length; i++) yield parts.slice(i).join('.');
}

function safeUrl(s) {
  try {
    return new URL(s);
  } catch {
    return null;
  }
}

function countMatches(text, re) {
  const m = text.match(re);
  return m ? m.length : 0;
}

const ENTITY = { '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&#39;': "'", '&#x27;': "'", '&apos;': "'" };
export function decodeEntities(s = '') {
  return String(s).replace(/&(?:amp|lt|gt|quot|#39|#x27|apos);/gi, (m) => ENTITY[m.toLowerCase()] ?? m);
}

function extractInlineScripts(html) {
  const out = [];
  const re = /<script\b[^>]*?(?:type=["']([^"']+)["'])?[^\>]*>([\s\S]{0,20000}?)<\/script\s*>/gi;
  let m;
  while ((m = re.exec(html))) {
    const type = (m[1] || 'text/javascript').toLowerCase();
    if (!/javascript|module|ecmascript/.test(type)) continue;
    if (m[2]?.trim()) out.push(m[2]);
  }
  return out;
}

/** ページの登録ドメインと異なる origin を持つ <script src> の host 一覧 */
function foreignScriptHosts(html, pageReg) {
  const out = [];
  const re = /<script[^>]+src=["']([^"']+)["']/gi;
  let m;
  while ((m = re.exec(html))) {
    const u = safeUrl(m[1]);
    if (!u || !u.hostname) continue;
    if (registrableDomain(u.hostname) !== pageReg) out.push(u.hostname);
  }
  return out;
}

export default ThreatEngine;
