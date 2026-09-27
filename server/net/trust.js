/**
 * 外向き TLS の信頼設定 — 「Node 同梱ルート + OS の信頼ストア」
 * ---------------------------------------------------------------
 * なぜこれが必要か:
 *  Node の `fetch` / `https` は既定で **Node に焼き込まれた CA だけ** を信頼する。
 *  社内プロキシ / フィルタリング機器 / コンテナ基盤が TLS を途中で終端している環境では、
 *  機器の CA が OS の信頼ストアに入っていても Node だけが
 *  `UNABLE_TO_VERIFY_LEAF_SIGNATURE` / `SELF_SIGNED_CERT_IN_CHAIN` で失敗する。
 *  結果として「GitHub のリストだけ取得できない」「Geo API だけ落ちる」という
 *  原因の見えにくい不具合になる。curl やブラウザは OS ストアを使うので動くため、
 *  利用者からは「アプリだけが壊れている」ように見える。
 *
 *  そこで **外向きの管理系リクエスト (リスト取得・Geo・検証プローブ)** では
 *  `tls.rootCertificates` に OS のバンドルを足した CA 集合で検証する。
 *  検証は常に ON (証明書を確認しない通信はしない)。どうしても通らない環境向けに
 *  `MIRAGE_TLS_INSECURE=1` を用意するが、既定は OFF で、失敗時は理由と対処を返す。
 *
 * 注意: 上流サイトの中継 (`net/http1.js` の既定) は従来どおり宽松 (rejectUnauthorized:false)。
 *  あちらは「閲覧対象サイトの証明書が古くても表示を止めない」ためのプロキシとしての仕様で、
 *  こちら (自分の管理通信) とは信頼の要求が違う。
 * @module net/trust
 */

import tls from 'node:tls';
import { readFileSync } from 'node:fs';

/** OS ごとに CA バンドルの場所が違うので候補を順に探す */
const BUNDLE_CANDIDATES = [
  process.env.SSL_CERT_FILE,
  process.env.NODE_EXTRA_CA_CERTS,
  '/etc/ssl/certs/ca-certificates.crt', // Debian / Ubuntu
  '/etc/pki/tls/certs/ca-bundle.crt', // RHEL / CentOS / Fedora
  '/etc/ssl/ca-bundle.pem', // openSUSE
  '/etc/pki/tls/cacert.pem', // OpenELEC
  '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem', // RHEL ca-trust
  '/etc/ssl/cert.pem', // macOS / Alpine / FreeBSD
];

const PEM_SPLIT = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

/** @type {{certs:string[], bundle:string|null, at:number}|null} */
let cached = null;

function splitPem(text) {
  const out = String(text || '').match(PEM_SPLIT);
  return out || [];
}

/**
 * OS の信頼ストアから読めた CA (PEM 配列)。読めなければ空配列。
 * @returns {string[]}
 */
export function systemCaCerts() {
  const now = Date.now();
  if (cached && now - cached.at < 60 * 60 * 1000) return cached.certs;
  for (const file of BUNDLE_CANDIDATES) {
    if (!file) continue;
    try {
      const certs = splitPem(readFileSync(file, 'utf8'));
      if (certs.length) {
        cached = { certs, bundle: file, at: now };
        return certs;
      }
    } catch {
      /* 次の候補へ */
    }
  }
  cached = { certs: [], bundle: null, at: now };
  return [];
}

/** Node 同梱 + OS の CA を合わせた集合 (重複除去済み) */
export function trustedCa() {
  const sys = systemCaCerts();
  if (!sys.length) return tls.rootCertificates;
  const set = new Set(tls.rootCertificates);
  for (const c of sys) set.add(c.trim());
  return [...set];
}

/**
 * `tls.connect` / `https.request` にそのまま渡せる信頼オプション。
 * @param {{strict?:boolean, insecure?:boolean}} [opts]
 */
export function trustOptions({ strict = true, insecure = false } = {}) {
  if (insecure || !strict) return { rejectUnauthorized: false };
  return { ca: trustedCa(), rejectUnauthorized: true };
}

/** 診断/UI 表示用のメタ */
export function trustInfo() {
  const sys = systemCaCerts();
  const bundle = BUNDLE_CANDIDATES.find((f) => f && sys.length && cached?.bundle === f) || cached?.bundle || null;
  return {
    nodeRoots: tls.rootCertificates.length,
    systemRoots: sys.length,
    systemBundle: bundle,
    total: trustedCa().length,
    insecure: false,
  };
}

const TLS_ERROR_HINTS = {
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: '証明書チェーンが不完全です。社内プロキシ/フィルタが TLS を終端している可能性が高いので、その CA を OS の信頼ストアか NODE_EXTRA_CA_CERTS に入れてください。',
  SELF_SIGNED_CERT_IN_CHAIN: '自己署名 CA がチェーンに含まれています。社内プロキシの CA を OS の信頼ストア (または NODE_EXTRA_CA_CERTS) に追加してください。',
  DEPTH_ZERO_SELF_SIGNED_CERT: '相手が自己署名証明書です。OS の信頼ストアに追加するか、MIRAGE_TLS_INSECURE=1 (非推奨) で回避できます。',
  CERT_HAS_EXPIRED: '相手の証明書が期限切れです。',
  ERR_TLS_CERT_ALTNAME_INVALID: '証明書のホスト名が一致しません (SNI/ホスト名の書き換えを疑ってください)。',
  UNABLE_TO_GET_ISSUER_CERT_LOCALLY: '発行元 CA がローカルに見つかりません。OS の信頼ストアを確認してください。',
};

/**
 * TLS/接続エラーを「人が読んで対処できる形」にする。
 * @returns {{code:string, kind:'tls'|'dns'|'tcp'|'timeout'|'http'|'other', message:string, hint?:string}}
 */
export function classifyNetError(err) {
  const cause = err?.cause || err;
  const code = String(err?.code || cause?.code || cause?.errors?.[0]?.code || '');
  const raw = String(err?.message || cause?.message || err || 'unknown');
  const message = raw.length > 220 ? `${raw.slice(0, 220)}…` : raw;

  // 1) 明示的なネットワークコードを先に判定する。
  //    「TLS ハンドシェイク中の ECONNRESET」は証明書の問題ではなく **経路が塞がれている** ので、
  //    ここを TLS と誤分類すると利用者に対処できないヒントを出してしまう。
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN' || /getaddrinfo/i.test(raw)) {
    return { code: code || 'dns_failed', kind: 'dns', message, hint: 'DNS が解決できません。この実行環境の DNS / 送信許可ドメインを確認してください。' };
  }
  if (code === 'ECONNRESET' || code === 'ECONNREFUSED' || code === 'EHOSTUNREACH' || code === 'ENETUNREACH' || code === 'EPIPE' || code === 'ECONNABORTED') {
    return {
      code,
      kind: 'tcp',
      message,
      hint:
        code === 'ECONNREFUSED'
          ? '接続を拒否されました (ポートが閉じています)。'
          : 'TCP 接続が途中で切れました。ファイアウォール / 送信ドメイン許可リスト (egress 制限) でブロックされている可能性が高いです。',
    };
  }
  if (code === 'ETIMEDOUT' || code === 'head_timeout' || code === 'idle_timeout' || code === 'tls_timeout' || code === 'connect_timeout' || /timeout|timed out/i.test(raw)) {
    return { code: code || 'timeout', kind: 'timeout', message, hint: 'タイムアウトしました。相手ホストへの送信が遅いか、ブロックされています。' };
  }

  // 2) 証明書まわり (ここに来て初めて TLS 検証の問題)
  if (TLS_ERROR_HINTS[code] || /UNABLE_TO_VERIFY|SELF_SIGNED|CERT_|ERR_TLS|certificate|verify/i.test(code + raw)) {
    return {
      code: code || 'tls_failed',
      kind: 'tls',
      message,
      hint: TLS_ERROR_HINTS[code] || 'TLS 検証に失敗しました。社内プロキシが TLS を終端している場合は、その CA を OS の信頼ストアか NODE_EXTRA_CA_CERTS に入れてください。',
    };
  }
  if (/SSL|TLS/i.test(raw)) {
    return { code: code || 'tls_failed', kind: 'tls', message, hint: 'TLS ハンドシェイクに失敗しました。' };
  }
  return { code: code || 'error', kind: 'other', message };
}

export default { systemCaCerts, trustedCa, trustOptions, trustInfo, classifyNetError };
