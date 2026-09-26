/**
 * SSRF / 内部アドレス ガード
 * ---------------------------------------------------------------
 * 「何でもプロキシできる」機能は、そのまま置くとクラウドのメタデータエンドポイント
 * (169.254.169.254) や VPC 内サービスへの SSRF に化ける。MirageVPN は
 * デフォルトで RFC1918 / loopback / link-local / ULA / CGNAT / クラウドメタデータを遮断する。
 *
 * テスト・ローカル検証でのみ MIRAGE_BLOCK_PRIVATE_TARGETS=0 で解除する。
 * @module security/ssrf
 */

import { lookup } from 'node:dns/promises';
import { LRU } from '../util.js';
import { log } from '../log.js';

const IPV4_BLOCKLIST = [
  ['0.0.0.0', 8], // this-network
  ['10.0.0.0', 8],
  ['100.64.0.0', 10], // CGNAT (多くの PaaS 内部)
  ['127.0.0.0', 8],
  ['169.254.0.0', 16], // link-local / cloud metadata
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24], // TEST-NET-1
  ['192.168.0.0', 16],
  ['198.18.0.0', 15], // benchmark
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // reserved / broadcast
];

const HOST_DENY_RE =
  /(^|\.)(local|localhost|internal|intranet|lan|localdomain|home.arpa|docker.internal|cloudnet)$/i;

const METADATA_HOSTS = new Set([
  'metadata.google.internal',
  'metadata.goog',
  'metadata',
  'instance-data',
  '169.254.169.254',
  'fd00:ec2::254',
  'metadata.azure.internal',
]);

const dnsCache = new LRU(4000, 60_000);

function toV4Int([a, b, c, d]) {
  return (((a << 24) | (b << 16) | (c << 8) | d) >>> 0);
}

export class TargetGuard {
  /** @param {import('../config.js').Config} config */
  constructor(config) {
    this.config = config;
    this.blockPrivate = config.safety.blockPrivateTargets;
    this.allowedProtocols = new Set(config.safety.allowProtocols);
    /** ユーザーが許可した internal exception (カンマ区切り host) */
    this.exceptions = new Set();
    this.denied = 0;
  }

  setExceptions(list = []) {
    this.exceptions = new Set(list.map((h) => String(h).toLowerCase().trim()).filter(Boolean));
  }

  static isPrivateAddress(ip) {
    if (!ip) return false;
    if (ip.includes('.')) {
      const parts = ip.split('.').map(Number);
      if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true; // parse 不能は遮断
      const int = toV4Int(parts);
      for (const [base, bits] of IPV4_BLOCKLIST) {
        const baseInt = toV4Int(base.split('.').map(Number));
        const mask = bits <= 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
        if ((int & mask) >>> 0 === (baseInt & mask) >>> 0) return true;
      }
      return false;
    }
    if (ip.includes(':')) {
      const lower = ip.toLowerCase();
      if (lower === '::' || lower === '::1') return true;
      if (/^f[cd][0-9a-f]{2}:/.test(lower)) return true; // ULA
      if (/^fe[89ab][0-9a-f]:/.test(lower)) return true; // link-local
      // IPv4-mapped (::ffff:127.0.0.1)
      const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(lower);
      if (m) return TargetGuard.isPrivateAddress(m[1]);
      return false;
    }
    return true; // 不明形式
  }

  /**
   * @param {URL} url
   * @param {{resolve?:boolean, role?:string}} [opts]
   * @returns {{ok:boolean, reason?:string, code?:string, host?:string}}
   */
  check(url, opts = {}) {
    if (!url) return { ok: false, reason: 'パース不能な URL', code: 'bad_url' };
    if (!this.allowedProtocols.has(url.protocol)) {
      this.denied++;
      return { ok: false, reason: `スキーム ${url.protocol} は許可されていません`, code: 'protocol' };
    }
    if (url.username || url.password) {
      return { ok: false, reason: 'URL 内 userinfo は禁止', code: 'userinfo' };
    }
    const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    if (!host) return { ok: false, reason: 'host 欠落', code: 'no_host' };
    if (METADATA_HOSTS.has(host) || host.endsWith('.internal')) {
      this.denied++;
      return { ok: false, reason: 'クラウドメタデータ/内部ホストはブロック対象', code: 'metadata' };
    }
    if (this.exceptions.has(host)) return { ok: true, host };
    if (!this.blockPrivate) return { ok: true, host };
    if (HOST_DENY_RE.test(host)) {
      this.denied++;
      return { ok: false, reason: `内部ドメインサフィックス: ${host}`, code: 'internal_tld' };
    }
    // リテラル IP はその場で判定
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(':')) {
      if (TargetGuard.isPrivateAddress(host)) {
        this.denied++;
        return { ok: false, reason: 'プライベートアドレス指定は禁止', code: 'private_ip' };
      }
      return { ok: true, host };
    }
    if (opts.resolve) {
      const cached = dnsCache.get(host);
      if (cached && TargetGuard.isPrivateAddress(cached)) {
        this.denied++;
        return { ok: false, reason: '解決先がプライベートアドレス', code: 'private_dns', host };
      }
    }
    return { ok: true, host };
  }

  /** 非同期: DNS 解決まで見たガード (接続直前に使う) */
  async checkDeep(url) {
    const quick = this.check(url);
    if (!quick.ok || !this.blockPrivate) return quick;
    const host = url.hostname;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(':')) return quick;
    try {
      const rec = await dnsCache.wrap(`dns:${host}`, async () => {
        const r = await lookup(host, { all: false });
        return r ? { address: r.address } : null;
      });
      if (rec && TargetGuard.isPrivateAddress(rec.address)) {
        this.denied++;
        return { ok: false, reason: 'DNS 解決先がプライベート範囲', code: 'dns_rebind', host };
      }
    } catch (err) {
      return { ok: false, reason: `DNS 解決失敗: ${err.code || err.message}`, code: 'dns_fail', host };
    }
    return { ok: true, host };
  }

  stats() {
    return { denied: this.denied, blockPrivate: this.blockPrivate, exceptions: [...this.exceptions] };
  }
}

export function warnGuardDisabled() {
  log.warn(
    'MIRAGE_BLOCK_PRIVATE_TARGETS=0 — 内部アドレスへのリクエストが許可されています。ローカル検証専用で使ってください。',
  );
}

export default TargetGuard;
