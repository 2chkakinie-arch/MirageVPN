/**
 * 国籍 (国コード) 解決と地域情報
 * ---------------------------------------------------------------
 * MirageVPN における「国籍の自動判別」は 3 段構え:
 *  1. リスト側のメタデータ (proxifly は IP ごとに国コードを同梱) → 最速・オフライン可
 *  2. 出口 IP の実測 (プロキシ経由で ip 情報 API を叩き、本当にその国から出ているか検証)
 *  3. オンライン GeoIP API フォールバック (未到達なら 'XX' として扱う=国籍不明だが使用可)
 * @module data/geo
 */

import { LRU, registrableDomain } from '../util.js';
import { fetchJson } from '../net/outbound.js';
import { log } from '../log.js';

const ns = log.child('geo');

/** 国コード → 日本語名称/地域。UI のピッカーとヘッダ Localize に使う。 */
export const COUNTRIES = {
  JP: { ja: '日本', region: 'Asia', tz: 'Asia/Tokyo', lang: 'ja-JP,ja;q=0.9' },
  US: { ja: 'アメリカ', region: 'North America', tz: 'America/New_York', lang: 'en-US,en;q=0.9' },
  GB: { ja: 'イギリス', region: 'Europe', tz: 'Europe/London', lang: 'en-GB,en;q=0.9' },
  DE: { ja: 'ドイツ', region: 'Europe', tz: 'Europe/Berlin', lang: 'de-DE,de;q=0.9' },
  FR: { ja: 'フランス', region: 'Europe', tz: 'Europe/Paris', lang: 'fr-FR,fr;q=0.9' },
  IT: { ja: 'イタリア', region: 'Europe', tz: 'Europe/Rome', lang: 'it-IT,it;q=0.9' },
  ES: { ja: 'スペイン', region: 'Europe', tz: 'Europe/Madrid', lang: 'es-ES,es;q=0.9' },
  NL: { ja: 'オランダ', region: 'Europe', tz: 'Europe/Amsterdam', lang: 'nl-NL,nl;q=0.9' },
  SE: { ja: 'スウェーデン', region: 'Europe', tz: 'Europe/Stockholm', lang: 'sv-SE,sv;q=0.9' },
  NO: { ja: 'ノルウェー', region: 'Europe', tz: 'Europe/Oslo', lang: 'nb-NO,nb;q=0.9' },
  FI: { ja: 'フィンランド', region: 'Europe', tz: 'Europe/Helsinki', lang: 'fi-FI,fi;q=0.9' },
  DK: { ja: 'デンマーク', region: 'Europe', tz: 'Europe/Copenhagen', lang: 'da-DK,da;q=0.9' },
  PL: { ja: 'ポーランド', region: 'Europe', tz: 'Europe/Warsaw', lang: 'pl-PL,pl;q=0.9' },
  CZ: { ja: 'チェコ', region: 'Europe', tz: 'Europe/Prague', lang: 'cs-CZ,cs;q=0.9' },
  AT: { ja: 'オーストリア', region: 'Europe', tz: 'Europe/Vienna', lang: 'de-AT,de;q=0.9' },
  CH: { ja: 'スイス', region: 'Europe', tz: 'Europe/Zurich', lang: 'de-CH,de;q=0.9' },
  BE: { ja: 'ベルギー', region: 'Europe', tz: 'Europe/Brussels', lang: 'nl-BE,nl;q=0.9' },
  PT: { ja: 'ポルトガル', region: 'Europe', tz: 'Europe/Lisbon', lang: 'pt-PT,pt;q=0.9' },
  IE: { ja: 'アイルランド', region: 'Europe', tz: 'Europe/Dublin', lang: 'en-IE,en;q=0.9' },
  RU: { ja: 'ロシア', region: 'Europe', tz: 'Europe/Moscow', lang: 'ru-RU,ru;q=0.9' },
  UA: { ja: 'ウクライナ', region: 'Europe', tz: 'Europe/Kyiv', lang: 'uk-UA,uk;q=0.9' },
  TR: { ja: 'トルコ', region: 'Europe', tz: 'Europe/Istanbul', lang: 'tr-TR,tr;q=0.9' },
  RO: { ja: 'ルーマニア', region: 'Europe', tz: 'Europe/Bucharest', lang: 'ro-RO,ro;q=0.9' },
  HU: { ja: 'ハンガリー', region: 'Europe', tz: 'Europe/Budapest', lang: 'hu-HU,hu;q=0.9' },
  GR: { ja: 'ギリシャ', region: 'Europe', tz: 'Europe/Athens', lang: 'el-GR,el;q=0.9' },
  BG: { ja: 'ブルガリア', region: 'Europe', tz: 'Europe/Sofia', lang: 'bg-BG,bg;q=0.9' },
  RS: { ja: 'セルビア', region: 'Europe', tz: 'Europe/Belgrade', lang: 'sr-RS,sr;q=0.9' },
  HR: { ja: 'クロアチア', region: 'Europe', tz: 'Europe/Zagreb', lang: 'hr-HR,hr;q=0.9' },
  LT: { ja: 'リトアニア', region: 'Europe', tz: 'Europe/Vilnius', lang: 'lt-LT,lt;q=0.9' },
  LV: { ja: 'ラトビア', region: 'Europe', tz: 'Europe/Riga', lang: 'lv-LV,lv;q=0.9' },
  EE: { ja: 'エストニア', region: 'Europe', tz: 'Europe/Tallinn', lang: 'et-EE,et;q=0.9' },
  IS: { ja: 'アイスランド', region: 'Europe', tz: 'Atlantic/Reykjavik', lang: 'is-IS,is;q=0.9' },
  CN: { ja: '中国', region: 'Asia', tz: 'Asia/Shanghai', lang: 'zh-CN,zh;q=0.9' },
  HK: { ja: '香港', region: 'Asia', tz: 'Asia/Hong_Kong', lang: 'zh-HK,zh;q=0.9' },
  TW: { ja: '台湾', region: 'Asia', tz: 'Asia/Taipei', lang: 'zh-TW,zh;q=0.9' },
  KR: { ja: '韓国', region: 'Asia', tz: 'Asia/Seoul', lang: 'ko-KR,ko;q=0.9' },
  SG: { ja: 'シンガポール', region: 'Asia', tz: 'Asia/Singapore', lang: 'en-SG,en;q=0.9' },
  IN: { ja: 'インド', region: 'Asia', tz: 'Asia/Kolkata', lang: 'en-IN,en;q=0.9' },
  TH: { ja: 'タイ', region: 'Asia', tz: 'Asia/Bangkok', lang: 'th-TH,th;q=0.9' },
  VN: { ja: 'ベトナム', region: 'Asia', tz: 'Asia/Ho_Chi_Minh', lang: 'vi-VN,vi;q=0.9' },
  ID: { ja: 'インドネシア', region: 'Asia', tz: 'Asia/Jakarta', lang: 'id-ID,id;q=0.9' },
  MY: { ja: 'マレーシア', region: 'Asia', tz: 'Asia/Kuala_Lumpur', lang: 'ms-MY,ms;q=0.9' },
  PH: { ja: 'フィリピン', region: 'Asia', tz: 'Asia/Manila', lang: 'en-PH,en;q=0.9' },
  IL: { ja: 'イスラエル', region: 'Asia', tz: 'Asia/Jerusalem', lang: 'he-IL,he;q=0.9' },
  AE: { ja: 'UAE', region: 'Asia', tz: 'Asia/Dubai', lang: 'ar-AE,ar;q=0.9' },
  SA: { ja: 'サウジアラビア', region: 'Asia', tz: 'Asia/Riyadh', lang: 'ar-SA,ar;q=0.9' },
  KZ: { ja: 'カザフスタン', region: 'Asia', tz: 'Asia/Almaty', lang: 'kk-KZ,kk;q=0.9' },
  AU: { ja: 'オーストラリア', region: 'Oceania', tz: 'Australia/Sydney', lang: 'en-AU,en;q=0.9' },
  NZ: { ja: 'ニュージーランド', region: 'Oceania', tz: 'Pacific/Auckland', lang: 'en-NZ,en;q=0.9' },
  CA: { ja: 'カナダ', region: 'North America', tz: 'America/Toronto', lang: 'en-CA,en;q=0.9' },
  MX: { ja: 'メキシコ', region: 'North America', tz: 'America/Mexico_City', lang: 'es-MX,es;q=0.9' },
  PA: { ja: 'パナマ', region: 'North America', tz: 'America/Panama', lang: 'es-PA,es;q=0.9' },
  CR: { ja: 'コスタリカ', region: 'North America', tz: 'America/Costa_Rica', lang: 'es-CR,es;q=0.9' },
  BR: { ja: 'ブラジル', region: 'South America', tz: 'America/Sao_Paulo', lang: 'pt-BR,pt;q=0.9' },
  AR: { ja: 'アルゼンチン', region: 'South America', tz: 'America/Argentina/Buenos_Aires', lang: 'es-AR,es;q=0.9' },
  CL: { ja: 'チリ', region: 'South America', tz: 'America/Santiago', lang: 'es-CL,es;q=0.9' },
  CO: { ja: 'コロンビア', region: 'South America', tz: 'America/Bogota', lang: 'es-CO,es;q=0.9' },
  PE: { ja: 'ペルー', region: 'South America', tz: 'America/Lima', lang: 'es-PE,es;q=0.9' },
  EC: { ja: 'エクアドル', region: 'South America', tz: 'America/Guayaquil', lang: 'es-EC,es;q=0.9' },
  VE: { ja: 'ベネズエラ', region: 'South America', tz: 'America/Caracas', lang: 'es-VE,es;q=0.9' },
  ZA: { ja: '南アフリカ', region: 'Africa', tz: 'Africa/Johannesburg', lang: 'en-ZA,en;q=0.9' },
  NG: { ja: 'ナイジェリア', region: 'Africa', tz: 'Africa/Lagos', lang: 'en-NG,en;q=0.9' },
  KE: { ja: 'ケニア', region: 'Africa', tz: 'Africa/Nairobi', lang: 'en-KE,en;q=0.9' },
  EG: { ja: 'エジプト', region: 'Africa', tz: 'Africa/Cairo', lang: 'ar-EG,ar;q=0.9' },
  MA: { ja: 'モロッコ', region: 'Africa', tz: 'Africa/Casablanca', lang: 'ar-MA,ar;q=0.9' },
  TN: { ja: 'チュニジア', region: 'Africa', tz: 'Africa/Tunis', lang: 'ar-TN,ar;q=0.9' },
  GH: { ja: 'ガーナ', region: 'Africa', tz: 'Africa/Accra', lang: 'en-GH,en;q=0.9' },
  ET: { ja: 'エチオピア', region: 'Africa', tz: 'Africa/Addis_Ababa', lang: 'am-ET,am;q=0.9' },
  BD: { ja: 'バングラデシュ', region: 'Asia', tz: 'Asia/Dhaka', lang: 'bn-BD,bn;q=0.9' },
  PK: { ja: 'パキスタン', region: 'Asia', tz: 'Asia/Karachi', lang: 'ur-PK,ur;q=0.9' },
  IR: { ja: 'イラン', region: 'Asia', tz: 'Asia/Tehran', lang: 'fa-IR,fa;q=0.9' },
  IQ: { ja: 'イラク', region: 'Asia', tz: 'Asia/Baghdad', lang: 'ar-IQ,ar;q=0.9' },
  UA_: { ja: '(予備)', region: 'Europe', tz: 'Europe/Kyiv', lang: 'uk-UA,uk;q=0.9' },
  XX: { ja: '不明', region: 'Unknown', tz: 'UTC', lang: 'en-US,en;q=0.9' },
};
delete COUNTRIES.UA_;

export const REGION_BY_COUNTRY = new Map(
  Object.entries(COUNTRIES).map(([cc, v]) => [cc, v.region]),
);

/** 🇯🇵 のような地域指示記号 (regional indicator) から国旗絵文字 */
export function flagOf(cc) {
  const s = String(cc || '').toUpperCase();
  if (!/^[A-Z]{2}$/.test(s) || s === 'XX') return '🏳️';
  return String.fromCodePoint(...[...s].map((c) => 0x1f1e6 + (c.charCodeAt(0) - 65)));
}

export function countryLabel(cc) {
  const meta = COUNTRIES[cc];
  return meta ? `${flagOf(cc)} ${meta.ja} (${cc})` : `${flagOf(cc)} ${cc || '不明'}`;
}

/** リストメタで国が不明な IP に対するオンライン照合 (複数プロバイダ、到達不能なら null) */
const GEO_PROVIDERS = [
  {
    name: 'ip-api',
    url: (ip) => `http://ip-api.com/json/${ip}?fields=status,countryCode,country,regionName,city,isp,as`,
    parse: (j) =>
      j.status === 'success'
        ? { country: j.countryCode, countryName: j.country, region: j.regionName, city: j.city, isp: j.isp, asn: j.as }
        : null,
  },
  {
    name: 'ipwho',
    url: (ip) => `https://ipwho.is/${ip}`,
    parse: (j) => (j.success !== false ? { country: j.country_code, countryName: j.country, region: j.region, city: j.city, isp: j.connection?.isp, asn: j.connection?.asn } : null),
  },
  {
    name: 'ipinfo',
    url: (ip) => `https://ipinfo.io/${ip}/json`,
    parse: (j) => {
      const org = String(j.org || '');
      return { country: j.country, city: j.city, region: j.region, isp: org.split(' ')[0] || undefined, asn: org.split(' ')[1] };
    },
  },
];

export class GeoResolver {
  /**
   * @param {{seed?:Map<string,{country?:string,city?:string,isp?:string}>, offline?:boolean, timeoutMs?:number}} [opts]
   */
  constructor({ seed = new Map(), offline = false, timeoutMs = 4000 } = {}) {
    this.seed = seed;
    this.cache = new LRU(20000, 1000 * 60 * 60 * 24 * 7);
    this.offline = offline;
    this.timeoutMs = timeoutMs;
    this.lookups = 0;
    this.providerOk = new Map(GEO_PROVIDERS.map((p) => [p.name, 0]));
    this.providerFail = new Map(GEO_PROVIDERS.map((p) => [p.name, 0]));
  }

  putSeed(ip, meta) {
    this.seed.set(ip, meta);
    this.cache.delete(ip);
  }

  /** @returns {{country:string, city?:string, isp?:string, source:string}|null} */
  resolveSync(ip) {
    if (!ip) return null;
    const seeded = this.seed.get(ip);
    if (seeded) return { ...seeded, source: 'list' };
    const cached = this.cache.get(ip);
    if (cached) return { ...cached, source: 'cache' };
    return null;
  }

  /**
   * @returns {Promise<{country:string, countryName?:string, city?:string, isp?:string, asn?:string, source:string}>}
   */
  async resolve(ip) {
    const sync = this.resolveSync(ip);
    if (sync) return sync;
    if (this.offline || typeof fetch !== 'function') {
      return { country: 'XX', source: 'offline' };
    }
    this.lookups++;
    for (const p of GEO_PROVIDERS) {
      if ((this.providerFail.get(p.name) || 0) > 4) continue;
      try {
        const parsed = p.parse(
          await fetchJson(p.url(ip), {
            timeoutMs: this.timeoutMs,
            maxBytes: 512 * 1024,
            headers: { accept: 'application/json', 'user-agent': 'MirageVPN/1.0 (geo-resolver)' },
          }),
        );
        if (!parsed || !parsed.country) throw new Error('国コードが取得できません');
        const rec = {
          country: String(parsed.country).toUpperCase().slice(0, 2),
          countryName: parsed.countryName,
          region: parsed.region,
          city: parsed.city,
          isp: parsed.isp,
          asn: parsed.asn,
          source: `api:${p.name}`,
        };
        this.cache.set(ip, rec);
        this.providerOk.set(p.name, (this.providerOk.get(p.name) || 0) + 1);
        return rec;
      } catch (err) {
        this.providerFail.set(p.name, (this.providerFail.get(p.name) || 0) + 1);
        ns.debug(() => `provider ${p.name} failed for ${ip}: ${err.message}`);
      }
    }
    return { country: 'XX', source: 'unresolved' };
  }

  stats() {
    return {
      lookups: this.lookups,
      seedEntries: this.seed.size,
      cacheSize: this.cache.size,
      providers: Object.fromEntries(GEO_PROVIDERS.map((p) => [p.name, { ok: this.providerOk.get(p.name) || 0, fail: this.providerFail.get(p.name) || 0 }])),
    };
  }
}

/**
 * リクエストヘッダからクライアントの国籍を推定。
 * `lookup:false` は高頻度の dashboard status 用。外部 Geo API を待たないので、
 * API 障害や送信制限で UI 全体が「読み込み中」のままにならない。
 */
export async function clientCountry(req, geo, { lookup = true } = {}) {
  const h = req.headers || {};
  const direct =
    h['cf-ipcountry'] ||
    h['x-vercel-ip-country'] ||
    h['x-geo-country'] ||
    h['x-client-country'] ||
    h['x-forwarded-country'];
  if (direct && /^[A-Za-z]{2}$/.test(String(direct))) return { country: String(direct).toUpperCase(), source: 'header' };
  const ip = publicIpOf(req);
  if (!ip) return { country: 'XX', source: 'no-ip' };
  if (!lookup) return { country: 'XX', source: 'deferred', ip };
  const rec = await geo.resolve(ip);
  return { country: rec.country, city: rec.city, isp: rec.isp, source: rec.source, ip };
}

export function publicIpOf(req) {
  const fwd = req.headers?.['x-forwarded-for'];
  const candidates = [];
  if (fwd) candidates.push(...String(fwd).split(',').map((s) => s.trim()));
  if (req.socket?.remoteAddress) candidates.push(req.socket.remoteAddress);
  for (const c of candidates) {
    if (!c) continue;
    if (isPrivateish(c)) continue;
    return c;
  }
  return null;
}

function isPrivateish(ip) {
  if (/^127\.|^10\.|^192\.168\.|^169\.254\.|^172\.(1[6-9]|2\d|3[01])\.|^::1$|^fe80:/i.test(ip)) return true;
  if (ip.startsWith('::ffff:')) return isPrivateish(ip.slice(7));
  return false;
}

/** Accept-Language / タイムゾーンなど、国籍に合わせたヘッダ Localize を生成 */
export function localizeHeaders(cc) {
  const meta = COUNTRIES[cc];
  if (!meta) return {};
  return {
    'accept-language': meta.lang,
    'sec-ch-ua-arch': undefined,
    'x-mirage-locale': cc.toLowerCase(),
  };
}

export function tzOf(cc) {
  return COUNTRIES[cc]?.tz || 'UTC';
}

/** 国コードの正規化 (big5/全角/小文字/国名混在対策) */
export function normalizeCountry(input) {
  if (!input) return null;
  let s = String(input).trim().toUpperCase();
  if (s === 'UK') s = 'GB';
  if (s === 'ZZ' || s === 'YY' || s === 'A1' || s === 'A2' || s === '--') s = 'XX';
  if (s === 'EU') return 'EU';
  if (!/^[A-Z]{2}$/.test(s)) return null;
  return s;
}

export { registrableDomain };

export default GeoResolver;
