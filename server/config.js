/**
 * MirageVPN — 設定の一元管理
 * ---------------------------------------------------------------
 * すべて環境変数で上書き可能。Vercel / Render / Railway / Docker で
 * 同じコードが動くように「永続ディスク前提の挙動はすべて opt-in」にする。
 *
 * @module config
 */

import { randomBytes } from 'node:crypto';

const BOOL = (v, d) => {
  if (v === undefined || v === null || v === '') return d;
  const s = String(v).trim().toLowerCase();
  if (['1', 'true', 'yes', 'on', 'y'].includes(s)) return true;
  if (['0', 'false', 'no', 'off', 'n'].includes(s)) return false;
  return d;
};
const NUM = (v, d) => {
  if (v === undefined || v === null || v === '') return d;
  const n = Number(v);
  return Number.isFinite(n) ? n : d;
};
const LIST = (v, d = []) => {
  if (v === undefined || v === null || v === '') return d;
  return String(v)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
};

/** プロキシ経由で取得してよい応答の上限 (デフォルト 24MB) */
const HARD_MAX_BODY = 128 * 1024 * 1024;

/**
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {import('./types.js').Config}
 */
export function loadConfig(env = process.env) {
  const port = NUM(env.PORT, NUM(env.PORT_NUM, 8080));
  const host = env.HOST || env.HOSTNAME_BIND || '0.0.0.0';
  const isServerless = BOOL(env.VERCEL, false) || BOOL(env.AWS_LAMBDA_FUNCTION_NAME, false);
  const writable = env.MIRAGE_STATE_DIR || (isServerless ? '/tmp/mirage' : '');

  const cfg = {
    meta: {
      name: 'MirageVPN',
      version: '1.0.0',
      codename: 'aurora',
    },

    /* ---------- server ---------- */
    env: env.NODE_ENV || (isServerless ? 'production' : 'development'),
    isServerless,
    port,
    host,
    /** 公開ベースURL (reverse proxy / preview host 用). 未指定なら req から推定 */
    publicBase: env.MIRAGE_PUBLIC_BASE || env.PUBLIC_URL || '',
    /** HMAC/署名用シークレット。未指定なら起動毎にランダム (＝再起動でトークンは失効) */
    secret: env.MIRAGE_SECRET || env.GITHUB_CLIENT_SECRET || randomHex(24),
    trustProxy: BOOL(env.TRUST_PROXY, true),
    basePath: normalizeBase(env.MIRAGE_BASE_PATH || ''),

    /* ---------- capabilities ---------- */
    /** WS (WISP) を有効にするか。serverless では自動で無効化される */
    wisp: {
      enabled: BOOL(env.MIRAGE_WISP, !isServerless),
      path: '/mirage/wisp',
      maxStreamsPerSession: NUM(env.MIRAGE_WISP_MAX_STREAMS, 64),
      keepaliveMs: NUM(env.MIRAGE_WISP_KEEPALIVE, 20000),
      idleTimeoutMs: NUM(env.MIRAGE_WISP_IDLE_TIMEOUT, 90000),
      maxMessageBytes: NUM(env.MIRAGE_WISP_MAX_FRAME, 512 * 1024),
      /** pause/resume による flow control の高水位 */
      highWaterMarkBytes: NUM(env.MIRAGE_WISP_HWM, 2 * 1024 * 1024),
    },

    /* ---------- URL scheme ---------- */
    url: {
      /** 'token' = host を base64url トークン難読化 (既定) / 'plain' = 平文URL */
      encoding: env.MIRAGE_URL_ENCODING === 'plain' ? 'plain' : 'token',
      prefix: '/mirage/t',
      swPath: '/mirage/sw.js',
      corePath: '/mirage/core.js',
      apiPrefix: '/mirage/api',
      appPath: '/mirage/app',
      swScope: '/',
    },

    /* ---------- transport ---------- */
    transport: {
      /** 'uv' (HTTP, 高速) / 'wisp' (WS 多重トンネル) / 'auto' */
      defaultMode: ['uv', 'wisp', 'auto'].includes(env.MIRAGE_MODE) ? env.MIRAGE_MODE : 'uv',
      connectTimeoutMs: NUM(env.MIRAGE_CONNECT_TIMEOUT, 12000),
      responseTimeoutMs: NUM(env.MIRAGE_RESPONSE_TIMEOUT, 35000),
      streamIdleTimeoutMs: NUM(env.MIRAGE_STREAM_IDLE_TIMEOUT, 90000),
      maxRedirects: NUM(env.MIRAGE_MAX_REDIRECTS, 6),
      maxBodyBytes: Math.min(NUM(env.MIRAGE_MAX_BODY, 24 * 1024 * 1024), HARD_MAX_BODY),
      keepAlive: BOOL(env.MIRAGE_KEEPALIVE, true),
      /** 圧縮は常に解いてから書き換える (rewrite の前提) */
      decompress: true,
      /** 書き換え済み静的アセットのメモリキャッシュ */
      cache: {
        enabled: BOOL(env.MIRAGE_CACHE, true),
        ttlMs: NUM(env.MIRAGE_CACHE_TTL, 5 * 60 * 1000),
        maxBytes: NUM(env.MIRAGE_CACHE_MAX, 64 * 1024 * 1024),
        maxEntryBytes: NUM(env.MIRAGE_CACHE_MAX_ENTRY, 2 * 1024 * 1024),
      },
    },

    /* ---------- egress (出口) ---------- */
    egress: {
      /** direct = 自前IP / pool = フリープロキシプール / auto = プール優先→直接フォールバック */
      defaultStrategy: ['direct', 'pool', 'auto'].includes(env.MIRAGE_EGRESS)
        ? env.MIRAGE_EGRESS
        : 'auto',
      /** 狙う国籍 (ISO 3166-1 alpha-2). 'auto' なら未指定=プール全体から最適選択 */
      country: (() => {
        const v = String(env.MIRAGE_COUNTRY || '').trim().toUpperCase();
        if (!v || v === 'AUTO' || v === 'ANY' || v === 'OPTIMAL') return null; // 自動判定 (UX: 「AUTO」)
        return /^[A-Z]{2}$/.test(v) ? v : null;
      })(),
      protocols: LIST(env.MIRAGE_EGRESS_PROTOCOLS, ['http', 'https', 'socks5', 'socks4']),
      maxPoolSize: NUM(env.MIRAGE_MAX_POOL, 1200),
      /** 応答がこの以上のプロキシは避ける */
      maxLatencyMs: NUM(env.MIRAGE_MAX_LATENCY, 4200),
      /** 連続失敗で除外 */
      failThreshold: NUM(env.MIRAGE_FAIL_THRESHOLD, 3),
      /** 除外後の再試用までの時間 */
      cooldownMs: NUM(env.MIRAGE_PROXY_COOLDOWN, 15 * 60 * 1000),
      /** ヘルスチェックの間隔 / 同時実行数 */
      healthcheckMs: NUM(env.MIRAGE_HEALTHCHECK_INTERVAL, 5 * 60 * 1000),
      healthcheckConcurrency: NUM(env.MIRAGE_HEALTHCHECK_CONCURRENCY, 48),
      healthcheckTimeoutMs: NUM(env.MIRAGE_HEALTHCHECK_TIMEOUT, 6500),
      /** 1リクエスト当たりのプロキシ再試行回数 */
      retries: NUM(env.MIRAGE_EGRESS_RETRIES, 2),
      /** クライアントの偽装IPヘッダ (X-Forwarded-For 等) を注入する */
      spoofForwardedHeaders: BOOL(env.MIRAGE_SPOOF_FORWARDED, true),
      /** 国別の Accept-Language / UA  Localization */
      localizeHeaders: BOOL(env.MIRAGE_LOCALIZE_HEADERS, true),
      /** Do-Not-Track / GPC を上流に伝える */
      sendPrivacySignals: BOOL(env.MIRAGE_SEND_PRIVACY_SIGNALS, true),
      /** 一般ユーザー向けデフォルトUA (Trace を減らすため統一) */
      userAgent:
        env.MIRAGE_USER_AGENT ||
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    },

    /* ---------- proxy list sources ---------- */
    lists: {
      /** 自動更新の間隔 (既定 30 分) */
      refreshMs: NUM(env.MIRAGE_LIST_REFRESH, 30 * 60 * 1000),
      enabled: BOOL(env.MIRAGE_LIST_AUTO_REFRESH, true),
      /** 組み込みシードを最初に読み込む */
      useBundledSeed: BOOL(env.MIRAGE_USE_SEED, true),
      fetchTimeoutMs: NUM(env.MIRAGE_LIST_TIMEOUT, 20000),
      /** 追加ソース (カンマ区切り url または url#proto#country) */
      extra: LIST(env.MIRAGE_PROXY_SOURCES, []),
      /** GitHub 生ファイルがブロックされた環境向けの api.github.com ミラー */
      githubApiMirror: BOOL(env.MIRAGE_GITHUB_API_MIRROR, true),
      /** ミラーの優先順位 */
      // raw.githubusercontent.com は環境によって TLS/egress 制限を受けやすい。
      // GitHub API は同じリポジトリを直接返せるため、まず API を試してからミラーへ落とす。
      mirrorOrder: LIST(env.MIRAGE_MIRROR_ORDER, ['github-api', 'raw', 'jsdelivr', 'codeberg']),
      minKeep: NUM(env.MIRAGE_MIN_KEEP, 40),
    },

    /* ---------- shields (広告ブロック) ---------- */
    shields: {
      enabled: BOOL(env.MIRAGE_ADBLOCK, true),
      /** standard = EasyList系 / aggressive = トラッキング/フィンチも / off */
      privacyLevel: ['standard', 'aggressive', 'off'].includes(env.MIRAGE_PRIVACY_LEVEL)
        ? env.MIRAGE_PRIVACY_LEVEL
        : 'standard',
      cosmetic: BOOL(env.MIRAGE_COSMETIC, true),
      unbreakable: BOOL(env.MIRAGE_UNBREAKABLE, true),
      customLists: LIST(env.MIRAGE_AD_LISTS, []),
      maxRules: NUM(env.MIRAGE_MAX_RULES, 260000),
      refreshMs: NUM(env.MIRAGE_AD_LIST_REFRESH, 12 * 60 * 60 * 1000),
      /** 生成済み同梱シード (uAssets + EasyList)。`''` で読まない */
      seedFile: env.MIRAGE_ADBLOCK_SEED ?? 'data/adblock/mirage-shields.seed.txt',
      /** hard-block 層 (||host^ のみ・ネットワーク不要で広告網を落とす)。`''` で無効 */
      hostsSeed: env.MIRAGE_ADBLOCK_HOSTS_SEED ?? 'data/adblock/hosts.seed.txt',
    },

    /* ---------- threats ---------- */
    threats: {
      enabled: BOOL(env.MIRAGE_THREAT_SCAN, true),
      /** 検知した要素をレスポンスから自動削除する */
      autoDelete: BOOL(env.MIRAGE_THREAT_AUTODELETE, true),
      /** このスコア以上で block (quarantine) */
      blockScore: NUM(env.MIRAGE_THREAT_BLOCK_SCORE, 80),
      /** このスコア以上で自動除去 / 以下は警告のみ */
      sanitizeScore: NUM(env.MIRAGE_THREAT_SANITIZE_SCORE, 40),
      maxReportEvents: NUM(env.MIRAGE_THREAT_REPORT_SIZE, 800),
      /** 本文スキャンの上限バイト (これ以上は先頭のみ) */
      scanBytes: NUM(env.MIRAGE_THREAT_SCAN_BYTES, 3 * 1024 * 1024),
      /** 危険ファイル拡張子のダウンロードを止める */
      blockDangerousDownloads: BOOL(env.MIRAGE_BLOCK_DANGEROUS_FILES, true),
      /** クレデンシャルを別ドメインへ送るフォームを検知したら遮断 */
      credentialLeakGuard: BOOL(env.MIRAGE_CRED_GUARD, true),
      /** 検知イベントの保持期間 (レポート用) */
      retentionMs: NUM(env.MIRAGE_THREAT_RETENTION, 24 * 60 * 60 * 1000),
    },

    /* ---------- safety ---------- */
    safety: {
      /** 内部アドレス/メタデータへのリクエストを遮断 (SSRF 対策)。テスト時のみ false に */
      blockPrivateTargets: BOOL(env.MIRAGE_BLOCK_PRIVATE_TARGETS, true),
      allowProtocols: LIST(env.MIRAGE_ALLOW_PROTOCOLS, ['http:', 'https:']),
      /** ログインフォームを検知したら UI で警告する */
      warnOnCredentials: BOOL(env.MIRAGE_WARN_CREDENTIALS, true),
      /** ページ本文をログに出さない (メタのみ) */
      redactLogging: BOOL(env.MIRAGE_REDACT_LOG, true),
      /** パニックキー: 押すと即座にタブを閉じて about:blank に */
      panicKeys: LIST(env.MIRAGE_PANIC_KEYS, ['Shift+Escape']),
      killSwitch: BOOL(env.MIRAGE_KILL_SWITCH, false),
    },

    /* ---------- rate limit ---------- */
    limits: {
      reqPerMin: NUM(env.MIRAGE_RATE_REQ, 900),
      bytesPerMin: NUM(env.MIRAGE_RATE_BYTES, 220 * 1024 * 1024),
      /** 1クライアントあたり同時ストリーム */
      maxConcurrent: NUM(env.MIRAGE_MAX_CONCURRENT, 24),
      windowMs: NUM(env.MIRAGE_RATE_WINDOW, 60000),
    },

    /* ---------- state ---------- */
    state: {
      /** 設定/検知履歴を永続化するディレクトリ ('' ならメモリのみ) */
      dir: writable,
      persist: BOOL(env.MIRAGE_PERSIST, !!writable),
      settingsFile: 'settings.json',
      reportFile: 'threat-report.json',
      poolFile: 'pool.json',
      maxPersistBytes: NUM(env.MIRAGE_PERSIST_MAX, 4 * 1024 * 1024),
    },

    /* ---------- search ---------- */
    search: {
      engine: env.MIRAGE_SEARCH_ENGINE || 'duckduckgo',
      engines: {
        duckduckgo: 'https://html.duckduckgo.com/html/?q={q}',
        duckduckgoLite: 'https://lite.duckduckgo.com/lite/?q={q}',
        brave: 'https://search.brave.com/search?q={q}',
        startpage: 'https://www.startpage.com/sp/search?query={q}',
        bing: 'https://www.bing.com/search?q={q}&format=rss',
        google: 'https://www.google.com/search?q={q}&num=50',
        wikipedia: 'https://ja.wikipedia.org/w/index.php?search={q}',
        episo: 'https://www.episo.me/?s={q}',
      },
      bangPrefix: '!',
    },

    /* ---------- AI Mode (Google 検索の AI を API として使う) ---------- */
    // 公式 API は存在しない。serp (自前スクレイプ) / relay (外部ブラウザ) /
    // serpapi (有料) の 3 経路を選べる。既定は自前の serp。
    aimode: {
      enabled: BOOL(env.MIRAGE_AIMODE, false),
      /** serp = 自前 (udm=50) / relay = 外部リレー / serpapi = 有料 SERP API */
      provider: ['relay', 'serpapi'].includes(env.MIRAGE_AIMODE_PROVIDER) ? env.MIRAGE_AIMODE_PROVIDER : 'serp',
      /** AI Mode は geo 制限があるので出口国を固定する */
      country: (env.MIRAGE_AIMODE_COUNTRY || 'US').toUpperCase().slice(0, 2),
      /** 出口戦略: pool (既定) = その国のプロキシだけ / auto = 健全な proxy→direct /
       *  direct = 自ホストの IP (US にあるホストだけ) */
      egressStrategy: ['auto', 'direct'].includes(env.MIRAGE_AIMODE_EGRESS_STRATEGY) ? env.MIRAGE_AIMODE_EGRESS_STRATEGY : 'pool',
      /** その国が見つからないとき他国へ譲歩するか (既定 false = geo を守る) */
      egressAllowFallback: BOOL(env.MIRAGE_AIMODE_EGRESS_FALLBACK, false),
      /** CAPTCHA/上流エpsilon時の出口変更リトライ回数 */
      retries: NUM(env.MIRAGE_AIMODE_RETRIES, 1),
      lang: env.MIRAGE_AIMODE_LANG || 'en',
      /** 接続先 (テスト/自前 origin 用。既定は本物の Google) */
      baseUrl: env.MIRAGE_AIMODE_BASE_URL || 'https://www.google.com',
      /** 同意ページを避けるクッキー (例: SOCS=CAI / CONSENT=YES+cb) */
      consentCookie: env.MIRAGE_AIMODE_CONSENT_COOKIE || 'SOCS=CAI',
      /** 引用の /goto?url= 包装を HTTP で解く (出口を余分に使う) */
      resolveWrapped: BOOL(env.MIRAGE_AIMODE_RESOLVE_WRAPPED, true),
      maxResolveCitations: NUM(env.MIRAGE_AIMODE_MAX_RESOLVE, 12),
      /** 抽出の調整 (DOM が変わった時の逃げ道) */
      containers: LIST(env.MIRAGE_AIMODE_CONTAINERS, []),
      disclaimerRe: env.MIRAGE_AIMODE_DISCLAIMER_RE ? safeRegex(env.MIRAGE_AIMODE_DISCLAIMER_RE) : null,
      sourcesLabelRe: env.MIRAGE_AIMODE_SOURCES_RE ? safeRegex(env.MIRAGE_AIMODE_SOURCES_RE) : null,
      googleHosts: LIST(env.MIRAGE_AIMODE_GOOGLE_HOSTS, []),
      /** 予算 (Google にブロックされないための自制) */
      perHour: NUM(env.MIRAGE_AIMODE_PER_HOUR, 30),
      perDay: NUM(env.MIRAGE_AIMODE_PER_DAY, 200),
      minIntervalMs: NUM(env.MIRAGE_AIMODE_MIN_INTERVAL, 4000),
      cooldownMs: NUM(env.MIRAGE_AIMODE_COOLDOWN, 1800000),
      /** キャッシュ (同じ問い合わせで出口を浪費しない) */
      cacheTtlMs: NUM(env.MIRAGE_AIMODE_CACHE_TTL, 900000),
      cacheMax: NUM(env.MIRAGE_AIMODE_CACHE_MAX, 300),
      /** relay プロバイダ (Playwright 常駐ブラウザ等) */
      relayUrl: env.MIRAGE_AIMODE_RELAY_URL || '',
      relayKey: env.MIRAGE_AIMODE_RELAY_KEY || '',
      relayTimeoutMs: NUM(env.MIRAGE_AIMODE_RELAY_TIMEOUT, 90000),
      /** serpapi プロバイダ */
      serpApiKey: env.MIRAGE_SERPAPI_KEY || '',
      /** 認証 (設定すると Bearer / ?key= が必須) */
      token: env.MIRAGE_AIMODE_TOKEN || '',
      /** 生 HTML を返すデバッグ API を許可するか */
      debug: BOOL(env.MIRAGE_AIMODE_DEBUG, false),
      /** OpenAI 互換エンドポイントのモデル名 */
      openaiModelId: env.MIRAGE_AIMODE_MODEL_ID || 'google-ai-mode',
    },

    /* ---------- observability ---------- */
    telemetry: {
      /** 内部メトリクス (req/s, p95, block数) を /mirage/api/metrics で公開 */
      exposeMetrics: BOOL(env.MIRAGE_METRICS, true),
      logLevel: env.MIRAGE_LOG_LEVEL || (env.NODE_ENV === 'test' ? 'silent' : 'info'),
      slowMs: NUM(env.MIRAGE_SLOW_MS, 4000),
    },
  };

  return cfg;
}

function normalizeBase(p) {
  if (!p) return '';
  let s = String(p).trim();
  if (!s.startsWith('/')) s = `/${s}`;
  if (s.endsWith('/')) s = s.slice(0, -1);
  return s === '/' ? '' : s;
}

function randomHex(n) {
  return randomBytes(n).toString('hex');
}

/** 環境変数の正規表現を安全にコンパイル (壊れていたら null) */
function safeRegex(pattern) {
  try {
    const re = new RegExp(pattern, 'i');
    return re.source.length > 4 ? re : null;
  } catch {
    return null;
  }
}

export default loadConfig;
