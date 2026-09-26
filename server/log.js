/**
 * レベル付きロガー。ログには「メタのみ」を出し、ページ本文・認証ヘッダは常時赤外する。
 * @module util/log
 */
const LEVELS = { silent: 0, error: 1, warn: 2, info: 3, debug: 4, trace: 5 };

const REDACT_KEYS =
  /^(authorization|cookie|set-cookie|proxy-authorization|x-api-key|password|passwd|secret|token|apikey|api_key)$/i;

let level = LEVELS.info;
let ns = 'mirage';

export function configureLogger({ level: l, namespace } = {}) {
  if (l && LEVELS[l] !== undefined) level = LEVELS[l];
  if (namespace) ns = namespace;
}

export function redact(value, depth = 0) {
  if (depth > 6) return '[…]';
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = REDACT_KEYS.test(k) ? `[redacted:${Buffer.byteLength(String(v ?? ''))}B]` : redact(v, depth + 1);
    }
    return out;
  }
  return value;
}

function stamp() {
  const d = new Date();
  const p = (n, l = 2) => String(n).padStart(l, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`;
}

function emit(kind, stream, msg, meta) {
  if (level < LEVELS[kind === 'error' ? 'error' : kind === 'warn' ? 'warn' : 'info']) return;
  const head = `${stamp()} ${kind.toUpperCase().padEnd(5)} [${ns}]`;
  if (meta === undefined) stream(`${head} ${msg}`);
  else stream(`${head} ${msg}`, typeof meta === 'string' ? meta : redact(meta));
}

export const log = {
  error: (m, meta) => emit('error', console.error, m, meta),
  warn: (m, meta) => emit('warn', console.warn, m, meta),
  info: (m, meta) => emit('info', console.log, m, meta),
  /** debug/trace はレベル判定してから文字列化する */
  debug: (m, meta) => {
    if (level < LEVELS.debug) return;
    emit('info', console.log, `· ${typeof m === 'function' ? m() : m}`, meta);
  },
  child(sub) {
    return {
      error: (m, x) => withNs(sub, () => log.error(m, x)),
      warn: (m, x) => withNs(sub, () => log.warn(m, x)),
      info: (m, x) => withNs(sub, () => log.info(m, x)),
      debug: (m, x) => {
        if (level < LEVELS.debug) return;
        withNs(sub, () => log.debug(m, x));
      },
    };
  },
};

function withNs(sub, fn) {
  const old = ns;
  ns = `${old}:${sub}`;
  try {
    fn();
  } finally {
    ns = old;
  }
}

export function shouldLog(l) {
  return level >= (LEVELS[l] ?? 99);
}

export default log;
