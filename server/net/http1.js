/**
 * MirageVPN — HTTP/1.1 クライアント (素の socket 上)
 * ---------------------------------------------------------------
 * undici / node-fetch を使わず自前実装にするのは次の理由:
 *  1. フリープロキシリストには socks4/socks5 が多数。dispatcher 抽象では扱えない
 *  2. WISP トンネル = 「WebSocket 上で流れる HTTP/1.1」を素のバイト列として扱いたい
 *  3. keep-alive・decompress・redirect・ヘッダ書き換えを 1 箇所で制御したい
 *  4. 依存を express + ws の 2 つに絞れ、Vercel/Render/Railway/Docker で差分が出ない
 *
 * 出力は Node Readable な生ストリーム + 既にパース済みのヘッダ。zlib はここで解く
 * （改写は平文に対して行う必要があるため）。
 * @module net/http1
 */

import net from 'node:net';
import tls from 'node:tls';
import zlib from 'node:zlib';
import { Buffer } from 'node:buffer';
import { PassThrough } from 'node:stream';
import { socks4Connect, socks5Connect } from './socks.js';

const CRLF = Buffer.from('\r\n');
const CRLFCRLF = Buffer.from('\r\n\r\n');
const MAX_HEAD = 256 * 1024;

export class HttpError extends Error {
  constructor(message, { code = 'http_error', stage = 'request', cause } = {}) {
    super(message);
    this.name = 'HttpError';
    this.code = code;
    this.stage = stage;
    if (cause) this.cause = cause;
  }
}

/**
 * @typedef {object} ProxyDef
 * @property {'http'|'https'|'socks4'|'socks4a'|'socks5'|'direct'} [protocol]
 * @property {string} [host]
 * @property {number} [port]
 * @property {string} [username]
 * @property {string} [password]
 */

/**
 * プロキシ経由で target への「リクエストを書ける socket」を作る
 * @param {{host:string,port:number,secure?:boolean,proxy?:ProxyDef|null,timeoutMs?:number,servername?:string,signal?:AbortSignal,tls?:{ca?:string[],rejectUnauthorized?:boolean,minVersion?:string}}} [o]
 */
export async function dial({ host, port, secure, proxy, timeoutMs = 12000, servername, signal, tls: tlsOpts }) {
  const t0 = Date.now();
  const connectTimeout = { timeout: timeoutMs };
  let socket;
  let forwardAbsolute = false; // http プロキシ + http target → URI を絶対形で送る
  let reused = false;

  const plain = (h, p) => new Promise((resolve, reject) => {
    const s = net.connect({ host: h, port: p, ...connectTimeout, allowHalfOpen: false });
    const onError = (err) => {
      s.destroy();
      reject(
        new HttpError(err.code === 'ETIMEDOUT' || err.message.includes('timed out')
          ? `接続タイムアウト (${h}:${p})`
          : `接続に失敗しました (${h}:${p}): ${err.message}`, {
          code: err.code || 'connect_failed',
          stage: 'connect',
          cause: err,
        }),
      );
    };
    s.once('error', onError);
    s.once('connect', () => {
      s.off('error', onError);
      s.setTimeout(0);
      resolve(s);
    });
    if (signal) {
      if (signal.aborted) {
        s.destroy();
        return reject(new HttpError('キャンセルされました', { code: 'aborted' }));
      }
      signal.once('abort', () => {
        s.destroy(new HttpError('キャンセルされました', { code: 'aborted' }));
      });
    }
  });

  const wrapTls = (sock, sni, alpn = ['http/1.1']) =>
    new Promise((resolve, reject) => {
      const ts = tls.connect(
        {
          socket: sock,
          servername: sni || undefined,
          ALPNProtocols: alpn,
          // 中継する上流サイトは「証明書が古くても表示を止めない」= 宽松 (プロキシとしての仕様)。
          // 当方自身の管理通信 (リスト取得/Geo/検証) は tlsOpts で厳格検証に切り替える (net/trust.js)。
          rejectUnauthorized: tlsOpts?.rejectUnauthorized ?? false,
          ca: tlsOpts?.ca,
          minVersion: tlsOpts?.minVersion || 'TLSv1.2',
        },
      );
      ts.setTimeout(timeoutMs);
      const onTimeout = () => ts.destroy(new HttpError('TLS ハンドシェイクがタイムアウトしました', { code: 'tls_timeout' }));
      ts.once('timeout', onTimeout);
      const onTlsError = (err) => {
        ts.destroy();
        reject(new HttpError(`TLS エラー (${sni}): ${err.message}`, { code: err.code || 'tls_failed', stage: 'tls', cause: err }));
      };
      ts.once('error', onTlsError);
      // 下層 socket の番人はハンドシェイク成功後に必ず外す (keep-alive で再利用されるため、
      // 外さないと再利用のたびに listener が積み上がり MaxListenersExceeded になる)
      const onSockError = (err) => ts.destroy(err);
      sock.once('error', onSockError);
      const ok = () => {
        ts.setTimeout(0);
        ts.off('timeout', onTimeout);
        ts.off('error', onTlsError);
        sock.off('error', onSockError);
        resolve(ts);
      };
      ts.once('secureConnect', ok);
    });

  const proto = proxy?.protocol || 'direct';
  try {
    if (proto === 'direct' || !proxy?.host) {
      socket = await plain(host, port);
      if (secure) socket = await wrapTls(socket, servername || host);
    } else if (proto === 'socks5' || proto === 'socks4' || proto === 'socks4a') {
      socket = await plain(proxy.host, proxy.port);
      if (proto === 'socks5') {
        ({ socket } = await socks5Connect(socket, {
          host,
          port,
          username: proxy.username,
          password: proxy.password,
          timeoutMs,
        }));
      } else {
        ({ socket } = await socks4Connect(socket, {
          host,
          port,
          username: proxy.username,
          timeoutMs,
          use4a: true,
        }));
      }
      if (secure) socket = await wrapTls(socket, servername || host);
    } else if (proto === 'http' || proto === 'https') {
      // http(s) プロキシ
      socket = await plain(proxy.host, proxy.port);
      if (proto === 'https') socket = await wrapTls(socket, proxy.host, ['http/1.1']);
      if (secure) {
        await connectViaProxy(socket, host, port, proxy, timeoutMs);
        socket = await wrapTls(socket, servername || host);
      } else {
        forwardAbsolute = true; // 平文は absolute-URI フォワード
      }
    } else {
      throw new HttpError(`未対応のプロキシ種別: ${proto}`, { code: 'proxy_unsupported' });
    }
  } catch (err) {
    if (socket && !socket.destroyed) socket.destroy();
    throw err;
  }

  socket.setNoDelay(true);
  return { socket, forwardAbsolute, reused, connectMs: Date.now() - t0 };
}

async function connectViaProxy(socket, host, port, proxy, timeoutMs) {
  const authLine = proxy.username
    ? `Proxy-Authorization: Basic ${Buffer.from(`${proxy.username}:${proxy.password || ''}`).toString('base64')}\r\n`
    : '';
  socket.write(
    `CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n${authLine}Proxy-Connection: keep-alive\r\n\r\n`,
  );
  const resp = await readUntil(socket, CRLFCRLF, timeoutMs, MAX_HEAD);
  const statusLine = resp.head.toString('latin1').split('\r\n')[0] || '';
  const m = /^HTTP\/\d(?:\.\d)?\s+(\d{3})/.exec(statusLine);
  const code = m ? Number(m[1]) : 0;
  if (code !== 200) {
    throw new HttpError(`プロキシの CONNECT が拒否されました (HTTP ${code || '?'}: ${statusLine})`, {
      code: 'proxy_connect',
      stage: 'proxy',
    });
  }
  if (resp.rest.length) socket.unshift(resp.rest);
}

/** socket から delim まで読む (プロキシ handshake など) */
export function readUntil(socket, delim, timeoutMs, maxBytes = MAX_HEAD, acc = Buffer.alloc(0)) {
  return new Promise((resolve, reject) => {
    let buf = acc;
    let timer;
    const cleanup = () => {
      if (timer) clearTimeout(timer);
      socket.off('data', onData);
      socket.off('end', onEndOrErr);
      socket.off('error', onEndOrErr);
      socket.off('close', onEndOrErr);
    };
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      const idx = buf.indexOf(delim);
      if (idx !== -1) {
        cleanup();
        resolve({ head: buf.subarray(0, idx + delim.length), rest: buf.subarray(idx + delim.length) });
      } else if (buf.length > maxBytes) {
        cleanup();
        reject(new HttpError('レスポンスヘッダが大きすぎます', { code: 'head_too_large' }));
      }
    };
    const onEndOrErr = (err) => {
      cleanup();
      reject(err instanceof Error ? err : new HttpError('応答前に接続が閉じられました', { code: 'premature_close' }));
    };
    timer = setTimeout(() => {
      cleanup();
      reject(new HttpError(`ヘッダ待ちタイムアウト (${timeoutMs}ms)`, { code: 'head_timeout' }));
    }, timeoutMs);
    timer.unref?.();
    socket.on('data', onData);
    socket.on('end', onEndOrErr);
    socket.on('error', onEndOrErr);
    socket.on('close', onEndOrErr);
  });
}

/** 1 応答分のパーサ。HEAD が揃ったら onHead、本文は onBody(data) */
class ResponseParser {
  constructor(socket, { onHead, onBody, onEnd, onError, maxBodyBytes, method = 'GET' }) {
    this.socket = socket;
    this.method = String(method).toUpperCase();
    this.onHead = onHead;
    this.onBody = onBody;
    this.onEnd = onEnd;
    this.onError = onError;
    this.maxBodyBytes = maxBodyBytes || 0;
    this.state = 'head';
    this.acc = Buffer.alloc(0);
    this.bodyRead = 0;
    this.chunkRemaining = -1;
    this.done = false;
    this.keepAlive = false;
    this.info = null;
    this.rawHead = Buffer.alloc(0);
    this.socket.on('data', this.onData = this.onData.bind(this));
    this.socket.on('end', this.onEndOfData = this.onEndOfData.bind(this));
    this.socket.on('error', this.onErr = (e) => this.fail(e));
  }

  detach() {
    this.socket.off('data', this.onData);
    this.socket.off('end', this.onEndOfData);
    this.socket.off('error', this.onErr);
  }

  fail(err) {
    if (this.done) return;
    this.done = true;
    this.detach();
    this.onError(err);
  }

  finish(reusable) {
    if (this.done) return;
    this.done = true;
    this.detach();
    this.reusable = Boolean(reusable && this.keepAlive);
    this.onEnd();
  }

  onData(chunk) {
    try {
      this.consume(chunk);
    } catch (err) {
      this.fail(err);
    }
  }

  consume(chunk) {
    if (this.state === 'head') {
      this.acc = Buffer.concat([this.acc, chunk]);
      const idx = this.acc.indexOf(CRLFCRLF);
      if (idx === -1) {
        if (this.acc.length > MAX_HEAD) {
          this.fail(new HttpError('レスポンスヘッダが大きすぎます', { code: 'head_too_large' }));
        }
        return;
      }
      const headBuf = this.acc.subarray(0, idx + 4);
      this.rawHead = headBuf;
      const rest = this.acc.subarray(idx + 4);
      this.acc = Buffer.alloc(0);
      let info;
      try {
        info = parseHead(headBuf.toString('latin1'));
      } catch (err) {
        return this.fail(err);
      }
      // 1xx (Continue など) はヘッダの続きとして扱い、次の応答行を待つ
      if (info.statusCode >= 100 && info.statusCode < 200 && info.statusCode !== 101) {
        this.state = 'head';
        this.acc = Buffer.alloc(0);
        if (rest.length) this.consume(rest);
        return undefined;
      }
      if (Number.isNaN(info.contentLength)) {
        return this.fail(new HttpError('不正な Content-Length', { code: 'bad_cl' }));
      }
      this.info = info;
      this.keepAlive = info.keepAlive;
      this.onHead(info);
      const noBody = this.method === 'HEAD' || info.statusCode === 204 || info.statusCode === 304;
      if (noBody) return this.finish(true);
      if (info.transferEncoding === 'chunked') {
        this.state = 'chunksize';
      } else if (info.contentLength != null) {
        this.state = 'length';
        this.lengthRemaining = info.contentLength;
        if (info.contentLength === 0) return this.finish(true);
      } else {
        this.state = 'eof';
      }
      if (rest.length) this.consume(rest);
      return undefined;
    }

    if (this.state === 'length') {
      const take = Math.min(chunk.length, this.lengthRemaining);
      this.emit(chunk.subarray(0, take));
      this.lengthRemaining -= take;
      const leftover = chunk.subarray(take);
      if (this.lengthRemaining <= 0) {
        this.finish(true);
        if (leftover.length) this.socket.unshift(leftover);
      } else if (leftover.length) {
        this.socket.unshift(leftover); // 理論上来ない
      }
      return undefined;
    }

    if (this.state === 'eof') {
      if (chunk.length) this.emit(chunk);
      return undefined;
    }

    if (this.state === 'chunksize') {
      this.acc = Buffer.concat([this.acc, chunk]);
      const idx = this.acc.indexOf(CRLF);
      if (idx === -1) {
        if (this.acc.length > 1024) return this.fail(new HttpError('不正な chunk ヘッダ', { code: 'chunk_head' }));
        return undefined;
      }
      const line = this.acc.subarray(0, idx).toString('latin1');
      const leftoverAfterLine = this.acc.subarray(idx + 2);
      this.acc = Buffer.alloc(0);
      const size = parseInt(line.split(';')[0].trim(), 16);
      if (!Number.isFinite(size) || size < 0) {
        return this.fail(new HttpError(`不正な chunk サイズ: ${line}`, { code: 'chunk_size' }));
      }
      if (size === 0) {
        // trailers を読み飛ばす (\r\n もしくは 名前行群)
        this.state = 'trailer';
        this.acc = leftoverAfterLine;
        this.tryFinishTrailer();
        return undefined;
      }
      this.chunkRemaining = size;
      this.state = 'chunkdata';
      if (leftoverAfterLine.length) this.consume(leftoverAfterLine);
      return undefined;
    }

    if (this.state === 'chunkdata') {
      const take = Math.min(chunk.length, this.chunkRemaining);
      this.emit(chunk.subarray(0, take));
      this.chunkRemaining -= take;
      if (this.chunkRemaining > 0) return undefined;
      this.state = 'chunkskip';
      this.skipRemaining = 2; // 末尾 CRLF
      return this.consume(chunk.subarray(take));
    }

    if (this.state === 'chunkskip') {
      const take = Math.min(chunk.length, this.skipRemaining);
      this.skipRemaining -= take;
      const rest = chunk.subarray(take);
      if (this.skipRemaining > 0) return undefined;
      this.state = 'chunksize';
      if (rest.length) return this.consume(rest);
      return undefined;
    }

    if (this.state === 'trailer') {
      this.acc = Buffer.concat([this.acc, chunk]);
      this.tryFinishTrailer();
      return undefined;
    }
    return undefined;
  }

  tryFinishTrailer() {
    const idx = this.acc.indexOf(CRLFCRLF);
    const lone = this.acc.indexOf(CRLF);
    if (idx === 0 || (idx === -1 && lone === 0 && this.acc.length >= 2)) {
      const rest = this.acc.subarray(idx === 0 ? 4 : 2);
      this.acc = Buffer.alloc(0);
      this.finish(true);
      if (rest.length) this.socket.unshift(rest);
    } else if (idx > 0) {
      const rest = this.acc.subarray(idx + 4);
      this.acc = Buffer.alloc(0);
      this.finish(true);
      if (rest.length) this.socket.unshift(rest);
    } else if (this.acc.length > 64 * 1024) {
      this.fail(new HttpError('trailer が長すぎます', { code: 'trailer_too_large' }));
    }
  }

  onEndOfData() {
    if (this.state === 'eof') return this.finish(false);
    if (this.done) return;
    this.fail(new HttpError('本文を読み切る前に接続が閉じられました', { code: 'incomplete' }));
  }

  emit(data) {
    this.bodyRead += data.length;
    if (this.maxBodyBytes && this.bodyRead > this.maxBodyBytes) {
      this.fail(
        new HttpError(`応答が上限 (${this.maxBodyBytes} bytes) を超えました`, { code: 'body_too_large' }),
      );
      return;
    }
    const ok = this.onBody(data);
    if (ok === false) {
      this.socket.pause();
      this.paused = true;
    }
  }

  resume() {
    if (this.paused) {
      this.paused = false;
      this.socket.resume();
    }
  }
}

export function parseHead(text) {
  const lines = text.split('\r\n');
  const statusLine = lines.shift() || '';
  const m = /^HTTP\/(\d(?:\.\d)?)\s+(\d{3})\s*(.*)$/.exec(statusLine);
  if (!m) throw new HttpError(`不正なステータスライン: ${statusLine.slice(0, 120)}`, { code: 'bad_status' });
  const headers = new Map();
  let prev = null;
  for (const line of lines) {
    if (!line) continue;
    if (/^[ \t]/.test(line) && prev) {
      headers.set(prev, `${headers.get(prev)} ${line.trim()}`); // obsolete folding
      continue;
    }
    const i = line.indexOf(':');
    if (i < 0) continue;
    const k = line.slice(0, i).trim().toLowerCase();
    const v = line.slice(i + 1).trim();
    prev = k;
    if (headers.has(k)) headers.set(k, `${headers.get(k)}, ${v}`);
    else headers.set(k, v);
  }
  const conn = (headers.get('connection') || '').toLowerCase();
  const version = m[1];
  const statusCode = Number(m[2]);
  const keepAlive =
    (version === '1.1' ? !conn.includes('close') : conn.includes('keep-alive')) &&
    !conn.includes('close');
  const te = (headers.get('transfer-encoding') || '').toLowerCase();
  const cl = headers.get('content-length');
  return {
    httpVersion: version,
    statusCode,
    statusText: m[3] || '',
    headers,
    keepAlive,
    transferEncoding: te.includes('chunked') ? 'chunked' : te.includes('compress') ? 'bad' : 'identity',
    contentLength: cl != null && /^\d+$/.test(cl) ? Number(cl) : cl != null ? NaN : null,
    raw: text,
  };
}

/** keep-alive プール。origin + 出口プロキシ単位でソケットを使い回す */
export class Http1Pool {
  constructor(opts = {}) {
    this.maxIdlePerKey = opts.maxIdlePerKey ?? 6;
    this.idleTimeoutMs = opts.idleTimeoutMs ?? 15000;
    this.idle = new Map(); // key → [{socket, at}]
    this.inUse = new Set();
    this.stats = { reuse: 0, fresh: 0, dropped: 0 };
    this.timer = setInterval(() => this.#sweep(), 10000);
    this.timer.unref?.();
  }

  #sweep() {
    const now = Date.now();
    for (const [key, arr] of this.idle) {
      const keep = arr.filter((e) => {
        if (now - e.at > this.idleTimeoutMs || e.socket.destroyed || e.socket.readableEnded) {
          e.socket.destroy();
          this.stats.dropped++;
          return false;
        }
        return true;
      });
      if (keep.length) this.idle.set(key, keep);
      else this.idle.delete(key);
    }
  }

  take(key) {
    const arr = this.idle.get(key);
    while (arr?.length) {
      const e = arr.pop();
      if (e.socket.destroyed || e.socket.readableEnded || e.socket.readableLength > 0) {
        e.socket.destroy();
        this.stats.dropped++;
        continue;
      }
      // idle 中はプロセスを存活させない (serverless/スクリプトが終了できるように)。使う時に戻す
      try { e.socket.ref(); } catch { /* ignore */ }
      if (!arr.length) this.idle.delete(key);
      this.stats.reuse++;
      return e.socket;
    }
    return null;
  }

  /** プールから特定 socket を除外 */
  drop(socket) {
    for (const [key, arr] of this.idle) {
      const i = arr.findIndex((e) => e.socket === socket);
      if (i !== -1) arr.splice(i, 1);
      if (!arr.length) this.idle.delete(key);
    }
  }

  give(key, socket, hasPendingParser = false) {
    if (!socket || socket.destroyed || !socket.readable || hasPendingParser) {
      socket?.destroy();
      return;
    }
    // idle 中のエラーでプロセスが落ちないよう番人を張る (実質 keep-alive watchdog)
    if (!socket.__mirageIdleGuard) {
      const guard = () => {
        socket.destroy();
        this.drop(socket);
      };
      socket.__mirageIdleGuard = guard;
      socket.on('error', guard);
      socket.on('close', () => this.drop(socket));
    }
    if (socket.readableLength > 0) {
      // 応答以上のデータが来ている = プロトコル同期が取れない → 捨てて張り直し
      socket.destroy();
      this.stats.dropped++;
      return;
    }
    const arr = this.idle.get(key) || [];
    if (arr.length >= this.maxIdlePerKey) {
      socket.destroy();
      this.stats.dropped++;
      return;
    }
    arr.push({ socket, at: Date.now() });
    this.idle.set(key, arr);
    // idle ソケットがイベントループを生かし続けないようにする
    // (これをしないと serverless の応答完了後や CLI スクリプトが数十秒終了できない)
    try { socket.unref(); } catch { /* ignore */ }
    // idle 中は data を捨てないよう listener を待たせる
  }

  close() {
    clearInterval(this.timer);
    for (const arr of this.idle.values()) for (const e of arr) e.socket.destroy();
    this.idle.clear();
    for (const s of this.inUse) s.destroy();
    this.inUse.clear();
  }

  size() {
    let n = 0;
    for (const arr of this.idle.values()) n += arr.length;
    return n;
  }
}

/** decompress ストリーム生成 */
export function decompressStream(encoding) {
  const enc = (encoding || '').toLowerCase().split(',').pop().trim();
  if (enc === 'gzip' || enc === 'x-gzip') return zlib.createGunzip();
  if (enc === 'deflate') return zlib.createInflateRaw();
  if (enc === 'br') return zlib.createBrotliDecompress({ flush: zlib.constants.BROTLI_OPERATION_FLUSH });
  if (enc === 'zstd') return null; // Node 22 は zstd なし → 圧縮のまま流す (改写しない)
  return null;
}

/**
 * 1 リクエスト実行 (プール/リダイレクトは呼び出し側)
 * @param {object} o
 * @returns {Promise<{statusCode:number,statusText:string,headers:Map,stream:PassThrough,keepAlive:boolean,info:object,release:()=>void,abort:()=>void>}>
 */
export async function request(o) {
  const {
    method = 'GET',
    url,
    headers = new Map(),
    body = null,
    proxy = null,
    connectTimeoutMs = 12000,
    headTimeoutMs = 35000,
    idleTimeoutMs = 60000,
    maxBodyBytes = 0,
    pool = null,
    signal = null,
    httpVersionString = '1.1',
    rawPathOverride = null,
    tls = null,
  } = o;

  const target = typeof url === 'string' ? new URL(url) : url;
  const secure = target.protocol === 'https:';
  const port = Number(target.port) || (secure ? 443 : 80);
  const hostHeader = target.host; // ポート含む
  const proxyKey = proxy?.host ? `${proxy.protocol}:${proxy.host}:${proxy.port}` : 'direct';
  const trustKey = tls?.rejectUnauthorized ? 'strict' : 'loose';
  const key = `${proxyKey}|${target.origin}|${secure ? 1 : 0}|${trustKey}`;

  let socket = pool?.take(key) || null;
  let forwardAbsolute = false;
  if (socket && (socket.destroyed || socket.readableEnded || socket.errored)) socket = null;
  if (!socket) {
    const dialed = await dial({
      host: target.hostname,
      port,
      secure,
      proxy,
      timeoutMs: connectTimeoutMs,
      servername: target.hostname,
      signal,
      tls,
    });
    socket = dialed.socket;
    forwardAbsolute = dialed.forwardAbsolute;
    if (pool) pool.stats.fresh++;
  }

  const reqHeaders = new Map();
  for (const [k, v] of headers) if (v !== undefined && v !== null) reqHeaders.set(k.toLowerCase(), v);
  if (!reqHeaders.has('host')) reqHeaders.set('host', hostHeader);
  // absolute-URI フォワード時は Proxy-Authorization を本体リクエストに載せる
  if (forwardAbsolute && proxy?.username && !reqHeaders.has('proxy-authorization')) {
    reqHeaders.set(
      'proxy-authorization',
      `Basic ${Buffer.from(`${proxy.username}:${proxy.password || ''}`, 'utf8').toString('base64')}`,
    );
  }
  if (!reqHeaders.has('accept-encoding')) reqHeaders.set('accept-encoding', 'gzip, deflate, br');
  if (!reqHeaders.has('connection')) reqHeaders.set('connection', httpVersionString === '1.1' ? 'keep-alive' : 'close');
  if (body?.length != null && !reqHeaders.has('content-length')) reqHeaders.set('content-length', String(body.length));

  const path = rawPathOverride ?? (forwardAbsolute ? target.href : target.pathname + target.search || '/');

  const head = [`${method.toUpperCase()} ${path || '/'} HTTP/${httpVersionString}`];
  for (const [k, v] of reqHeaders) head.push(`${k}: ${v}`);
  const payload = Buffer.concat([Buffer.from(head.join('\r\n') + '\r\n\r\n', 'latin1'), body || Buffer.alloc(0)]);

  const out = new PassThrough({ highWaterMark: 256 * 1024 });
  let headTimer = null;
  let idleTimer = null;
  let parser = null;
  let settled = false;
  let released = false;
  let requestFail = null;

  const arm = () => {
    if (idleTimeoutMs > 0) {
      clearTimeout(idleTimer);
      idleTimer = setTimeout(() => {
        socket.destroy(new HttpError('データ転送が止まりました (idle timeout)', { code: 'idle_timeout' }));
      }, idleTimeoutMs);
      idleTimer.unref?.();
    }
  };
  const clearTimers = () => {
    clearTimeout(headTimer);
    clearTimeout(idleTimer);
    headTimer = idleTimer = null;
  };

  const release = () => {
    if (released) return;
    released = true;
    clearTimers();
    if (signal) signal.removeEventListener?.('abort', onAbort);
    // keep-alive で socket を返し回すので、このリクエスト専用の error 番人は必ず外す
    if (requestFail) socket.off('error', requestFail);
    if (pool) pool.give(key, socket, !parser?.done || !parser?.reusable);
    else if (!socket.destroyed) socket.destroy();
  };

  const onAbort = () => {
    if (!socket.destroyed) socket.destroy(new HttpError('キャンセルされました', { code: 'aborted' }));
  };
  if (signal) {
    if (signal.aborted) {
      socket.destroy();
      throw new HttpError('キャンセルされました', { code: 'aborted' });
    }
    signal.addEventListener?.('abort', onAbort, { once: true });
  }

  return await new Promise((resolve, reject) => {
    const fail = (err) => {
      if (settled) {
        socket.off('error', fail);
        out.destroy(err);
        return;
      }
      settled = true;
      clearTimers();
      if (signal) signal.removeEventListener?.('abort', onAbort);
      socket.off('error', fail);
      if (socket && !socket.destroyed) socket.destroy();
      reject(err);
    };
    requestFail = fail;
    socket.on('error', fail);

    parser = new ResponseParser(socket, {
      method,
      maxBodyBytes,
      onHead: (info) => {
        clearHeadTimer();
        arm();
        settled = true;
        resolve({
          statusCode: info.statusCode,
          statusText: info.statusText,
          headers: info.headers,
          keepAlive: info.keepAlive,
          info,
          stream: out,
          release,
          abort: () => {
            if (!socket.destroyed) socket.destroy(new HttpError('中断されました', { code: 'aborted' }));
          },
          get reusable() {
            return Boolean(parser.reusable);
          },
        });
      },
      onBody: (chunk) => {
        arm();
        const ok = out.write(chunk);
        return ok;
      },
      onEnd: () => {
        clearTimers();
        out.end();
        release();
      },
      onError: (err) => fail(err),
    });

    const onDrain = () => parser?.resume();
    out.on('drain', onDrain);
    out.on('error', () => {
      if (!socket.destroyed) socket.destroy();
    });

    function clearHeadTimer() {
      if (headTimer) {
        clearTimeout(headTimer);
        headTimer = null;
      }
    }

    if (headTimeoutMs > 0) {
      headTimer = setTimeout(() => {
        fail(new HttpError(`応答ヘッダ待ちタイムアウト (${headTimeoutMs}ms)`, { code: 'head_timeout' }));
      }, headTimeoutMs);
      headTimer.unref?.();
    }

    socket.write(payload, (err) => {
      if (err) fail(new HttpError(`リクエスト送信に失敗: ${err.message}`, { code: 'write_failed', stage: 'write', cause: err }));
    });
  });
}

export default { request, dial, Http1Pool, parseHead, decompressStream, HttpError, CRLF, CRLFCRLF };
