/**
 * WISP サーバ (WebSocket 上のストリーム多重化)
 * ---------------------------------------------------------------
 * 「UV のさらに上に WISP をかぶせる」という要求の実装本体。
 * ブラウザ側 (public/mirage/wisp-client.js) は 1 本の WebSocket しか張らず、
 * リクエストごとに streamId を割り当ててここへ流す。ここでは:
 *
 *   mode:'http'   → パイプライン (出口プロキシ/シールド/脅威/改写) を実行し、
 *                   完成した HTTP/1.1 応答バイト列を DATA フレームで返し、CLOSE する。
 *                   ※ 上流が https でも、サーバ側で TLS を終端できるので素の tunnel で足りる。
 *   mode:'tunnel' → host:port へ素の TCP を張って双向にパイプ (http:// と ws:// のみ。
 *                   ブラウザはトンネル内で TLS を張れないため https は http モードへ寄せる)。
 *
 * フロー制御: ws の bufferedAmount が閾値を超えた stream には PAUSE を送り、
 * 空いたら RESUME。大量レスポンスでメモリを吹き飛ばさないため。
 * @module wisp/server
 */

import { WebSocketServer } from 'ws';
import net from 'node:net';
import tls from 'node:tls';
import { Buffer } from 'node:buffer';
import { FRAME, decodeFrame, encodeFrame } from './protocol.js';
import { log } from '../log.js';
import { fmtBytes } from '../util.js';

const ns = log.child('wisp');

const ZERO_STREAM = '0'.repeat(32);
const WISP_VERSION = 'mirage-wisp/1 (wisp-0.5 framing)';

export class WispServer {
  /**
   * @param {{config:object, pipeline:object, store?:object, guard?:object}} deps
   */
  constructor(deps) {
    this.config = deps.config;
    this.pipeline = deps.pipeline;
    this.store = deps.store;
    this.guard = deps.guard;
    this.wss = new WebSocketServer({ noServer: true, maxPayload: this.config.wisp.maxMessageBytes });
    this.conns = new Set();
    this.stats = { connections: 0, streams: 0, httpStreams: 0, tunnelStreams: 0, bytes: 0, errors: 0, rejections: 0, active: 0, peak: 0 };
    this.enabled = this.config.wisp.enabled;
  }

  /** http.Server の upgrade を配線する */
  attach(httpServer) {
    if (!this.enabled) return false;
    const path = `${this.config.basePath || ''}${this.config.wisp.path}`;
    const proxyPrefix = `${this.config.basePath || ''}${this.config.url.prefix}`;
    httpServer.on('upgrade', (req, socket, head) => {
      let url;
      try {
        url = new URL(req.url, 'http://localhost');
      } catch {
        socket.destroy();
        return;
      }
      if (url.pathname !== path) {
        if (url.pathname.startsWith(`${proxyPrefix}/`)) return; // proxied ws は routes 側で処理
        socket.destroy();
        return;
      }
      // CSWSH 対策: 同じオリジンからのみ受け付ける
      const origin = req.headers.origin;
      const host = req.headers.host;
      if (origin && host) {
        try {
          if (new URL(origin).host !== host) {
            this.stats.rejections++;
            ns.warn(`origin mismatch rejected: ${origin} != ${host}`);
            socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
            return socket.destroy();
          }
        } catch {
          socket.destroy();
          return;
        }
      }
      this.wss.handleUpgrade(req, socket, head, (ws) => this.#conn(ws, req, url));
    });
    return true;
  }

  #conn(ws, req, url) {
    const sid = (url.searchParams.get('sid') || '').slice(0, 64) || null;
    const clientId = (url.searchParams.get('client') || '').slice(0, 64) || null;
    const conn = {
      ws,
      sid,
      clientId,
      streams: new Map(),
      acc: Buffer.alloc(0),
      openedAt: Date.now(),
      bytes: 0,
      ip: req.socket.remoteAddress,
      alive: true,
    };
    this.conns.add(conn);
    this.stats.connections++;
    this.stats.active++;
    if (this.stats.active > this.stats.peak) this.stats.peak = this.stats.active;

    const keepalive = setInterval(() => {
      if (ws.readyState !== 1) return;
      try {
        ws.send(encodeFrame('0'.repeat(32), FRAME.KEEPALIVE));
      } catch (e) {
        /* noop */
      }
    }, this.config.wisp.keepaliveMs);
    if (keepalive.unref) keepalive.unref();

    ws.on('message', (data, isBinary) => {
      try {
        this.#message(conn, data, isBinary);
      } catch (err) {
        this.stats.errors++;
        ns.debug(() => `frame error: ${err.message}`);
        safeSend(ws, encodeFrame('0'.repeat(32), FRAME.ERROR, Buffer.from(String(err.message).slice(0, 200))));
      }
    });

    const cleanup = () => {
      conn.alive = false;
      clearInterval(keepalive);
      for (const [id, st] of conn.streams) {
        st.closed = true;
        st.socket?.destroy();
      }
      conn.streams.clear();
      this.conns.delete(conn);
      this.stats.active = Math.max(0, this.stats.active - 1);
    };
    ws.on('close', cleanup);
    ws.on('error', (err) => {
      this.stats.errors++;
      ns.debug(() => `ws error: ${err.message}`);
      cleanup();
    });
    ws.on('pong', () => (conn.alive = true));

    // 能力通知 (HELLO)。客户端はこれを受けて maxStreams を自分に合わせる。
    // 旧実装はここで CONNECT をエコーしていた (方向が誤っており、客户端には単に無視される)。
    safeSend(
      ws,
      encodeFrame(
        ZERO_STREAM,
        FRAME.HELLO,
        Buffer.from(
          JSON.stringify({
            ok: true,
            version: WISP_VERSION,
            maxStreams: this.config.wisp.maxStreamsPerSession,
            keepaliveMs: this.config.wisp.keepaliveMs,
            modes: ['http', 'tunnel'],
            sid,
          }),
        ),
      ),
    );
  }

  #message(conn, data, isBinary) {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    conn.acc = Buffer.concat([conn.acc, buf]);
    let offset = 0;
    let frame;
    while ((frame = decodeFrame(conn.acc, offset))) {
      offset = frame.next;
      conn.bytes += frame.payload.length;
      this.stats.bytes += frame.payload.length;
      this.#handle(conn, frame);
    }
    if (offset > 0) conn.acc = conn.acc.subarray(offset);
    if (conn.acc.length > 4 * 1024 * 1024) {
      ns.warn('frame buffer overflow, closing conn');
      try { conn.ws.close(1009, 'buffer overflow'); } catch (e) {}
    }
  }

  #handle(conn, { streamId, type, payload }) {
    const { ws } = conn;
    if (type === FRAME.KEEPALIVE) return;
    if (type === FRAME.PAUSE || type === FRAME.RESUME) {
      const st = conn.streams.get(streamId);
      if (st) st.paused = type === FRAME.PAUSE;
      return;
    }
    if (type === FRAME.CLOSE) {
      const st = conn.streams.get(streamId);
      if (st) {
        st.closed = true;
        st.socket?.destroy();
        conn.streams.delete(streamId);
      }
      return;
    }
    if (type === FRAME.DATA) {
      const st = conn.streams.get(streamId);
      if (!st) return;
      if (st.mode === 'tunnel') {
        st.socket?.write(payload);
        return;
      }
      st.reqBuf.push(payload); // http モードでクライアントがリクエスト本文を後追いした場合
      return;
    }
    if (type === FRAME.CONNECT) {
      this.#connectStream(conn, streamId, payload);
      return;
    }
    safeSend(ws, encodeFrame(streamId, FRAME.ERROR, Buffer.from('unsupported frame type')));
  }

  async #connectStream(conn, streamId, payload) {
    let msg;
    try {
      msg = JSON.parse(payload.toString('utf8') || '{}');
    } catch (err) {
      return this.#error(conn, streamId, `CONNECT payload が解析できません: ${err.message}`);
    }
    if (conn.streams.size >= this.config.wisp.maxStreamsPerSession) {
      return this.#error(conn, streamId, `ストリーム数が上限 (${this.config.wisp.maxStreamsPerSession}) を超えました`);
    }
    const stream = {
      mode: msg.mode === 'tunnel' ? 'tunnel' : 'http',
      reqBuf: [],
      closed: false,
      paused: false,
      startedAt: Date.now(),
      bytes: 0,
    };
    conn.streams.set(streamId, stream);
    this.stats.streams++;
    if (stream.mode === 'tunnel') this.stats.tunnelStreams++;
    else this.stats.httpStreams++;

    if (stream.mode === 'tunnel') return this.#tunnel(conn, streamId, stream, msg);

    // ---- HTTP over WISP ----
    let target;
    try {
      target = new URL(msg.url);
    } catch {
      return this.#error(conn, streamId, 'url が不正です');
    }
    if (this.guard) {
      const g = this.guard.check(target);
      if (!g.ok) return this.#error(conn, streamId, `blocked: ${g.reason}`);
    }
    const body = msg.body ? Buffer.from(msg.body, 'base64') : null;
    try {
      const res = await this.pipeline.wispExecute({
        sid: conn.sid || msg.sid || 'wisp',
        clientId: conn.clientId,
        method: msg.method || 'GET',
        url: target.href,
        headers: msg.headers || {},
        body,
        referrer: msg.referrer,
      });
      if (stream.closed) return;
      this.#writeAll(conn, streamId, stream, res);
    } catch (err) {
      this.#error(conn, streamId, err?.message || 'upstream failed');
    }
  }

  #writeAll(conn, streamId, stream, buffer) {
    const CHUNK = 64 * 1024;
    let i = 0;
    const pump = () => {
      if (stream.closed || conn.ws.readyState !== 1) return;
      while (i < buffer.length) {
        const slice = buffer.subarray(i, i + CHUNK);
        i += slice.length;
        stream.bytes += slice.length;
        const tooMuch = conn.ws.bufferedAmount > this.config.wisp.highWaterMarkBytes;
        if (tooMuch) {
          safeSend(conn.ws, encodeFrame(streamId, FRAME.PAUSE));
          return setTimeout(pump, 25);
        }
        safeSend(conn.ws, encodeFrame(streamId, FRAME.DATA, slice));
      }
      safeSend(conn.ws, encodeFrame(streamId, FRAME.CLOSE));
      conn.streams.delete(streamId);
      this.store?.touchSession(conn.sid, { wispBytes: (this.store?.session(conn.sid)?.wispBytes || 0) + stream.bytes, wispMs: Date.now() - stream.startedAt });
    };
    pump();
  }

  #tunnel(conn, streamId, stream, msg) {
    const host = String(msg.host || '').trim();
    const port = Number(msg.port) || 80;
    if (!host) return this.#error(conn, streamId, 'host がありません');
    const secure = msg.tls === true;
    const open = () =>
      new Promise((resolve, reject) => {
        const sock = net.connect({ port, host, timeout: 9000 }, () => resolve(sock));
        sock.once('error', reject);
        sock.once('timeout', () => sock.destroy(new Error('connect timeout')));
      });
    (secure ? open().then((s) => connectTls(s, host)) : open())
      .then((socket) => {
        if (stream.closed) return socket.destroy();
        stream.socket = socket;
        socket.on('data', (chunk) => {
          if (stream.closed) return;
          stream.bytes += chunk.length;
          safeSend(conn.ws, encodeFrame(streamId, FRAME.DATA, chunk));
          if (conn.ws.bufferedAmount > this.config.wisp.highWaterMarkBytes) {
            socket.pause();
            safeSend(conn.ws, encodeFrame(streamId, FRAME.PAUSE));
            const resume = () => {
              if (stream.closed || conn.ws.readyState !== 1) return;
              safeSend(conn.ws, encodeFrame(streamId, FRAME.RESUME));
              socket.resume();
            };
            setTimeout(resume, 40);
          }
        });
        const end = () => {
          safeSend(conn.ws, encodeFrame(streamId, FRAME.CLOSE));
          conn.streams.delete(streamId);
          stream.closed = true;
        };
        socket.on('end', end);
        socket.on('close', end);
        socket.on('error', (err) => this.#error(conn, streamId, `tunnel: ${err.message}`));
        for (const p of stream.reqBuf) socket.write(p);
        stream.reqBuf = [];
        return undefined;
      })
      .catch((err) => this.#error(conn, streamId, `tunnel connect failed: ${err.message}`));
    return undefined;
  }

  #error(conn, streamId, message) {
    this.stats.errors++;
    safeSend(conn.ws, encodeFrame(streamId, FRAME.ERROR, Buffer.from(String(message).slice(0, 300))));
    safeSend(conn.ws, encodeFrame(streamId, FRAME.CLOSE));
    conn.streams.delete(streamId);
  }

  summary() {
    return {
      enabled: this.enabled,
      path: `${this.config.basePath || ''}${this.config.wisp.path}`,
      connections: this.conns.size,
      totalConnections: this.stats.connections,
      streams: this.stats.streams,
      httpStreams: this.stats.httpStreams,
      tunnelStreams: this.stats.tunnelStreams,
      bytes: this.stats.bytes,
      bytesHuman: fmtBytes(this.stats.bytes),
      errors: this.stats.errors,
      originRejections: this.stats.rejections,
      peak: this.stats.peak,
    };
  }

  close() {
    for (const c of this.conns) {
      try { c.ws.close(1001, 'server restart'); } catch (e) {}
    }
    this.conns.clear();
    this.wss.close();
  }
}

function safeSend(ws, buf) {
  if (!ws || ws.readyState !== 1) return false;
  try {
    ws.send(buf);
    return true;
  } catch {
    return false;
  }
}

function connectTls(socket, host) {
  return new Promise((resolve, reject) => {
    const ts = tls.connect({ socket, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: false }, () => resolve(ts));
    ts.once('error', reject);
  });
}

export default WispServer;
