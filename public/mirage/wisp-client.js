/**
 * MirageVPN WISP クライアント (Service Worker 内で importScripts される)
 * ---------------------------------------------------------------
 * 仕様上の対応: WISP v0.5 フレーミング
 *   [16B streamId][1B type][4B BE len][payload] / type: 0 DATA, 1 CONNECT, 2 CLOSE, 3 KEEPALIVE, 4 PAUSE, 5 RESUME, 6 ERROR
 *
 * このブラウザ側実装は「サーバが確立した 1 本の WebSocket」上で
 * リクエストごとに擬似ストリーム (streamId) を割り当てて HTTP を流す。
 * - PAUSE/RESUME による flow control
 * - 切断時の自動再接続 + 未完了リクエストは UV へフォールバック (SW 側で catch)
 * - 外部 WISP サーバ URL を指定すれば raw tunnel モードでも使える (http/ws のみ)
 */
/* global self, TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, WebSocket, Blob */
(function () {
  'use strict';
  const HEADER = 21;
  const T = { DATA: 0, CONNECT: 1, CLOSE: 2, KEEPALIVE: 3, PAUSE: 4, RESUME: 5, ERROR: 6, HELLO: 7 };
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  function hex16() {
    const b = new Uint8Array(16);
    crypto.getRandomValues(b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let s = '';
    for (let i = 0; i < 16; i++) s += b[i].toString(16).padStart(2, '0');
    return s;
  }
  function hexToBytes(h) {
    const a = new Uint8Array(16);
    for (let i = 0; i < 16; i++) a[i] = parseInt(h.substr(i * 2, 2), 16);
    return a;
  }
  function encodeFrame(id, type, payload) {
    const body = payload || new Uint8Array(0);
    const out = new Uint8Array(HEADER + body.byteLength);
    out.set(hexToBytes(id), 0);
    out[16] = type;
    new DataView(out.buffer).setUint32(17, body.byteLength, false);
    if (body.byteLength) out.set(body, HEADER);
    return out;
  }
  function bufToB64(buf) {
    const bytes = new Uint8Array(buf);
    let bin = '';
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    return btoa(bin);
  }
  function b64ToBuf(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }

  class WispClient {
    constructor(opts) {
      this.url = opts.url;
      this.sid = opts.sid || null;
      this.ws = null;
      this.connected = false;
      this.connecting = null;
      this.streams = new Map(); // id → {resolve, reject, chunks, head, done, paused, started}
      this.serverInfo = null; // サーバの HELLO 内容 (version / maxStreams / modes)
      this.queue = [];
      this.cfg = Object.assign({ maxStreams: 48, reconnectMs: 1500, idleCloseMs: 60000, timeoutMs: 45000 }, opts);
      this.stats = { requests: 0, bytes: 0, frames: 0, reconnects: 0, errors: 0, closed: 0, avgMs: 0, maxStreams: 0 };
      this._acc = new Uint8Array(0);
      this._idleTimer = null;
      this._keepalive = null;
      this._failures = 0;
      this._disabledUntil = 0;
    }

    available() {
      return Date.now() > this._disabledUntil && (this.connected || this.cfg.retries > 0);
    }

    connect() {
      if (this.connected && this.ws && this.ws.readyState === 1) return Promise.resolve(true);
      if (this.connecting) return this.connecting;
      this.connecting = new Promise((resolve) => {
        let settled = false;
        let ws;
        try {
          ws = new WebSocket(this.url, ['wisp.v0.5', 'mirage.v1']);
        } catch (e) {
          this._disabledUntil = Date.now() + 30000;
          this.connecting = null;
          return resolve(false);
        }
        ws.binaryType = 'arraybuffer';
        const failTimeout = setTimeout(() => {
          if (settled) return;
          settled = true;
          try { ws.close(); } catch (e) {}
          this.connecting = null;
          this._disabledUntil = Date.now() + 30000; // WISP は諦めて UV に戻す
          resolve(false);
        }, this.cfg.connectTimeoutMs || 6000);

        ws.onopen = () => {
          this.connected = true;
          this._failures = 0;
          clearTimeout(failTimeout);
          if (settled) return;
          settled = true;
          this.connecting = null;
          this._startKeepalive();
          this._flush();
          resolve(true);
        };
        ws.onmessage = (ev) => this._onData(ev.data);
        ws.onerror = () => {
          clearTimeout(failTimeout);
          if (!settled) {
            settled = true;
            this.connecting = null;
            this._disabledUntil = Date.now() + 20000;
            resolve(false);
          }
        };
        ws.onclose = () => {
          this.connected = false;
          this.stats.closed++;
          this._stopKeepalive();
          const err = new Error('wisp closed');
          for (const [id, s] of this.streams) {
            this.streams.delete(id);
            s.reject(err);
          }
          clearTimeout(failTimeout);
          if (!settled) {
            settled = true;
            this.connecting = null;
            this._disabledUntil = Date.now() + 20000;
            resolve(false);
          }
        };
      });
      return this.connecting;
    }

    _startKeepalive() {
      this._stopKeepalive();
      this._keepalive = setInterval(() => {
        if (this.connected && this.ws && this.ws.readyState === 1) {
          try { this.ws.send(encodeFrame('0'.repeat(32), T.KEEPALIVE)); } catch (e) {}
        }
      }, this.cfg.keepaliveMs || 20000);
      if (this._keepalive.unref) this._keepalive.unref();
    }
    _stopKeepalive() {
      if (this._keepalive) clearInterval(this._keepalive);
      this._keepalive = null;
    }

    _onData(arrayBuffer) {
      const incoming = new Uint8Array(arrayBuffer);
      let buf = new Uint8Array(this._acc.length + incoming.length);
      buf.set(this._acc, 0);
      buf.set(incoming, this._acc.length);
      this._acc = buf;
      let offset = 0;
      while (buf.length - offset >= HEADER) {
        const view = new DataView(buf.buffer, buf.byteOffset + offset);
        const idBytes = buf.subarray(offset, offset + 16);
        let id = '';
        for (let i = 0; i < 16; i++) id += idBytes[i].toString(16).padStart(2, '0');
        const type = buf[offset + 16];
        const len = view.getUint32(17, false);
        if (buf.length - offset - HEADER < len) break;
        const payload = buf.subarray(offset + HEADER, offset + HEADER + len);
        offset += HEADER + len;
        this.stats.frames++;
        this.stats.bytes += len;
        if (type === T.DATA) {
          const s = this.streams.get(id);
          if (s) { s.head.push(payload); s.onChunk && s.onChunk(payload); }
        } else if (type === T.CLOSE) {
          const s = this.streams.get(id);
          if (s) this._finish(id, s, null);
        } else if (type === T.ERROR) {
          const s = this.streams.get(id);
          if (s) this._finish(id, s, new Error(dec.decode(payload) || 'wisp error'));
        } else if (type === T.PAUSE) {
          const s = this.streams.get(id);
          if (s) s.paused = true;
        } else if (type === T.RESUME) {
          const s = this.streams.get(id);
          if (s) { s.paused = false; if (s.pendingWrite) { this._rawSend(id, T.DATA, s.pendingWrite); s.pendingWrite = null; } }
        } else if (type === T.KEEPALIVE) {
          /* noop */
        } else if (type === T.HELLO) {
          // 接続直後の能力通知。古い/異なるサーバが送ってこなくても動作は壊れない (既定値のまま)
          try {
            const info = JSON.parse(dec.decode(payload));
            this.serverInfo = info;
            this.stats.hello = true;
            if (info.maxStreams > 0) this.cfg.maxStreams = Math.min(this.cfg.maxStreams || info.maxStreams, info.maxStreams);
            if (info.keepaliveMs > 0) this.cfg.keepaliveMs = Math.max(5000, Math.min(info.keepaliveMs, 60000));
          } catch (e) {
            /* ignore malformed hello */
          }
        }
      }
      this._acc = buf.subarray(offset);
    }

    _rawSend(id, type, payload) {
      if (!this.ws || this.ws.readyState !== 1) return false;
      try {
        this.ws.send(encodeFrame(id, type, payload));
        return true;
      } catch (e) {
        this.stats.errors++;
        return false;
      }
    }

    _flush() {
      const q = this.queue.splice(0, this.queue.length);
      q.forEach((job) => job());
    }

    _finish(id, s, err) {
      if (s.finished) return;
      s.finished = true;
      this.streams.delete(id);
      const body = concatBytes(s.head);
      s.head = [];
      if (err) return s.reject(err);
      try {
        const parsed = parseHttp(body, s.url);
        s.resolve(parsed);
      } catch (e) {
        s.reject(e);
      }
    }

    /**
     * HTTP リクエスト 1 本を WISP ストリームとして流す。
     * @returns {Promise<{status:number,statusText:string,headers:Object,body:ArrayBuffer,text:string,headerString:string,url:string}>}
     */
    request(method, absUrl, headers, body, opts) {
      opts = opts || {};
      if (this.streams.size >= this.cfg.maxStreams) {
        return Promise.reject(new Error('wisp: too many streams'));
      }
      this.stats.requests++;
      if (this.streams.size > this.stats.maxStreams) this.stats.maxStreams = this.streams.size;
      const id = hex16();
      const started = Date.now();
      const self2 = this;

      return new Promise((resolve, reject) => {
        const stream = {
          id,
          url: absUrl,
          head: [],
          resolve: (v) => {
            self2.stats.avgMs = Math.round(self2.stats.avgMs * 0.7 + (Date.now() - started) * 0.3);
            resolve(v);
          },
          reject: (e) => {
            self2.stats.errors++;
            reject(e);
          },
          finished: false,
          paused: false,
          pendingWrite: null,
        };
        this.streams.set(id, stream);
        const timer = setTimeout(() => this._finish(id, stream, new Error('wisp timeout')), this.cfg.timeoutMs);
        const origFinish = stream.resolve;
        stream.resolve = (v) => {
          clearTimeout(timer);
          origFinish(v);
        };

        const job = () => {
          const payload = {
            mode: 'http',
            method: method || 'GET',
            url: absUrl,
            headers: headers || {},
            sid: opts.sid || this.sid || undefined,
          };
          if (body && body.byteLength) payload.body = bufToB64(body instanceof ArrayBuffer ? body : body.buffer ? body.buffer : body);
          if (!this._rawSend(id, T.CONNECT, enc.encode(JSON.stringify(payload)))) {
            this._finish(id, stream, new Error('wisp not connected'));
          }
        };
        if (!this.connected) {
          this.connect().then((ok) => {
            if (ok) job();
            else this._finish(id, stream, new Error('wisp unavailable'));
          });
        } else job();
      });
    }

    fetch(absUrl, init) {
      init = init || {};
      const method = (init.method || 'GET').toUpperCase();
      const headers = {};
      const src = init.headers;
      if (src) {
        if (typeof src.forEach === 'function') src.forEach((v, k) => (headers[k] = v));
        else Object.assign(headers, src);
      }
      const finish = (r) =>
        new Response(r.body, {
          status: r.status,
          statusText: r.statusText,
          headers: r.headers,
        });
      const bodyPromise = !['GET', 'HEAD'].includes(method) && init.body ? init.body.arrayBuffer ? init.body.arrayBuffer() : Promise.resolve(new TextEncoder().encode(String(init.body)).buffer) : Promise.resolve(null);
      return bodyPromise.then((body) => this.request(method, absUrl, headers, body, { sid: init.sid })).then(finish);
    }

    statsSnapshot() {
      return {
        connected: this.connected,
        streams: this.streams.size,
        disabledUntil: this._disabledUntil,
        server: this.serverInfo?.version || null,
        ...this.stats,
      };
    }
  }

  function concatBytes(list) {
    let len = 0;
    for (const c of list) len += c.byteLength;
    const out = new Uint8Array(len);
    let o = 0;
    for (const c of list) {
      out.set(c, o);
      o += c.byteLength;
    }
    return out;
  }

  /** サーバが返した生の HTTP レスポンスバイトをパース (chunked / content-length / EOF) */
  function parseHttp(bytes, url) {
    let text = '';
    let sep = -1;
    const scan = Math.min(bytes.length, 65536);
    for (let i = 0; i < scan; i++) {
      if (bytes[i] === 13 && bytes[i + 1] === 10 && bytes[i + 2] === 13 && bytes[i + 3] === 10) {
        sep = i;
        break;
      }
    }
    if (sep === -1) {
      text = dec.decode(bytes);
      const idx = text.indexOf('\r\n\r\n');
      if (idx === -1) throw new Error('wisp: bad response (no head)');
      return build(text.slice(0, idx), bytes.subarray(idx + 4), url);
    }
    text = dec.decode(bytes.subarray(0, sep));
    return build(text, bytes.subarray(sep + 4), url);
  }

  function build(headText, bodyBytes, url) {
    const lines = headText.split('\r\n');
    const m = /^HTTP\/\d(?:\.\d)?\s+(\d{3})\s*(.*)$/.exec(lines[0] || '');
    if (!m) throw new Error('wisp: bad status line');
    const status = Number(m[1]);
    const statusText = m[2] || '';
    const headers = {};
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];
      if (!line) continue;
      const idx = line.indexOf(':');
      if (idx < 0) continue;
      const k = line.slice(0, idx).trim().toLowerCase();
      const v = line.slice(idx + 1).trim();
      headers[k] = headers[k] ? headers[k] + ', ' + v : v;
    }
    let body = bodyBytes;
    const te = (headers['transfer-encoding'] || '').toLowerCase();
    if (te.includes('chunked')) body = dechunk(bodyBytes);
    const headersObj = {};
    Object.keys(headers).forEach((k) => {
      if (['transfer-encoding', 'content-length', 'content-encoding'].includes(k)) return;
      headersObj[k] = headers[k];
    });
    return {
      status,
      statusText,
      headers: headersObj,
      headerString: Object.keys(headers)
        .map((k) => `${k}: ${headers[k]}`)
        .join('\r\n'),
      body: body.buffer ? body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) : body,
      text: () => dec.decode(body),
      url,
    };
  }

  function dechunk(bytes) {
    const parts = [];
    let i = 0;
    while (i < bytes.length) {
      let j = i;
      while (j < bytes.length - 1 && !(bytes[j] === 13 && bytes[j + 1] === 10)) j++;
      if (j >= bytes.length - 1) break;
      const line = dec.decode(bytes.subarray(i, j));
      const size = parseInt(line.split(';')[0].trim(), 16);
      if (!Number.isFinite(size)) break;
      if (size === 0) break;
      const start = j + 2;
      const end = Math.min(bytes.length, start + size);
      parts.push(bytes.subarray(start, end));
      i = end + 2;
    }
    return concatBytes(parts);
  }

  if (typeof self !== 'undefined') {
    self.MirageWisp = { WispClient, encodeFrame, decodeFrame, T };
  }

  const cfg = self.__MIRAGE_SW_CFG || {};
  if (cfg.wispUrl) {
    const client = new WispClient(cfg);
    self.__mrgWisp = client;
    client.connect();
    self.__mrgWispStats = () => client.statsSnapshot();
  }
})();
