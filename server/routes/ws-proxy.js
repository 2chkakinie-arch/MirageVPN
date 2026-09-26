/**
 * WebSocket 中継 (UV モード) — /mirage/t/<sid>/ws/h.<origin>/<path>
 * ---------------------------------------------------------------
 * ブラウタブロック回避のため、プロキシ済みページの `new WebSocket('wss://host/…')` は
 * core.js によって `wss://<当方origin>/mirage/t/<sid>/ws/<符号化host>/path` に書き換えられる。
 * ここではその接続を受け取り、上流 WebSocket との双向ブリッジを張る。
 *
 * 出口プロキシ: http1.dial() が作ったソケット (http プロキシには絶対形式、https プロキシには
 * CONNECT トンネル) を ws に渡す。プロキシが使えない場合は 1 回だけ direct に retry する。
 * @module routes/ws-proxy
 */

import { WebSocketServer, WebSocket } from 'ws';
import { Buffer } from 'node:buffer';
import { dial } from '../net/http1.js';
import { log } from '../log.js';

const ns = log.child('ws');

export function attachWsProxy(httpServer, ctx) {
  const { config, engine } = ctx;
  const { urlmap, guard, cookies, pool } = engine;
  const wss = new WebSocketServer({ noServer: true, maxPayload: Math.min(config.transport.maxBodyBytes, 8 * 1024 * 1024), perMessageDeflate: false });
  const live = new Set();
  const stats = { opened: 0, failed: 0, proxied: 0, direct: 0, framesUp: 0, framesDown: 0, bytesUp: 0, bytesDown: 0 };

  httpServer.on('upgrade', (req, clientSocket, head) => {
    const raw = req.url || '/';
    const qIdx = raw.indexOf('?');
    const pathname = qIdx === -1 ? raw : raw.slice(0, qIdx);
    const search = qIdx === -1 ? '' : raw.slice(qIdx);
    if (!/\/ws\//.test(pathname)) {
      // 当方が知らない upgrade には何も答えない (WISP が先に処理している)
      if (pathname.startsWith(config.url.prefix + '/')) {
        try {
          clientSocket.destroy();
        } catch (e) {}
      }
      return;
    }
    const base = config.basePath && pathname.startsWith(config.basePath) ? pathname.slice(config.basePath.length) : pathname;
    const withoutWs = base.replace('/ws/', '/');
    let parsed = null;
    try {
      parsed = urlmap.deproxify(withoutWs, search);
    } catch (err) {
      parsed = null;
    }
    if (!parsed) {
      clientSocket.write('HTTP/1.1 404 Not Found\r\n\r\n');
      clientSocket.destroy();
      return;
    }
    const targetUrl = parsed.url; // ws:// or wss://
    if (guard) {
      const g = guard.check(httpEquivalent(targetUrl));
      if (!g.ok) {
        clientSocket.write(`HTTP/1.1 403 Forbidden\r\nx-mirage-blocked: ${g.reason}\r\n\r\n`);
        clientSocket.destroy();
        return;
      }
    }
    const sid = parsed.sid;
    const protocols = (req.headers['sec-websocket-protocol'] || '').split(',').map((s) => s.trim()).filter(Boolean).filter((p) => p !== 'mirage-v1');

    wss.handleUpgrade(req, clientSocket, head, (browser) => {
      stats.opened++;
      live.add(browser);
      const state = { browser, upstream: null, queue: [], open: false, closed: false, socket: null, startedAt: Date.now(), sid };
      browser.on('message', (data, isBinary) => {
        stats.framesUp++;
        stats.bytesUp += data.length;
        if (state.open && state.upstream && state.upstream.readyState === WebSocket.OPEN) {
          state.upstream.send(data, { binary: isBinary });
        } else if (!state.closed) {
          state.queue.push([data, isBinary]);
        }
      });
      const teardown = (code, reason) => {
        if (state.closed) return;
        state.closed = true;
        live.delete(browser);
        try { state.upstream?.close(code || 1000, reason); } catch (e) {}
        try { state.upstream?.socket?.destroy(); } catch (e) {}
        try { browser.close(code || 1000, reason); } catch (e) {}
        state.socket?.destroy();
      };
      browser.on('close', () => teardown());
      browser.on('error', () => teardown(1011, 'client error'));

      const upstreamHeaders = {
        'user-agent': config.egress.userAgent || 'Mozilla/5.0',
        origin: targetUrl.origin,
        'accept-encoding': 'identity',
        'cache-control': 'no-cache',
      };
      const jarCookie = cookies ? cookies.clientStringFor?.(sid, httpEquivalent(targetUrl)) || '' : '';
      if (jarCookie) upstreamHeaders.cookie = jarCookie;
      if (protocols.length) upstreamHeaders['sec-websocket-protocol'] = protocols.join(', ');

      const wantProxy = pickProxyFor(sid, targetUrl);
      connect(wantProxy)
        .then(() => {
          if (wantProxy && state.proxied === undefined) stats.proxied++;
        })
        .catch(async (err) => {
          if (wantProxy && !state.closed) {
            ns.debug(() => `ws via ${wantProxy.host}:${wantProxy.port} failed (${err.message}) → direct`);
            try {
              await connect(null);
              return undefined;
            } catch (err2) {
              return undefined;
            }
          }
          return undefined;
        })
        .catch(() => undefined)
        .finally(() => {
          if (state.closed) return;
        });

      async function connect(proxy) {
        const secure = targetUrl.protocol === 'wss:';
        const port = Number(targetUrl.port) || (secure ? 443 : 80);
        let socket = null;
        if (proxy) {
          socket = await dial({ host: targetUrl.hostname, port, secure, proxy: { protocol: proxy.protocol === 'https' ? 'http' : proxy.protocol, host: proxy.host, port: proxy.port }, timeoutMs: config.transport.connectTimeoutMs });
          state.proxied = true;
          stats.proxied++;
        }
        state.socket = socket;
        const opts = {
          headers: upstreamHeaders,
          handshakeTimeout: config.transport.responseTimeoutMs,
          protocolVersion: 13,
          maxPayload: wss.options.maxPayload,
          followRedirects: false,
          origin: targetUrl.origin,
        };
        if (socket) opts.socket = socket;
        const up = new WebSocket(targetUrl.href, protocols.length ? protocols : undefined, opts);
        state.upstream = up;
        return new Promise((resolve, reject) => {
          const to = setTimeout(() => reject(new Error('upstream handshake timeout')), config.transport.connectTimeoutMs + 4000);
          up.once('open', () => {
            clearTimeout(to);
            state.open = true;
            for (const [data, isBinary] of state.queue) {
              try { up.send(data, { binary: isBinary }); } catch (e) {}
            }
            state.queue = [];
            resolve();
          });
          up.once('error', (err) => {
            clearTimeout(to);
            stats.failed++;
            reject(err);
          });
          up.on('message', (data, isBinary) => {
            stats.framesDown++;
            stats.bytesDown += data.length;
            if (browser.readyState === WebSocket.OPEN) {
              try { browser.send(data, { binary: isBinary }); } catch (e) {}
            }
          });
          up.on('close', (code, reason) => teardown(Math.min(4999, Math.max(1000, code || 1000)), reason?.length ? reason.toString('utf8').slice(0, 120) : undefined));
          up.on('unexpected-response', (_req, res2) => {
            clearTimeout(to);
            reject(new Error(`upstream HTTP ${res2.statusCode} (WebSocket upgrade 拒否)`));
          });
        });
      }
    });
  });

  function pickProxyFor(sid, targetUrl) {
    if (config.isServerless || config.egress.defaultStrategy === 'direct') return null;
    try {
      const settings = engine.store?.settingsFor?.(null) || {};
      const egress = settings.egress || {};
      if (egress.strategy === 'direct') return null;
      const rec = pool?.select?.({
        country: egress.country && egress.country !== 'AUTO' ? egress.country : undefined,
        sid,
        protocols: ['http', 'https'],
        requireHealthy: true,
      });
      return rec ? { protocol: rec.protocol, host: rec.host, port: rec.port } : null;
    } catch (err) {
      return null;
    }
  }

  return {
    stats: () => ({ ...stats, live: live.size, enabled: true }),
    close() {
      for (const b of live) {
        try { b.close(1001, 'server restart'); } catch (e) {}
      }
      live.clear();
      wss.close();
    },
    broadcast(text) {
      for (const b of live) {
        try { b.send(text); } catch (e) {}
      }
    },
  };
}

function httpEquivalent(wsUrl) {
  const u = new URL(wsUrl.href);
  if (u.protocol === 'ws:') u.protocol = 'http:';
  else if (u.protocol === 'wss:') u.protocol = 'https:';
  return u;
}

export default attachWsProxy;
