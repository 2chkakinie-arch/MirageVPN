/**
 * テスト用ターゲットサーバー + 偽プロキシ (HTTP forward / CONNECT / SOCKS5)
 * net/http1.js を「本物の socket」を通して検証するための足場。
 */
import http from 'node:http';
import net from 'node:net';
import zlib from 'node:zlib';
import { Buffer } from 'node:buffer';

export const HTML = `<!doctype html><html><head><title>Mirage Target</title></head>
<body><h1 id="t">hello</h1><a href="/next.html">next</a><img src="/pix.png"></body></html>`;

export function startTargetServer() {
  const reqs = [];
  const server = http.createServer((req, res) => {
    reqs.push({ url: req.url, headers: req.headers, method: req.method });
    const u = new URL(req.url, 'http://x');
    if (u.pathname === '/') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      return res.end(HTML);
    }
    if (u.pathname === '/chunked-gzip') {
      const gz = zlib.gzipSync(Buffer.from('chunked-and-gzipped-payload-'.repeat(400)));
      res.writeHead(200, { 'content-type': 'text/plain', 'content-encoding': 'gzip' });
      res.write(gz.subarray(0, 900));
      return setTimeout(() => res.end(gz.subarray(900)), 5);
    }
    if (u.pathname === '/trailer') {
      res.writeHead(200, { 'content-type': 'text/plain', trailer: 'X-Total' });
      res.write('hello');
      res.addTrailers({ 'X-Total': '5' });
      return res.end();
    }
    if (u.pathname === '/echo') {
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(
          JSON.stringify({
            method: req.method,
            url: req.url,
            headers: req.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          }),
        );
      });
      return undefined;
    }
    if (u.pathname === '/redirect') {
      res.writeHead(302, { location: '/final' });
      return res.end('redirecting');
    }
    if (u.pathname === '/final') {
      res.writeHead(200, { 'content-type': 'text/html' });
      return res.end('<html><body>final</body></html>');
    }
    if (u.pathname === '/cookies') {
      res.writeHead(200, {
        'content-type': 'text/plain',
        'set-cookie': ['a=1; Path=/; Secure; SameSite=None', 'b=2; Domain=x; HttpOnly'],
      });
      return res.end(`cookie:${req.headers.cookie || ''}`);
    }
    if (u.pathname === '/no-length') {
      res.writeHead(200, { 'content-type': 'text/plain', connection: 'close' });
      res.write('stream-part-1\n');
      setTimeout(() => res.end('stream-part-2\n'), 20);
      return undefined;
    }
    if (u.pathname === '/slow') {
      setTimeout(() => {
        res.writeHead(200, { 'content-type': 'text/plain' });
        res.end('late');
      }, Number(u.searchParams.get('ms') || 300));
      return undefined;
    }
    if (u.pathname === '/huge') {
      const size = Number(u.searchParams.get('size') || 1024 * 1024);
      res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': String(size) });
      let sent = 0;
      const buf = Buffer.alloc(64 * 1024, 0x41);
      const pump = () => {
        while (sent < size) {
          const take = Math.min(buf.length, size - sent);
          sent += take;
          if (!res.write(buf.subarray(0, take))) return res.once('drain', pump);
        }
        return res.end();
      };
      return pump();
    }
    if (u.pathname === '/status') {
      res.writeHead(Number(u.searchParams.get('code') || 500), { 'content-type': 'text/plain' });
      return res.end('status');
    }
    if (u.pathname === '/keepalive-check') {
      res.writeHead(200, { 'content-type': 'text/plain', 'x-conn-count': String(reqs.length) });
      return res.end(String(reqs.length));
    }
    res.writeHead(404, { 'content-type': 'text/plain' });
    return res.end('not found');
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () =>
      resolve({
        server,
        port: server.address().port,
        reqs,
        origin: `http://127.0.0.1:${server.address().port}`,
        close: () =>
          new Promise((r) => {
            server.closeAllConnections?.();
            server.close(() => r());
          }),
      }),
    );
  });
}

/** 素の HTTP forward プロキシ (absolute-URI) + CONNECT トンネル */
export function startHttpProxy({ requireAuth = false, user = 'u', pass = 'p' } = {}) {
  let forwards = 0;
  let connects = 0;
  const proxy = net.createServer((client) => {
    let buf = Buffer.alloc(0);
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      const idx = buf.indexOf('\r\n\r\n');
      if (idx === -1) return;
      const head = buf.subarray(0, idx).toString('latin1');
      const rest = buf.subarray(idx + 4);
      client.removeListener('data', onData);
      const [method, target] = head.split('\r\n')[0].split(' ');
      if (requireAuth) {
        const auth = /proxy-authorization: basic (.+)/i.exec(head)?.[1];
        const decoded = auth ? Buffer.from(auth, 'base64').toString('utf8') : '';
        if (decoded !== `${user}:${pass}`) {
          client.write('HTTP/1.1 407 Proxy Authentication Required\r\ncontent-length: 0\r\nconnection: close\r\n\r\n');
          return client.end();
        }
      }
      if (method === 'CONNECT') {
        connects++;
        const [host, port] = target.split(':');
        const up = net.connect(Number(port), host, () => {
          client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
          if (rest.length) up.write(rest);
          up.pipe(client).pipe(up);
        });
        up.on('error', () => client.destroy());
        client.on('error', () => up.destroy());
        return undefined;
      }
      forwards++;
      const u = new URL(target);
      const up = net.connect(Number(u.port) || 80, u.hostname, () => {
        const path = u.pathname + u.search;
        const rewritten = head
          .split('\r\n')
          .map((l, i) => (i === 0 ? `${method} ${path} HTTP/1.1` : l))
          .filter((l) => !/^proxy-|^connection:/i.test(l))
          .join('\r\n');
        up.write(`${rewritten}\r\n\r\n`, 'latin1');
        if (rest.length) up.write(rest);
        up.pipe(client).pipe(up);
      });
      up.on('error', () => client.destroy());
      return undefined;
    };
    client.on('data', onData);
    client.on('error', () => {});
  });
  return new Promise((resolve) => {
    proxy.listen(0, '127.0.0.1', () =>
      resolve({
        proxy,
        port: proxy.address().port,
        host: '127.0.0.1',
        get counts() {
          return { forwards, connects };
        },
        close: () => new Promise((r) => proxy.close(() => r())),
      }),
    );
  });
}

/** 最小の SOCKS5 サーバ (no-auth / username+password) */
export function startSocks5Proxy({ username, password, rejectAt } = {}) {
  let handled = 0;
  const proxy = net.createServer((client) => {
    let buf = Buffer.alloc(0);
    let stage = 'greeting';
    const pump = () => {
      if (stage === 'greeting') {
        if (buf.length < 2) return;
        const nmethods = buf[1];
        if (buf.length < 2 + nmethods) return;
        const methods = [...buf.subarray(2, 2 + nmethods)];
        buf = buf.subarray(2 + nmethods);
        if (username) {
          if (!methods.includes(2)) {
            client.write(Buffer.from([5, 0xff]));
            return client.end();
          }
          client.write(Buffer.from([5, 2]));
          stage = 'auth';
          return pump();
        }
        client.write(Buffer.from([5, 0]));
        stage = 'request';
        return pump();
      }
      if (stage === 'auth') {
        if (buf.length < 3) return;
        const ulen = buf[1];
        if (buf.length < 2 + ulen + 1) return;
        const plen = buf[2 + ulen];
        if (buf.length < 3 + ulen + plen) return;
        const u = buf.subarray(2, 2 + ulen).toString();
        const p = buf.subarray(3 + ulen, 3 + ulen + plen).toString();
        buf = buf.subarray(3 + ulen + plen);
        const ok = u === username && p === password;
        client.write(Buffer.from([1, ok ? 0 : 255]));
        if (!ok) return client.end();
        stage = 'request';
        return pump();
      }
      if (stage === 'request') {
        if (buf.length < 5) return;
        const atyp = buf[3];
        let hostLen;
        if (atyp === 1) hostLen = 4;
        else if (atyp === 4) hostLen = 16;
        else if (atyp === 3) {
          if (buf.length < 5) return;
          hostLen = buf[4] + 1;
        } else {
          client.write(Buffer.from([5, 8, 0, 1, 0, 0, 0, 0, 0, 0]));
          return client.end();
        }
        if (buf.length < 4 + hostLen + 2) return;
        let host;
        if (atyp === 3) host = buf.subarray(5, 5 + buf[4]).toString();
        else {
          const raw = buf.subarray(4, 4 + hostLen);
          host =
            atyp === 1
              ? [...raw].join('.')
              : Array.from({ length: 8 }, (_, i) => raw.readUInt16BE(i * 2).toString(16)).join(':');
        }
        const port = buf.readUInt16BE(4 + hostLen);
        buf = buf.subarray(4 + hostLen + 2);
        handled++;
        stage = 'connect';
        client.removeListener('data', onData);
        const finish = () => {
          if (rejectAt && host === rejectAt.host && port === rejectAt.port) {
            client.write(Buffer.from([5, 5, 0, 1, 0, 0, 0, 0, 0, 0]));
            return client.end();
          }
          const up = net.connect(port, host, () => {
            const reply = Buffer.alloc(10);
            reply[0] = 5;
            reply[3] = 1;
            [127, 0, 0, 1].forEach((n, i) => (reply[4 + i] = n));
            reply.writeUInt16BE(port, 8);
            client.write(reply);
            if (buf.length) up.write(buf);
            client.pipe(up).pipe(client);
          });
          up.on('error', () => client.destroy());
          client.on('error', () => up.destroy());
          return undefined;
        };
        return finish();
      }
      return undefined;
    };
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      pump();
    };
    client.on('data', onData);
    client.on('error', () => {});
  });
  return new Promise((resolve) => {
    proxy.listen(0, '127.0.0.1', () =>
      resolve({
        proxy,
        port: proxy.address().port,
        host: '127.0.0.1',
        get handled() {
          return handled;
        },
        close: () => new Promise((r) => proxy.close(() => r())),
      }),
    );
  });
}

export async function readAll(stream) {
  const chunks = [];
  for await (const c of stream) chunks.push(c);
  return Buffer.concat(chunks);
}
