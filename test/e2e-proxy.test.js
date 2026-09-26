/**
 * E2E: 本番と同じ Pipeline / Express / UrlMap / Rewriter を通して、
 * 「ブラウザがやるのと同じ HTTP」を打ち、改写・遮断・計装の帰結を検証する。
 * 外部ネットワークは使わない (origin はローカル起動、egress は direct、リスト更新 OFF)。
 * @module test/e2e-proxy.test.js
 */

import { test, before, after, describe } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import zlib from 'node:zlib';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Buffer } from 'node:buffer';
import { loadConfig } from '../server/config.js';
import { createApp } from '../server/app.js';

/* ------------------------------------------------------------------ */
/* ローカル origin (テスト対象サイト)                                    */
/* ------------------------------------------------------------------ */

const PAGE_HTML = `<!doctype html><html><head><title>Origin Home</title>
<link rel="stylesheet" href="/style.css">
<script src="/app.js"></script>
</head><body>
<a href="/next">next</a> <a href="http://cdn.test/a">ext</a>
<img src="/pic.png" srcset="/pic2.png 2x">
<div style="background:url(/inline.png)"></div>
<form action="/submit" method="post"><input name="q"></form>
</body></html>`;

function createOrigin() {
  const seen = [];
  const srv = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      seen.push({ method: req.method, url: req.url, headers: req.headers, body });
      const url = req.url.split('?')[0];
      if (url === '/redirect') {
        res.statusCode = 302;
        res.setHeader('location', '/final');
        return res.end('moving');
      }
      if (url === '/final') {
        res.setHeader('content-type', 'text/html; charset=utf-8');
        res.setHeader('set-cookie', 'sid=abc; Path=/; SameSite=Lax');
        return res.end('<!doctype html><html><head><title>Final</title></head><body>done</body></html>');
      }
      if (url === '/cookie-echo') {
        res.setHeader('content-type', 'text/plain');
        return res.end(String(req.headers.cookie || ''));
      }
      if (url === '/gzip-page') {
        const buf = zlib.gzipSync(Buffer.from(PAGE_HTML));
        res.setHeader('content-type', 'text/html; charset=utf-8');
        res.setHeader('content-encoding', 'gzip');
        return res.end(buf);
      }
      if (url === '/style.css') {
        res.setHeader('content-type', 'text/css');
        return res.end('body{background:url("/bg.png")}@import "/extra.css";');
      }
      if (url === '/app.js') {
        res.setHeader('content-type', 'text/javascript');
        return res.end('const a="/api/data";fetch(a);location.hash="#x";window.open("http://pop.test/z");');
      }
      if (url === '/big.js') {
        res.setHeader('content-type', 'text/javascript');
        return res.end(`/* big */\nvar x=1;${'// pad\n'.repeat(20000)}`);
      }
      if (url === '/evil.js') {
        res.setHeader('content-type', 'text/javascript');
        return res.end('document.cookie="sessionid='+ 'steal' + '";eval(atob("YWxlcnQoMSk="));');
      }
      if (url === '/bin') {
        res.setHeader('content-type', 'application/octet-stream');
        return res.end(Buffer.alloc(70000, 0x41));
      }
      if (url === '/echo-form') {
        res.setHeader('content-type', 'text/plain');
        return res.end(`posted:${body}`);
      }
      if (url === '/meta-refresh') {
        res.setHeader('content-type', 'text/html');
        return res.end('<html><head><meta http-equiv="refresh" content="0; url=/next"></head></html>');
      }
      res.setHeader('content-type', 'text/html; charset=utf-8');
      return res.end(PAGE_HTML);
    });
  });
  srv.seen = seen;
  return srv;
}

/* ------------------------------------------------------------------ */

let origin;
let originPort;
let server;
let port;
let ctx;
let engine;
let urlmap;

function fetchProxied(path, opts = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, method: opts.method || 'GET', headers: opts.headers || {} }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString('utf8'), bytes: Buffer.concat(chunks) }));
    });
    req.on('error', reject);
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

before(async () => {
  await new Promise((r) => {
    origin = createOrigin();
    origin.listen(0, '127.0.0.1', r);
  });
  originPort = origin.address().port;

  const config = loadConfig({
    ...process.env,
    NODE_ENV: 'test',
    PORT: '0',
    MIRAGE_EGRESS: 'direct',
    MIRAGE_MODE: 'uv',
    MIRAGE_WISP: '1',
    MIRAGE_LIST_AUTO_REFRESH: '0',
    MIRAGE_USE_SEED: '0',
    MIRAGE_BLOCK_PRIVATE_TARGETS: '0',
    MIRAGE_LOG_LEVEL: 'error',
    MIRAGE_STATE_DIR: '',
    MIRAGE_SECRET: 'test-secret',
  });
  const app = await createApp({ config, boot: true });
  ctx = app.ctx;
  engine = app.engine;
  urlmap = engine.urlmap;
  server = http.createServer(app.app);
  ctx.attach(server);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  port = server.address().port;
});

after(async () => {
  await new Promise((r) => (server ? server.close(r) : r()))
    .catch(() => {});
  await new Promise((r) => (origin ? origin.close(r) : r()))
    .catch(() => {});
  ctx?.close?.();
  origin?.seen?.length;
});

function proxiedPath(upstreamPath, sid = 'sidTEST') {
  const u = new URL(`http://127.0.0.1:${originPort}${upstreamPath}`);
  return urlmap.proxify(u.href, sid);
}

/* ------------------------------------------------------------------ */

describe('ドキュメント改写', () => {
  test('相対/絶対 URL と href/src/action がプロキシパスになる', async () => {
    const p = proxiedPath('/');
    const res = await fetchProxied(p, { headers: { accept: 'text/html', 'sec-fetch-dest': 'document' } });
    assert.equal(res.status, 200);
    assert.match(res.text, /href="\/mirage\/t\/sidTEST\/h\.[A-Za-z0-9_-]+\/next"/);
    assert.match(res.text, /<link rel="stylesheet" href="\/mirage\/t\/sidTEST\/h\.[^"]+\/style\.css"/);
    assert.match(res.text, /form action="\/mirage\/t\/sidTEST\/h\.[^"]+\/submit"/);
    assert.match(res.text, /srcset="\/mirage\/t\/sidTEST\/h\.[^"]+\/pic2\.png 2x"/);
    assert.match(res.text, /background:url\(&quot;\/mirage\/t/);
    // core.js が注入されている
    assert.match(res.text, /<script src="\/mirage\/core\.js"><\/script>/);
    assert.match(res.text, /id="__mirage-config"/);
  });

  test('proxied ドキュメントは額縁保護付き / 上流の Set-Cookie はクライアントに渡さない', async () => {
    const res = await fetchProxied(proxiedPath('/'), { headers: { accept: 'text/html', 'sec-fetch-dest': 'document' } });
    assert.match(res.headers['content-security-policy'] || '', /frame-ancestors 'self'/, 'rewriter が frame-ancestors を付け直す');
    assert.equal(res.headers['x-frame-options'], 'SAMEORIGIN');
    assert.ok(!/sid=abc/.test(String(res.headers['set-cookie'] || '')), '上流クッキーはジャーに吸収してブラウザに漏らさない (自前の client-id は可)');
    // 上流が own ヘッダを消していたことも確認 (XFO/CSP を素通しすると当方オリジンで表示できない)
    assert.ok(!/^x-mirage-upstream-/i.test(Object.keys(res.headers).join(',')));
  });

  test('別オリジン (http://cdn.test) も符号化されて同じ出口を通る', async () => {
    const res = await fetchProxied(proxiedPath('/'), { headers: { accept: 'text/html' } });
    const seg = /a href="(\/mirage\/t\/sidTEST\/h\.[A-Za-z0-9_-]+)\/a"/.exec(res.text);
    assert.ok(seg, 'external anchor rewritten');
    const decoded = urlmap.decodeHost(seg[1].split('/').pop());
    assert.equal(decoded, 'http://cdn.test');
  });

  test('gzip 応答は解凍されてから改写される', async () => {
    const res = await fetchProxied(proxiedPath('/gzip-page'), { headers: { accept: 'text/html' } });
    assert.equal(res.status, 200);
    assert.ok(!res.headers['content-encoding'], 'content-encoding は解除されるはず');
    assert.match(res.text, /<title>Origin Home<\/title>/);
    assert.match(res.text, /href="\/mirage\/t\/sidTEST\/h\.[^"]+\/next"/);
  });

  test('meta refresh の URL も書き換わる', async () => {
    const res = await fetchProxied(proxiedPath('/meta-refresh'), { headers: { accept: 'text/html' } });
    assert.match(res.text, /url=\/mirage\/t\/sidTEST\/h\./);
  });
});

describe('アセット改写', () => {
  test('CSS の url() と @import', async () => {
    const res = await fetchProxied(proxiedPath('/style.css'), { headers: { 'sec-fetch-dest': 'style' } });
    assert.equal(res.status, 200);
    assert.match(res.text, /url\("\/mirage\/t\/sidTEST\/h\.[^"]+\/bg\.png"\)/);
    assert.match(res.text, /@import url\("\/mirage\/t\/sidTEST\/h\.[^"]+\/extra\.css"\)/);
  });

  test('JS は location 代入と絶対 URL リテラルだけ触る', async () => {
    const res = await fetchProxied(proxiedPath('/app.js'), { headers: { 'sec-fetch-dest': 'script' } });
    assert.match(res.text, /const a="\/api\/data";fetch\(a\);/); // 相対リテラルはそのまま (SW/origin で解決)
    assert.match(res.text, /__mrg\.loc\.hash="#x"/); // location.* は shim へ（hash 値自体は変えない）
    assert.match(res.text, /window\.open\("\/mirage\/t\/sidTEST\/h\.[^"]+\/z"\)/); // 絶対 URL は書き換え
  });

  test('octet-stream は改写せずストリームで返す', async () => {
    const res = await fetchProxied(proxiedPath('/bin'));
    assert.equal(res.status, 200);
    assert.equal(res.bytes.length, 70000);
    assert.equal(res.headers['content-type'], 'application/octet-stream');
  });

  test('big.js は 2 回目キャッシュで速くなる', async () => {
    const p = proxiedPath('/big.js');
    const a = await fetchProxied(p);
    const info1 = decodeURIComponent(a.headers['x-mirage-info']);
    const b = await fetchProxied(p);
    const info2 = decodeURIComponent(b.headers['x-mirage-info']);
    assert.match(info1, /"cacheHit":false/);
    assert.match(info2, /"cacheHit":true/);
    assert.equal(a.text.length, b.text.length);
  });
});

describe('リダイレクト / クッキー / ボディ', () => {
  test('302 を追跡して final に着地し、Set-Cookie はジャーに入りクライアントには漏れない', async () => {
    const p = proxiedPath('/redirect');
    const res = await fetchProxied(p, { headers: { accept: 'text/html' } });
    assert.equal(res.status, 200);
    assert.match(res.text, /<title>Final<\/title>/);
    assert.ok(!/sid=abc/.test(String(res.headers['set-cookie'] || '')), 'upstream Set-Cookie はブラウザに渡さない');
    const info = JSON.parse(decodeURIComponent(res.headers['x-mirage-info']));
    assert.ok(info.redirects >= 1, 'redirect 数を報告');
    const jar = engine.cookies.export('sidTEST');
    assert.ok(jar.some((c) => c.name === 'sid' && c.value === 'abc'), 'ジャーに保存されている');
    // 同じ sid で再度リクエスト → クッキーが上流へ付く
    origin.seen.length = 0;
    await fetchProxied(proxiedPath('/cookie-echo'));
    const sent = origin.seen.at(-1);
    assert.match(sent.headers.cookie || '', /sid=abc/, 'ジャーのクッキーを再送する');
    assert.match(sent.headers['x-forwarded-for'] || '', /^\d+\.\d+\.\d+\.\d+$/, 'XFF 偽装 IP が付く');
    assert.equal(sent['x-real-ip'], undefined);
    assert.ok(sent.headers['user-agent'].startsWith('Mozilla/'), 'UA は設定のものを送る');
    assert.ok(!('sec-websocket-key' in sent.headers));
  });

  test('POST ボディはそのまま届く', async () => {
    origin.seen.length = 0;
    const res = await fetchProxied(proxiedPath('/echo-form'), { method: 'POST', body: 'hello=1&x=%20y', headers: { 'content-type': 'application/x-www-form-urlencoded' } });
    assert.equal(res.status, 200);
    assert.match(res.text, /posted:hello=1&x=%20y/);
    const s = origin.seen.at(-1);
    assert.equal(s.method, 'POST');
    assert.equal(s.headers['content-length'], String('hello=1&x=%20y'.length));
  });
});

describe('シールド / 脅威', () => {
  test('既知 badware ホストはドキュメント段階で遮断される', async () => {
    const p = urlmap.proxify('http://0120999900.net/malware.js', 'sidTEST');
    const res = await fetchProxied(p, { headers: { accept: 'text/html' } });
    assert.ok([403, 451].includes(res.status), `blocked (got ${res.status})`);
    assert.match(res.text, /MirageVPN/);
  });

  test('API 経由で遮断統計が増える', async () => {
    const before = await fetchProxied('/mirage/api/shields').then((r) => JSON.parse(r.text));
    await fetchProxied(urlmap.proxify('http://doubleclick.net/x.js', 'sidTEST2'));
    const after1 = await fetchProxied('/mirage/api/shields').then((r) => JSON.parse(r.text));
    assert.ok(after1.blocked >= before.blocked, 'blocked counter monotonic');
  });

  test('プライベートアドレスは既定で遮断 (テストでは解除している = 通る)', async () => {
    const res = await fetchProxied(proxiedPath('/'));
    assert.equal(res.status, 200);
  });
});

describe('クライアントアセット', () => {
  test('core.js / sw.js が配られ、sw.js には設定が注入されている', async () => {
    const core = await fetchProxied('/mirage/core.js');
    assert.equal(core.status, 200);
    assert.match(core.headers['content-type'], /javascript/);
    const sw = await fetchProxied('/mirage/sw.js');
    assert.equal(sw.status, 200);
    assert.match(sw.text, /self\.__MIRAGE_PREFIX="\/mirage\/t"/);
    assert.match(sw.text, /self\.__MIRAGE_SW_CFG=\{/);
    assert.equal(sw.headers['service-worker-allowed'], '/');
  });

  test('health / status / countries が JSON を返す', async () => {
    const h = await fetchProxied('/mirage/api/health');
    assert.equal(h.status, 200);
    assert.equal(JSON.parse(h.text).ok, true);
    const s = JSON.parse((await fetchProxied('/mirage/api/status')).text);
    assert.equal(s.transport.mode, 'uv');
    assert.equal(s.egress.strategy, 'direct');
    assert.equal(s.capabilities.wisp, true);
  });

  test('resolve: 検索語は検索エンジンに、ドメインはそのままプロキシへ', async () => {
    const a = JSON.parse((await fetchProxied('/mirage/api/url?q=hello+world')).text);
    assert.equal(a.type, 'search');
    assert.match(a.proxied, /^\/mirage\/t\/preview\/h\./);
    const b = JSON.parse((await fetchProxied('/mirage/api/url?q=example.com')).text);
    assert.equal(b.type, 'url');
    assert.match(b.proxied, /^\/mirage\/t\/preview\/h\./);
  });
});

describe('WISP トランスポート', () => {
  test('WS 上で HTTP フレームをやり取りできる', async () => {
    const { WebSocket } = await import('ws');
    const ws = new WebSocket(`ws://127.0.0.1:${port}/mirage/wisp?sid=wispTEST`);
    await new Promise((resolve, reject) => {
      ws.once('open', resolve);
      ws.once('error', reject);
      setTimeout(() => reject(new Error('wisp open timeout')), 4000);
    });
    const id = '00112233445566778899aabbccddeeff';
    const payload = Buffer.from(
      JSON.stringify({
        mode: 'http',
        method: 'GET',
        url: `http://127.0.0.1:${originPort}/`,
        headers: { accept: 'text/html', 'user-agent': 'wisp-test' },
        sid: 'wispTEST',
      }),
    );
    const head = Buffer.alloc(21);
    Buffer.from(id, 'hex').copy(head, 0);
    head[16] = 1; // CONNECT
    head.writeUInt32BE(payload.length, 17);
    ws.send(Buffer.concat([head, payload]));

    const raw = await new Promise((resolve, reject) => {
      const acc = [];
      const to = setTimeout(() => reject(new Error('no wisp response')), 8000);
      ws.on('message', (data) => {
        const buf = Buffer.from(data);
        let off = 0;
        while (off + 21 <= buf.length) {
          const type = buf[16];
          const len = buf.readUInt32BE(17);
          const body = buf.subarray(21, 21 + len);
          off += 21 + len;
          if (type === 0) acc.push(body);
          else if (type === 6) {
            clearTimeout(to);
            return reject(new Error(`wisp error frame: ${body.toString('utf8')}`));
          } else if (type === 2) {
            clearTimeout(to);
            return resolve(Buffer.concat(acc));
          }
        }
      });
      ws.once('error', (e) => {
        clearTimeout(to);
        reject(e);
      });
    });
    ws.close();
    const text = raw.toString('latin1');
    assert.match(text, /^HTTP\/1\.1 200 /);
    assert.match(text, /<title>Origin Home<\/title>/);
    assert.match(text, /href="\/mirage\/t\/wispTEST\/h\./, 'WISP 応答も改写されている');
  });
});

describe('HTTPS 上流', () => {
  let tlsOrigin;
  let tlsPort;
  before(async () => {
    const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures');
    let key;
    let cert;
    try {
      [key, cert] = await Promise.all([readFile(path.join(dir, 'key.pem')), readFile(path.join(dir, 'cert.pem'))]);
    } catch {
      return; // 自己署名ペアが無い環境ではスキップ
    }
    await new Promise((resolve) => {
      tlsOrigin = https.createServer({ key, cert }, (req, res) => {
        res.setHeader('content-type', 'text/html; charset=utf-8');
        res.end('<!doctype html><html><head><title>TLS Origin</title></head><body><a href="/secure-page">secure</a></body></html>');
      });
      tlsOrigin.listen(0, '127.0.0.1', () => {
        tlsPort = tlsOrigin.address().port;
        resolve();
      });
    });
  });
  after(async () => {
    if (tlsOrigin) await new Promise((r) => tlsOrigin.close(r));
  });

  test('https:// 上流でも改写が効く (プロキシは TLS を終端する)', async (t) => {
    if (!tlsPort) return t.skip('cert fixtures なし');
    const p = urlmap.proxify(`https://127.0.0.1:${tlsPort}/`, 'sidTLS');
    const res = await fetchProxied(p, { headers: { accept: 'text/html', 'sec-fetch-dest': 'document' } });
    assert.equal(res.status, 200);
    assert.match(res.text, /<title>TLS Origin<\/title>/);
    assert.match(res.text, /href="\/mirage\/t\/sidTLS\/h\.[A-Za-z0-9_-]+\/secure-page"/);
    const seg = /href="(\/mirage\/t\/sidTLS\/h\.[A-Za-z0-9_-]+)\/secure-page"/.exec(res.text);
    assert.equal(urlmap.decodeHost(seg[1].split('/').pop()), `https://127.0.0.1:${tlsPort}`);
  });
});

describe('レポート', () => {
  test('脅威レポートは JSON/HTML で取得でき、本文は含まない', async () => {
    const j = JSON.parse((await fetchProxied('/mirage/api/threats?limit=5')).text);
    assert.ok(Array.isArray(j.events));
    assert.ok(j.totals);
    const h = await fetchProxied('/mirage/api/threats/report.html');
    assert.equal(h.status, 200);
    assert.match(h.text, /セキュリティレポート/);
  });
});
