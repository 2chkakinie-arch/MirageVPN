import test from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import zlib from 'node:zlib';
import { request, Http1Pool, parseHead, decompressStream } from '../server/net/http1.js';
import { readAll, startTargetServer, startHttpProxy, startSocks5Proxy } from './helpers/fake-net.mjs';

const opts = { connectTimeoutMs: 4000, headTimeoutMs: 5000, idleTimeoutMs: 5000 };

test('parseHead: status/headers/keep-alive/obssolete folding', () => {
  const h = parseHead(
    'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nX-Fold: one\r\n  two\r\nConnection: close\r\n\r\n',
  );
  assert.equal(h.statusCode, 200);
  assert.equal(h.statusText, 'OK');
  assert.equal(h.headers.get('set-cookie'), 'a=1, b=2');
  assert.equal(h.headers.get('x-fold'), 'one two');
  assert.equal(h.keepAlive, false);
});

test('direct GET: body + headers', async () => {
  const t = await startTargetServer();
  try {
    const res = await request({ url: `${t.origin}/`, ...opts });
    assert.equal(res.statusCode, 200);
    const body = await readAll(res.stream);
    assert.match(body.toString(), /Mirage Target/);
    assert.equal(res.headers.get('content-type'), 'text/html; charset=utf-8');
  } finally {
    await t.close();
  }
});

test('chunked + gzip decode', async () => {
  const t = await startTargetServer();
  try {
    const res = await request({ url: `${t.origin}/chunked-gzip`, ...opts });
    const gz = await readAll(res.stream);
    assert.equal(zlib.gunzipSync(gz).toString(), 'chunked-and-gzipped-payload-'.repeat(400));
    const res2 = await request({
      url: `${t.origin}/chunked-gzip`,
      ...opts,
      headers: new Map([['accept-encoding', 'gzip']]),
    });
    const stream = decompressStream(res2.headers.get('content-encoding'));
    res2.stream.pipe(stream);
    assert.equal((await readAll(stream)).toString(), 'chunked-and-gzipped-payload-'.repeat(400));
  } finally {
    await t.close();
  }
});

test('trailers are skipped, body exact', async () => {
  const t = await startTargetServer();
  try {
    const res = await request({ url: `${t.origin}/trailer`, ...opts });
    assert.equal((await readAll(res.stream)).toString(), 'hello');
  } finally {
    await t.close();
  }
});

test('no content-length (EOF terminated)', async () => {
  const t = await startTargetServer();
  try {
    const res = await request({ url: `${t.origin}/no-length`, ...opts });
    assert.equal((await readAll(res.stream)).toString(), 'stream-part-1\nstream-part-2\n');
  } finally {
    await t.close();
  }
});

test('POST body echo + host header', async () => {
  const t = await startTargetServer();
  try {
    const res = await request({
      url: `${t.origin}/echo`,
      method: 'POST',
      body: Buffer.from('q=mirage'),
      headers: new Map([['content-type', 'application/x-www-form-urlencoded']]),
      ...opts,
    });
    const json = JSON.parse((await readAll(res.stream)).toString());
    assert.equal(json.method, 'POST');
    assert.equal(json.body, 'q=mirage');
    assert.equal(json.headers['content-type'], 'application/x-www-form-urlencoded');
    assert.match(json.headers.host, /127\.0\.0\.1/);
  } finally {
    await t.close();
  }
});

test('keep-alive pool reuses one socket', async () => {
  const t = await startTargetServer();
  const pool = new Http1Pool({ idleTimeoutMs: 5000 });
  try {
    const seen = [];
    for (let i = 0; i < 4; i++) {
      const res = await request({ url: `${t.origin}/keepalive-check`, pool, ...opts });
      seen.push((await readAll(res.stream)).toString());
    }
    assert.deepEqual(seen, ['1', '2', '3', '4'], '同一ソケット上で sequential なリクエスト番号が増えるはず');
    assert.ok(pool.stats.reuse >= 3, `reuse=${pool.stats.reuse}`);
  } finally {
    pool.close();
    await t.close();
  }
});

test('http forward proxy (absolute-URI) for plain http', async () => {
  const [t, px] = await Promise.all([startTargetServer(), startHttpProxy()]);
  try {
    const res = await request({
      url: `${t.origin}/`,
      proxy: { protocol: 'http', host: px.host, port: px.port },
      ...opts,
    });
    assert.equal(res.statusCode, 200);
    assert.match((await readAll(res.stream)).toString(), /Mirage Target/);
    assert.equal(px.counts.forwards, 1);
  } finally {
    await px.close();
    await t.close();
  }
});

test('http proxy with basic auth (407 without creds, 200 with)', async () => {
  const [t, px] = await Promise.all([startTargetServer(), startHttpProxy({ requireAuth: true, user: 'bob', pass: 'pw' })]);
  try {
    const denied = await request({ url: `${t.origin}/`, proxy: { protocol: 'http', host: px.host, port: px.port }, ...opts });
    assert.equal(denied.statusCode, 407, '資格情報なしならプロキシが 407 を返す');
    await readAll(denied.stream);
    const res = await request({
      url: `${t.origin}/`,
      proxy: { protocol: 'http', host: px.host, port: px.port, username: 'bob', password: 'pw' },
      ...opts,
    });
    assert.equal(res.statusCode, 200);
    await readAll(res.stream);
  } finally {
    await px.close();
    await t.close();
  }
});

test('socks5 no-auth tunnel', async () => {
  const [t, px] = await Promise.all([startTargetServer(), startSocks5Proxy()]);
  try {
    const res = await request({
      url: `${t.origin}/echo`,
      proxy: { protocol: 'socks5', host: px.host, port: px.port },
      ...opts,
    });
    const json = JSON.parse((await readAll(res.stream)).toString());
    assert.equal(json.url, '/echo');
    assert.equal(px.handled, 1);
  } finally {
    await px.close();
    await t.close();
  }
});

test('socks5 username/password handshake', async () => {
  const [t, px] = await Promise.all([startTargetServer(), startSocks5Proxy({ username: 'mir', password: 'age' })]);
  try {
    const res = await request({
      url: `${t.origin}/`,
      proxy: { protocol: 'socks5', host: px.host, port: px.port, username: 'mir', password: 'age' },
      ...opts,
    });
    assert.match((await readAll(res.stream)).toString(), /Mirage Target/);
    await assert.rejects(
      () =>
        request({
          url: `${t.origin}/`,
          proxy: { protocol: 'socks5', host: px.host, port: px.port, username: 'mir', password: 'WRONG' },
          ...opts,
        }),
      /認証/,
    );
  } finally {
    await px.close();
    await t.close();
  }
});

test('socks5 refused target surfaces a clear error', async () => {
  const [t, px] = await Promise.all([
    startTargetServer(),
    startSocks5Proxy({ rejectAt: { host: '127.0.0.1', port: 1 } }),
  ]);
  try {
    await assert.rejects(
      () => request({ url: 'http://127.0.0.1:1/', proxy: { protocol: 'socks5', host: px.host, port: px.port }, ...opts }),
      (err) => {
        assert.equal(err.code, 'socks_refused');
        return true;
      },
    );
  } finally {
    await px.close();
    await t.close();
  }
});

test('head timeout + idle handling on slow upstream', async () => {
  const t = await startTargetServer();
  try {
    await assert.rejects(
      () => request({ url: `${t.origin}/slow?ms=400`, ...opts, headTimeoutMs: 80 }),
      /タイムアウト/,
    );
  } finally {
    await t.close();
  }
});

test('maxBodyBytes aborts oversized responses', async () => {
  const t = await startTargetServer();
  try {
    const res = await request({ url: `${t.origin}/huge?size=400000`, maxBodyBytes: 100_000, ...opts });
    await assert.rejects(() => readAll(res.stream), /上限/);
  } finally {
    await t.close();
  }
});

test('aborted signal rejects immediately', async () => {
  const t = await startTargetServer();
  try {
    const ac = new AbortController();
    ac.abort();
    await assert.rejects(() => request({ url: `${t.origin}/`, signal: ac.signal, ...opts }), /キャンセル/);
  } finally {
    await t.close();
  }
});

test('error status codes are surfaced, not thrown', async () => {
  const t = await startTargetServer();
  try {
    const res = await request({ url: `${t.origin}/status?code=503`, ...opts });
    assert.equal(res.statusCode, 503);
    await readAll(res.stream);
  } finally {
    await t.close();
  }
});
