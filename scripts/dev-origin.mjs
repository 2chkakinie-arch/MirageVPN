/**
 * デモ/スモーク用の簡易 origin (上流サイトを装するだけの小さな Web サーバ)。
 * 実サイトを使わないので、ネットワークが塞がれた環境でも改写・遮断・クッキーの挙動を確認できる。
 *
 *   node scripts/dev-origin.mjs [port]     (既定 8099)
 *
 * `MIRAGE_BLOCK_PRIVATE_TARGETS=0` で起動したゲートウェイと組み合わせて使う (README §6 参照)。
 * @module scripts/dev-origin
 */

import http from 'node:http';

const port = Number(process.argv[2] || process.env.ORIGIN_PORT || 8099);

const PAGE = `<!doctype html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <title>Mirage Dev Origin</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <h1>ローカル origin です</h1>
  <p><a href="/docs/relative">相対リンク</a> / <a href="/search?q=hello">クエリ付き</a> / <a href="#anchor">フラグメント</a></p>
  <img src="/pic.png" srcset="/pic2.png 2x" alt="">
  <div style="background:url(/bg.png)"></div>

  <!-- 広告/トラッカーのフリ (ゲートウェイ側で落ちる) -->
  <div class="adsbygoogle" data-ad-client="ca-pub-0000">ad slot</div>
  <script async src="https://www.googletagmanager.com/gtag/js?id=G-XXXX"></script>
  <script src="/track.js" data-src="https://doubleclick.net/r;__x__=1"></script>
  <img src="https://stats.g.doubleclick.net/g/collect?v=2&amp;t=pageview" width="1" height="1">

  <!-- 脅威エンジンのフリ (meta refresh と javascript: URL) -->
  <a href="javascript:void(0)" id="jsurl">js url</a>
  <iframe src="//ads.example/embed"></iframe>

  <form action="/submit" method="post"><input name="q" value="ok"><button>send</button></form>
  <script>document.title = 'Dev Origin ' + location.pathname;</script>
</body>
</html>`;

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname === '/style.css') {
    res.writeHead(200, { 'content-type': 'text/css; charset=utf-8' });
    return res.end('body{margin:0;background:url(/bg.png)}@import url("/extra.css");\n.ad{color:#333}');
  }
  if (url.pathname === '/extra.css') {
    res.writeHead(200, { 'content-type': 'text/css; charset=utf-8' });
    return res.end('.x{background:url(/deep/x.png)}');
  }
  if (url.pathname === '/track.js') {
    res.writeHead(200, { 'content-type': 'application/javascript; charset=utf-8' });
    return res.end('window.__t=1;var u="https://doubleclick.net/r";history.pushState({}, "", "/now");');
  }
  if (url.pathname === '/submit' && req.method === 'POST') {
    let n = 0;
    req.on('data', (c) => (n += c.length));
    req.on('end', () => {
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ ok: true, receivedBytes: n }));
    });
    return;
  }
  if (url.pathname === '/redirect') {
    res.writeHead(302, { location: '/docs/relative' });
    return res.end();
  }
  if (url.pathname === '/download.bin') {
    res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-disposition': 'attachment; filename="x.bin"' });
    return res.end(Buffer.alloc(2048, 7));
  }
  res.writeHead(200, {
    'content-type': 'text/html; charset=utf-8',
    'set-cookie': 'sid=abc; Path=/; SameSite=Lax',
    'x-frame-options': 'DENY', // ゲートウェイが外して再付与することになる
    'content-security-policy': "default-src 'none'",
  });
  res.end(PAGE);
});

server.listen(port, '127.0.0.1', () => {
  process.stdout.write(`dev origin: http://127.0.0.1:${port}/\n`);
});
