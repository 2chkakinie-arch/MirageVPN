/**
 * スモーク: 起動中のゲートウェイに対して
 *  A) UV 転送でローカル origin を取得 → 改写 / cosmetic / cookie / threat
 *  B) 広告サブ资源がブロックされるか (ネットワーク不要: 出口前に止まる)
 *  C) WISP ハンドシェイク (HELLO) → CONNECT → DATA → CLOSE
 */
import { WebSocket } from 'ws';
import { encodeFrame, decodeFrame, FRAME } from '../server/wisp/protocol.js';

// node scripts/smoke.mjs [gatewayURL] [originURL]
// ゲートウェイを別に起動しておき、実 HTTP/実 WebSocket で「本当に通るか」を 15 項目チェックする。
const GW = (process.argv[2] || 'http://127.0.0.1:8080').replace(/\/$/, '');
const ORIGIN = (process.argv[3] || 'http://127.0.0.1:8099/').replace(/\/$/, '') + '/';
const SID = 'smoke000000000000000000';
const results = [];
const chk = (name, cond, extra = '') => {
  results.push({ name, pass: !!cond, extra });
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? `  — ${extra}` : ''}`);
};

const j = async (p, opts) => {
  const r = await fetch(GW + p, opts);
  return { status: r.status, body: await r.text() };
};

/* ---------- A: UV 転送でドキュメント ---------- */
const url = JSON.parse((await j(`/mirage/api/url?q=${encodeURIComponent(ORIGIN)}&sid=${SID}`)).body);
chk('resolve: /mirage/api/url が proxied を返す', !!url.proxied, url.proxied);
const res = await fetch(GW + url.proxied, { headers: { cookie: '' } });
const html = await res.text();
chk('proxied doc: 200', res.status === 200, `status=${res.status}`);
chk('proxied doc: core.js が注入されている', /__mirage-config/.test(html) && /mirage\/core\.js/.test(html));
chk('proxied doc: 相対 href がプロキシパスに書き換わった', /href="\/mirage\/t\//.test(html));
const gtag = html.match(/<script[^>]*src="(\/mirage\/t\/[^"]+)"/)?.[1] || '';
chk('proxied doc: 絶対 URL (gtag.js) も符号化されて同じ出口を通る', /h\.[A-Za-z0-9_-]+\/gtag\/js/.test(gtag), gtag.slice(0, 78));
chk('proxied doc: プロトコル相対 //ads.example も復号できる', /<iframe src="\/mirage\/t\/[^"]+"/.test(html), html.match(/<iframe src="[^"]{0,70}/)?.[0] || 'missing');
const upstreamCookieLeaked = /(^|,\s*)sid=abc/.test(res.headers.get('set-cookie') || '');
chk('proxied doc: 上流の Set-Cookie は漏れず、自前の client-id だけ', !upstreamCookieLeaked, res.headers.get('set-cookie')?.split(';')[0] || 'none');
chk('proxied doc: frame-ancestors で額縁保護', (res.headers.get('content-security-policy') || '').includes("frame-ancestors 'self'"), res.headers.get('content-security-policy') || 'none');
chk('proxied doc: cosmetic <style> が注入された', /__mirage-cosmetic/.test(html), html.match(/__mirage-cosmetic[^>]*>/)?.[0] || '');
chk('proxied doc: セキュリティヘッダ (referrer-policy)', (res.headers.get('referrer-policy') || '') !== '' || /meta name="referrer"/.test(html));

// CSS / クッキージャー
const cssPath = html.match(/<link rel="stylesheet" href="([^"]+)"/)?.[1];
if (cssPath) {
  const css = await fetch(GW + cssPath);
  const cssText = await css.text();
  chk('アセット: CSS の url() も書き換わる', css.status === 200 && /url\("\/mirage\/t\//.test(cssText), cssText.slice(0, 60).replace(/\n/g, ' '));
} else {
  chk('アセット: CSS の url() も書き換わる', false, 'link が見つからない');
}
const jar = JSON.parse((await j(`/mirage/api/cookies?sid=${SID}`)).body);
chk('クッキー: ジャーに吸収されている', (jar.cookies || []).some((c) => c.name === 'sid'), JSON.stringify(jar).slice(0, 120));

/* ---------- A2: リダイレクト追跡 / バイナリ素通し / cosmetic ヘッダ ---------- */
chk('proxied doc: cosmetic CSS 注入件数がヘッダに出る', /x-mirage-cosmetic: \d+/i.test('x-mirage-cosmetic: ' + (res.headers.get('x-mirage-cosmetic') ?? '')), `n=${res.headers.get('x-mirage-cosmetic')}`);
const redPath = JSON.parse((await j(`/mirage/api/url?q=${encodeURIComponent(ORIGIN + 'redirect')}&sid=${SID}`)).body).proxied;
const red = await fetch(GW + redPath, { redirect: 'manual' });
const finalUrl = decodeURIComponent(red.headers.get('x-mirage-final-url') || '');
chk('リダイレクト: 302 を追って final url をヘッダで返す', /\/docs\/relative/.test(finalUrl), `status=${red.status} final=${finalUrl || '(none)'}`);
const binPath = JSON.parse((await j(`/mirage/api/url?q=${encodeURIComponent(ORIGIN + 'download.bin')}&sid=${SID}`)).body).proxied;
const bin = await fetch(GW + binPath);
const binBytes = await bin.arrayBuffer();
chk('ダウンロード: octet-stream は改写せず素通し', bin.status === 200 && binBytes.byteLength === 2048, `len=${binBytes.byteLength} type=${bin.headers.get('content-type')}`);

/* ---------- B: 広告リクエストは出口前に捨てる ---------- */
const before = JSON.parse((await j('/mirage/api/shields')).body).blocked;
// 実在の広告ドメイン (シードに ||doubleclick.net^ がある) を使えば、上流に一切触れずに止まる
const adTarget = 'https://stats.g.doubleclick.net/g/collect?v=2&t=pageview';
const adUrl = JSON.parse((await j(`/mirage/api/url?q=${encodeURIComponent(adTarget)}&sid=${SID}`)).body);
const ad = await fetch(GW + adUrl.proxied, { headers: { referer: `${GW}${url.proxied}`, accept: '*/*' } });
const adBody = await ad.text();
const after = JSON.parse((await j('/mirage/api/shields')).body).blocked;
const stubbed = /mirage-blocked|blocked|shields/i.test(adBody) || ad.headers.get('x-mirage-blocked') === '1';
chk('シールド: 広告リクエストを出口前に捨てた', after > before || stubbed, `before=${before} after=${after} status=${ad.status} hdr=${ad.headers.get('x-mirage-blocked')}`);

/* ---------- C: WISP ---------- */
async function wisp() {
  const ws = new WebSocket(GW.replace('http', 'ws') + '/mirage/wisp', { headers: { origin: GW } });
  const frames = [];
  let hello = null;
  const streamId = Array.from({ length: 16 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join('');
  let acc = Buffer.alloc(0);
  let done = null;
  const finished = new Promise((resolve) => (done = resolve));
  let body = Buffer.alloc(0);
  let head = null;

  const FRAME_NAMES = { 0: 'DATA', 1: 'CONNECT', 2: 'CLOSE', 3: 'KEEPALIVE', 4: 'PAUSE', 5: 'RESUME', 6: 'ERROR', 7: 'HELLO' };
  ws.on('message', (data) => {
    acc = Buffer.concat([acc, Buffer.from(data)]);
    let off = 0;
    let f;
    while ((f = decodeFrame(acc, off))) {
      off = f.next;
      frames.push(FRAME_NAMES[f.type] || f.type);
      if (f.type === FRAME.HELLO) hello = JSON.parse(f.payload.toString() || '{}');
      else if (f.type === FRAME.DATA) {
        if (!head) {
          const txt = f.payload.toString('latin1');
          const i = txt.indexOf('\r\n\r\n');
          if (i >= 0) {
            head = txt.slice(0, i);
            body = Buffer.concat([body, Buffer.from(txt.slice(i + 4), 'latin1')]);
          } else body = Buffer.concat([body, f.payload]);
        } else body = Buffer.concat([body, f.payload]);
      } else if (f.type === FRAME.CLOSE) done('close');
      else if (f.type === FRAME.ERROR) done(`error:${f.payload.toString()}`);
    }
    if (off) acc = acc.subarray(off);
  });
  await new Promise((r) => ws.on('open', r));
  await new Promise((r) => setTimeout(r, 250));
  chk('WISP: HELLO フレームが届く', !!hello && hello.ok === true, JSON.stringify(hello || {}).slice(0, 120));

  const payload = Buffer.from(
    JSON.stringify({ mode: 'http', method: 'GET', url: ORIGIN, headers: { host: '127.0.0.1:8099', accept: '*/*' }, sid: SID }),
  );
  ws.send(encodeFrame(streamId, FRAME.CONNECT, payload));
  const why = await Promise.race([finished, new Promise((r) => setTimeout(() => r('timeout'), 12000))]);
  const text = body.toString('latin1');
  chk('WISP: CONNECT → DATA で HTTP 応答が返る', !!head && /^HTTP\/1\.[01] 200/.test(head), `${why} head=${(head || '').split('\r\n')[0] || 'none'}`);
  chk('WISP: 応答本文も改写されている', /__mirage-config|__mirage-cosmetic|\/mirage\/t\//.test(text), `bytes=${body.length}`);
  chk('WISP: content-length が本体長と一致', head ? Number(/content-length: *(\d+)/i.exec(head)?.[1]) === body.length : false, `cl=${/content-length: *(\d+)/i.exec(head)?.[1]} body=${body.length}`);
  ws.close();
  console.log('   frames:', frames.join(','));
}
await wisp();

/* ---------- metrics / status 最終確認 ---------- */
const st = JSON.parse((await j('/mirage/api/status')).body);
chk('status: lists/sources が可視 (UI のリストフィード)', (st.lists?.sources || []).length > 0, `sources=${st.lists?.sources?.length}`);
chk('status: wisp 能力が立つ', st.capabilities.wisp === true);
const met = JSON.parse((await j('/mirage/api/metrics')).body);
chk('metrics: latency/series 付き', met.latency && Array.isArray(met.series), `req=${met.requests} err=${met.errors}`);

const fails = results.filter((r) => !r.pass);
console.log(`\n=== ${results.length - fails.length}/${results.length} passed ===`);
process.exit(fails.length ? 1 : 0);
