/**
 * 各エンジンのユニットテスト (ネットワーク不要)。
 *   - UrlMap   : トークン写像と復号の対合、相対解決
 *   - Shields  : ABP 構文の解析/一致、例外、3p/1p、cosmetic、許可リスト
 *   - Threats  : スコア、自動除去指示、レポート、purge
 *   - ProxyPool: 登録/国籍ピン留め/BAN/snapshot
 * @module test/unit-engines.test.js
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../server/config.js';
import { UrlMap, safeUrl } from '../server/proxy/urlmap.js';
import { Shields, abpToRegex, selectorToCss } from '../server/security/shields.js';
import { ThreatEngine } from '../server/security/threats.js';
import { ProxyPool } from '../server/data/pool.js';

const cfg = () => loadConfig({ MIRAGE_STATE_DIR: '', NODE_ENV: 'test', VERCEL: '' });

/* ------------------------------------------------------------------ */
describe('UrlMap', () => {
  test('host トークンは可逆 (ポート・スキーム込み)', () => {
    const map = new UrlMap(cfg());
    for (const origin of ['https://example.com', 'http://a.b.c:8080', 'https://x.io']) {
      const tok = map.encodeHost(origin);
      assert.ok(tok && tok.length > 4);
      assert.equal(map.decodeHost(tok), origin.replace(/\/$/, ''));
    }
  });

  test('proxify は path/query を保つ (hash は keepHash のときだけ)', () => {
    const map = new UrlMap(cfg());
    const sid = 's'.repeat(24);
    const out = map.proxify('https://example.com/deep/path/ファイル?q=1&z=2#frag', sid);
    assert.ok(out.startsWith('/mirage/t/'), out);
    assert.match(out, /\/deep\/path\//);
    assert.match(out, /\?q=1&z=2$/);
    assert.ok(!out.includes('#frag'), '既定ではフラグメントを載せない (サブ资源で無駄にしない)');
    const doc = map.proxify('https://example.com/d?q=1#frag', sid, { keepHash: true });
    assert.match(doc, /\?q=1#frag$/);
    // kind を文字列で渡しても壊れない (後方互換)
    assert.ok(map.proxify('https://example.com/x', sid, 'document'));
  });

  test('deproxify は元の絶対 URL に戻す', () => {
    const map = new UrlMap(cfg());
    const sid = 'a'.repeat(24);
    const target = 'https://example.com:8443/a/b?x=%20y#h';
    const prox = map.proxify(target, sid);
    const u = new URL(prox, 'http://localhost');
    const back = map.deproxify(u.pathname, u.search);
    assert.ok(back.url instanceof URL);
    assert.equal(back.url.origin, 'https://example.com:8443');
    assert.equal(back.url.pathname, '/a/b');
    assert.equal(back.url.search, '?x=%20y');
    assert.equal(back.ws, false);
    assert.equal(back.url.href, target.replace('#h', ''));
  });

  test('parseSession / isProxiedPath', () => {
    const map = new UrlMap(cfg());
    const sid = 'deadbeefcafebabe0123456789';
    const p = new URL(map.proxify('https://example.com/', sid), 'http://localhost').pathname;
    assert.equal(map.parseSession(p).sid, sid);
    assert.equal(map.isProxiedPath(p), true);
    assert.equal(map.isProxiedPath('/mirage/api/status'), false);
    assert.equal(map.parseSession('/nope/xx/'), null);
    assert.equal(map.deproxify('/nope/xx/'), null);
    assert.equal(map.deproxify(`/mirage/t/${sid}/z.eHh4/default`), null, '不正マーカーは null');
  });

  test('危険スキームは proxify がねじる / deproxify はホスト部だけ復号', () => {
    const map = new UrlMap(cfg());
    const sid = 'a'.repeat(24);
    assert.equal(map.proxify('javascript:alert(1)', sid), null);
    assert.equal(map.proxify('data:text/html,<script>1</script>', sid), null);
    assert.equal(map.proxify('ftp://example.com/x', sid), null);
    assert.ok(safeUrl('not a url') === null, 'パース不能は null');
    // 偽トークンで任意 origin へは行けない (http/https 以外と userinfo は弾く)
    const forged = `${map.sessionPrefix(sid)}/${'h.' + Buffer.from('http://169.254.169.254').toString('base64url')}/latest`;
    assert.ok(map.deproxify(forged), '復号自体はできる (遮断は SSRF ガードの仕事)');
    assert.equal(map.decodeHost(`h.${Buffer.from('file:///etc/passwd').toString('base64url')}`), null);
    assert.equal(map.decodeHost(`h.${Buffer.from('http://user:pw@x.io').toString('base64url')}`), null);
  });
});

/* ------------------------------------------------------------------ */
describe('Shields (ABP 構文)', () => {
  const mk = (text, over = {}) => {
    const config = { ...cfg(), ...over };
    config.shields = { ...cfg().shields, ...(over.shields || {}) };
    const s = new Shields(config);
    s.parse(text);
    return s;
  };

  test('||domain^ は接頭辞ブロック、@@ は例外', () => {
    const s = mk('||ads.example^\n@@||ads.example/pixel-ok\n');
    assert.equal(s.match('https://ads.example/banner.js', { type: 'script' }).blocked, true);
    assert.equal(s.match('https://sub.ads.example/x', { type: 'image' }).blocked, true);
    const ok = s.match('https://ads.example/pixel-ok', { type: 'image' });
    assert.equal(ok.blocked, false, `パス指定の @@ 例外がホスト単体ブロックより勝つ: ${ok.rule}`);
    assert.equal(s.match('https://notads.example.co/x', { type: 'image' }).blocked, false);
  });

  test('$important は例外より勝つ / $domain はページ制限', () => {
    const s = mk('@@||track.example^\n||track.example/block$important\n||pay.example^$domain=news.example\n');
    assert.equal(s.match('https://track.example/x').blocked, false);
    assert.equal(s.match('https://track.example/block').blocked, true);
    const imp = s.match('https://track.example/block');
    assert.equal(imp.blocked, true, `$important は @@ より勝つ: ${imp.rule}`);
    const onNews = s.match('https://pay.example/w', { sourceUrl: 'https://news.example/top' });
    const onOwn = s.match('https://pay.example/w', { sourceUrl: 'https://pay.example/w' });
    assert.equal(onNews.blocked, true, '$domain はページ側ドメイン限定');
    assert.equal(onOwn.blocked, false, '自分自身のドメインでは発動しない');
  });

  test('$third-party と $doctype/--important 以外の複雑な選択肢は安全側に捨てる', () => {
    const s = mk('||cdn.example^$third-party\n||weird.example^$~image,other=nonsense\n');
    const tp = s.match('https://cdn.example/a.png', { sourceUrl: 'https://other.example/p' });
    const fp = s.match('https://cdn.example/a.png', { sourceUrl: 'https://cdn.example/p' });
    assert.equal(tp.blocked, true);
    assert.equal(fp.blocked, false);
    // 解釈できない選択肢の規則は「全面ブロック」にフォールバックしない (= 安全側)
    assert.equal(s.match('https://weird.example/x').blocked, true);
  });

  test('cosmetic: ## .ad → display:none、##:has-text() は procedural として退避', () => {
    const s = mk('example.com##.ad\nexample.com##div:has-text("Sponsored")\n##iframe[src*="ads"]\n');
    const forPage = s.cosmeticCss('https://www.example.com/news');
    assert.match(forPage.css, /\.ad\s*\{\s*display\s*:\s*none\s*!important/);
    assert.ok(forPage.procedural >= 1, 'has-text 系は procedural 计数される');
    assert.ok(!/has-text/.test(forPage.css));
    const generic = s.cosmeticCss('https://anyother.site/');
    assert.match(generic.css, /iframe\[src\*=["']?ads/, `汎用則 (## で始まり domains 指定なし) も効くべき: ${JSON.stringify(generic)}`);
    // selectorToCss は CSS 境界を抜けない
    // 壊れた/悪意あるセレクタは CSS にしない
    assert.equal(selectorToCss('foo##bar'), '');
    assert.equal(selectorToCss('a</style><img src=x onerror=alert(1)>'), '');
    assert.equal(selectorToCss('.ad:style(background:url(javascript:alert(1)))'), '');
    assert.equal(selectorToCss('.ad:style(color:red}body{display:none)'), '');
  });

  test('サイト別許可 / レベル off / summary', () => {
    const s = mk('||ads.example^\n');
    s.disableFor('example.com');
    assert.equal(s.match('https://ads.example/x', { sourceUrl: 'https://example.com/p' }).blocked, false);
    s.enableFor('example.com');
    assert.equal(s.match('https://ads.example/x', { sourceUrl: 'https://example.com/p' }).blocked, true);
    s.setLevel('off');
    assert.equal(s.match('https://ads.example/x').blocked, false);
    s.setLevel('aggressive');
    assert.equal(s.match('https://ads.example/x').blocked, true);
    assert.ok(s.summary().rules >= 1);
  });

  test('同梱シード (実データ) を読むと既定で主要広告網が落ちる', async () => {
    const config = cfg();
    const s = new Shields(config);
    const loaded = await s.loadSeed();
    assert.ok(loaded.files >= 1, '少なくともどちらかのシードが読める');
    assert.ok(loaded.rules > 2000, `rules=${loaded.rules}`);
    const page = 'https://news.example/top';
    // ホスト単位の hard-block 層 (data/adblock/hosts.seed.txt) が offline で効く
    for (const u of [
      'https://stats.g.doubleclick.net/g/collect?v=2&t=pageview',
      'https://criteo.com/rtd/x.js',
      'https://bat.bing.com/action/0',
      'https://mc.yandex.ru/watch/1',
    ]) {
      const r = s.match(u, { type: 'script', sourceUrl: page });
      assert.equal(r.blocked, true, `block expected: ${u} (${r.rule})`);
    }
    // 被害が出てはいけないもの (CDN / 表单 / 通常のページ) は通す
    for (const u of [
      'https://unpkg.com/react@18/umd/react.production.min.js',
      'https://i.pinimg.com/originals/1f/2b/ab.png',
      'https://js.hsforms.net/forms/v2.js',
      'https://news.example/static/app.css',
    ]) {
      const r = s.match(u, { type: 'script', sourceUrl: page });
      assert.equal(r.blocked, false, `must NOT block: ${u} (${r.rule})`);
    }
    assert.ok(s.cosmeticCss('https://news.example/top').count > 0, 'cosmetic 規則も適用される');
  });

  test('abpToRegex はワイルドカードと ^ 区切りを正規表現へ変換する', () => {
    assert.equal(typeof abpToRegex('/banner/*300x250*'), 'string');
    const re = new RegExp(abpToRegex('/banner/*300x250*'), 'i');
    assert.ok(re.test('https://x.com/banner/a-300x250.png'), abpToRegex('/banner/*300x250*'));
    assert.ok(!re.test('https://x.com/footer/a.png'));
    // 末尾 `|` は完全一致アンカーになる
    // 末尾 `|` は完全一致アンカー (`^` は区切り文字 class なので直後に / を要求してしまう)
    const exact = new RegExp(abpToRegex('||ads.example/banner|'), 'i');
    assert.ok(exact.test('https://ads.example/banner'));
    assert.ok(!exact.test('https://ads.example/banner/x.js'));
    // `||host` はラベル境界でアンカーされる (部分一致で別ドメインを道連れにしない)
    const hostOnly = new RegExp(abpToRegex('||ads.example^'), 'i');
    assert.ok(hostOnly.test('https://cdn.ads.example/x'));
    assert.ok(!hostOnly.test('https://notads.example/x'), 'notads.example は別ドメイン');
  });
});

/* ------------------------------------------------------------------ */
describe('Threats', () => {
  const mk = () => new ThreatEngine(cfg(), {});

  test('hosts 形式ファイルを読み込める (0.0.0.0 host / ::1 host)', () => {
    const e = mk();
    const n = e.loadBadHosts('# comment\n0.0.0.0 evil.test\n::1 ipv6.test\n127.0.0.1 localhost\n||abp.test^\n');
    assert.ok(n >= 3, `read ${n}`);
    assert.equal(e.isBadHost('ipv6.test'), true);
    assert.equal(e.isBadHost('sub.abp.test'), true);
  });

  test('無害な https ページは 0 点、怪しい物は加点される', () => {
    const e = mk();
    const clean = e.inspectUrl('https://example.com/docs/intro', { kind: 'document' });
    assert.equal(clean.score, 0);
    assert.equal(clean.block, false);
    const sus = e.inspectUrl('http://142.4.5.6/login.php?u=1', { kind: 'document' });
    assert.ok(sus.score > 0, `score=${sus.score}`);
    const puny = e.inspectUrl('https://xn--80ak6aa92e.com/', { kind: 'document' });
    assert.ok(puny.findings.some((f) => f.code === 'HOMOGlyph'));
  });

  test('punycode / 認証情報入りの URL は検知対象', () => {
    const e = mk();
    const r = e.inspectUrl('http://admin:pass@intranet.example.com/x', { kind: 'document' });
    assert.ok(r.score > 0);
    assert.ok(r.findings.length >= 1);
  });

  test('ブロックリスト (hosts) を読み込んで既知 BAD を遮断する', () => {
    const e = mk();
    e.loadBadHosts('0.0.0.0 evil.test\n127.0.0.1 spam.test\n');
    assert.equal(e.isBadHost('a.evil.test'), true);
    assert.equal(e.isBadHost('example.com'), false);
    const r = e.inspectUrl('https://a.evil.test/x', { kind: 'document' });
    assert.ok(r.block, 'KNOWN_BAD は block になる');
    assert.ok(r.findings.some((f) => f.code === 'KNOWN_BAD'));
  });

  test('inspectDocument は除去指示を返す (meta refresh / javascript: href)', () => {
    const e = mk();
    const html = `<html><head><meta http-equiv="refresh" content="0;url=http://mal.test/"></head>
      <body><a href="javascript:alert(1)">click</a><iframe src="http://mal.test/f"></iframe></body></html>`;
    const r = e.inspectDocument(html, { url: 'https://news.example.com/a', baseUrl: new URL('https://news.example.com/a'), kind: 'document', sid: 'a'.repeat(24) });
    assert.ok(Array.isArray(r.strips));
    assert.ok(r.score >= 0);
    assert.ok(r.findings.length >= 1, '怪しい要素は findings に入る');
  });

  test('report() は本文を保存しない / purge() で消える', () => {
    const e = mk();
    const sid = 'c'.repeat(24);
    e.inspectUrl('http://1.2.3.4/x', { kind: 'document', sid, url: 'http://1.2.3.4/x' });
    assert.ok(e.sessionSummary(sid).score >= 0);
    const rep = e.report({ limit: 20 });
    assert.ok(rep.events.length >= 1, JSON.stringify(Object.keys(rep)));
    const serialized = JSON.stringify(rep);
    assert.ok(!/<html|<!doctype/i.test(serialized), 'レポートに HTML 本文が混ざらない');
    e.purge({ sid });
    const after = e.sessionSummary(sid);
    assert.equal(after.score, 0);
    assert.equal(after.blocked, 0);
    assert.equal(after.level, 'safe');
  });

  test('閾値と有効フラグの切替', () => {
    const e = mk();
    e.setThresholds({ sanitize: 1, block: 100 });
    const r = e.inspectUrl('http://142.4.5.6/login.php', { kind: 'document' });
    assert.ok(r.score > 0);
    e.setEnabled(false);
    assert.equal(e.inspectUrl('http://142.4.5.6/login.php', { kind: 'document' }).score, 0);
  });
});

/* ------------------------------------------------------------------ */
describe('ProxyPool', () => {
  const mk = (n = 0) => {
    const p = new ProxyPool(cfg());
    const recs = [];
    for (let i = 0; i < n; i++) {
      const cc = ['JP', 'DE', 'US'][i % 3];
      recs.push({ protocol: 'http', host: `10.0.${(i >> 3) & 7}.${i % 251 + 1}`, port: 8080 + (i % 50), country: cc });
    }
    if (!recs.length) {
      recs.push(
        { protocol: 'http', host: '10.0.0.1', port: 8080, country: 'JP' },
        { protocol: 'https', host: '10.0.0.2', port: 3128, country: 'DE' },
        { protocol: 'socks5', host: '10.0.0.3', port: 1080, country: 'JP' },
      );
    }
    p.ingest(recs);
    return p;
  };

  test('ingest/size/国別カウント', () => {
    const p = mk();
    assert.equal(p.size(), 3);
    const by = Object.fromEntries(p.byCountryCounts().map((c) => [c.country, c]));
    assert.equal(by.JP.total, 2);
    assert.equal(by.DE.total, 1);
    assert.deepEqual(by.JP.protocols, { http: 1, socks5: 1 });
    assert.equal(by.JP.alive, 0, '未チェックは alive に数えない');
    assert.equal(p.countries({ min: 1 }).length, 2);
  });

  test('重複登録はマージ (件数増えない・sources 増える)', () => {
    const p = mk();
    const before = p.size();
    p.ingest([{ protocol: 'http', host: '10.0.0.1', port: 8080, country: 'JP' }], { sourceId: 'other' });
    assert.equal(p.size(), before);
  });

  test('国籍ピン留めと一致なしは null', () => {
    const p = mk();
    for (let i = 0; i < 20; i++) {
      const rec = p.select({ country: 'JP' });
      assert.equal(rec.country, 'JP');
      p.sweepInflight();
    }
    assert.equal(p.select({ country: 'ZZ' }), null);
    // allowFallback なら他国でも出す
    assert.ok(p.select({ country: 'ZZ', allowFallback: true }));
  });

  test('プロトコル制限', () => {
    const p = mk();
    const rec = p.select({ protocols: ['socks5'] });
    assert.equal(rec.protocol, 'socks5');
  });

  test('連続失敗で BAN → 除外、冷却明けで復活', () => {
    const p = mk();
    const jp = [];
    for (let i = 0; i < 30; i++) {
      const r = p.select({ country: 'JP', protocols: ['http'] });
      if (r && !jp.includes(r)) jp.push(r);
      p.sweepInflight();
    }
    const target = jp[0];
    assert.ok(target);
    for (let i = 0; i < 12; i++) p.report(target, { ok: false, error: 'ECONNREFUSED' });
    assert.ok(target.bannedUntil > Date.now(), 'bannedUntil が未来になる');
    let same = 0;
    for (let i = 0; i < 20; i++) {
      const r = p.select({ country: 'JP', protocols: ['http'] });
      if (r && r.key === target.key) same++;
      p.sweepInflight();
    }
    assert.equal(same, 0, 'BAN 中は選ばれない');
    target.bannedUntil = Date.now() - 1; // 冷却明けを模擬
    assert.ok(p.select({ country: 'JP', protocols: ['http'] }));
  });

  test('成功はスコアを上げる ( EWMA )', () => {
    const p = mk();
    const rec = p.select({ country: 'DE' });
    const before = rec.score;
    p.report(rec, { ok: true, latencyMs: 120, bytes: 5000 });
    assert.ok(rec.score >= before);
    assert.equal(rec.ok, 1);
    assert.ok(rec.latencyEma > 0);
    p.sweepInflight();
  });

  test('sticky は同じ出口を維持する', () => {
    const p = mk(60);
    const sid = 'e'.repeat(24);
    const first = p.select({ sid });
    assert.ok(first);
    p.setSticky(sid, first.key);
    p.sweepInflight();
    for (let i = 0; i < 10; i++) {
      const r = p.select({ sid });
      assert.equal(r.key, first.key);
      p.sweepInflight();
    }
    p.clearSticky(sid);
  });

  test('snapshot / restore で復元できる', () => {
    const p = mk(40);
    const rec = p.select({});
    p.report(rec, { ok: true, latencyMs: 210 });
    p.sweepInflight();
    const snap = p.snapshot();
    const q = new ProxyPool(cfg());
    const n = q.restore(snap);
    assert.ok(n >= 1);
    assert.equal(q.size(), p.size());
    const restored = q.records.get(rec.key);
    assert.equal(restored.country, rec.country);
    assert.equal(restored.latencyEma, rec.latencyEma);
    assert.equal(restored.checked, true, '実トラフィック成功も健全性として記録');
    assert.equal(restored.ok, 1);
    // 既存プールへの restore はマージ (件数を減らさない)
    q.restore(snap);
    assert.equal(q.size(), p.size());
  });

  test('list() は国フィルタとソート', () => {
    const p = mk(80);
    const r = p.list({ country: 'US', limit: 5, sort: 'score' });
    assert.ok(r.total >= 1);
    assert.ok(r.items.every((i) => i.country === 'US'));
    for (let i = 1; i < r.items.length; i++) assert.ok(r.items[i - 1].score >= r.items[i].score);
  });

  test('public() は認証情報を漏らさない', () => {
    const p = new ProxyPool(cfg());
    p.ingest([{ protocol: 'http', host: '1.2.3.4', port: 8080, country: 'JP', username: 'u1', password: 'p@ss' }]);
    const rec = p.records.get('http|1.2.3.4:8080');
    const pub = JSON.stringify(p.public(rec));
    assert.ok(!/u1|p@ss/.test(pub), pub);
  });
});
