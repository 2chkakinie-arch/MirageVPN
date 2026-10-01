/**
 * AI Mode 連携のテスト
 * ---------------------------------------------------------------
 *  - 抽出器: 実 DOM フィクスチャ (test/fixtures/aimode/) に対するリグレッション
 *  - quota: 予算/クールダウン
 *  - client: パイプライン/relay/SerpApi をスタブしてプロバイダ抽象を検証
 *  - routes: OpenAI 互換エンドポイントの形状
 * 外部ネットワークは使わない。
 * @module test/aimode.test.js
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { extractAiMode, unwrapGoogleUrl, parseLinkLabel, DEFAULT_OPTIONS } from '../server/aimode/extract.js';
import { AiModeQuota } from '../server/aimode/quota.js';
import { AiModeClient, normalizeProviderResult } from '../server/aimode/client.js';
import { createAiModeRouter } from '../server/routes/aimode.js';
import { loadConfig } from '../server/config.js';
import { createApp } from '../server/app.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = path.join(__dirname, 'fixtures', 'aimode');
const read = (f) => readFile(path.join(FIX, f), 'utf8');

/* ------------------------------------------------------------------ */
/* 抽出器                                                               */
/* ------------------------------------------------------------------ */

describe('AI Mode 抽出: 合成 HTML', () => {
  test('本文・見出し・リスト・テーブル・引用を取る', async () => {
    const r = extractAiMode(await read('synthetic_ai_mode.html'));
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.match(r.answer, /En iyi CRM yazilimlari/);
    assert.match(r.answer, /^## /m); // 見出し
    assert.match(r.answer, /^- /m); // リスト
    assert.match(r.answer, /\*\*HubSpot\*\*/); // strong → markdown
    assert.match(r.answer, /_Pipedrive_/); // em
    assert.match(r.answer, /`Zoho CRM`/); // code
    assert.match(r.answer, /Urun \| Baslangic fiyati/); // テーブル行
    assert.equal(r.citations.length, 4);
    assert.equal(r.citations[0].domain, 'ornek.org');
    assert.equal(r.citations[2].domain, 'ornek-otomasyon.com');
    // Google 自身 (maps) は引用に数えない
    assert.ok(!r.citations.some((c) => (c.domain || '').includes('google')));
  });

  test('Chrome (aria-hidden / button / role=button) を混ぜない', async () => {
    const r = extractAiMode(await read('synthetic_ai_mode.html'));
    for (const bad of ['BU METIN CIKTIDA OLMAMALI', 'Geri bildirim gonder', 'Bu cevabi paylas']) {
      assert.ok(!r.answer.includes(bad), `Chrome が混入: ${bad}`);
    }
  });

  test('aria-label の後置語 (新規タブで開く/関連結果) を落とす', async () => {
    const r = extractAiMode(await read('synthetic_ai_mode.html'));
    const web = r.citations.find((c) => c.domain === 'ornek-otomasyon.com');
    assert.equal(web.title, 'Web sitesi');
  });

  test('追加質問チップは回答に混ぜず followUps に分ける', async () => {
    const r = extractAiMode(await read('synthetic_followups.html'));
    assert.equal(r.ok, true);
    assert.match(r.answer, /Paris is the capital/);
    assert.ok(!/population of Paris/.test(r.answer), 'チップが回答に混入');
    assert.deepEqual(r.followUps, ['What is the population of Paris?', 'How far is Paris from London?']);
    assert.equal(r.confidence, 0.9);
  });
});

describe('AI Mode 抽出: 実 DOM フィクスチャ', () => {
  test('完全ページ: 回答 + 引用 + 出典カード (日付入り)', async () => {
    const r = extractAiMode(await read('real_ai_mode_tr.html'));
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.ok(r.text.length > 1500, `回答が短すぎる: ${r.text.length}`);
    assert.match(r.answer, /Salesforce/);
    assert.match(r.answer, /Bitrix24/);
    // Chrome が入っていないこと
    for (const bad of ['Kopyala', 'Paylaş', 'İyi yanıt', 'Kötü yanıt', 'Tasarruf edilen zaman']) {
      assert.ok(!r.answer.includes(bad), `Chrome が混入: ${bad}`);
    }
    // 引用: 外部ドメインのみ、Google 自身は除く
    assert.ok(r.citations.length >= 5);
    for (const c of r.citations) {
      assert.ok(c.domain && !c.domain.endsWith('google.com'), `Google ホストが引用になった: ${c.domain}`);
      assert.ok(c.title.length > 0);
    }
    // 出典カード: 日付が取れている
    assert.ok(r.sources.length >= 4);
    const dated = r.sources.filter((s) => s.date);
    assert.ok(dated.length >= 2, `日付が取れていない: ${JSON.stringify(r.sources[0])}`);
    assert.ok(r.sources.some((s) => s.snippet && s.snippet.length > 20));
    assert.ok(r.stats.chars > 1000);
  });

  test('出典カードは回答本文に混ぜない', async () => {
    const r = extractAiMode(await read('real_ai_mode_tr_sources.html'));
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.match(r.answer, /Bursa/);
    assert.ok(!/Bursa Yapay Zeka ve AI Otomasyon Sistemleri \| KA Bili/.test(r.answer), '出典カードが回答に混入');
    assert.ok(r.sources.length >= 3);
    // 回答は「専門分野があれば案内する」で終わる
    assert.match(r.answer, /y[oö]nlendirebilirim/);
  });

  test('/goto?url= の署名ブロブは wrapped として報告する', async () => {
    const r = extractAiMode(await read('real_ai_mode_goto_links.html'));
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.ok(r.citations.length >= 3);
    assert.ok(r.citations.every((c) => c.wrapped === true), 'wrapped ではない citation がある');
    assert.ok(r.citations.some((c) => /CRM/i.test(c.title || '')), 'タイトルが取れていない');
    assert.equal(r.stats.wrappedCitations, r.citations.length);
  });

  test('aria-label を {title, site} に割る', () => {
    const a = parseLinkLabel('Kaitek Yazılım (+1) - Hakkımızda | Kaitek Yazılım. İlgili sonuçlar');
    assert.equal(a.title, 'Hakkımızda');
    assert.equal(a.site, 'Kaitek Yazılım');
    const b = parseLinkLabel('Makrops - Bursa Yapay Zeka Çözümleri - Makrops. İlgili sonuçlar');
    assert.equal(b.title, 'Bursa Yapay Zeka Çözümleri - Makrops');
    assert.equal(b.site, 'Makrops');
    const c = parseLinkLabel('VERODIKA. Yeni sekmede açılır');
    assert.equal(c.title, 'VERODIKA');
    const d = parseLinkLabel('VERODIKA. Yeni sekmede acilir'); // ASCII 折りたたみ
    assert.equal(d.title, 'VERODIKA');
  });

  test('CAPTCHA / 回答なし / 同意ページを reason で区別する', async () => {
    const captcha = extractAiMode('<html><body><div class="g-recaptcha"></div>Our systems have detected unusual traffic</body></html>');
    assert.equal(captcha.ok, false);
    assert.equal(captcha.reason, 'captcha');

    const plain = extractAiMode('<html><head><title>x</title></head><body><div id="search">結果だけ</div></body></html>');
    assert.equal(plain.ok, false);
    assert.equal(plain.reason, 'no_answer');

    const consent = extractAiMode('<html><body><form action="https://consent.google.com/save">Yes I agree</form></body></html>');
    assert.equal(consent.ok, false);
    assert.equal(consent.reason, 'consent_required');
  });

  test('unwrapGoogleUrl: /url?q= は剥がし /goto?url= は wrapped', () => {
    assert.equal(unwrapGoogleUrl('/url?q=https%3A%2F%2Fexample.com%2Fa%3Fx%3D1'), 'https://example.com/a?x=1');
    assert.equal(unwrapGoogleUrl('https://example.com/direct'), 'https://example.com/direct');
    assert.equal(unwrapGoogleUrl('/search?q=test'), null);
    assert.equal(unwrapGoogleUrl('#'), null);
    const wrapped = unwrapGoogleUrl('/goto?url=CAESTestBlob');
    assert.deepEqual(wrapped, { wrapped: '/goto?url=CAESTestBlob' });
  });

  test('セレクタ/マーカーは環境変数で上書きできる', async () => {
    const html = await read('synthetic_ai_mode.html');
    const broken = extractAiMode(html, { containers: ['div[data-subtree="nope"]'] });
    assert.equal(broken.ok, false);
    const forced = extractAiMode(html, { disclaimerRe: /存在しない注意文/ });
    assert.equal(forced.ok, true);
    assert.equal(DEFAULT_OPTIONS.containers[0], 'div[data-subtree="aimc"]');
  });
});

describe('AI Mode quota', () => {
  test('時間上限と最小間隔で止める', () => {
    const q = new AiModeQuota({ perHour: 2, perDay: 0, minIntervalMs: 1000, cooldownMs: 5000 });
    const t = 1_000_000;
    assert.equal(q.check(t).ok, true);
    q.note(t);
    assert.equal(q.check(t + 100).ok, false); // min interval
    assert.equal(q.check(t + 100).reason, 'min_interval');
    assert.equal(q.check(t + 2000).ok, true);
    q.note(t + 2000);
    const gate = q.check(t + 3000);
    assert.equal(gate.ok, false);
    assert.equal(gate.reason, 'per_hour');
    assert.ok(gate.retryAfterMs > 0);
  });

  test('CAPTCHA を踏むとクールダウンが階段的に延びる', () => {
    const q = new AiModeQuota({ perHour: 100, perDay: 0, minIntervalMs: 0, cooldownMs: 1000 });
    const t = 5_000_000;
    const first = q.noteBlocked(t);
    const second = q.noteBlocked(t + 10);
    assert.equal(first, 1000);
    assert.equal(second, 2000);
    assert.equal(q.check(t + 100).reason, 'cooldown');
    assert.equal(q.check(t + 5000).ok, true);
    q.noteSuccess();
    const third = q.noteBlocked(t + 6000);
    assert.equal(third, 2000); // 1 段戻った
  });
});

/* ------------------------------------------------------------------ */
/* client (スタブ)                                                      */
/* ------------------------------------------------------------------ */

function fakeEngine(html, { status = 200, finalUrl = 'https://www.google.com/search?q=x&udm=50' } = {}) {
  const calls = [];
  return {
    calls,
    pipeline: {
      async execute(req) {
        calls.push(req);
        return {
          status,
          headers: new Map([['x-mirage-final-url', encodeURIComponent(finalUrl)]]),
          body: Buffer.from(html),
          info: { egressLabel: 'pool:US:8080', egressCountry: 'US', egressProxy: '1.2.3.4:8080', upstreamMs: 120 },
        };
      },
    },
    store: { settingsFor: () => ({}) },
  };
}

function makeClient(engine, overrides = {}) {
  const config = loadConfig({
    MIRAGE_AIMODE: '1',
    MIRAGE_AIMODE_PER_HOUR: '100',
    MIRAGE_AIMODE_MIN_INTERVAL: '0',
    ...overrides,
  });
  const client = new AiModeClient({ config, engine });
  return { client, config };
}

describe('AI Mode client', () => {
  test('serp プロバイダ: udm=50 を raw で取り、正規化して返す', async () => {
    const html = await read('real_ai_mode_tr.html');
    const engine = fakeEngine(html);
    const { client } = makeClient(engine);
    const out = await client.ask({ q: 'en iyi CRM', sid: 's1' });
    assert.equal(out.ok, true, JSON.stringify(out));
    assert.equal(out.meta.provider, 'serp');
    assert.equal(out.meta.egressCountry, 'US');
    assert.match(out.answer, /Salesforce/);
    assert.ok(out.citations.length >= 5);
    // パイプラインには raw: true で渡っている (改写してほしくない)
    assert.equal(engine.calls[0].raw, true);
    assert.match(engine.calls[0].url, /udm=50/);
    assert.equal(engine.calls[0].settings.egress.country, 'US');
    assert.equal(engine.calls[0].settings.egress.strategy, 'pool');
  });

  test('キャッシュ: 同じ問い合わせはパイプラインを叩かない', async () => {
    const html = await read('real_ai_mode_tr.html');
    const engine = fakeEngine(html);
    const { client } = makeClient(engine);
    const a = await client.ask({ q: 'cache test' });
    const b = await client.ask({ q: 'cache test' });
    assert.equal(engine.calls.length, 1);
    assert.equal(a.meta.cache, false);
    assert.equal(b.meta.cache, true);
    assert.equal(client.clearCache(), 1);
  });

  test('CAPTCHA: cooldown に入り、次の問い合わせは quota で止まる', async () => {
    const engine = fakeEngine('<html>Our systems have detected unusual traffic from your computer</html>');
    const { client } = makeClient(engine, { MIRAGE_AIMODE_COOLDOWN: '60000' });
    const a = await client.ask({ q: 'blocked query' });
    assert.equal(a.ok, false);
    assert.equal(a.reason, 'captcha');
    assert.ok(a.cooldownMs >= 60000);
    const b = await client.ask({ q: 'another query' });
    assert.equal(b.ok, false);
    assert.equal(b.reason, 'quota:cooldown');
    assert.ok(b.retryAfterMs > 0);
  });

  test('quota 超過時は上流を叩かない', async () => {
    const engine = fakeEngine('<html></html>');
    const { client } = makeClient(engine, { MIRAGE_AIMODE_PER_HOUR: '1' });
    await client.ask({ q: 'first' });
    const second = await client.ask({ q: 'second' });
    assert.equal(second.reason, 'quota:per_hour');
    assert.equal(engine.calls.length, 1);
  });

  test('wrapped 引用を /goto リダイレクトで解く', async () => {
    const html = await read('real_ai_mode_goto_links.html');
    const engine = fakeEngine(html, { finalUrl: 'https://www.example.com/article/1' });
    const { client } = makeClient(engine);
    const out = await client.ask({ q: 'goto test', resolveCitations: true });
    assert.equal(out.ok, true, JSON.stringify(out));
    const resolved = out.citations.filter((c) => !c.wrapped);
    assert.ok(resolved.length >= 1, ' wrapped が解決できていない');
    assert.equal(resolved[0].domain, 'example.com');
    // 解決リクエストは /goto を叩いている
    assert.ok(engine.calls.some((c) => c.url.includes('/goto?url=')));
  });

  test('relay プロバイダ: 外部リレーの JSON を正規化する', async () => {
    const engine = fakeEngine('');
    const { client } = makeClient(engine, {
      MIRAGE_AIMODE_PROVIDER: 'relay',
      MIRAGE_AIMODE_RELAY_URL: 'http://relay.test/',
      MIRAGE_AIMODE_RELAY_KEY: 'k',
    });
    const realFetch = globalThis.fetch;
    globalThis.fetch = async (url, init) => {
      assert.match(String(url), /^http:\/\/relay\.test\/v1\/query$/);
      assert.equal(init.headers.authorization, 'Bearer k');
      return {
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            ok: true,
            answer: '## 回答\n\nテスト回答',
            citations: [{ url: 'https://a.example/x', title: 'A' }],
            follow_ups: ['それってどういう意味?'],
            confidence: 0.8,
          }),
      };
    };
    try {
      const out = await client.ask({ q: 'relay query' });
      assert.equal(out.ok, true, JSON.stringify(out));
      assert.equal(out.meta.provider, 'relay');
      assert.match(out.answer, /テスト回答/);
      assert.equal(out.citations[0].domain, 'a.example');
      assert.deepEqual(out.followUps, ['それってどういう意味?']);
    } finally {
      globalThis.fetch = realFetch;
    }
  });

  test('relay は /v1/query が無ければ OpenAI 互応にフォールバックする', async () => {
    const engine = fakeEngine('');
    const { client } = makeClient(engine, {
      MIRAGE_AIMODE_PROVIDER: 'relay',
      MIRAGE_AIMODE_RELAY_URL: 'http://relay.test/',
    });
    const seen = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = async (url) => {
      seen.push(String(url));
      if (String(url).endsWith('/v1/query')) return { ok: false, status: 404, text: async () => '{"detail":"Not Found"}' };
      return {
        ok: true,
        status: 200,
        json: async () => ({ choices: [{ message: { role: 'assistant', content: 'OpenAI 互換の回答' } }] }),
      };
    };
    try {
      const out = await client.ask({ q: 'fallback query' });
      assert.equal(out.ok, true, JSON.stringify(out));
      assert.equal(out.answer, 'OpenAI 互応の回答'.replace('互応', '互換'));
      assert.deepEqual(out.citations, []);
      assert.ok(out.warnings.some((w) => /OpenAI 互換/.test(w)));
      assert.deepEqual(seen, ['http://relay.test/v1/query', 'http://relay.test/v1/chat/completions']);
    } finally {
      globalThis.fetch = realFetch;
    }
  });

  test('serpapi プロバイダ: text_blocks / references を正規化する', () => {
    const r = normalizeProviderResult(
      {
        text_blocks: [
          { type: 'paragraph', text: '最初の段落' },
          { type: 'heading', text: '見出し' },
          { type: 'list', snippet: '箇条条' },
        ],
        references: [{ title: 'Example', link: 'https://example.com/1' }],
        related_questions: [{ question: '関連質問?' }],
      },
      'serpapi',
    );
    assert.equal(r.ok, true);
    assert.match(r.answer, /^最初の段落/);
    assert.match(r.answer, /^## 見出し$/m);
    assert.match(r.answer, /^- 箇条条$/m);
    assert.equal(r.citations[0].url, 'https://example.com/1');
    assert.deepEqual(r.followUps, ['関連質問?']);
  });

  test('プロバイダが answer を返さなければ no_answer', () => {
    const r = normalizeProviderResult({ ok: true }, 'relay');
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'no_answer');
  });

  test('無効なら disabled', async () => {
    const config = loadConfig({});
    const client = new AiModeClient({ config, engine: fakeEngine('') });
    assert.equal(client.enabled, false);
    const out = await client.ask({ q: 'x' });
    assert.equal(out.ok, false);
    assert.equal(out.reason, 'disabled');
  });
});

/* ------------------------------------------------------------------ */
/* routes (OpenAI 互換)                                                 */
/* ------------------------------------------------------------------ */

async function withServer(fn) {
  const config = loadConfig({ MIRAGE_AIMODE: '1', MIRAGE_AIMODE_MODEL_ID: 'google-ai-mode' });
  const engine = fakeEngine(await read('real_ai_mode_tr.html'));
  const client = new AiModeClient({ config, engine });
  client.engine = engine;
  const ctx = { config, engine: { ...engine, aimode: client }, limiter: null };
  const app = express();
  app.use(createAiModeRouter(ctx));
  const server = http.createServer(app);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    await fn(base, client);
  } finally {
    await new Promise((r) => server.close(r));
  }
}

describe('AI Mode routes', () => {
  test('GET /query?q= が正規化 JSON を返す', async () => {
    await withServer(async (base) => {
      const res = await fetch(`${base}/mirage/api/aimode/query?q=${encodeURIComponent('CRM yazilimlari')}`);
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.ok, true);
      assert.match(json.answer, /Salesforce/);
      assert.ok(Array.isArray(json.citations));
      assert.ok(json.meta.provider === 'serp');
    });
  });

  test('q が無ければ 400', async () => {
    await withServer(async (base) => {
      const res = await fetch(`${base}/mirage/api/aimode/query`);
      assert.equal(res.status, 400);
    });
  });

  test('OpenAI 互換: /v1/models と /v1/chat/completions', async () => {
    await withServer(async (base) => {
      const models = await fetch(`${base}/mirage/v1/models`);
      assert.equal(models.status, 200);
      const mj = await models.json();
      assert.equal(mj.data[0].id, 'google-ai-mode');

      const res = await fetch(`${base}/mirage/v1/chat/completions`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          model: 'google-ai-mode',
          messages: [
            { role: 'system', content: '日本語で答えて' },
            { role: 'user', content: 'CRM yazilimlari' },
          ],
        }),
      });
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.object, 'chat.completion');
      assert.equal(json.choices[0].message.role, 'assistant');
      assert.match(json.choices[0].message.content, /Salesforce/);
      assert.equal(json.choices[0].finish_reason, 'stop');
      assert.ok(json.usage.total_tokens > 0);
      assert.ok(Array.isArray(json.mirage.citations));
    });
  });

  test('OpenAI 互換: stream=true は SSE を返す', async () => {
    await withServer(async (base) => {
      const res = await fetch(`${base}/mirage/v1/chat/completions`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ model: 'google-ai-mode', stream: true, messages: [{ role: 'user', content: 'CRM' }] }),
      });
      assert.equal(res.status, 200);
      assert.match(res.headers.get('content-type'), /text\/event-stream/);
      const text = await res.text();
      assert.match(text, /^data: \{/m);
      assert.match(text, /"role":"assistant"/);
      assert.match(text, /data: \[DONE\]/);
    });
  });

  test('token を設定すると 401', async () => {
    const config = loadConfig({ MIRAGE_AIMODE: '1', MIRAGE_AIMODE_TOKEN: 'sekret' });
    const engine = fakeEngine(await read('real_ai_mode_tr.html'));
    const client = new AiModeClient({ config, engine });
    client.engine = engine;
    const app = express();
    app.use(createAiModeRouter({ config, engine: { ...engine, aimode: client } }));
    const server = http.createServer(app);
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const base = `http://127.0.0.1:${server.address().port}`;
    try {
      const no = await fetch(`${base}/mirage/api/aimode/status`);
      assert.equal(no.status, 200); // status は認証なし
      const bad = await fetch(`${base}/mirage/api/aimode/query?q=x`);
      assert.equal(bad.status, 401);
      const good = await fetch(`${base}/mirage/api/aimode/query?q=x&key=sekret`);
      assert.equal(good.status, 200);
    } finally {
      await new Promise((r) => server.close(r));
    }
  });
});

/* ------------------------------------------------------------------ */
/* E2E: 本物のパイプライン + ローカル origin を通す                      */
/* ------------------------------------------------------------------ */

describe('AI Mode E2E (実パイプライン + ローカル origin)', () => {
  test('app を MIRAGE_AIMODE=1 で起動し、実フィクスチャを origin から取る', async () => {
    const fixture = await read('real_ai_mode_tr.html');
    let hits = 0;
    const origin = http.createServer((req, res) => {
      hits++;
      assert.match(req.url, /udm=50/);
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      res.end(fixture);
    });
    await new Promise((r) => origin.listen(0, '127.0.0.1', r));
    const originPort = origin.address().port;

    const config = loadConfig({
      ...process.env,
      NODE_ENV: 'test',
      PORT: '0',
      MIRAGE_AIMODE: '1',
      MIRAGE_AIMODE_BASE_URL: `http://127.0.0.1:${originPort}`,
      MIRAGE_AIMODE_COUNTRY: 'US',
      MIRAGE_AIMODE_EGRESS_STRATEGY: 'direct', // ローカル origin へ直接
      MIRAGE_AIMODE_MIN_INTERVAL: '0',
      MIRAGE_EGRESS: 'direct',
      MIRAGE_LIST_AUTO_REFRESH: '0',
      MIRAGE_USE_SEED: '0',
      MIRAGE_BLOCK_PRIVATE_TARGETS: '0',
      MIRAGE_LOG_LEVEL: 'error',
      MIRAGE_STATE_DIR: '',
      MIRAGE_SECRET: 'aimode-e2e',
    });
    const { app, ctx } = await createApp({ config, boot: false });
    const server = http.createServer(app);
    ctx.attach(server);
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const base = `http://127.0.0.1:${server.address().port}`;
    try {
      const res = await fetch(`${base}/mirage/api/aimode/query?q=${encodeURIComponent('en iyi CRM yazilimlari')}`);
      const json = await res.json();
      assert.equal(res.status, 200, JSON.stringify(json).slice(0, 300));
      assert.equal(json.ok, true, JSON.stringify(json));
      assert.match(json.answer, /Salesforce/);
      assert.ok(json.citations.length >= 5);
      assert.ok(json.sources.length >= 4);
      assert.equal(json.meta.provider, 'serp');
      assert.equal(hits, 1);
      // 2 回目はキャッシュ (origin を叩かない)
      const again = await fetch(`${base}/mirage/api/aimode/query?q=${encodeURIComponent('en iyi CRM yazilimlari')}`);
      assert.equal((await again.json()).meta.cache, true);
      assert.equal(hits, 1);
      // ステータス
      const st = await (await fetch(`${base}/mirage/api/aimode/status`)).json();
      assert.equal(st.enabled, true);
      assert.equal(st.counters.ok, 1);
      assert.equal(st.counters.cacheHit, 1);
    } finally {
      await new Promise((r) => server.close(r));
      await new Promise((r) => origin.close(r));
      ctx?.close?.();
    }
  });
});
