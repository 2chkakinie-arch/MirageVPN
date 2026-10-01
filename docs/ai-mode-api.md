# Google AI Mode を「うちの API」として使う方法

**結論から言うと、Google AI Mode に公式 API は存在しない。**
だから (a) 公式の代替で満たせるかを見極め、(b) 足りなければ「自前で API 化するか
金で解決するか」を選ぶ。この repo (MirageVPN) は「出口を国籍で選んで IP をごまかす」
パイプラインを既に持っているので、**自前 API 化の一番つらい部分 (geo・出口・レート) が
そのまま乗る**。というわけで、この repo に `serp` プロバイダとして実装した。

```
POST /mirage/api/aimode/query?q=...      → {answer, citations[], sources[], followUps[]}
POST /mirage/v1/chat/completions         → OpenAI 互換 (Open WebUI / LangChain からそのまま叩ける)
```

---

## 1. AI Mode とは何で、なぜ API がないか

- Google 検索の「AI モード」タブ。`?udm=50` で呼べる。中身は **Gemini のカスタム版 +
  検索ランキング + ナレッジグラフ** の組合せ (query fan-out で分割検索して合成)。
- 個人コンテキスト・音声・画像・フォローアップ対話があり、「SERP のブロック」ではなく
  **独立した会話サーフェス**。
- Google はこれを **コンシューマ検索体験**として出しており、開発者向けの API は
 公開していない。`generativelanguage.googleapis.com` (Gemini API) とは別物。

## 2. 選択肢の比較

| # | 手段 | 費用 | 安定性 | AI Mode そのもの? | 向く人 |
|---|---|---|---|---|---|
| A | **Gemini API + Google Search グラウンディング** | 無料枠〜従量 | ◎ (公式) | △ (モデルは同じ系統だが検索連携・パーソナライズなし) | とにかく壊れたくない人 |
| B | **有料 SERP API** (SerpApi / DataForSEO / HasData / ScrapingDog / Bright Data / Oxylabs) | $0.001〜/クエリ、初期デポジット | ◎ | ◎ | 本番サービス・GEO 計測 |
| C | **自前 + ブラウザ自動化** (Playwright + `udm=50`) | インフラ代のみ | △ (DOM 変更で壊れる) | ◎ | 完全自前でやりたい人 |
| D | **自前 + 素の HTTP** (`udm=50` の HTML を解析) | インフラ代のみ | △ (DOM 変更で壊れる) | ○ | 少数・低速でいい人 |

参考にした公開計測 ([TurkerYakup/google-ai-mode-api](https://github.com/TurkerYakup/google-ai-mode-api)):
**約 40 クエリ/時/IP でブロック、回復に数時間**。レート制限というより
「IP あたりの累積予算」で、間隔を空けても閾値は下がらない。
→ **自前で API 化するなら、quota と出口ローテーションは必須**。

## 3. なぜこの repo に実装するのが得か

MirageVPN は既にこれを持っている:

| 必要なもの | 既にあるもの |
|---|---|
| US など**特定国の出口** | プロキシプール + 国籍ピン + `X-Forwarded-For` 偽装 (`#pickEgress`) |
| **出口の自動ローテーション** | per-request sticky、失敗時リトライ、BAN/cooldown |
| **UA / Accept-Language の現地化** | `MIRAGE_LOCALIZE_HEADERS` |
| **HTTP クライアント** (keep-alive, 解凍, リダイレクト) | `server/net/http1.js` |
| **レート制限** | `routes/ratelimit.js` |
| **Cookie ジャー** (同意ページ回避) | `server/proxy/cookies.js` |

自前スクレイパが抱える「出口が尽きる」「CAPTCHA を踏む」「同意ページが出る」は
全部この repo の守備範囲。**AI Mode 用に足したのは「抽出器」と「quota」だけ**。

## 4. 実装

### 4.1 構成

```
server/aimode/extract.js   HTML → {answer(markdown), citations, sources, followUps}  (依存ゼロ)
server/aimode/client.js    プロバイダ抽象 (serp / relay / serpapi) + quota + キャッシュ
server/aimode/quota.js     予算 (perHour/perDay/最小間隔/CAPTCHA クールダウン)
server/routes/aimode.js    /mirage/api/aimode/* と OpenAI 互換 /mirage/v1/*
server/proxy/pipeline.js   req.raw: true で「改写せず生 HTML」を返すモードを追加
```

### 4.2 パイプラインに `raw` を足した (1 行の思想)

プロキシは HTML を書き換えるが、AI Mode の抽出には**上流の生 HTML**が要る。
そこで `execute({ raw: true })` を追加。SSRF ガード・シールド・出口選択・計装は
そのまま効かせて、**改写とドキュメント脅威スキャンだけを飛ばす**。

### 4.3 抽出器 (`extract.js`)

依存を express と ws だけに保つ方針なので、DOM ライブラリを使わず
「タグスキャナ + 軽量ツリー + ウォーカ」を自前実装。やること:

1. **コンテナ探索** — `div[data-subtree="aimc"]` ほか (候補は設定で差し替え可)
2. **Chrome 落とし** — `script/style/svg/button/textarea/form/iframe`、
   `[role=dialog]` `[popover]` `[aria-live]` `[role=alert]` `[aria-hidden]`
   `display:none` を子孫ごと除外
3. **ブロック化** — 段落/見出し/リスト/テーブル行に切り、`strong/em/code/a` は
   markdown 化 (`**bold**`, `_em_`, `` `code` ``, `[text](url)`)
4. **回答の終点** — 優先順は
   ① 「AI は間違えることがある」注意書き (主要ロケールの正規表現)
   ② 出典トグル (`aria-label="9 site"`)
   ③ フォールバック: Chrome 語を含む短文が 4 個連続した位置
5. **引用** — 外部ホストの `<a>` を出現順に収集。`/url?q=` は剥がす、
   `/goto?url=<署名ブロブ>` は `wrapped: true` として報告 (後段で HTTP 解決)
6. **出典カード** — 出典トグルを含むサブツリーの `<li>` から
   `{title, date, source, snippet}` を復元。`aria-label` の
   `"<site> - <page title> | <site name>. İlgili sonuçlar"` 形式も解析
7. **フォローアップ** — 疑問形 (`?` 終わり) のチップだけ `followUps` へ

**壊れることを前提にしている**: 取れなければ `{ok:false, reason}` を返す
(`captcha` / `consent_required` / `no_answer` / `container_not_found` / `empty_answer`)。
推測で埋めない。取れた場合も `confidence` と `warnings` を必ず返す。

### 4.4 quota (`quota.js`)

Google の「累積予算」に対してこちら側も同じ性質の guard を掛ける:

- `perHour` / `perDay` の問い合わせ上限 (既定 30 / 200)
- `minIntervalMs` (既定 4 秒) — バースト防止
- CAPTCHA を踏んだら `cooldownMs` (既定 30 分)、連続するほど **指数関数的に延びる**
  (最大 8 段階・8 時間)
- 成功するたびに段階を 1 つ戻す

状態はインメモリ (再起動でリセット)。「昨日ブロックされた IP」を引きずらないため。

### 4.5 プロバイダ (差し替え可能)

| provider | 何をするか | 設定 |
|---|---|---|
| `serp` (既定) | 自前。`/search?q=...&udm=50` をパイプライン経由で取り、aimc を抽出 | `MIRAGE_AIMODE=1` |
| `relay` | 外部リレー (Playwright 常駐ブラウザ等) に `POST {relay}/v1/query` | `MIRAGE_AIMODE_PROVIDER=relay`, `MIRAGE_AIMODE_RELAY_URL` |
| `serpapi` | SerpApi `engine=google_ai_mode` (`text_blocks` / `references` を正規化) | `MIRAGE_AIMODE_PROVIDER=serpapi`, `MIRAGE_SERPAPI_KEY` |

`relay` は [TurkerYakup/google-ai-mode-api](https://github.com/TurkerYakup/google-ai-mode-api) の
Docker イメージをそのまま指せる。relay への問い合わせは 2 段構え:

1. `POST {RELAY_URL}/v1/query` (当方の thin contract — `answer` / `citations` /
   `sources` / `follow_ups` を返す。引用まで欲しい場合はこちら)
2. 404/405 なら `POST {RELAY_URL}/v1/chat/completions` (OpenAI 互換 — 引用は空になる)

**堅い方がよければ切り替えは 1 行** (エンドポイントと戻り値の形は同じ)。
Playwright を入れたくない/入れられない環境では `serpapi` に逃がせる。

## 5. 使い方

### 5.1 起動

```bash
MIRAGE_AIMODE=1 MIRAGE_AIMODE_COUNTRY=US MIRAGE_AIMODE_PER_HOUR=30 node server/index.js
```

- `MIRAGE_AIMODE_COUNTRY=US` … AI Mode は geo 制限があるので、**出口国は US/UK/IN 等に固定**。
- 自ホストが US にあるなら `MIRAGE_AIMODE_EGRESS_STRATEGY=direct` で proxy 不要・最速。

### 5.2 単発

```bash
curl -s 'http://localhost:8080/mirage/api/aimode/query?q=best%20CRM%20for%20small%20teams'
```

```json
{
  "ok": true,
  "answer": "## En iyi CRM yazilimlari\n\nKucuk ve orta olcekli ekipler icin ...",
  "citations": [{ "index": 1, "url": "https://ornek.org/crm-rehberi", "domain": "ornek.org", "title": "..." }],
  "sources":    [{ "url": "...", "title": "...", "date": "21 Oca 2026", "source": "www.bitrix24.com.tr", "snippet": "..." }],
  "followUps":  [],
  "confidence": 0.9,
  "meta": { "provider": "serp", "egressCountry": "US", "egress": "pool:US:8080", "ms": 842 }
}
```

### 5.3 OpenAI 互換 (Open WebUI / LangChain / Cursor)

```bash
curl -s http://localhost:8080/mirage/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"google-ai-mode","messages":[{"role":"user","content":"Bursadaki yapay zeka firmalari"}]}'
```

Open WebUI なら「設定 → 接続」に `http://<host>:8080/v1`、API キーに
`MIRAGE_AIMODE_TOKEN` を入れるだけ。モデル名は `google-ai-mode`
(`MIRAGE_AIMODE_MODEL_ID` で変更可)。`stream: true` も SSE で応える。

### 5.4 状態の確認

```bash
curl -s http://localhost:8080/mirage/api/aimode/status
# → {enabled, provider, country, quota:{usedLastHour, cooldownRemainingMs, blocks}, counters, lastError}
```

## 6. 壊れ方と対策

| 症状 | reason | 対策 |
|---|---|---|
| DOM が変わって取れない | `container_not_found` / `empty_answer` | `MIRAGE_AIMODE_CONTAINERS='["div[data-subtree=\"aimc\"]","..."]'` で上書き。`MIRAGE_AIMODE_DEBUG=1` + `/debug/html?q=` で生 HTML を見る |
| 注意書きの文言が変わった | `confidence` が下がる / Chrome が混入 | `MIRAGE_AIMODE_DISCLAIMER_RE` で上書き |
| CAPTCHA | `captcha` → 自動クールダウン | 出口を増やす、`perHour` を下げる、`relay`/`serpapi` に逃がす |
| 出口が枯れた | `upstream_502` / `upstream_503` | プールの更新を待つ / `MIRAGE_AIMODE_EGRESS_STRATEGY=auto` |
| 同意ページ | `consent_required` | `MIRAGE_AIMODE_CONSENT_COOKIE='SOCS=CAI...'` |
| そのクエリでは AI が出ない | `no_answer` | 正常系 (クエリを変える) |

## 7. 既知の限界 (正直に)

1. **多ターン会話は未対応** (`serp`)。AI Mode のフォローアップは内部の
   `batchexecute` RPC + 会話コンテキストトークンが必要で、rpcid が頻繁に変わる。
   1 問 1 レスポンス。「会話」として使う場合は `relay` / `serpapi`
   (SerpApi は `subsequent_request_token` で多ターン可) を使う。
2. **引用の `/goto?url=` 解決は出口を余分に消費する** (既定 ON、12 件まで)。
   重いなら `MIRAGE_AIMODE_RESOLVE_WRAPPED=0`。
3. **`udm=50` の HTML に回答が入っているかは Google 次第**。キャプチャした実 DOM では
   入っていたが、ロケール/クエアによっては JS ストリーミング後にしか現れない
   (その場合 `empty_answer`)。その環境では `relay` (ブラウザ) を使う。
4. **ToS**。Google の利用規約上、自動アクセスはグレー。個人利用・調査目的にとどめ、
   公開サービスにするなら B (有料 API) を推奨。この repo の quota 既定値は
   それを意識した控えめな値。

## 8. テスト

```bash
node --test test/aimode.test.js     # 27 tests
```

`test/fixtures/aimode/` に**実 DOM キャプチャ** (完全ページ・`/goto` スキーマ・
出典カード多い版・合成最小形) を置いてある。抽出器を直したら必ずここで回帰確認。
Google は DOM を頻繁に変えるので、フィクスチャの更新手順も
`test/fixtures/aimode/README.md` に書いてある。

E2E は**外部ネットワーク不要**。`MIRAGE_AIMODE_BASE_URL` でローカル origin を指し、
実フィクスチャを配信する HTTP サーバを立てて、route → client → パイプライン
(guard/shields/egress/`raw`) → 抽出器 → キャッシュ まで通している
(`test/aimode.test.js` の「AI Mode E2E」)。

## 8.5 Serverless (Vercel) で動かす場合

`vercel.json` はそのまま動きます (AI Mode ルートも Express アプリに載る)。
ただし serverless は「1 リクエスト = 短命プロセス」なので:

* **quota はインスタンスごと**。コールドスタートでリセットされる → ブロックはされにくいが、
  予測はできない。本番用途では常駐 (Render/Railway/Docker) を推奨。
* 出口は `MIRAGE_AIMODE_EGRESS_STRATEGY=direct` (Vercel は US リージョンが多い) か
  `pool` (フリープロキシは serverless の短寿命だと当たり率が悪い)。
* `MIRAGE_AIMODE_TOKEN` を**必ず**設定する (誰でも quota を消費できる)。

## 9. リファレンス

- [TurkerYakup/google-ai-mode-api](https://github.com/TurkerYakup/google-ai-mode-api) — 自前 API 化の参考実装 (Playwright + FastAPI + OpenAI 互換)。フィクスチャと実測レートの出典
- [SerpApi: Scrape Google AI Mode](https://serpapi.com/blog/scrape-google-ai-mode-introducing-the-new-google-ai-mode-api/) — 有料 API の構造 (`text_blocks` / `references` / `related_questions`)
- [Bright Data: How to Scrape Google AI Mode](https://brightdata.com/blog/ai/scrape-google-ai-mode) — `udm=50` と `div[data-subtree="aimc"]` の入門
- [Gemini API グラウンディング](https://ai.google.dev/gemini-api/docs/grounding) — 公式の代替 (選択肢 A)
