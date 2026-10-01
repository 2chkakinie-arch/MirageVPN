# MirageVPN

**ブラウザだけで動く “VPNもどき” を、ちゃんと使える形に。**
Web(proxy)レイヤーに **UV 相当の書き換えエンジン**、そのさらに上に **WISP 相当の多重化トンネル** を重ねた、タブ型 UI 付きのゲートウェイです。GitHub の無料プロキシリストを常時取り込み、出口の**国籍を選んで**上流に見せる IP を替え、Brave 風の広告/トラッカー遮断と、リアルタイムの脅威検知＋自動削除を備えます。

- 依存は **`express` と `ws` の 2 つだけ**。ビルド工程なし、トランスパイルなし、フロントは素の JS/CSS。
- サーバ処理は全部自前実装: HTTP/1.1 クライアント、SOCKS4/5 クライアント、ABP 構文フィルタ、改写器、WISP フレーム、SSRF ガード、レート制限。
- **Vercel / Render / Railway / Docker** に対応 (サーバレスでは WISP を自動で無効化し UV のみで動作)。

```bash
npm ci
node server/index.js        # → http://localhost:8080
```

---

## 1. 何をどう実現しているか

| 要求 | 実装 | 場所 |
|---|---|---|
| UV テクノロジーを使う | **UV と同じ役割を自前実装** (URL トークン写像 + DOM 改写 + クライアント shim + Service Worker 転送)。`ultraviolet` npm は squat 済み (0.0.1) なので使わない | `server/proxy/{urlmap,rewrite,pipeline,cookies}.js`, `public/mirage/{core.js,sw.js}` |
| UV の **さらに上**に WISP を重ねる | UV と同じパイプラインを **WISP 方式 (1 本の WebSocket + 多重ストリーム)** で駆動する層を追加。ブラウザは WS 1 本、リクエスト毎に streamId、PAUSE/RESUME フロー制御、keepalive、自動フォールバック | `server/wisp/{protocol.js,server.js}`, `public/mirage/wisp-client.js` |
| 既定は UV (高速モード) | `MIRAGE_MODE=uv` が既定。UI の pill で `uv → wisp → auto` に切替。auto は能力判定 (WISP 到達不可なら UV に固定) | `server/config.js`, `public/mirage/sw.js` |
| GitHub の無料プロキシリストを全自動で取得 | `TheSpeedX/PROXY-List`・`proxifly/free-proxy-list` ほかを **30 分間隔 + ジッタ**で更新。raw / api.github.com / jsDelivr / githack のミラー順、失敗時は指数バックオフ。同梱シードがあるのでオフラインでも起動直後から効く | `server/data/{sources,pool,scheduler}.js`, `data/seeds/` |
| 国籍を自動判定して IP を偽装 | ①クライアントの国を Geo API で判定 → UI にフラグ表示 ②出口を 2 文字コードで固定 (プールがその国の生きている候補だけを使う) ③`X-Forwarded-For` 等に**その国らしい公開 IP を偽装**し、`Accept-Language`/UA も出口国に合わせる ④`/mirage/api/egress/verify` で **上流が実際に見た IP/国**を返す (思い込みを防ぐ) | `server/data/geo.js`, `#pickEgress` in `server/proxy/pipeline.js` |
| Brave 風の広告ブロック ON/OFF | uBlock Origin uAssets + EasyList (ad servers / third-party) を **既定の自動更新リスト** (12h 間隔・ミラー自動フォールバック) として取得し、ABP 構文をその場でパース。ネットワークが全滅でも **同梱の hard-block 層** (`data/adblock/hosts.seed.txt` = 主要広告網 100 ホスト) が効く。**ホスト単位インデックス + 接尾辞一致 + 決定キャッシュ**で高速化。`$domain/$3p/$1p/$type/$method/$important/@@例外`、cosmetic 規則 → **ネイティブ CSS に変換して注入**。全体トグル・レベル (standard/aggressive/off)・**サイト別トグル**・壊れたら自動で緩める (unbreakable) | `server/security/shields.js`, `data/adblock/` |
| リアルタイム脅威検知 + 自動削除 + レポート | 0..100 スコアの検知エンジン (URL / ドキュメント / アセット / ダウンロード / 認証フォーム の 5 段)。`sanitizeScore` 以上 → **その場で要素を自動除去**、`blockScore` 以上 → 遮断ページ。全イベントはリングバッファに残し、UI ライブフィード・JSON・印刷用レポート (本文は保存しない) | `server/security/threats.js`, `GET /mirage/api/threats*` |
| タブ型 UI・最高峰のデザイン | タブブラウザ風のシェル (新規/閉じる/戻る/進む、`Ctrl/⌘+T/W/L/1..9`)、aurora + glass のダーク/ライト、国グリッドピッカー、プール表、スパークライン、脅威フィード、設定パネル、パニックキー | `public/index.html`, `public/assets/{app.css,app.js}` |
| Vercel / Render / Railway にデプロイ | `vercel.json` (rewrite → `api/index.js`)、`render.yaml` (Blueprints)、`railway.json` + `Procfile`、`Dockerfile` (non-root + healthcheck)、`docker-compose.yml` | リポジトリ直下 |

## 1.5 Google AI Mode を API として使う (`MIRAGE_AIMODE=1`)

Google AI Mode に公式 API はありません。この repo は「出口を国籍で選んで IP をごまかす」
パイプラインを既に持っているので、**AI Mode を自前 API 化する際の一番つらい部分
(geo・出口ローテーション・レート) がそのまま乗ります**。追加したのは抽出器と quota だけ。

```bash
MIRAGE_AIMODE=1 MIRAGE_AIMODE_COUNTRY=US node server/index.js

curl -s 'http://localhost:8080/mirage/api/aimode/query?q=best+CRM+for+small+teams'
# → {answer:"## ...", citations:[{url,domain,title}], sources:[{title,date,source,snippet}], followUps:[]}

# OpenAI 互換 (Open WebUI / LangChain / Cursor からそのまま)
curl -s http://localhost:8080/mirage/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"google-ai-mode","messages":[{"role":"user","content":"..."}]}'
```

* `serp` (既定・自前) / `relay` (外部ブラウザリレー) / `serpapi` (有料) を
  `MIRAGE_AIMODE_PROVIDER` で差し替え可能。戻り値の形は共通。
* Google は「IP あたりの累積予算」で弾く (公開計測で約 40 問/時)。だから
  **quota・最小間隔・CAPTCHA 後の自動クールダウン**を内蔵。
* 多ターン会話・`/goto?url=` 解決の詳細と壊れ方の対策は
  **[docs/ai-mode-api.md](docs/ai-mode-api.md)** に正直に書いてあります。

## 2. アーキテクチャ

```
 ブラウザ                ┌─────────────────────────── サーバ (Express) ───────────────────────────┐
 ┌───────────────┐      │  /mirage/app/*  UI (静的)                                              │
 │ iframe (上流)  │      │  /mirage/core.js /mirage/sw.js  client core / SW (設定を注入して配る)     │
 │  ▲ 改写済みHTML │◀────│  /mirage/api/*    状態・設定・レポート・プール制御 (JSON)                  │
 │  │            │      │  /mirage/t/<sid>/h.<tok>/<path>   ← UV 転送 (SW が出す素の HTTP)         │
 │ Service Worker│      │  /mirage/t/<sid>/ws/h.<tok>/...   ← WebSocket 中継                        │
 │  (same-origin)│      │  /mirage/wisp     ← WISP (WS 多重) ─┐                                     │
 └───────┬───────┘      │                                     │ pipeline を共用                      │
         │ fetch/XHR/WS │                       ┌─────────────▼─────────────┐
         └──────────────┼──────────────────────▶│ Pipeline                   │
                       │                        │  1 SSRF ガード              │
                       │                        │  2 脅威: URL 段             │
                       │                        │  3 シールド: リクエスト段     │
                       │                        │  4 出口選択 (pool/country)  │
                       │                        │  5 キャッシュ               │
                       │                        │  6 上流 HTTP (自前クライアント)│
                       │                        │  7 ダウンロード検査          │
                       │                        │  8 改写 (html/css/js/svg)   │
                       │                        │    + 脅威の自動除去 + cosmetic│
                       │                        │  9 ヘッダ整形 + 計装         │
                       │                        └──────┬───────────┬────────┘
                       │                    net/http1 │           │ data/pool
                       │                 (raw socket, │           │ (GitHub lists, geo,
                       │                  keep-alive, │           │  health, sticky 出口)
                       │                  pool)       │           │
                       │                    net/socks ─┘           │  SOCKS4/5 ホップ
                       └──────────────────────────────────────────┘
```

要点は **2 つのトランスポートが同じパイプラインを共有する**ことです。UV 転送は「Service Worker が出す素の HTTP」を `/mirage/t/...` で受けて書き、WISP は「1 本の WS 上のフレーム」を受けて**同じ** `pipeline.execute()` を呼んで、完成した HTTP バイトを `DATA` フレームで返します (`pipeline.wispExecute()`)。だから広告ブロックも脅威の自動削除も出口偽装も、どちらの経路でも同じように効きます。

### 2.1 URL スキーム (相対解決を壊さない)

```
https://<host>/mirage/t/<sid>/h.<b64url("https://example.com")>/docs/intro?x=1#frag
```

* **path と query はそのまま**、`scheme://host:port` だけ符号化 → リンクの相対解決・`history.pushState`・画像の相対 src が全部自然に動く。
* `<base>` は読み取って**消費**し、上流の base を `CFG.base` として client core に渡す。
* 改写をすり抜けた絶対パス (`/foo.png`) は SW が救出する (リファラの proxied URL から復号した base を使って書き換え、無ければ素の origin へ透過)。
* `<sid>` で、Cookie ジャー・出口の sticky・脅威レポート・タブ状態が分離される。

### 2.2 改写の方針 (“サイトを壊さない” 側の設計)

静的にやるのは **URL の写像だけ**。振る舞いはランタイムで_patch_します (上流の JS を壊さないため)。

| 手段 | 対象 |
|---|---|
| **サーバ側 (静的)** | `<a href>` `<img src/srcset>` `<script src>` `<link href>` `<iframe src>` `<form action>` `style` 属性 `<style>` `<script>` 内の絶対 URL リテラル、`location`(=unforgeable な代入だけ) `meta http-equiv=refresh`、CSS の `url()`/`@import` |
| **クライアント側 (core.js)** | `fetch` / `XHR` / `WebSocket` / `EventSource` / `Worker` / `importScripts` / `navigator.sendBeacon` / `document.cookie` / `document.baseURI` / `document.referrer` / `document.URL` / URL プロパティ (`a.href` 等) / `history.*` / `window.top|parent|open` / `localStorage|sessionStorage` の隔離 / `serviceWorker`・`Notification` の無効化 / `<title>` と URL のハートビート報告 |
| **ヘッダ** | 上流の CSP / `X-Frame-Options` / CORP / COOP を除去 (フレーム内表示のため)、`Set-Cookie` はブラウザに渡さず**セッションジャーに吸收**、`Content-Security-Policy: frame-ancestors` を注入して外からの framing を防ぐ |

### 2.3 出口 (egress) の選び方

1. `direct` … 自前 IP で出す (速い・匿名性なし)
2. `pool` … プールから選ぶ。**失敗したら別プロキシへ再試行** (`MIRAGE_EGRESS_RETRIES`)、`pool` は direct に落ちない
3. `auto` (既定) … プール優先、全滅なら direct。タブ毎に sticky なので**国籍が途中で揺れない**

* 国籍指定時は `protocols` (http/https/socks5/socks4) と健全度 (EWMA 延迟、連続失敗で自動 BAN + cooldown) で絞り込む
* `Accept-Language` と UA を出口国のものに寄せる (`MIRAGE_LOCALIZE_HEADERS`)
* `X-Forwarded-For` / `X-Real-IP` / `CF-Connecting-IP` などへ**その国のそれらしい公開 IP** を入れる (`MIRAGE_SPOOF_FORWARDED`)
* `GET /mirage/api/egress/verify` が「上流が実際に見た IP と国」を返すので、UI の **出口を検証** ボタンで裏取りできる

### 2.4 WISP の仕様 (clean-room)

```
frame = [16B streamId (hex uuid4)][1B type][4B BE payload length][payload]
type  = 0 DATA | 1 CONNECT | 2 CLOSE | 3 KEEPALIVE | 4 PAUSE | 5 RESUME | 6 ERROR
CONNECT payload (mode:'http') = {"mode":"http","method","url","headers":{},"body":base64?,"sid"}
CONNECT payload (mode:'tunnel')= {"mode":"tunnel","host","port","tls":bool}
```

* **同一オリジン限定** (Upgrade 時に `Origin` を照合 → CSWSH 対策)
* ストリーム上限 (`MIRAGE_WISP_MAX_STREAMS=64`)、`bufferedAmount` を見た PAUSE/RESUME、keepalive で idle 切断回避
* クライアント側は接続失敗時に 20–30s の間 WISP を諦めて UV に退避 (自動デグレード)
* **ブラウザは WS トンネル内で TLS を張れない**ため、ページ側の WISP は HTTP レイヤーで運び、TLS はサーバ側で終端する (tunnel モードは `http://` と `ws://` の上流にのみ有効)

## 3. デプロイ

### Vercel (Serverless)

```bash
npm i -g vercel && vercel env add MIRAGE_SECRET && vercel --prod
```

* `vercel.json` が全リクエストを `api/index.js` (Express をそのまま載せた 1 関数) にリライトし、`public/` はファイルシステムから速く返す
* **WebSocket は使えないので WISP は自動で無効**、UV 転送で動く。UI にその旨が出る
* ファイルシステムは読取専用 → 設定はブラウザ側 localStorage にフォールバック、リストはリクエスト時に短時間で取得
* 無料枠の関数実行時間/帯域に注意 (`maxDuration: 300`)

### Render

`render.yaml` を Blueprint として読むだけ。`healthCheckPath=/mirage/api/health`、`MIRAGE_SECRET` は自動生成。

### Railway

`railway.json` (または `railway.toml`) を配置済み。`railway up` でも Dashboard からでも OK。Volume を付けるなら `MIRAGE_STATE_DIR=/data`。

### Docker / 自分の PC

```bash
docker compose up -d                 # → http://localhost:8080
# もしくは
node server/index.js
MIRAGE_EGRESS=pool MIRAGE_COUNTRY=JP node server/index.js
```

`node >= 18.17` (推奨 22)。`node --watch` 対応の dev スクリプトあり。

## 4. 設定

全 env は [.env.example](.env.example) に解説付き (よく弄るのはこの 6 つ)。

| 変数 | 既定 | 意味 |
|---|---|---|
| `MIRAGE_SECRET` | ランダム | client 識別 Cookie の署名鍵。**本番では必ず設定** |
| `MIRAGE_MODE` | `uv` | 既定トランスポート `uv` / `wisp` / `auto` |
| `MIRAGE_EGRESS` | `auto` | 出口戦略 `auto` / `pool` / `direct` |
| `MIRAGE_COUNTRY` | 空=自動 | 初期出口国 (2 文字) |
| `MIRAGE_ADBLOCK` | `1` | シールド本体の ON/OFF |
| `MIRAGE_AD_LISTS` | 空 | 追加の ABP リスト URL (カンマ区切り)。既定で uAssets×3 + EasyList×2 を取得済み |
| `MIRAGE_AD_LIST_REFRESH` | 12h | リスト自動更新の間隔 (`0` で停止) |
| `MIRAGE_ADBLOCK_HOSTS_SEED` | `data/adblock/hosts.seed.txt` | hard-block 層。`''` で無効 |
| `MIRAGE_BLOCK_PRIVATE_TARGETS` | `1` | SSRF ガード。**ローカル検証以外では絶対に 0 にしない** |

UI の設定パネルから変えた項目は `MIRAGE_STATE_DIR` が書ければ `settings.json` に永続化され、全タブ/全クライアントの既定 (global) として効きます。

## 5. API (ダッシュボードはこれだけ見ている)

```
GET  /mirage/api/health                 生存確認
GET  /mirage/api/status                 全エンジン状態 (UI が 2.5s 毎)
GET  /mirage/api/countries              プール内の国籍 + 国別生存数
GET  /mirage/api/pool?country=&sort=    プロキシ一覧
POST /mirage/api/pool/country           出口国籍を固定
POST /mirage/api/pool/refresh           GitHub リスト再取得
POST /mirage/api/pool/probe             健全性チェック
GET  /mirage/api/egress/verify          実際にどこから出ているか
GET  /mirage/api/shields   POST 同      シールド状態・ON/OFF・レベル・サイト別
GET  /mirage/api/threats                脅威レポート (JSON)
GET  /mirage/api/threats/report.html   印刷できるレポート
GET  /mirage/api/threats/report.json    ダウンロード
POST /mirage/api/threats/purge          履歴の自動削除
GET  /mirage/api/metrics                req/s・延迟 p50/p95・モード別
GET  /mirage/api/docs                   一覧 ( mechanically 読む用)

# --- AI Mode (Google 検索の AI を API 化・既定 OFF) ---
GET  /mirage/api/aimode/status          予算・直近の失敗・プロバイダ
GET  /mirage/api/aimode/query?q=        回答 + 引用 + 出典カード (JSON)
POST /mirage/api/aimode/query {q}       同上
POST /mirage/api/aimode/chat {messages} 会話の最後の user を投げる
DELETE /mirage/api/aimode/cache         キャッシュ全掃除
GET  /mirage/api/aimode/debug/html?q=   生 HTML (MIRAGE_AIMODE_DEBUG=1 のみ)
POST /mirage/v1/chat/completions        OpenAI 互換 (stream 対応)
GET  /mirage/v1/models                  OpenAI 互換のモデル一覧
```

## 6. セキュリティ上の注意 (正直に)

これは**自己防衛用のプロキシ**であり、匿名化インフラではありません。

* **当方サーバは通過する全リクエスト/レスポンスを見られる位置にあります。** 認証情報を伴うサイト (銀行・社内システム・メール本番) を通さないこと。HTTPS 上流の TLS は**当方で終端**します。
* 無料プロキシは第三者が運営しています。`pool` は「上流に見える IP を変える」もので、**プロキシ運営者に中身を見られない保証はありません**。機密を扱うなら `direct` にしてください。
* `data/` のシードは public filter/proxy list のスナップショットです (README の LICENSE 節を参照)。
* レスポンス本文は**ログにもレポートにも保存しません** (メタのみ)。脅威レポートも host/score/根拠の断片だけ。
* Vercel など共有環境では、同一オリジンの全利用者が**同じ出口設定 (global) を共有**します。個人利用前提で、公開インスタンスにするなら Basic Auth を前でかけてください。
* Service Worker を登録する関係上、`/` スコープを借ります。同一ドメインの他のアプリと同じブラウザで動かさないでください。

## 7. 既知の制限

* `https://` の上流を **WISP tunnel モード**で素通しすることはできません (ブラウザ側で TLS を張れないため、HTTP レイヤーで運びます)。
* 監査証跡は薄いです (本文は残さないので後から「何が表示されたか」は復元できません)。
* Cosmetic 規則は uBO の `+js()` / procedural selector 系を**サポートしません** (素の CSS に変換できるものだけ)。
* `wisp` は長寿命プロセスが必要です (Vercel では自動 OFF)。
* 大きな動画/ドラッグ&ドロップ系・Service Worker を使う上流サイト (PWA) は、当方の SW と競合するため正しく動かないことがあります (core.js が上流 SW 登録を止めます)。
* AI Mode 連携は Google の DOM 変更で壊れます (抽出器は実 DOM フィクスチャでテスト済みだが、継続的な監視が必要)。多ターン会話は未対応 (1 問 1 レスポンス)。

## 8. 開発

```bash
npm test                 # node:test (unit + e2e)
npm run test:e2e         # ローカル origin + 実パイプラインを通す E2E
npm run lint             # 構文 + import 解決 + 自作ルール (ESLint 不要)
npm run seeds:refresh    # GitHub からシードを再生成
npm run origin           # デモ用ローカル origin (:8099) を起動
npm run smoke            # 起動中のゲートウェイへ 23 項目の実地検査 (UV/WISP 両方)
npm run fixtures:tls     # HTTPS テスト用自己署名証明書を生成
```

`node --test` がテストファイルを自動発見します。E2E は外部ネット不要 (ローカル origin を立てて、改写/遮断/クッキー/キャッシュ/WISP/HTTPS まで実コードで検証)。

`npm run smoke` は別に起動したゲートウェイへ本物の HTTP/WebSocket を流す実地検査で、UV 経路 (改写・cosmetic・クッキージャー・額縁保護・広告遮断) と WISP 経路 (HELLO → CONNECT → DATA → CLOSE、`content-length` 一致) を確認します:

```bash
PORT=8080 node server/index.js &      # ゲートウェイ
npm run origin &                       # 上流のフリをするローカル origin
npm run smoke                          # → "=== 23/23 passed ==="
```

### 貢献ガイド (この中の約束)

* **ビルド工程を増やさない**。追加依存は本当に必要なときだけ。
* 上流 JS を**書き換えすぎない** (静的には URL だけ、振る舞いは runtime patch)。
* 機微な情報を**ログとレポートに載せない**。
* 新しい遮断・改写の規則は、必ずテストを 1 つ増やす (`test/e2e-proxy.test.js`)。
