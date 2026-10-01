# AI Mode フィクスチャ

Google 検索「AI Mode」(`?udm=50`) の実 DOM キャプチャ。`test/aimode.test.js` の
リグレッション試験に使う。Google は DOM を頻繁に変えるので、抽出器
(`server/aimode/extract.js`) を直したらここで回帰確認すること。

| ファイル | 内容 |
|---|---|
| `real_ai_mode_tr.html` | 完全な AI Mode 回答ページ (tr ロケール)。`data-subtree="aimc"` 内に本文・引用リンク・出典カード (日付入り) を含む |
| `real_ai_mode_goto_links.html` | 引用が `/goto?url=<署名ブロブ>` で包まれているケース (2026-08 以降のスキーマ) |
| `real_ai_mode_tr_sources.html` | 出典カードが多いケース。`aria-label` に「サイト - ページ題 | サイト名」形式の情報が入る |
| `synthetic_ai_mode.html` | 最小構成 (段落/見出し/リスト/注意書き/引用) の合成 HTML。構造テスト用 |

出典: [TurkerYakup/google-ai-mode-api](https://github.com/TurkerYakup/google-ai-mode-api) の
`tests/fixtures/` (MIT) から引用。Google のページのスクラップであり、再配布は
テスト目的の範囲で。
