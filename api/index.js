/**
 * Vercel Serverless Function エントリ
 * ---------------------------------------------------------------
 * Vercel では Express アプリごと 1 関数に載せる (vercel.json の rewrites で全部ここへ送る)。
 *  ・WebSocket / WISP は使えない → UV (Service Worker) 転送で動く
 *  ・ファイルシステムは読み取り専用 → 設定はブラウザ側 localStorage にフォールバック
 *  ・リスト更新は常駐タイマーの代わりに、初回ブート時に短い予算で 1 回だけ行う
 * @module api/index
 */

let ready = null;

async function boot() {
  const { createApp } = await import('../server/app.js');
  const { app, ctx } = await createApp({ boot: true });
  // serverless には upgrade を扱うソケットがないので attach しない (WISP は自動で無効化される)
  return { app, ctx };
}

export default async function handler(req, res) {
  try {
    if (!ready) ready = boot();
    const { app } = await ready;
    return await app(req, res);
  } catch (err) {
    if (res.headersSent) throw err;
    res.statusCode = 500;
    res.setHeader('content-type', 'application/json; charset=utf-8');
    res.end(JSON.stringify({ error: 'boot_failed', message: String(err && err.message ? err.message : err).slice(0, 300) }));
    return undefined;
  }
}

/** Vercel 組み込みの body パーサを止めて、プロキシの生ボディを守る */
export const config = {
  api: { bodyParser: false },
};
