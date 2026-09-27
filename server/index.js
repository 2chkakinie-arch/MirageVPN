#!/usr/bin/env node
/**
 * MirageVPN — 常駐サーバのエントリ (Render / Railway / Docker / 自分の PC)
 * ---------------------------------------------------------------
 *   node server/index.js            → http://0.0.0.0:8080
 *   MIRAGE_EGRESS=pool MIRAGE_COUNTRY=JP node server/index.js
 *
 * Vercel では `api/index.js` が代わりに使われる (WebSocket は使えないが UV は動く)。
 * @module server/index
 */

import http from 'node:http';
import { createApp } from './app.js';
import { loadConfig } from './config.js';
import { warnGuardDisabled } from './security/ssrf.js';
import { log } from './log.js';

const ns = log.child('main');
const config = loadConfig(process.env);

async function main() {
  if (!process.env.MIRAGE_SECRET) {
    ns.warn('MIRAGE_SECRET が未設定です — 起動のたびにクライアント識別 Cookie の署名鍵が変わります (設定すると再起動後も設定が維持されます)');
  }
  const { app, ctx, engine } = await createApp({ config });
  const server = http.createServer(app);
  server.keepAliveTimeout = 65000;
  server.headersTimeout = 70000;
  server.requestTimeout = 0; // 大きなダウンロード/遅い出口に合わせる (socket 側で制御)
  server.maxHeadersCount = 200;
  ctx.attach(server);

  await new Promise((resolve) => server.listen(config.port, config.host, resolve));
  const shownHost = config.host === '0.0.0.0' ? 'localhost' : config.host;
  const url = `http://${shownHost}:${config.port}${config.basePath}/`;
  if (config.safety.blockPrivateTargets === false) warnGuardDisabled();

  process.stdout.write(`
  ██╗   ██╗██████╗  ██████╗  █████╗  ██████╗     ██╗   ██╗███╗   ███╗
  ███║  ╚██║██╔══██╗██╔═══██╗██╔══██╗██╔═══██╗    ██║   ██║████╗ ████║
  ╚██║   ██║██████╔╝██║   ██║███████║██║   ██║    ██║   ██║██╔████╔██║
   ██║   ██║██╔═══╝ ██║▄▄ ██║██╔══██║██║   ██║    ╚██╗ ██╔╝██║╚██╔╝██║
   ╚██║  ██║██║     ╚██████╔╝██║  ██║╚██████╔╝     ╚████╔╝ ██║ ╚═╝ ██║
    ╚═╝  ╚═╝╚═╝      ╚══▀▀═╝ ╚═╝  ╚═╝ ╚═════╝       ╚═══╝  ╚═╝     ╚═╝
  MirageVPN v${config.meta.version} "${config.meta.codename}"  —  ${url}
    transport : ${config.transport.defaultMode.toUpperCase()}${config.wisp.enabled ? ' + WISP (' + config.basePath + config.wisp.path + ')' : ''}
    egress    : ${config.egress.defaultStrategy}${config.egress.country ? ' / ' + config.egress.country : ' / auto-detect'}  (pool=${engine.pool.summary().size})
    shields   : ${engine.shields.summary().rules} rules  (cosmetic ${engine.shields.summary().cosmeticRules})
    threats   : ${engine.threats.stats().enabled ? 'on' : 'off'}  (autoDelete ${engine.threats.stats().autoDelete ? 'on' : 'off'})
    lists     : ${config.lists.enabled ? 'auto-refresh ' + Math.round(config.lists.refreshMs / 60000) + 'min' : 'manual'}
  \n`);

  let closing = false;
  const shutdown = async (sig) => {
    if (closing) return;
    closing = true;
    ns.info(`${sig} を受けたので安全にシャットダウンします…`);
    try {
      await engine.store.flush({ force: true });
    } catch (err) {
      ns.debug(() => `flush: ${err.message}`);
    }
    server.close();
    await ctx.close().catch(() => {});
    setTimeout(() => process.exit(0), 300).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('unhandledRejection', (r) => ns.warn(`unhandledRejection: ${r && r.message ? r.message : r}`));
  process.on('uncaughtException', (e) => {
    ns.error(`uncaughtException: ${e.stack || e}`);
    setTimeout(() => shutdown('uncaughtException'), 200).unref();
  });

  // 長時間稼働でヒープがふくれたらレポート (logLevel=debug のときだけ詳細)
  let lastWarn = 0;
  setInterval(() => {
    const mb = process.memoryUsage().heapUsed / 1048576;
    if (mb > 512 && Date.now() - lastWarn > 300000) {
      lastWarn = Date.now();
      ns.warn(`heap ${Math.round(mb)}MB (pool=${engine.pool.records.size} cache=${engine.pipeline.cacheStats().size})`);
    }
  }, 30000).unref?.();

  return { server, ctx, engine };
}

main().catch((err) => {
  ns.error(`起動に失敗しました: ${err.stack || err}`);
  process.exitCode = 1;
});
