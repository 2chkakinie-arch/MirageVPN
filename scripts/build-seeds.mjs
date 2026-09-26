#!/usr/bin/env node
/**
 * オフライン用シードの再生成ツール
 * ---------------------------------------------------------------
 * 本番 (サーバ) は起動後に GitHub へ出自己去るが、
 *  ・初回リクエストを速くする
 *  ・リスト取得がブロックされる環境 (社内/ミラー障害) でも广告ブロックと国籍固定を効かせる
 * ために、`data/` にスナップショットを同梱している。それを更新するスクリプト。
 *
 *   node scripts/build-seeds.mjs               # 全部更新
 *   node scripts/build-seeds.mjs --only=proxies
 *   node scripts/build-seeds.mjs --only=adblock
 *   node scripts/build-seeds.mjs --limit=4000  # 1 ソースあたり最大件数
 *
 * 取得は server/data/sources.js と同じミラー順序 (raw → api.github.com → jsDelivr …) を使う。
 * @module scripts/build-seeds
 */

import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { BUILTIN_SOURCES, BUILTIN_AD_LISTS, fetchSourceText, parseProxies } from '../server/data/sources.js';
import { loadConfig } from '../server/config.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const argv = Object.fromEntries(process.argv.slice(2).map((a) => a.replace(/^--/, '').split('=')));
const only = argv.only || 'all';
const limit = Number(argv.limit || 12000);
const config = loadConfig({ ...process.env, MIRAGE_LOG_LEVEL: argv.verbose ? 'debug' : 'info' });
const outDir = { proxies: path.join(ROOT, 'data', 'seeds'), adblock: path.join(ROOT, 'data', 'adblock') };

const log = (...a) => console.log(...a);
const warn = (...a) => console.warn('⚠ ', ...a);

/* ------------------------------------------------------------------ */
/* プロキシリスト                                                       */
/* ------------------------------------------------------------------ */

async function buildProxySeeds() {
  await mkdir(outDir.proxies, { recursive: true });
  const perProto = new Map(); // proto → Map<key, entry>
  const manifest = { generatedAt: new Date().toISOString(), kind: 'proxies', sources: [] };

  for (const src of BUILTIN_SOURCES) {
    if (only === 'proxies' && src.format === 'none') continue;
    try {
      const got = await fetchSourceText(src, { timeoutMs: config.lists.fetchTimeoutMs, order: config.lists.mirrorOrder });
      if (!got?.text) {
        warn(`${src.id}: 全ミラーから取得できず`);
        manifest.sources.push({ id: src.id, ok: false });
        continue;
      }
      const parsed = parseProxies(got.text, src.format, src.protocol);
      const map = perProto.get(src.protocol) || new Map();
      let added = 0;
      for (const p of parsed.slice(0, limit)) {
        const key = `${p.host}:${p.port}`;
        if (map.has(key)) continue;
        map.set(key, { ...p, source: src.id, cc: (p.country || 'XX').toUpperCase() });
        added++;
      }
      perProto.set(src.protocol, map);
      manifest.sources.push({ id: src.id, ok: true, parsed: parsed.length, added, via: got.via, bytes: got.bytes });
      log(`✓ ${src.id}: ${parsed.length} 解析 / ${added} 新規 (${src.protocol})`);
    } catch (err) {
      warn(`${src.id}: ${err.message}`);
      manifest.sources.push({ id: src.id, ok: false, error: err.message });
    }
  }

  // 書き出し: proxifly 形式 (CSV, 国情報あり) と thespeedx 形式 (ip:port のみ)
  for (const [proto, map] of perProto) {
    const entries = [...map.values()].sort((a, b) => String(a.cc).localeCompare(String(b.cc)) || a.host.localeCompare(b.host));
    const known = entries.filter((e) => /^[A-Z]{2}$/.test(e.cc) && e.cc !== 'XX');
    const unknown = entries.filter((e) => !known.includes(e));
    if (known.length) {
      const lines = known.map((e) => `${e.protocol || proto}://${e.host}:${e.port}${e.username ? `:${e.username}:${e.password}` : ''},${e.cc},${(e.city || '').replace(/,/g, ' ')}`);
      await writeFile(path.join(outDir.proxies, `proxifly-${proto}.csv`), lines.join('\n') + '\n', 'utf8');
      log(`  → proxifly-${proto}.csv (${lines.length})`);
    }
    if (unknown.length) {
      const lines = unknown.map((e) => `${e.host}:${e.port}`);
      await writeFile(path.join(outDir.proxies, `thespeedx-${proto}.txt`), lines.join('\n') + '\n', 'utf8');
      log(`  → thespeedx-${proto}.txt (${lines.length})`);
    }
  }
  manifest.total = [...perProto.values()].reduce((a, m) => a + m.size, 0);
  if (manifest.total) {
    await writeFile(path.join(outDir.proxies, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', 'utf8');
  } else {
    warn('取得 0 件 — 既存の proxifly/thespeedx シードは変更しませんでした');
  }
  log(`プロキシシード合計: ${manifest.total}`);
}

/* ------------------------------------------------------------------ */
/* 広告ブロック / 脅威リスト                                             */
/* ------------------------------------------------------------------ */

const TRACKER_HINT = /(ad|ads|adserv|analytic|track|metric|pixel|beacon|report|collect|counter|stat|telemetry|monitor|popup|pop|banner|sponsor|doubleclick|googlesyndication|googletag|facebook|scorecard|quantserve|hotjar|mixpanel|segment|amplitude|criteo|taboola|outbrain|rubicon|pubmatic|openx|casale|serving|flip|monetiz)/i;

async function buildAdblockSeeds() {
  await mkdir(outDir.adblock, { recursive: true });
  const lists = BUILTIN_AD_LISTS;
  const manifest = { generatedAt: new Date().toISOString(), kind: 'adblock', sources: [] };
  const network = new Set();
  const cosmetic = new Map(); // domain → Set<selector>
  const badHosts = new Set();
  const docRules = new Set();
  let fetched = 0;

  for (const list of lists) {
    try {
      const got = await fetchSourceText(list, { timeoutMs: config.lists.fetchTimeoutMs, order: config.lists.mirrorOrder });
      if (!got?.text) {
        warn(`${list.id}: 取得できず`);
        manifest.sources.push({ id: list.id, ok: false });
        continue;
      }
      fetched++;
      let counts = { network: 0, cosmetic: 0, hosts: 0 };
      for (const rawLine of got.text.split(/\r?\n/)) {
        const line = rawLine.trim();
        if (!line || line.startsWith('!') || line.startsWith('[')) continue;

        // ---- cosmetic ----
        const cm = /^(.{1,120}?)#(@?)#?(agent|\+js|\$?)?(.*)$/s.exec(line);
        if (cm && cm[4]) {
          const domains = cm[1]
            .split(',')
            .map((d) => d.trim())
            .filter((d) => d && !d.startsWith('~') && /^[a-z0-9.*_-]+$/i.test(d.replace(/^\^/, '')));
          const sel = line.slice(cm[0].length - cm[4].length).trim();
          if (!sel || domains.length !== 1) continue;
          const key = domains[0].replace(/^\^/, '').toLowerCase();
          if (!cosmetic.has(key)) cosmetic.set(key, new Set());
          const set = cosmetic.get(key);
          if (set.size < 12) set.add(sel);
          counts.cosmetic++;
          continue;
        }

        // ---- network ----
        if (line.startsWith('@@')) continue; // 例外は本実装の高速経路では表現しない (uBO の redirect 前提の例外も多い)
        const pattern = line.split('$')[0];
        const opts = line.slice(pattern.length);
        const pureHost = /^\|\|[a-z0-9][a-z0-9.-]*\.[a-z]{2,}\^?$/i.test(pattern);
        if (pureHost) {
          const host = pattern.replace(/^\|\|/, '').replace(/\^$/, '');
          network.add(`||${host}^`);
          badHosts.add(host);
          counts.hosts++;
          continue;
        }
        if (/\$.*(doc|popup)\b/.test(opts) && pattern.length > 8) {
          docRules.add(line);
          counts.network++;
          continue;
        }
        if (pattern.length >= 10 && TRACKER_HINT.test(pattern)) {
          network.add(line);
          counts.network++;
        }
      }
      manifest.sources.push({ id: list.id, ok: true, bytes: got.bytes, via: got.via, ...counts });
      log(`✓ ${list.id}: network=${counts.network} hosts=${counts.hosts} cosmetic=${counts.cosmetic}`);
    } catch (err) {
      warn(`${list.id}: ${err.message}`);
      manifest.sources.push({ id: list.id, ok: false, error: err.message });
    }
  }
  if (!fetched) {
    warn('1 件も取得できませんでした — 既存シードは変更しません');
    return;
  }

  const netLines = [...network].sort();
  const cosmeticLines = [...cosmetic.entries()]
    .sort((a, b) => b[1].size - a[1].size)
    .flatMap(([d, sels]) => [...sels].map((s) => `${d}##${s}`));
  const shieldsSeed = [
    `! MirageVPN Shields seed list`,
    `! generated ${new Date().toISOString()} from uBlockOrigin/uAssets (filters/privacy/badware) — data only, AGPL 由来のフィルタデータ`,
    `! network rules: ${netLines.length} / cosmetic: ${cosmeticLines.length} / doctargeted: ${docRules.size}`,
    ...netLines,
    ...cosmeticLines,
  ];
  await writeFile(path.join(outDir.adblock, 'mirage-shields.seed.txt'), shieldsSeed.join('\n') + '\n', 'utf8');

  const hosts = [...badHosts].sort();
  await writeFile(
    path.join(outDir.adblock, 'threat-domains.seed.txt'),
    [`# MirageVPN known-badware hosts (${hosts.length})`, ...hosts].join('\n') + '\n',
    'utf8',
  );
  const dl = [...docRules].sort();
  await writeFile(
    path.join(outDir.adblock, 'threat-list.seed.txt'),
    [`! MirageVPN threat rules (${dl.length})`, ...dl].join('\n') + '\n',
    'utf8',
  );

  // hosts.seed.txt (Adblock Plus 形式の hosts 行) — 任意で使う環境向け
  await writeFile(
    path.join(outDir.adblock, 'hosts.seed.txt'),
    [`# MirageVPN hosts-format mirror (${hosts.length}) — generated`, ...hosts.map((h) => `0.0.0.0 ${h}`)].join('\n') + '\n',
    'utf8',
  );
  manifest.counts = { network: netLines.length, cosmetic: cosmeticLines.length, hosts: hosts.length, doc: dl.length };
  await writeFile(path.join(outDir.adblock, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', 'utf8');
  log(`シールドシード: network=${netLines.length} cosmetic=${cosmeticLines.length} hosts=${hosts.length}`);
}

/* ------------------------------------------------------------------ */

async function main() {
  log(`MirageVPN seed builder — out=${path.relative(ROOT, outDir.proxies)}, ${path.relative(ROOT, outDir.adblock)}`);
  if (only === 'all' || only === 'proxies') await buildProxySeeds();
  if (only === 'all' || only === 'adblock') await buildAdblockSeeds();
  log('完了。`git diff --stat data/` で差分を確認してください。');
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
