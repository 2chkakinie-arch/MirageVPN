#!/usr/bin/env node
/**
 * 依存ゼロの静的チェック (ESLint を入れたくないので自作)
 * ---------------------------------------------------------------
 *  1) 全 JS を `node --check` する (構文)
 *  2) 相対 import が解決するか (ファイル存在)
 *  3) 名前付き import が実在する export と突き合うか (typo をここで落とす)
 *  4) 禁止事項: server 側で console.* を直接使う、CRLF 混入、全角区切り文字、TODO(urgent)
 *
 *   node scripts/lint.mjs              → 全部
 *   node scripts/lint.mjs --check-only → 構文だけ (速い)
 */

import { execFileSync } from 'node:child_process';
import { readFile, readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CHECK_ONLY = process.argv.includes('--check-only');
const DIRS = ['server', 'public', 'test', 'scripts', 'api'];

const problems = [];
const files = [];

async function walk(dir) {
  let entries;
  try {
    entries = await readdir(path.join(ROOT, dir), { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    const rel = `${dir}/${e.name}`;
    if (e.isDirectory()) {
      if (['node_modules', '.git', 'fixtures'].includes(e.name)) continue;
      await walk(rel);
    } else if (/\.(m?js)$/.test(e.name)) {
      files.push(rel);
    }
  }
}

async function exists(rel) {
  try {
    await stat(path.join(ROOT, rel));
    return true;
  } catch {
    return false;
  }
}

const EXPORT_RE = /^export\s+(?:async\s+)?(?:function|class|const|let|var)\s+([A-Za-z0-9_$]+)/gm;
const EXPORT_BRACE_RE = /^export\s*\{([^}]*)\}/gm;
const IMPORT_RE = /import\s+(?:([\w$]+)\s*,\s*)?(?:\{([^}]*)\}|([\w$]+)|\*\s+as\s+([\w$]+))?\s*from\s*['"]([^'"]+)['"]/g;

function exportsOf(src) {
  const out = new Set();
  let m;
  EXPORT_RE.lastIndex = 0;
  while ((m = EXPORT_RE.exec(src))) out.add(m[1]);
  EXPORT_BRACE_RE.lastIndex = 0;
  while ((m = EXPORT_BRACE_RE.exec(src))) {
    for (const part of m[1].split(',')) {
      const name = part.trim().split(/\s+as\s+/).pop();
      if (name) out.add(name);
    }
  }
  if (/^\s*export\s+default/m.test(src)) out.add('default');
  return out;
}

await Promise.all(DIRS.map((d) => walk(d)));

const sourceCache = new Map();
async function sourceOf(rel) {
  if (sourceCache.has(rel)) return sourceCache.get(rel);
  const text = await readFile(path.join(ROOT, rel), 'utf8');
  sourceCache.set(rel, text);
  return text;
}

let syntaxOk = 0;
for (const rel of files) {
  const abs = path.join(ROOT, rel);
  try {
    execFileSync(process.execPath, ['--check', abs], { stdio: ['ignore', 'ignore', 'pipe'] });
    syntaxOk++;
  } catch (err) {
    problems.push(`${rel}: 構文エラー\n${String(err.stderr || err.message).split('\n').slice(0, 6).join('\n')}`);
  }
  if (CHECK_ONLY) continue;

  const text = await sourceOf(rel);
  if (/\r\n/.test(text)) problems.push(`${rel}: CRLF が混ざっています`);
  const SELF = rel === 'scripts/lint.mjs'; // このスクリプト自身はパターン実体を持つので除外
  // コメント (ブロック + 行) と文字列リテラルを除いてから検査する
  const codeOnly = text
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\*.*$/gm, '')
    .replace(/(^|[^:'"`\\])\/\/[^\n]*/g, '$1');
  const noStr = SELF ? '' : codeOnly.replace(/(['"`])(?:\\.|(?!\1)[^\\])*\1/g, "''");
  if (/[；，：（）]/.test(noStr)) {
    problems.push(`${rel}: 全角記号がコード内にあります (文字列/コメント以外ならバグ)`);
  }
  if (rel.startsWith('server/') && !rel.endsWith('log.js') && /(^|\n)\s*console\.(log|warn|error)\(/.test(text)) {
    problems.push(`${rel}: console.* を直接使っています — server/log.js を使ってください`);
  }
  if (!SELF && /TODO\s*\(\s*(urgent|fix|fixme)\s*\)/i.test(codeOnly)) problems.push(`${rel}: 未解決の TODO(urgent)`);

  let m;
  IMPORT_RE.lastIndex = 0;
  while ((m = IMPORT_RE.exec(text))) {
    const spec = m[5];
    if (!spec || !spec.startsWith('.')) continue;
    const target = path.posix.normalize(path.join(path.dirname(rel), spec));
    if (!(await exists(target))) {
      problems.push(`${rel}: import 先がありません → ${spec}`);
      continue;
    }
    const named = (m[2] || '')
      .split(',')
      .map((s) => s.trim().split(/\s+as\s+/)[0])
      .filter(Boolean);
    if (!named.length) continue;
    if (target.endsWith('.css') || target.endsWith('.html')) continue;
    const ex = exportsOf(await sourceOf(target));
    for (const n of named) {
      if (!ex.has(n)) problems.push(`${rel}: ${spec} に '${n}' という export はありません (ある: ${[...ex].slice(0, 8).join(', ') || 'none'})`);
    }
  }
}

if (problems.length) {
  console.error(`\x1b[31m✗ lint: ${problems.length} 件\x1b[0m`);
  for (const p of problems.slice(0, 40)) console.error('  - ' + p);
  process.exitCode = 1;
} else {
  console.log(`\x1b[32m✓ lint pass\x1b[0m — ${syntaxOk} files${CHECK_ONLY ? ' (syntax only)' : ', imports resolved'}`);
}
