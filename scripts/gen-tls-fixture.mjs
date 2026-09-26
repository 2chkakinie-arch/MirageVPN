#!/usr/bin/env node
/**
 * テスト用の自己署名証明書を生成する (HTTPS 上流の e2e テストが対象)。
 * 本番では一切使わない。生成物は .gitignore 済み。
 *   node scripts/gen-tls-fixture.mjs
 */

import { execFileSync } from 'node:child_process';
import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'test', 'fixtures');
await mkdir(dir, { recursive: true });

const args = [
  'req',
  '-x509',
  '-newkey',
  'rsa:2048',
  '-keyout',
  path.join(dir, 'key.pem'),
  '-out',
  path.join(dir, 'cert.pem'),
  '-days',
  '36500',
  '-nodes',
  '-subj',
  '/CN=localhost',
  '-addext',
  'subjectAltName=DNS:localhost,IP:127.0.0.1',
];

try {
  execFileSync('openssl', args, { stdio: ['ignore', 'ignore', 'pipe'] });
  console.log(`✓ ${path.join(dir, 'cert.pem')} / key.pem を生成しました (テスト専用・自己署名)`);
} catch (err) {
  console.error('openssl が見つからないため生成できませんでした。HTTPS テストは自動でスキップされます。');
  console.error(String(err.stderr || err.message).split('\n')[0]);
  process.exitCode = 1;
}
