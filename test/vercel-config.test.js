import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { config as handlerConfig } from '../api/index.js';

const readJson = async (path) => JSON.parse(await readFile(new URL(path, import.meta.url), 'utf8'));

test('Vercel uses its built-in Node.js runtime and package.json selects Node 22', async () => {
  const [vercel, pkg, lock] = await Promise.all([
    readJson('../vercel.json'),
    readJson('../package.json'),
    readJson('../package-lock.json'),
  ]);

  assert.ok(vercel.functions['api/index.js']);
  assert.equal(Object.hasOwn(vercel.functions['api/index.js'], 'runtime'), false);
  assert.equal(vercel.functions['api/index.js'].includeFiles, 'data/**');
  assert.equal(pkg.engines.node, '22.x');
  assert.equal(lock.packages[''].engines.node, pkg.engines.node);
  assert.equal(Object.hasOwn(handlerConfig, 'runtime'), false);
  assert.equal(handlerConfig.api.bodyParser, false);
});
