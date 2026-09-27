import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { fetchText, parseProxyLine, parseProxies } from '../server/data/sources.js';

function response(text, ok = true, status = ok ? 200 : 503) {
  return { ok, status, text: async () => text };
}

describe('GitHub proxy-list sources', () => {
  test('parses current openproxylist rows with flag, latency and country prefix', () => {
    const proxy = parseProxyLine('🇧🇩 203.188.245.98:52837 182ms BD [Example ISP]', 'socks4');
    assert.deepEqual(
      { protocol: proxy.protocol, host: proxy.host, port: proxy.port, country: proxy.country },
      { protocol: 'socks4', host: '203.188.245.98', port: 52837, country: 'BD' },
    );
  });

  test('falls back from raw GitHub to API and decodes API base64 content', async () => {
    const calls = [];
    const fakeFetch = async (url) => {
      calls.push(url);
      if (url.includes('raw.githubusercontent.com')) throw new Error('raw blocked');
      return response(JSON.stringify({ content: Buffer.from('1.2.3.4:8080\n').toString('base64'), size: 14 }));
    };
    const got = await fetchText(
      { id: 'fixture', repo: 'owner/repo', branch: 'main', path: 'proxy.txt' },
      { order: ['raw', 'github-api'], fetchImpl: fakeFetch },
    );
    assert.equal(calls.length, 2);
    assert.match(calls[1], /api\.github\.com\/repos\/owner\/repo\/contents\/proxy\.txt/);
    assert.equal(got.text, '1.2.3.4:8080\n');
    assert.equal(parseProxies(got.text, 'ip:port', 'http').length, 1);
  });
});
