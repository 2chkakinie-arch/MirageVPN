/**
 * SOCKS4 / SOCKS4a / SOCKS5 クライハンドシェイク (依存ゼロ実装)
 * ---------------------------------------------------------------
 * フリープロキシリストには socks4/socks5 が大量に含まれるため、undici の ProxyAgent
 * (http/https プロキシ専用) ではなく自前実装にする。これで
 * 「UV 相当の HTTP トランスポートの上に、国籍付き SOCKS 出口を被せる」ことができる。
 * @module net/socks
 */

import { Buffer } from 'node:buffer';
import net from 'node:net';

export class SocksError extends Error {
  constructor(message, { code = 'socks_failed', stage = 'handshake', cause } = {}) {
    super(message);
    this.name = 'SocksError';
    this.code = code;
    this.stage = stage;
    if (cause) this.cause = cause;
  }
}

/**
 * socket から n バイトだけ読む (超過分は keep-alive のために押し戻す)
 * @returns {Promise<{head:Buffer, rest:Buffer}>}
 */
function readBytes(socket, n, timeoutMs, acc = Buffer.alloc(0)) {
  return new Promise((resolve, reject) => {
    let buf = acc;
    let timer = null;
    // すでに十分なバイトが届いている (ハンドシェイクの応答が 1 チャンクに纏まっている) 場合は即解決
    if (buf.length >= n) {
      resolve({ head: buf.subarray(0, n), rest: buf.subarray(n) });
      return;
    }
    const cleanup = () => {
      if (timer) clearTimeout(timer);
      socket.off('data', onData);
      socket.off('error', onError);
      socket.off('close', onClose);
    };
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length >= n) {
        cleanup();
        resolve({ head: buf.subarray(0, n), rest: buf.subarray(n) });
      }
    };
    const onError = (err) => {
      cleanup();
      reject(new SocksError(`SOCKS 接続が切れました: ${err.message}`, { code: 'socks_conn', cause: err }));
    };
    const onClose = () => {
      cleanup();
      reject(new SocksError('SOCKS プロキシが接続をクローズしました', { code: 'socks_closed' }));
    };
    if (timeoutMs > 0) {
      timer = setTimeout(() => {
        cleanup();
        reject(new SocksError(`SOCKS ハンドシェイクタイムアウト (${timeoutMs}ms)`, { code: 'socks_timeout' }));
      }, timeoutMs);
      timer.unref?.();
    }
    socket.on('data', onData);
    socket.on('error', onError);
    socket.on('close', onClose);
  });
}

function encodeAddress(host) {
  if (net.isIPv4(host)) {
    return Buffer.from([1, ...host.split('.').map((n) => Number(n))]);
  }
  if (net.isIPv6(host)) {
    const out = Buffer.alloc(17);
    out[0] = 4;
    const groups = host.split('::');
    const head = groups[0] ? groups[0].split(':').filter(Boolean) : [];
    const tail = groups[1] ? groups[1].split(':').filter(Boolean) : [];
    const full = [...head];
    if (groups.length > 1) for (let i = 8 - head.length - tail.length; i > 0; i--) full.push('0');
    full.push(...tail);
    let idx = 1;
    for (const w of full) {
      const v = parseInt(w || '0', 16) || 0;
      out[idx++] = (v >> 8) & 0xff;
      out[idx++] = v & 0xff;
    }
    return out;
  }
  const name = Buffer.from(host, 'ascii');
  if (name.length > 255) throw new SocksError('ホスト名が長すぎます', { code: 'socks_hostlen' });
  return Buffer.concat([Buffer.from([3, name.length]), name]);
}

/**
 * SOCKS5 CONNECT
 * @param {import('node:net').Socket} socket
 * @param {{host:string, port:number, username?:string, password?:string, timeoutMs?:number}} opts
 */
export async function socks5Connect(socket, { host, port, username, password, timeoutMs = 10000 }) {
  const methods = [0x00];
  if (username) methods.push(0x02);
  socket.write(Buffer.from([0x05, methods.length, ...methods]));
  const { head } = await readBytes(socket, 2, timeoutMs);
  const [ver, method] = head;
  if (ver !== 0x05) throw new SocksError('SOCKS5 を選択できないプロキシです', { code: 'socks_ver' });
  let rest = Buffer.alloc(0);
  if (method === 0xff) {
    throw new SocksError('プロキシが認証を要求しています (ネストされたユーザー認証は未対応)', {
      code: 'socks_noauth',
    });
  }
  if (method === 0x02) {
    if (!username) throw new SocksError('この SOCKS5 はユーザー認証が必須です', { code: 'socks_needauth' });
    const u = Buffer.from(String(username), 'utf8');
    const p = Buffer.from(String(password || ''), 'utf8');
    socket.write(Buffer.concat([Buffer.from([0x01, u.length]), u, Buffer.from([p.length]), p]));
    const auth = await readBytes(socket, 2, timeoutMs);
    if (auth.head[1] !== 0x00) throw new SocksError('SOCKS5 認証に失敗しました', { code: 'socks_auth' });
    rest = auth.rest;
  }
  const addr = encodeAddress(host);
  const portBuf = Buffer.alloc(2);
  portBuf.writeUInt16BE(port & 0xffff, 0);
  socket.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00]), addr, portBuf]));
  // 固定 4 バイト + アドレス長 (atyp で可変)
  const fixed = await readBytes(socket, 4, timeoutMs, rest);
  const [, rep, , atyp] = fixed.head;
  if (rep !== 0x00) {
    throw new SocksError(`SOCKS5 CONNECT 拒否 (rep=0x${rep.toString(16)}) ${describeRep(rep)}`, {
      code: 'socks_refused',
      stage: 'connect',
    });
  }
  const tailLen = atyp === 1 ? 4 : atyp === 4 ? 16 : atyp === 3 ? -1 : -2;
  if (tailLen === -2) throw new SocksError('不正な SOCKS5 レスポンス', { code: 'socks_atyp' });
  let leftover = fixed.rest;
  if (tailLen === -1) {
    const domLen = await readBytes(socket, 1, timeoutMs, leftover);
    leftover = domLen.rest;
    const dom = await readBytes(socket, domLen.head[0] + 2, timeoutMs, leftover);
    leftover = dom.rest;
  } else {
    const tail = await readBytes(socket, tailLen + 2, timeoutMs, leftover);
    leftover = tail.rest;
  }
  if (leftover.length) pushBack(socket, leftover);
  return { socket };
}

/** SOCKS4 / SOCKS4a CONNECT */
export async function socks4Connect(socket, { host, port, username, timeoutMs = 10000, use4a = true }) {
  const portBuf = Buffer.alloc(2);
  portBuf.writeUInt16BE(port & 0xffff, 0);
  const userId = Buffer.from(String(username || 'mirage').slice(0, 99), 'utf8');
  let ipBuf;
  const isV4 = net.isIPv4(host);
  if (isV4) {
    ipBuf = Buffer.from(host.split('.').map((n) => Number(n)));
  } else if (!use4a) {
    throw new SocksError('SOCKS4 は IPv4 リテラルのみ対応 (SOCKS4a を使用してください)', { code: 'socks4_host' });
  } else {
    // SOCKS4a: ip を 0.0.0.x にしてドメイン名を後ろに置く
    ipBuf = Buffer.from([0, 0, 0, 1]);
  }
  const head = Buffer.concat([Buffer.from([0x04, 0x01]), portBuf, ipBuf, userId, Buffer.from([0])]);
  socket.write(isV4 || !use4a ? head : Buffer.concat([head, Buffer.from(host, 'ascii'), Buffer.from([0])]));
  const { head: resp, rest } = await readBytes(socket, 8, timeoutMs);
  if (resp[0] !== 0x00) throw new SocksError('SOCKS4 応答形式が不正です', { code: 'socks4_ver' });
  const cd = resp[1];
  if (cd !== 0x5a) {
    throw new SocksError(`SOCKS4 CONNECT 拒否 (cd=0x${cd.toString(16)}) ${describeSocks4(cd)}`, {
      code: 'socks4_refused',
      stage: 'connect',
    });
  }
  if (rest.length) pushBack(socket, rest);
  return { socket };
}

function pushBack(socket, buf) {
  // ハンドシェイク応答に付いてきた本体データの先頭をソケットに戻す
  socket.unshift(buf);
}

function describeRep(rep) {
  return (
    {
      1: '一般失敗',
      2: 'ルールにより許可されない',
      3: 'ネットワーク到達不可',
      4: 'ホスト到達不可',
      5: '接続拒否',
      6: 'TTL 超過',
      7: 'コマンド未対応',
      8: 'アドレス種別未対応',
    }[rep] ?? ''
  );
}

function describeSocks4(cd) {
  return (
    {
      90: 'rejected/failed',
      91: 'rejected (identd)',
      92: 'failed (identd)',
      93: 'timeout (identd)',
    }[cd] ?? ''
  );
}

export const SOCKS_METHODS = { NOAUTH: 0, GSSAPI: 1, USERPASS: 2 };

export default { socks5Connect, socks4Connect, SocksError };
