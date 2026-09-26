/**
 * WISP フレーミング (MirageVPN 実装)
 * ---------------------------------------------------------------
 * WISP = 「WebSocket 上で TCP ストリームを多重化するための軽量フレームワーク」。
 * MirageVPN では UV 相当の HTTP トランスポートの "上" にこれをかぶせる。
 *
 *   フレーム: [16B streamId][1B type][4B BE payloadLen][payload…]
 *   type: 0=DATA 1=CONNECT 2=CLOSE 3=KEEPALIVE 4=PAUSE 5=RESUME 6=ERROR
 *
 *   CONNECT payload (Mirage 拡張, UTF-8 JSON):
 *     { mode:'http',    method, url, headers, bodyBase64? , sid }
 *     { mode:'tunnel',  host, port, hostType:'host'|'ipv4', sid }
 *
 * 1 本の WebSocket に複数ストリームを流すので、タブを開いたままでも
 * 接続数制限 (HTTP/1.1 は 6 本) に捕まらず、かつプロキシ先に HTTP を覗かれにくい。
 *
 * 注意: 外部 wisp サーバ (raw TCP 版) との相互運用は tunnel モードのみ。
 *       https はブラウザ側で TLS を張れないため、必ずサーバ側 terminate になる。
 * @module wisp/protocol
 */

import { Buffer } from 'node:buffer';

export const FRAME = {
  DATA: 0,
  CONNECT: 1,
  CLOSE: 2,
  KEEPALIVE: 3,
  PAUSE: 4,
  RESUME: 5,
  ERROR: 6,
  HELLO: 7, // サーバ → クライアント専用: 接続直後の能力通知 (maxStreams など)
};

export const FRAME_NAMES = Object.fromEntries(Object.entries(FRAME).map(([k, v]) => [v, k]));

export const HEADER_BYTES = 21; // 16 + 1 + 4

/**
 * @param {Uint8Array|Buffer} buf
 * @param {number} [offset]
 * @returns {{streamId:string,type:number,payload:Buffer,next:number}|null}
 */
export function decodeFrame(buf, offset = 0) {
  if (buf.length - offset < HEADER_BYTES) return null;
  const streamId = Buffer.from(buf.buffer, buf.byteOffset + offset, 16).toString('hex');
  const type = buf[offset + 16];
  const len = buf.readUInt32BE(offset + 17);
  if (buf.length - offset - HEADER_BYTES < len) return null;
  const payload = Buffer.from(buf.buffer, buf.byteOffset + offset + HEADER_BYTES, len);
  return { streamId, type, payload, next: offset + HEADER_BYTES + len };
}

/**
 * @param {string} streamId 32 hex chars
 * @param {number} type
 * @param {Buffer|Uint8Array|string} [payload]
 */
export function encodeFrame(streamId, type, payload = Buffer.alloc(0)) {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : Buffer.from(payload.buffer ?? payload, payload.byteOffset ?? 0, payload.length ?? payload.byteLength);
  const head = Buffer.alloc(HEADER_BYTES);
  head.set(Buffer.from(streamId, 'hex'), 0);
  head[16] = type;
  head.writeUInt32BE(body.length, 17);
  return Buffer.concat([head, body], HEADER_BYTES + body.length);
}

export function newStreamId() {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
}

/** ブラウザ側と同じ実装を共有するためのソース (importScripts 用) */
export const BROWSER_FRAMING = `
const HEADER_BYTES = 21;
const FRAME = { DATA: 0, CONNECT: 1, CLOSE: 2, KEEPALIVE: 3, PAUSE: 4, RESUME: 5, ERROR: 6, HELLO: 7 };
function encodeFrame(idHex, type, payload) {
  const id = hexToBytes(idHex);
  const body = payload || new Uint8Array(0);
  const out = new Uint8Array(HEADER_BYTES + body.length);
  out.set(id, 0);
  out[16] = type;
  new DataView(out.buffer).setUint32(17, body.length, false);
  out.set(body, HEADER_BYTES);
  return out;
}
function hexToBytes(h) {
  const a = new Uint8Array(16);
  for (let i = 0; i < 16; i++) a[i] = parseInt(h.substr(i * 2, 2), 16);
  return a;
}
`;

export default { FRAME, FRAME_NAMES, decodeFrame, encodeFrame, newStreamId, HEADER_BYTES };
