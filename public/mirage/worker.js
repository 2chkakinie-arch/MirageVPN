/**
 * MirageVPN — Worker 用シム (shim)
 * ---------------------------------------------------------------
 * クラシックワーカーは `importScripts()` で外部スクリプトを読む。core.js は DOM を
 * いじるのでワーカーにそのまま入れると壊れる。そこで「URL 変換 + fetch/importScripts/
 * XHR/WebSocket のパッチ」だけに絞ったのがこのファイル。
 *   親 (core.js) は new Worker(blob) の中で
 *     self.__MIRAGE_CFG = {...}; importScripts('/mirage/worker.js');
 *   として読み込む。
 * @file public/mirage/worker.js
 */
/* global self, Worker, Blob, URL, TextEncoder, TextDecoder, Request, Response */
(function () {
  'use strict';
  if (self.__MIRAGE_WORKER_READY) return;
  self.__MIRAGE_WORKER_READY = true;

  var CFG = self.__MIRAGE_CFG || {};
  var sid = CFG.sid || 'anon';
  var encoding = CFG.encoding || 'token';
  var prefixBase = (CFG.prefix || '/mirage/t').replace(/\/$/, '');
  var prefix = prefixBase.indexOf('/' + sid) === -1 ? prefixBase + '/' + sid : prefixBase;
  var pageBase = CFG.base ? new URL(CFG.base) : null;
  var blockedHosts = CFG.blockedHosts || [];
  var hostSuffixes = CFG.blockedSuffixes || [];
  var mode = CFG.mode || 'uv';
  var blockedSet = null;
  var stats = { proxied: 0, blocked: 0 };

  var DEFAULT_PORTS = { 'http:': '80', 'https:': '443' };

  function b64url(str) {
    var bytes = new TextEncoder().encode(str);
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function unb64url(b64) {
    var p = b64.replace(/-/g, '+').replace(/_/g, '/');
    while (p.length % 4) p += '=';
    var bin = atob(p);
    var out = new Uint8Array(bin.length);
    for (var i2 = 0; i2 < bin.length; i2++) out[i2] = bin.charCodeAt(i2);
    return new TextDecoder().decode(out);
  }
  function originOf(u) {
    var port = u.port ? (DEFAULT_PORTS[u.protocol] === u.port ? '' : ':' + u.port) : '';
    return u.protocol + '//' + u.hostname + port;
  }
  function encodeHost(origin) {
    return encoding === 'plain' ? 'u.' + encodeURIComponent(origin) : 'h.' + b64url(origin);
  }
  function decodeHost(seg) {
    try {
      if (seg.indexOf('h.') === 0) return unb64url(seg.slice(2));
      if (seg.indexOf('u.') === 0) return decodeURIComponent(seg.slice(2));
    } catch (e) {}
    return null;
  }
  function proxify(abs) {
    var u;
    try {
      u = typeof abs === 'string' ? new URL(abs) : abs;
    } catch (e) {
      return null;
    }
    if (!/^https?:$/.test(u.protocol)) return null;
    return prefix + '/' + encodeHost(originOf(u)) + (u.pathname || '/') + (u.search || '');
  }
  function deproxify(href) {
    try {
      var u = new URL(href, self.location.href);
      var path = u.pathname;
      if (path.indexOf(prefix + '/') !== 0) return null;
      var rest = path.slice(prefix.length + 1);
      var slash = rest.indexOf('/');
      var seg = slash === -1 ? rest : rest.slice(0, slash);
      var tail = slash === -1 ? '/' : rest.slice(slash);
      var origin = decodeHost(seg);
      if (!origin) return null;
      var out = new URL(origin + tail);
      out.search = u.search;
      return out;
    } catch (e) {
      return null;
    }
  }
  function isBlocked(host) {
    if (!CFG.shieldsOn || !host) return false;
    if (!blockedSet) blockedSet = new Set(blockedHosts);
    host = String(host).toLowerCase();
    if (pageBase && host === pageBase.hostname) return false;
    if (blockedSet.has(host)) return true;
    for (var i = 0; i < hostSuffixes.length; i++) {
      if (host === hostSuffixes[i] || host.endsWith('.' + hostSuffixes[i])) return true;
    }
    return false;
  }

  /** ワーカー内の絶対/相対を pageBase 基準で proxied URL にする */
  function map(raw) {
    if (raw == null) return raw;
    var s = String(raw);
    if (/^(data|blob|about|javascript):/i.test(s)) return s;
    var abs;
    try {
      abs = new URL(s, pageBase ? pageBase.href : self.location.href);
    } catch (e) {
      return s;
    }
    if (isBlocked(abs.hostname)) return null;
    if (self.location && abs.origin === self.location.origin) {
      // 自分 (Mirage) オリジン = はすでに proxied / 当方の静的ファイル → 触らない
      if (abs.pathname.indexOf(prefix + '/') === 0 || abs.pathname.indexOf('/mirage/') === 0) return abs.href;
    }
    var p = proxify(abs.href);
    if (!p) return s;
    stats.proxied++;
    return new URL(p, self.location.origin).href;
  }

  /* ---------------- fetch ---------------- */
  var nativeFetch = self.fetch ? self.fetch.bind(self) : null;
  if (nativeFetch) {
    self.fetch = function (input, init) {
      try {
        var isReq = typeof Request !== 'undefined' && input instanceof Request;
        var rawUrl = isReq ? input.url : typeof input === 'string' ? input : input && input.url;
        var mapped = map(rawUrl);
        if (mapped === null) return Promise.reject(new TypeError('MirageVPN: blocked by shields'));
        if (isReq) {
          init = init || {};
          var n = new Request(mapped, Object.assign({}, input, { url: mapped }));
          return nativeFetch(n, init);
        }
        return nativeFetch(mapped, init);
      } catch (e) {
        return nativeFetch(input, init);
      }
    };
  }

  /* ---------------- importScripts ---------------- */
  var nativeImport = self.importScripts ? self.importScripts.bind(self) : null;
  if (nativeImport) {
    self.importScripts = function () {
      var urls = [].slice.call(arguments).map(function (u) {
        var m = map(u);
        return m === null ? 'data:text/javascript,' : m;
      });
      return nativeImport.apply(null, urls);
    };
  }

  /* ---------------- XMLHttpRequest ---------------- */
  var NativeXHR = self.XMLHttpRequest;
  if (NativeXHR) {
    var origOpen = NativeXHR.prototype.open;
    var PatchedXHR = function () {
      var x = new NativeXHR();
      var targetUrl = null;
      x.open = function (method, url) {
        var m = map(url);
        targetUrl = m === null ? null : m;
        if (targetUrl === null) {
          // ブロックされた場合: 何も送らずに error にする
          setTimeout(function () {
            x.dispatchEvent(new Event('error'));
          }, 0);
          x.open = function () {};
          x.send = function () {};
          return;
        }
        var args = [].slice.call(arguments);
        args[1] = targetUrl;
        return origOpen.apply(x, args);
      };
      return x;
    };
    PatchedXHR.prototype = NativeXHR.prototype;
    self.XMLHttpRequest = PatchedXHR;
  }

  /* ---------------- WebSocket ---------------- */
  var NativeWS = self.WebSocket;
  if (NativeWS) {
    var PatchedWS = function (url, protocols) {
      var abs;
      try {
        abs = new URL(String(url), pageBase ? pageBase.origin.replace(/^http/, 'ws') : self.location.origin);
      } catch (e) {
        return new NativeWS(url, protocols);
      }
      if (!/^wss?:$/.test(abs.protocol)) return new NativeWS(url, protocols);
      var target = abs.origin.replace(/^ws/, 'http') + abs.pathname + abs.search;
      var wsBase = self.location.origin.replace(/^http/, 'ws');
      var wrapped = wsBase + prefix + '/ws/' + encodeHost(originOf(new URL(target))) + new URL(target).pathname + (new URL(target).search || '');
      return new NativeWS(wrapped, protocols || ['mirage-v1']);
    };
    PatchedWS.prototype = NativeWS.prototype;
    self.WebSocket = PatchedWS;
  }

  /* ---------------- import() 内 / 自己複製用 Worker ---------------- */
  var NativeWorker = self.Worker;
  if (NativeWorker) {
    var PatchedWorker = function (scriptURL, options) {
      var m = map(scriptURL);
      if (m === null) throw new Error('MirageVPN: worker blocked');
      return new NativeWorker(m, options);
    };
    PatchedWorker.prototype = NativeWorker.prototype;
    self.Worker = PatchedWorker;
  }

  /* ---------------- fetch の応答 URL を上流っぽく見せる ---------------- */
  // (site が res.url を見て相対解決することがあるため、可能なら deproxify した値を返すラッパを付ける)
  if (typeof Response !== 'undefined' && Response.prototype) {
    try {
      var desc = Object.getOwnPropertyDescriptor(Response.prototype, 'url');
      if (desc && desc.get) {
        Object.defineProperty(Response.prototype, 'url', {
          configurable: true,
          get: function () {
            var v = desc.get.call(this);
            var d = v ? deproxify(v) : null;
            return d ? d.href : v;
          },
        });
      }
    } catch (e) {}
  }

  self.__MIRAGE_WORKER = { sid: sid, prefix: prefix, proxify: proxify, deproxify: deproxify, map: map, stats: stats, mode: mode };
})();
