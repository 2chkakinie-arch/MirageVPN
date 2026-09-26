/**
 * MirageVPN — クライアントコア (core.js)
 * ---------------------------------------------------------------
 * プロキシ済みドキュメントの main world で最初に実行される。UV でいう uv.client.js の役割。
 * サーバ側の改写が「静的な HTML 属性」を見るのに対して、ここは「実行時に発生するあらゆる
 * リクエスト／ナビゲーション」を取り締まる。
 *
 *   書き換え対象: fetch / XHR / WebSocket / EventSource / Worker / importScripts /
 *                 document.cookie / baseURI / referrer / history / location(shim) /
 *                 要素の src|href|action… プロパティ / web storage / serviceWorker / window.name
 *
 * 設計方針: 「上流の URL を our-origin の proxied path に写像する」関数 1 つ (proxify) に
 * 集約し、各 API はそれを呼ぶだけにする。逆方向 (deproxify) は location シムと
 * document.URL などで使う。
 */
/* global window,document,Worker,Blob,AbortController,URL,TextEncoder,Uint8Array,ArrayBuffer */
(function () {
  'use strict';
  var CFG = window.__MIRAGE_CFG || {};
  if (window.__mrg) return; // 二重注入防止

  var sid = CFG.sid || 'anon';
  var pageBase = CFG.base ? new URL(CFG.base) : null; // 上流の実 URL
  var prefix = CFG.prefix || '/mirage/t/' + sid;
  var apiBase = CFG.apiBase || '/mirage/api';
  var transportMode = CFG.mode || 'uv'; // uv | wisp | auto
  var blockedHosts = CFG.blockedHosts || []; // 上位 N 件のブロックホスト (クライアント側で即止めのための小リスト)
  var hostSuffixes = CFG.blockedSuffixes || []; // 接尾辞一致 (subdomain 含む)
  var containTop = CFG.containTop !== false;
  var isolateStorage = CFG.isolateStorage !== false;
  var blockNotifications = CFG.blockNotifications !== false;
  var blockServiceWorker = CFG.blockServiceWorker !== false;
  var cookieMirror = CFG.cookies || '';
  var stats = { blocked: 0, proxied: 0, cookies: 0, navs: 0, wisp: 0 };
  var blockedByClient = [];

  var BLOBBASE = 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';

  /* ------------------------------------------------------------------ */
  /* URL 変換                                                            */
  /* ------------------------------------------------------------------ */

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
    var bytes = new Uint8Array(bin.length);
    for (var i2 = 0; i2 < bin.length; i2++) bytes[i2] = bin.charCodeAt(i2);
    return new TextDecoder().decode(bytes);
  }
  function originOf(u) {
    var port = u.port ? (DEFAULT_PORTS[u.protocol] === u.port ? '' : ':' + u.port) : '';
    return u.protocol + '//' + u.hostname + port;
  }
  function encodeHost(origin) {
    return CFG.encoding === 'plain' ? 'u.' + encodeURIComponent(origin) : 'h.' + b64url(origin);
  }
  function decodeHost(seg) {
    try {
      if (seg.indexOf('h.') === 0) return unb64url(seg.slice(2));
      if (seg.indexOf('u.') === 0) return decodeURIComponent(seg.slice(2));
    } catch (e) {}
    return null;
  }

  /** 上流絶対URL → our proxied path */
  function proxify(abs) {
    try {
      var u = typeof abs === 'string' ? new URL(abs) : abs;
      if (!/^https?:$/.test(u.protocol)) return null;
      return prefix + '/' + encodeHost(originOf(u)) + (u.pathname || '/') + (u.search || '');
    } catch (e) {
      return null;
    }
  }

  /** 相対/スchem-relative を pageBase 基準で絶対化してから proxify */
  function proxifyMaybe(raw) {
    if (raw == null) return null;
    var s = String(raw);
    if (!s) return null;
    if (/^(javascript|vbscript|mailto|tel|blob|data|about|file|chrome|moz-extension|filesystem):/i.test(s)) return null;
    try {
      var base = pageBase || new URL(window.location.href);
      var abs;
      if (s.charAt(0) === '#' && s.length > 1) return s; // 同一ページ内アンカーはそのまま
      if (/^\/\//.test(s)) abs = new URL((base.protocol || 'https:') + s);
      else if (/^[a-z][a-z0-9+.-]*:/i.test(s)) abs = new URL(s);
      else abs = new URL(s, pageBase ? pageBase.href : window.location.href);
      if (!/^https?:$/.test(abs.protocol)) return null;
      return proxify(abs);
    } catch (e) {
      return null;
    }
  }

  /** our proxied URL → 上流 URL (表示・戻り値用) */
  function deproxify(hrefLike) {
    try {
      var u = typeof hrefLike === 'string' ? new URL(hrefLike, window.location.href) : hrefLike;
      var path = u.pathname + u.search;
      var pre = prefix + '/';
      if (path.indexOf(pre) !== 0) return null;
      var rest = path.slice(pre.length);
      var slash = rest.indexOf('/');
      var seg = slash === -1 ? rest : rest.slice(0, slash);
      var tail = slash === -1 ? '' : rest.slice(slash);
      var origin = decodeHost(seg);
      if (!origin) return null;
      return new URL(origin + tail);
    } catch (e) {
      return null;
    }
  }

  function currentUpstream() {
    return deproxify(window.location.href) || pageBase || null;
  }

  /* ------------------------------------------------------------------ */
  /* シールド (クライアント側 即ブロック)                                 */
  /* ------------------------------------------------------------------ */

  var blockedSet = null;
  function isBlockedHost(host) {
    if (!CFG.shieldsOn) return false;
    if (!blockedSet) {
      blockedSet = new Set(blockedHosts);
    }
    if (!host) return false;
    host = String(host).toLowerCase();
    if (pageBase && host === pageBase.hostname) return false; // 今見ているページ自体は落とさない (広告ドメイン直リンク対策)
    for (var i = 0; i < hostSuffixes.length; i++) {
      var suf = hostSuffixes[i];
      if (host === suf || host.endsWith('.' + suf)) return true;
    }
    return false;
  }
  function clientBlocked(url) {
    try {
      var u = typeof url === 'string' ? new URL(url, pageBase ? pageBase.href : window.location.href) : url;
      if (!u || !/^https?:$/.test(u.protocol)) return false;
      var reg = u.hostname;
      if (!isBlockedHost(reg)) return false;
      stats.blocked++;
      if (blockedByClient.length < 60) blockedByClient.push({ h: u.hostname, t: Date.now() });
      note('shields.client_block', { host: u.hostname });
      return true;
    } catch (e) {
      return false;
    }
  }

  /* ------------------------------------------------------------------ */
  /* サーバへの通知 (薄く軽く)                                            */
  /* ------------------------------------------------------------------ */

  var pending = [];
  var flushTimer = null;
  function note(type, data) {
    pending.push({ type: type, at: Date.now(), sid: sid, data: data || null });
    if (pending.length > 40) flushNotes();
    else if (!flushTimer) flushTimer = setTimeout(flushNotes, 1200);
  }
  function flushNotes() {
    if (flushTimer) {
      clearTimeout(flushTimer);
      flushTimer = null;
    }
    if (!pending.length) return;
    var batch = pending.splice(0, pending.length);
    try {
      var body = JSON.stringify({ events: batch });
      if (navigator.sendBeacon) {
        var ok = navigator.sendBeacon(apiBase + '/events', new Blob([body], { type: 'application/json' }));
        if (ok) return;
      }
      fetch(apiBase + '/events', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: body,
        credentials: 'omit',
        keepalive: true,
      }).catch(function () {});
    } catch (e) {}
  }

  /* ------------------------------------------------------------------ */
  /* location シム                                                       */
  /* ------------------------------------------------------------------ */

  function upstreamOrSelf() {
    return currentUpstream() || new URL(window.location.href);
  }

  function navigate(raw, replace) {
    var p = proxifyMaybe(raw);
    stats.navs++;
    if (!p) {
      try {
        var u = new URL(String(raw), pageBase ? pageBase.href : window.location.href);
        if (u.protocol === 'blob:' || u.protocol === 'data:') {
          window.location[replace ? 'replace' : 'href' === 'x' ? 'assign' : 'assign'](u.href);
          return;
        }
      } catch (e) {}
      return;
    }
    var full = new URL(p, window.location.origin).href;
    if (full === window.location.href) return;
    if (replace) window.location.replace(full);
    else window.location.assign(full);
  }

  var locShim = {
    __isMirage: true,
    get href() {
      return upstreamOrSelf().href;
    },
    set href(v) {
      navigate(v, false);
    },
    get protocol() {
      return upstreamOrSelf().protocol;
    },
    get host() {
      return upstreamOrSelf().host;
    },
    get hostname() {
      return upstreamOrSelf().hostname;
    },
    get port() {
      return upstreamOrSelf().port;
    },
    get pathname() {
      return upstreamOrSelf().pathname;
    },
    get search() {
      return upstreamOrSelf().search;
    },
    set search(v) {
      var u = upstreamOrSelf();
      u.search = v;
      navigate(u.href, false);
    },
    get hash() {
      return upstreamOrSelf().hash;
    },
    set hash(v) {
      var u = upstreamOrSelf();
      u.hash = v;
      navigate(u.href, true);
    },
    get origin() {
      return upstreamOrSelf().origin;
    },
    get ancestorOrigins() {
      return window.location.ancestorOrigins;
    },
    assign: function (v) {
      navigate(v, false);
    },
    replace: function (v) {
      navigate(v, true);
    },
    reload: function (force) {
      if (force) window.location.reload();
      else window.location.replace(window.location.href);
    },
    toString: function () {
      return upstreamOrSelf().href;
    },
  };
  // `__mrg.loc = 'x'` / `__mrg.loc.assign()` など全て从这里。
  var locProxy = {
    __mrg: true,
  };
  Object.keys(locShim).forEach(function (k) {
    var d = Object.getOwnPropertyDescriptor(locShim, k);
    Object.defineProperty(locProxy, k, d);
  });

  /* ------------------------------------------------------------------ */
  /* fetch / XHR                                                         */
  /* ------------------------------------------------------------------ */

  var nativeFetch = window.fetch ? window.fetch.bind(window) : null;
  var nativeXHR = window.XMLHttpRequest;

  function metaHeaders(extra) {
    var h = {};
    h['x-mirage-sid'] = sid;
    h['x-mirage-mode'] = transportMode;
    h['x-mirage-base'] = pageBase ? pageBase.href : '';
    if (extra) for (var k in extra) h[k] = extra[k];
    return h;
  }

  function shouldUseWisp(url) {
    if (transportMode === 'uv') return false;
    if (transportMode === 'auto' && !CFG.wispAvailable) return false;
    var u = safeUrl(url);
    if (!u) return false;
    if (/^https?:$/.test(u.protocol) === false) return false;
    // 大きなレスポンス/ドキュメントは UV (SW→HTTP) のほうが速い
    return true;
  }

  window.__mrg = {
    sid: sid,
    config: CFG,
    stats: stats,
    prefix: prefix,
    api: apiBase,
    proxify: proxify,
    proxifyMaybe: proxifyMaybe,
    deproxify: deproxify,
    loc: locProxy,
    note: note,
    blocked: function () { return blockedByClient.slice(0, 20); },
    upstream: function () { return upstreamOrSelf(); },
    transport: function (mode) {
      transportMode = mode || transportMode;
      try { localStorage.setItem('mirage.mode', transportMode); } catch (e) {}
      note('transport.set', { mode: transportMode });
    },
  };

  /* ---------------- fetch ---------------- */

  function rewriteRequest(input, init) {
    var req = null;
    var rawUrl;
    if (typeof input === 'string' || input instanceof URL) rawUrl = String(input);
    else if (input && typeof input.url === 'string') {
      req = input;
      rawUrl = input.url;
    } else rawUrl = String(input);
    if (isOurOrigin(rawUrl)) return { input: input, init: init, proxied: false };
    if (clientBlocked(resolveAbs(rawUrl))) {
      return { blocked: true };
    }
    var p = proxifyMaybe(rawUrl);
    if (!p) return { input: input, init: init, proxied: false };
    var nextInit = init ? Object.assign({}, init) : {};
    var h = new Headers(nextInit.headers || (req && req.headers) || undefined);
    var meta = metaHeaders();
    for (var k in meta) h.set(k, meta[k]);
    nextInit.headers = h;
    if (req) {
      // Request オブジェクトは headers が immutable なことがある → new Request で作り直す
      try {
        req = new Request(p, req);
      } catch (e) {
        req = null;
      }
    }
    stats.proxied++;
    return { input: req || p, init: nextInit, proxied: true, absUrl: resolveAbs(rawUrl), proxiedPath: p };
  }

  function isOurOrigin(maybeUrl) {
    try {
      var u = new URL(String(maybeUrl), window.location.origin);
      return u.origin === window.location.origin && (u.pathname.indexOf(prefix + '/') === 0 || u.pathname.indexOf(apiBase + '/') === 0 || u.pathname === '/mirage/core.js' || u.pathname.indexOf('/mirage/static') === 0);
    } catch (e) {
      return false;
    }
  }
  function resolveAbs(raw) {
    try {
      return new URL(String(raw), pageBase ? pageBase.href : window.location.href).href;
    } catch (e) {
      return String(raw);
    }
  }
  function safeUrl(v) {
    try {
      return new URL(String(v), pageBase ? pageBase.href : window.location.href);
    } catch (e) {
      return null;
    }
  }

  if (nativeFetch) {
    window.fetch = function (input, init) {
      var r = rewriteRequest(input, init);
      if (r.blocked) return Promise.reject(new TypeError('MirageVPN: request blocked by shields'));
      if (!r.proxied) return nativeFetch(r.input, r.init);
      if (shouldUseWisp(r.absUrl) && window.__mrgWisp) {
        stats.wisp++;
        return window.__mrgWisp.fetch(r.absUrl, r.init).then(function (res) {
          return res;
        });
      }
      return nativeFetch(r.input, r.init);
    };
  }

  /* ---------------- XMLHttpRequest ---------------- */

  function PatchedXHR() {
    var x = new nativeXHR();
    var target = null;
    var openArgs = null;
    var headers = {};
    var origOpen = x.open;
    var origSend = x.send;
    var origSetH = x.setRequestHeader;
    x.open = function (method, url) {
      var abs = resolveAbs(url);
      if (clientBlocked(abs)) {
        openArgs = ['GET', 'about:blank#blocked'];
        target = null;
      } else {
        var p = proxifyMaybe(url) || url;
        openArgs = [method, p].concat([].slice.call(arguments, 2));
        target = abs;
        stats.proxied++;
      }
      return origOpen.apply(x, openArgs);
    };
    x.setRequestHeader = function (k, v) {
      headers[k] = v;
      return origSetH.apply(x, [k, v]);
    };
    x.send = function (body) {
      if (!openArgs) return origSend.call(x, body);
      try {
        origSetH.call(x, 'x-mirage-sid', sid);
        origSetH.call(x, 'x-mirage-mode', transportMode);
        if (target) origSetH.call(x, 'x-mirage-base', target);
      } catch (e) {}
      if (target && shouldUseWisp(target) && window.__mrgWisp) {
        stats.wisp++;
        window.__mrgWisp
          .request(openArgs[0], target, headers, body, { responseType: x.responseType })
          .then(function (r) {
            __mrgXhrDeliver(x, r);
          })
          .catch(function (err) {
            x.dispatchEvent(new Event('error'));
            void err;
          });
        return;
      }
      return origSend.call(x, body);
    };
    Object.defineProperty(x, '__mirageTarget', { get: function () { return target; } });
    return x;
  }
  PatchedXHR.prototype = nativeXHR ? nativeXHR.prototype : {};
  window.__mrgXHR = PatchedXHR;
  if (nativeXHR) {
    window.__mrgNativeXHR = nativeXHR;
    window.XMLHttpRequest = PatchedXHR;
  }

  /** WISP 応答を XHR っぽく届ける (進化的には最小実装: load 時に一括) */
  window.__mrgXhrDeliver = function (x, r) {
    try {
      Object.defineProperties(x, {
        readyState: { value: 4, configurable: true },
        status: { value: r.status, configurable: true },
        statusText: { value: r.statusText || '', configurable: true },
        response: { value: r.body, configurable: true },
        responseText: { value: r.text, configurable: true },
        responseURL: { value: r.url, configurable: true },
        getAllResponseHeaders: { value: function () { return r.headerString || ''; }, configurable: true },
        getResponseHeader: {
          value: function (k) { return r.headers && r.headers[k.toLowerCase()] ? r.headers[k.toLowerCase()] : null; },
          configurable: true,
        },
      });
      x.dispatchEvent(new Event('readystatechange'));
      x.dispatchEvent(new Event('load'));
      x.dispatchEvent(new Event('loadend'));
    } catch (e) {
      /* 内部プロパティを上書きできないブラウザは無視 (素の HTTP 経路にフォールバック) */
    }
  };

  /* ------------------------------------------------------------------ */
  /* WebSocket / EventSource / Worker                                    */
  /* ------------------------------------------------------------------ */

  var NativeWS = window.WebSocket;
  if (NativeWS) {
    function MirageWS(url, protocols) {
      var abs;
      try {
        abs = new URL(String(url), pageBase ? pageBase.origin.replace(/^http/, 'ws') : window.location.origin);
      } catch (e) {
        return new NativeWS(url, protocols);
      }
      if (!/^wss?:$/.test(abs.protocol)) return new NativeWS(url, protocols);
      var target = abs.origin.replace(/^ws/, 'http') + abs.pathname + abs.search;
      var wsBase = window.location.origin.replace(/^http/, 'ws');
      // prefix は既に '/mirage/t/<sid>' を含むことがあるので、sid は常に明示する
      var base = prefix.indexOf('/' + sid) === -1 ? prefix + '/' + sid : prefix;
      var wrapped = wsBase + base + '/ws/' + encodeHost(originOf(new URL(target))) + (new URL(target).pathname || '/') + (new URL(target).search || '');
      stats.proxied++;
      try {
        return new NativeWS(wrapped, protocols || ['mirage-v1']);
      } catch (e) {
        return new NativeWS(url, protocols);
      }
    }
    MirageWS.prototype = NativeWS.prototype;
    MirageWS.CONNECTING = NativeWS.CONNECTING;
    MirageWS.OPEN = NativeWS.OPEN;
    MirageWS.CLOSING = NativeWS.CLOSING;
    MirageWS.CLOSED = NativeWS.CLOSED;
    window.__mrgWS = MirageWS;
    window.__mrgNativeWS = NativeWS;
    try {
      Object.defineProperty(window, 'WebSocket', { value: MirageWS, writable: true, configurable: true });
    } catch (e) {
      window.WebSocket = MirageWS;
    }
  }

  if (window.EventSource) {
    var NativeES = window.EventSource;
    function MirageES(url, opts) {
      var p = proxifyMaybe(url) || url;
      return new NativeES(new URL(p, window.location.origin).href, opts);
    }
    MirageES.prototype = NativeES.prototype;
    window.__mrgEventSource = MirageES;
    window.__mrgNativeEventSource = NativeES;
    window.EventSource = MirageES;
  }

  var NativeWorker = window.Worker;
  if (NativeWorker) {
    function MirageWorker(scriptURL, options) {
      var p = proxifyMaybe(scriptURL);
      if (!p) return new NativeWorker(scriptURL, options);
      var abs = resolveAbs(scriptURL);
      if (clientBlocked(abs)) throw new Error('MirageVPN: worker blocked by shields');
      // クラシックワーカーはブロッブの薄いラッパーにして、importScripts を挂ける余地を残す
      var isModule = options && options.type === 'module';
      if (isModule) {
        return new NativeWorker(new URL(p, window.location.origin).href, options);
      }
      var shim = CFG.workerShimPath || '/mirage/worker.js';
      var src =
        'self.__MIRAGE_CFG=' + JSON.stringify(CFG) + ';' +
        'importScripts(' + JSON.stringify(shim) + ');' +
        'try{importScripts(' + JSON.stringify(new URL(p, window.location.origin).href) + ')}catch(e){' +
        '  if (!navigator.onLine) throw e;' +
        '}';
      try {
        return new NativeWorker(URL.createObjectURL(new Blob([src], { type: 'text/javascript' })), options);
      } catch (e) {
        return new NativeWorker(new URL(p, window.location.origin).href, options);
      }
    }
    MirageWorker.prototype = NativeWorker.prototype;
    window.__mrgWorker = MirageWorker;
    window.__mrgNativeWorker = NativeWorker;
    window.Worker = MirageWorker;
  }

  var nativeImport = self.importScripts ? self.importScripts.bind(self) : null;
  if (nativeImport) {
    self.importScripts = function () {
      var urls = [].slice.call(arguments).map(function (u) {
        return proxifyMaybe(u) || u;
      });
      return nativeImport.apply(null, urls);
    };
  }

  /* ------------------------------------------------------------------ */
  /* Cookie / Document プロパティ                                        */
  /* ------------------------------------------------------------------ */

  var cookieJar = {};
  function parseJar(str) {
    cookieJar = {};
    String(str || '')
      .split(/;\s*/)
      .forEach(function (pair) {
        var i = pair.indexOf('=');
        if (i > 0) cookieJar[pair.slice(0, i).trim()] = pair.slice(i + 1);
      });
  }
  parseJar(cookieMirror);

  function cookieString() {
    return Object.keys(cookieJar)
      .map(function (k) { return k + '=' + cookieJar[k]; })
      .join('; ');
  }
  try {
    Object.defineProperty(document, 'cookie', {
      configurable: true,
      get: function () {
        return cookieString();
      },
      set: function (v) {
        var name = String(v).split('=')[0].trim();
        var m = /max-age\s*=\s*(-?\d+)/i.exec(v);
        var exp = /expires\s*=\s*([^;]+)/i.exec(v);
        var remove = (m && Number(m[1]) <= 0) || (exp && Date.parse(exp[1]) < Date.now());
        if (remove) delete cookieJar[name];
        else {
          var idx = String(v).indexOf('=');
          var val = String(v).slice(idx + 1).split(';')[0];
          cookieJar[name] = val;
        }
        stats.cookies++;
        note('cookie.set', { name: name, removed: !!remove });
        try {
          nativeFetch(apiBase + '/cookies', {
            method: 'POST',
            headers: { 'content-type': 'application/json', 'x-mirage-sid': sid },
            body: JSON.stringify({ sid: sid, url: pageBase ? pageBase.href : location.href, raw: String(v) }),
            credentials: 'omit',
          });
        } catch (e) {}
      },
    });
  } catch (e) {}

  function defineDocProp(name, getter) {
    try {
      Object.defineProperty(document, name, { configurable: true, get: getter });
    } catch (e) {}
  }
  defineDocProp('baseURI', function () {
    return pageBase ? pageBase.href : document.baseURI;
  });
  defineDocProp('documentURI', function () {
    return pageBase ? pageBase.href : document.documentURI;
  });
  defineDocProp('URL', function () {
    return upstreamOrSelf().href;
  });
  defineDocProp('referrer', function () {
    var r = document.referrer;
    if (!r) return '';
    var d = deproxify(r);
    return d ? d.href : r;
  });

  /* ------------------------------------------------------------------ */
  /* 要素プロパティ (src / href / action / ...)                           */
  /* ------------------------------------------------------------------ */

  var URL_PROPS = [
    [window.HTMLAnchorElement, 'href'],
    [window.HTMLAnchorElement, 'protocol'],
    [window.HTMLAnchorElement, 'host'],
    [window.HTMLAnchorElement, 'hostname'],
    [window.HTMLAnchorElement, 'pathname'],
    [window.HTMLAnchorElement, 'search'],
    [window.HTMLAnchorElement, 'hash'],
    [window.HTMLAreaElement, 'href'],
    [window.HTMLScriptElement, 'src'],
    [window.HTMLImageElement, 'src'],
    [window.HTMLImageElement, 'srcset'],
    [window.HTMLSourceElement, 'src'],
    [window.HTMLSourceElement, 'srcset'],
    [window.HTMLIFrameElement, 'src'],
    [window.HTMLIFrameElement, 'srcdoc'],
    [window.HTMLFrameElement, 'src'],
    [window.HTMLLinkElement, 'href'],
    [window.HTMLMediaElement, 'src'],
    [window.HTMLInputElement, 'src'],
    [window.HTMLTrackElement, 'src'],
    [window.HTMLEmbedElement, 'src'],
    [window.HTMLObjectElement, 'data'],
    [window.HTMLFormElement, 'action'],
    [window.HTMLButtonElement, 'formAction'],
    [window.HTMLInputElement, 'formAction'],
    [window.HTMLQuoteElement, 'cite'],
    [window.HTMLModElement, 'cite'],
    [window.HTMLAnchorElement, 'ping'],
  ];

  function patchUrlProp(Ctor, prop) {
    if (!Ctor || !Ctor.prototype) return;
    var proto = Ctor.prototype;
    var desc = Object.getOwnPropertyDescriptor(proto, prop);
    if (!desc || !desc.get || !desc.set) return;
    // これらは「URL 全体」を代入するプロパティ。protocol/host/hostname/... は後段で組み立て直す。
    var isAbsoluteOnly = prop === 'href' || prop === 'src' || prop === 'action' || prop === 'formAction' || prop === 'data';
    try {
      Object.defineProperty(proto, prop, {
        configurable: true,
        enumerable: desc.enumerable,
        get: function () {
          var v = desc.get.call(this);
          if (prop === 'srcdoc') return v;
          var d = v ? deproxify(v) : null;
          return d ? d.href : v;
        },
        set: function (v) {
          if (prop === 'srcdoc' && typeof v === 'string') {
            // srcdoc の中身はサーバ側改写が使えないので、最小の相対 URL だけ proxify する
            var rewritten = String(v).replace(/(src|href)\s*=\s*("|')([^"']+)\2/gi, function (all, k, q, url) {
              var p = proxifyMaybe(url);
              return p ? k + '=' + q + p + q : all;
            });
            return desc.set.call(this, rewritten);
          }
          if (v == null || v === '') return desc.set.call(this, v);
          if (prop === 'srcset' || prop === 'imagesrcset') {
            var out = String(v)
              .split(',')
              .map(function (cand) {
                var m = /^\s*(\S+)(\s+[\d.]+[wx])?\s*$/.exec(cand);
                if (!m) return cand;
                var p = proxifyMaybe(m[1]);
                return (p || m[1]) + (m[2] || '');
              })
              .join(', ');
            return desc.set.call(this, out);
          }
          if (prop === 'ping') {
            var urls = String(v).trim().split(/\s+/).map(function (u) { return proxifyMaybe(u) || u; }).join(' ');
            return desc.set.call(this, urls);
          }
          if (clientBlocked(resolveAbs(v))) {
            return desc.set.call(this, prop === 'src' ? BLOBBASE : '#');
          }
          var abs = null;
          try {
            abs = new URL(String(v), pageBase ? pageBase.href : window.location.href);
          } catch (e) {}
          if (abs && !/^https?:$/.test(abs.protocol)) return desc.set.call(this, v);
          if (isOurOrigin(String(v))) return desc.set.call(this, v);
          if (isAbsoluteOnly) {
            var p2 = proxifyMaybe(v);
            return desc.set.call(this, p2 || v);
          }
          // protocol/host/... への代入は URL を組み立てて assign 相当にする
          var u2 = new URL(desc.get.call(this) || 'about:blank');
          u2[prop] = v;
          var p3 = proxify(u2.href);
          return desc.set.call(this, p3 || u2.href);
        },
      });
    } catch (e) {}
  }
  URL_PROPS.forEach(function (pair) {
    patchUrlProp(pair[0], pair[1]);
  });

  /* ------------------------------------------------------------------ */
  /* history / window                                                    */
  /* ------------------------------------------------------------------ */

  if (window.History && History.prototype.pushState) {
    var nativePush = History.prototype.pushState;
    var nativeReplace = History.prototype.replaceState;
    function rewriteStateUrl(native) {
      return function (state, title, url) {
        if (url == null || url === '') return native.call(this, state, title, url);
        var p = proxifyMaybe(url);
        stats.proxied++;
        return native.call(this, state, title, p || url);
      };
    }
    try {
      History.prototype.pushState = rewriteStateUrl(nativePush);
      History.prototype.replaceState = rewriteStateUrl(nativeReplace);
    } catch (e) {}
  }
  defineGetter(window, 'origin', function () { return pageBase ? pageBase.origin : window.origin; }, window);
  defineGetter(window, 'name', function () { return ''; }, window);
  try {
    Object.defineProperty(window, 'name', { configurable: true, get: function () { return ''; }, set: function () {} });
  } catch (e) {}

  if (containTop) {
    defineGetter(window, 'top', function () { return window; }, window);
    defineGetter(window, 'parent', function () { return window; }, window);
    defineGetter(window, 'frames', function () { return window; }, window);
  }
  defineGetter(window, 'opener', function () { return null; }, window);

  var nativeOpen = window.open;
  if (nativeOpen) {
    window.open = function (url, target, features) {
      if (url == null || url === '' || url === 'about:blank') return nativeOpen.call(window, url, target, features);
      var p = proxifyMaybe(url);
      stats.navs++;
      return nativeOpen.call(window, p ? new URL(p, window.location.origin).href : String(url), target, features);
    };
  }

  function defineGetter(obj, prop, getter, ctx) {
    try {
      Object.defineProperty(obj, prop, { configurable: true, get: getter });
    } catch (e) {
      void ctx;
    }
  }

  /* ------------------------------------------------------------------ */
  /* storage 分離                                                        */
  /* ------------------------------------------------------------------ */

  function storageShim(kind) {
    var native = window[kind];
    if (!native || !isolateStorage) return native;
    var pfx = 'mrg:' + sid + ':';
    var cache = null;
    function load() {
      if (cache) return cache;
      cache = {};
      try {
        for (var i = 0; i < native.length; i++) {
          var k = native.key(i);
          if (k && k.indexOf(pfx) === 0) cache[k.slice(pfx.length)] = native.getItem(k);
        }
      } catch (e) {}
      return cache;
    }
    return {
      get length() {
        return Object.keys(load()).length;
      },
      key: function (i) {
        return Object.keys(load())[i] || null;
      },
      getItem: function (k) {
        var v = load()[k];
        return v === undefined ? null : v;
      },
      setItem: function (k, v) {
        load()[k] = String(v);
        try { native.setItem(pfx + k, String(v)); } catch (e) {}
      },
      removeItem: function (k) {
        delete load()[k];
        try { native.removeItem(pfx + k); } catch (e) {}
      },
      clear: function () {
        var keys = Object.keys(load());
        cache = {};
        keys.forEach(function (k) {
          try { native.removeItem(pfx + k); } catch (e) {}
        });
      },
    };
  }
  if (isolateStorage) {
    try {
      Object.defineProperty(window, 'localStorage', { configurable: true, get: function () { return storageShim('localStorage'); } });
      Object.defineProperty(window, 'sessionStorage', { configurable: true, get: function () { return storageShim('sessionStorage'); } });
    } catch (e) {}
  }

  /* ------------------------------------------------------------------ */
  /* プライバシー強化 (serviceWorker / Notification / Geolocation)        */
  /* ------------------------------------------------------------------ */

  if (blockServiceWorker && navigator.serviceWorker) {
    try {
      Object.defineProperty(navigator, 'serviceWorker', {
        configurable: true,
        value: {
          ready: Promise.resolve({ scope: window.location.origin + prefix + '/' }),
          controller: null,
          register: function () {
            note('sw.blocked_register', {});
            return Promise.reject(new DOMException('MirageVPN: serviceWorker registration is disabled inside the proxy', 'NotAllowedError'));
          },
          getRegistration: function () { return Promise.resolve(undefined); },
          getRegistrations: function () { return Promise.resolve([]); },
          addEventListener: function () {},
          removeEventListener: function () {},
          startMessages: function () {},
          onmessage: null,
        },
      });
    } catch (e) {}
  }
  if (blockNotifications && window.Notification) {
    try {
      window.Notification = function Notification() {
        throw new DOMException('MirageVPN: notifications are blocked', 'NotAllowedError');
      };
      window.Notification.permission = 'denied';
      window.Notification.requestPermission = function () { return Promise.resolve('denied'); };
    } catch (e) {}
  }
  if (CFG.blockGeolocation && navigator.geolocation) {
    try {
      Object.defineProperty(navigator, 'geolocation', {
        configurable: true,
        value: {
          getCurrentPosition: function (ok, err) {
            if (err) err({ code: 1, message: 'blocked by MirageVPN' });
          },
          watchPosition: function () { return 0; },
          clearWatch: function () {},
        },
      });
    } catch (e) {}
  }
  if (CFG.stripCredentials !== false) {
    // フィンチングに使われやすい API の即席ブロック (必要なら設定で解除)
    var deny = {
      Bluetooth: 'navigator.bluetooth',
      USB: 'navigator.usb',
      Serial: 'navigator.serial',
      HID: 'navigator.hid',
    };
    Object.keys(deny).forEach(function (k) {
      try {
        var path = deny[k].split('.');
        var root = window[path[0]];
        if (root && path[1] in root) Object.defineProperty(root, path[1], { configurable: true, value: undefined });
      } catch (e) {}
    });
  }

  /* ------------------------------------------------------------------ */
  /* document.write 対応 (相対 URL を含む HTML 文字列をサーバへ投げて改写してもらう) */
  /* ------------------------------------------------------------------ */

  var nativeWrite = document.write;
  var nativeWriteln = document.writeln;
  function rewriteSync(html) {
    // 同期的に返す必要があるので、ローカルで軽い改写に留める (属性内の絶対 URL を proxify)
    return String(html).replace(/(src|href|action|formaction|poster|data|srcset)\s*=\s*("|')([^"']+)\2/gi, function (all, key, q, url) {
      var p = proxifyMaybe(url);
      return p ? key + '=' + q + p + q : all;
    });
  }
  if (nativeWrite) {
    document.write = function () {
      var s = [].slice.call(arguments).map(rewriteSync).join('');
      stats.rewritten = (stats.rewritten || 0) + 1;
      return nativeWrite.call(document, s);
    };
  }
  if (nativeWriteln) {
    document.writeln = function () {
      var s = [].slice.call(arguments).map(rewriteSync).join('') + '\n';
      return nativeWriteln.call(document, s);
    };
  }

  /* ------------------------------------------------------------------ */
  /* ページタイトル / URL の同期 + ハートビート                            */
  /* ------------------------------------------------------------------ */

  function reportState() {
    var u = upstreamOrSelf();
    note('tab.state', { url: u.href, title: document.title || u.hostname });
  }
  if (CFG.reportTabs !== false) {
    document.addEventListener('DOMContentLoaded', function () {
      reportState();
      try {
        new MutationObserver(function () {
          if (!flushTimer) {
            clearTimeout(flushTimer);
            flushTimer = setTimeout(reportState, 800);
          }
        }).observe(document.head || document.documentElement, { childList: true, subtree: true, characterData: true });
      } catch (e) {}
    });
    window.addEventListener('popstate', function () {
      reportState();
    });
    window.addEventListener('beforeunload', flushNotes);
  }

  /* ------------------------------------------------------------------ */
  /* form submit / a click の取りこぼし対策                               */
  /* ------------------------------------------------------------------ */

  document.addEventListener(
    'submit',
    function (ev) {
      var form = ev.target;
      if (!form || !form.action) return;
      var d = deproxify(form.action);
      if (d) return; // すでに proxied
      var p = proxifyMaybe(form.action);
      if (p) {
        form.action = new URL(p, window.location.origin).href;
      }
    },
    true,
  );

  /* ------------------------------------------------------------------ */
  /* サーバからの指示 (base 更新 / 設定反映)                               */
  /* ------------------------------------------------------------------ */

  window.__mrgApply = function (patch) {
    if (!patch || typeof patch !== 'object') return;
    if (patch.base) {
      try {
        pageBase = new URL(patch.base);
      } catch (e) {}
    }
    if (patch.cookies != null) parseJar(patch.cookies);
    if (patch.shieldsOn !== undefined) CFG.shieldsOn = !!patch.shieldsOn;
    if (patch.blockedHosts) {
      blockedHosts = patch.blockedHosts;
      blockedSet = null;
    }
    if (patch.mode) transportMode = patch.mode;
  };

  // リダイレクトで最終 URL が変わった → アドレスバー (our path) を同期
  if (CFG.finalUrl && pageBase && CFG.finalUrl !== pageBase.href) {
    try {
      pageBase = new URL(CFG.finalUrl);
      var p = proxify(CFG.finalUrl);
      if (p) history.replaceState(history.state, '', new URL(p, window.location.origin).href);
    } catch (e) {}
  }

  /* ------------------------------------------------------------------ */
  /* WISP (ページ側クライアント) — rewriter が core.js より前に読んでいる  */
  /* ------------------------------------------------------------------ */

  function initWisp() {
    if (window.__mrgWisp) return true;
    var Ctor = window.MirageWisp && window.MirageWisp.WispClient;
    if (!Ctor || !CFG.wispUrl) return false;
    try {
      var c = new Ctor({
        url: CFG.wispUrl,
        sid: sid,
        mode: transportMode,
        retries: CFG.wispRetries || 2,
        connectTimeoutMs: CFG.wispConnectTimeoutMs || 3500,
        pageUrl: pageBase ? pageBase.href : null,
      });
      window.__mrgWisp = c;
      window.__mrgWispStats = function () { return c.statsSnapshot(); };
      var pr = c.connect();
      if (pr && pr.catch) pr.catch(function () { window.__mrgWispDown = true; });
      return true;
    } catch (e) {
      window.__mrgWisp = null;
      return false;
    }
  }
  if (transportMode !== 'uv') initWisp();
  // 「auto」は最初の数リクエストで WISP が生きているかを見る。死んでいたら UV に固定。
  if (transportMode === 'auto') {
    setTimeout(function () {
      if (!window.__mrgWisp || (window.__mrgWispDown || (window.__mrgWisp.statsSnapshot && window.__mrgWisp.statsSnapshot().disabledUntil > Date.now()))) {
        transportMode = 'uv';
        try { window.__mrg && (window.__mrg.config.wispAvailable = false); } catch (e) {}
        note('transport.auto_downgrade', { to: 'uv' });
      }
    }, 2500);
  }

  note('page.ready', { url: upstreamOrSelf().href, mode: transportMode, wisp: !!window.__mrgWisp });
})();
