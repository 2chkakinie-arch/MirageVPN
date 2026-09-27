/**
 * MirageVPN — UI コントローラ (ビルド不要・依存ゼロ)
 * ---------------------------------------------------------------
 * 役割:
 *  ・タブ管理 (各タブ = 1 つの sid → サーバ側でジャー/出口/脅威が分離される)
 *  ・アドレスバー (検索と URL を /mirage/api/url で解決 → プロキシ URL を iframe へ)
 *  ・出口ピッカー (GitHub 由来プールの国籍別表示・実出口の検証)
 *  ・脅威フィード (poll → diff → 「自動削除済み / 遮断」表示)
 *  ・設定 (Brave 風のシールドトグル含め、サーバの settings に保存 + SW へ localStorage で伝搬)
 *  ・サーマル: statusbar のスパークライン (req/s, B/s)
 * 状態は原則サーバが持つ (UI は薄い)。localStorage は SW との共有にだけ使う。
 */
/* global window, document, location, navigator, customElements */

const API = '/mirage/api';
const LS = { mode: 'mirage.mode', lang: 'mirage.lang', theme: 'mirage.theme', recent: 'mirage.recent' };
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const el = (tag, props = {}, kids = []) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') n.className = v;
    else if (k === 'html') n.innerHTML = v;
    else if (k === 'text') n.textContent = v;
    else if (k === 'dataset') Object.assign(n.dataset, v);
    else if (k.startsWith('on') && typeof v === 'function') n.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null && v !== false) n.setAttribute(k, v === true ? '' : v);
  }
  for (const c of [].concat(kids)) if (c) n.append(c.nodeType ? c : document.createTextNode(c));
  return n;
};

/* ------------------------------------------------------------------ */
/* i18n                                                               */
/* ------------------------------------------------------------------ */

const I18N = {
  ja: {
    openFailed: '開けませんでした',
    newTab: '新規タブ',
    connected: '接続中',
    egressAuto: '自動 (最適)',
    verified: 'この国から出ています',
    notVerified: '出口を検証できませんでした (direct にフォールバック中)',
    poolUpdated: 'プロキシリストを更新しました',
    poolProbed: '健全性チェック完了',
    shieldsOn: (n) => `シールド: ${n} 件ブロック`,
    threatFound: (l) => `脅威を検知・自動除去: ${l}`,
    threatBlock: (l) => `脅威を遮断: ${l}`,
    settingsSaved: '設定を保存しました',
    panic: '全タブとセッション情報を破棄しました',
    cleared: 'レポート履歴を削除しました',
    allowed: (d) => `${d} のシールドを一時的に解除しました`,
    blockedSite: (d) => `${d} のシールドを再有効化しました`,
    modeSet: (m) => `転送モードを ${m} に切り替えました`,
    reloadNeeded: '新しいタブで反映されます',
    speedMeasured: (v) => `実測スループット: ${v}`,
  },
  en: {
    openFailed: 'Failed to open',
    newTab: 'New tab',
    connected: 'Connected',
    egressAuto: 'Auto (best)',
    verified: 'Your traffic exits from this country',
    notVerified: 'Could not verify the exit (falling back to direct)',
    poolUpdated: 'Proxy list refreshed',
    poolProbed: 'Health check finished',
    shieldsOn: (n) => `Shields: ${n} blocked`,
    threatFound: (l) => `Threat auto-stripped: ${l}`,
    threatBlock: (l) => `Threat blocked: ${l}`,
    settingsSaved: 'Settings saved',
    panic: 'All tabs and session data destroyed',
    cleared: 'Report history purged',
    allowed: (d) => `Shields relaxed for ${d}`,
    blockedSite: (d) => `Shields re-enabled for ${d}`,
    modeSet: (m) => `Transport set to ${m}`,
    reloadNeeded: 'Applies to new tabs',
    speedMeasured: (v) => `Measured throughput: ${v}`,
  },
};
const lang = () => localStorage.getItem(LS.lang) || 'ja';
const t = (key, ...a) => {
  const v = (I18N[lang()] || I18N.ja)[key] ?? I18N.ja[key] ?? key;
  return typeof v === 'function' ? v(...a) : v;
};

/* ------------------------------------------------------------------ */
/* API client                                                          */
/* ------------------------------------------------------------------ */

let clientIdCookie = '';
async function api(path, opts = {}) {
  const init = { method: opts.method || (opts.body ? 'POST' : 'GET'), credentials: 'same-origin', headers: { ...(opts.headers || {}) } };
  if (opts.body !== undefined) {
    init.headers['content-type'] = 'application/json';
    init.body = typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body);
  }
  if (clientIdCookie) init.headers['x-mirage-client'] = clientIdCookie;
  // Never leave the UI waiting forever when a serverless cold start or upstream stalls.
  init.signal = AbortSignal.timeout(opts.timeoutMs || 12000);
  const res = await fetch(API + path, init);
  const ct = res.headers.get('content-type') || '';
  const data = ct.includes('json') ? await res.json().catch(() => null) : await res.text();
  if (!res.ok) throw Object.assign(new Error((data && data.message) || (data && data.error) || `HTTP ${res.status}`), { status: res.status, data });
  return data;
}

/* ------------------------------------------------------------------ */
/* state                                                              */
/* ------------------------------------------------------------------ */

const state = {
  tabs: [], // {id, sid, title, url, host, blocked, threat, ready, favicon}
  active: null,
  status: null,
  settings: null,
  threats: { seen: new Set(), events: [], totals: null, topRules: [] },
  countries: [],
  pool: { items: [], total: 0 },
  selectedCountry: 'AUTO',
  strategy: 'auto',
  protocols: '',
  panel: null,
  metrics: null,
  lastVerify: null,
  speed: null,
};

const uid = (n = 8) => Math.random().toString(36).slice(2, 2 + n);
const fmtBps = (b) => (b > 1048576 ? `${(b / 1048576).toFixed(1)} MB/s` : b > 1024 ? `${(b / 1024).toFixed(0)} KB/s` : `${b} B/s`);
const fmtNum = (n) => (n == null ? '—' : n >= 10000 ? `${(n / 1000).toFixed(1)}k` : String(n));
const hostOf = (u) => {
  try {
    return new URL(u).host;
  } catch {
    return '';
  }
};

/* ------------------------------------------------------------------ */
/* toasts / modal                                                      */
/* ------------------------------------------------------------------ */

function toast(msg, tone = '', ms = 4200) {
  const node = el('div', { class: 'toast', dataset: { tone } }, [el('span', { class: 't-ico', text: tone === 'bad' ? '⚠' : tone === 'ok' ? '✓' : '◆' }), el('span', { text: msg })]);
  $('#toasts').append(node);
  setTimeout(() => {
    node.style.transition = 'opacity 260ms, transform 260ms';
    node.style.opacity = '0';
    node.style.transform = 'translateY(6px)';
    setTimeout(() => node.remove(), 280);
  }, ms);
}

function modal(title, bodyNode) {
  const m = $('#modal');
  const card = $('#modalCard');
  card.textContent = '';
  card.append(el('h3', { text: title }), bodyNode, el('div', { class: 'verify-actions' }, [el('button', { class: 'btn', text: '閉じる', onclick: () => (m.hidden = true) })]));
  m.hidden = false;
  m.onclick = (e) => {
    if (e.target === m) m.hidden = true;
  };
}

/* ------------------------------------------------------------------ */
/* tabs                                                              */
/* ------------------------------------------------------------------ */

function newTab(url = '', { activate = true } = {}) {
  const id = uid(10);
  const sid = id.replace(/[^a-z0-9]/gi, '').slice(0, 16);
  const tab = { id, sid, title: url ? hostOf(url) : '', url, host: hostOf(url), blocked: 0, threat: 0, ready: false };
  state.tabs.push(tab);
  if (activate) state.active = id;
  renderTabs();
  renderFrames();
  if (url) loadTab(tab, url);
  else {
    $('#hero').hidden = false;
    renderHero();
  }
  api('/tabs/open', { body: { sid, url, title: tab.title || 'New tab', mode: state.settings?.mode } }).catch(() => {});
  return tab;
}

function closeTab(id) {
  const i = state.tabs.findIndex((t2) => t2.id === id);
  if (i === -1) return;
  const [gone] = state.tabs.splice(i, 1);
  fetch(`iframe-${gone.sid}`)?.remove();
  api('/tabs/close', { body: { sid: gone.sid } }).catch(() => {});
  if (state.active === id) state.active = state.tabs.at(-1)?.id || null;
  renderTabs();
  renderFrames();
  if (!state.tabs.length) {
    $('#hero').hidden = false;
    renderHero();
  }
}

function activateTab(id) {
  state.active = id;
  renderTabs();
  renderFrames();
  const tab = activeTab();
  const input = $('#address');
  if (input) input.value = tab ? tab.url : '';
  syncShieldToggle();
}

const activeTab = () => state.tabs.find((t2) => t2.id === state.active) || null;

async function loadTab(tab, rawInput) {
  const input = String(rawInput || '').trim();
  if (!input) return;
  let res;
  try {
    res = await api(`/url?sid=${encodeURIComponent(tab.sid)}&q=${encodeURIComponent(input)}`);
  } catch (err) {
    toast(`${t('openFailed')}: ${err.message}`, 'bad');
    return;
  }
  if (res.error) {
    toast(res.error, 'bad');
    return;
  }
  const target = res.proxied || res.url;
  if (!target) {
    toast(t('openFailed'), 'bad', 5200);
    return;
  }
  tab.url = res.url || input;
  tab.type = res.type;
  tab.host = hostOf(tab.url);
  tab.title = tab.host || input;
  renderTabs();
  const frame = $(`#iframe-${tab.sid}`);
  if (frame) {
    frame.dataset.target = tab.url;
    frame.src = target;
  }
  pushRecent({ url: tab.url, title: tab.title, at: Date.now() });
}

function pushRecent(item) {
  try {
    const list = JSON.parse(localStorage.getItem(LS.recent) || '[]').filter((r) => r.url !== item.url);
    list.unshift(item);
    localStorage.setItem(LS.recent, JSON.stringify(list.slice(0, 24)));
  } catch (e) {
    /* ignore */
  }
}

function renderTabs() {
  const wrap = $('#tabs');
  wrap.textContent = '';
  for (const tab of state.tabs) {
    const node = el(
      'div',
      {
        class: `tab${tab.id === state.active ? ' active' : ''}`,
        role: 'tab',
        'aria-selected': tab.id === state.active ? 'true' : 'false',
        tabindex: '0',
        onclick: (e) => {
          if (e.target.closest('.x')) return;
          activateTab(tab.id);
        },
        onkeydown: (e) => {
          if (e.key === 'Enter') activateTab(tab.id);
        },
      },
      [
        el('span', { class: 'fav', html: tab.favicon ? `<img src="${escapeAttr(tab.favicon)}" alt="">` : tab.ready ? '🔒' : '◇' }),
        el('span', { class: 'ttl', text: tab.title || t('newTab') }),
        el('span', { class: 'meta' }, [
          tab.blocked ? el('span', { class: 'chip b', title: 'blocked', text: String(tab.blocked) }) : null,
          tab.threat ? el('span', { class: 'chip t', title: 'threats', text: String(tab.threat) }) : null,
          el('button', {
            class: 'x',
            title: '閉じる (Ctrl/⌘+W)',
            'aria-label': 'タブを閉じる',
            text: '✕',
            onclick: (e) => {
              e.stopPropagation();
              closeTab(tab.id);
            },
          }),
        ]),
      ],
    );
    wrap.append(node);
  }
}

function renderFrames() {
  const wrap = $('#frames');
  for (const tab of state.tabs) {
    if (!$(`#iframe-${tab.sid}`)) {
      const f = el('iframe', {
        id: `iframe-${tab.sid}`,
        'data-sid': tab.sid,
        allow: 'fullscreen; clipboard-write; autoplay',
        referrerpolicy: 'no-referrer',
        onload: () => {
          tab.ready = true;
          try {
            const doc = f.contentDocument;
            if (doc && doc.title) tab.title = doc.title.slice(0, 90);
            if (doc) {
              const icon = doc.querySelector('link[rel~="icon"]');
              if (icon?.href) tab.favicon = absolutizeIcon(icon.href, tab.url);
            }
          } catch (e) {
            /* cross-origin: core.js の event が補う */
          }
          renderTabs();
        },
      });
      wrap.append(f);
    }
    const node = $(`#iframe-${tab.sid}`);
    node.classList.toggle('active', tab.id === state.active);
  }
  $('#hero').hidden = state.tabs.length > 0;
  if (!state.tabs.length) renderHero();
}

function absolutizeIcon(href, pageUrl) {
  try {
    return new URL(href, pageUrl).href;
  } catch {
    return null;
  }
}
const escapeAttr = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

/* ------------------------------------------------------------------ */
/* hero (start page)                                                  */
/* ------------------------------------------------------------------ */

const QUICK = [
  { label: 'Wikipedia', url: 'https://ja.wikipedia.org', g: '📖' },
  { label: 'GitHub', url: 'https://github.com', g: '🐙' },
  { label: 'YouTube', url: 'https://www.youtube.com', g: '▶' },
  { label: 'Reddit', url: 'https://www.reddit.com', g: '👽' },
  { label: 'Twitch', url: 'https://www.twitch.tv', g: '🎮' },
  { label: 'nyan.cat', url: 'https://nyan.cat', g: '🐱' },
  { label: 'example.com', url: 'http://example.com', g: '🧪' },
];

function renderHero() {
  const quick = $('#heroQuick');
  const recent = (() => {
    try {
      return JSON.parse(localStorage.getItem(LS.recent) || '[]').slice(0, 6);
    } catch {
      return [];
    }
  })();
  quick.textContent = '';
  for (const q of QUICK) {
    quick.append(el('button', { class: 'quick', onclick: () => openFromHero(q.url), title: q.url }, [el('span', { class: 'g', text: q.g }), q.label]));
  }
  for (const r of recent) {
    quick.append(el('button', { class: 'quick', onclick: () => openFromHero(r.url), title: r.url }, [el('span', { class: 'g', text: '🕘' }), (r.title || hostOf(r.url)).slice(0, 22)]));
  }
  const s = state.status;
  const stats = $('#heroStats');
  stats.textContent = '';
  const cards = s
    ? [
        ['transport', `${s.transport.mode.toUpperCase()}${s.capabilities.wisp ? ' + WISP' : ''}`, s.capabilities.wisp ? 'UV 既定 / WISP 併用可' : 'Vercel 等では UV のみ'],
        ['egress', s.egress.strategy.toUpperCase(), `${s.egress.country === 'AUTO' ? t('egressAuto') : s.egress.country} · ${fmtNum(s.egress.pool.size)} proxies`],
        ['shields', fmtNum(s.shields.blocked), `${fmtNum(s.shields.rules)} rules`],
        ['threats', fmtNum(s.threats.events), s.threats.autoDelete ? '自動削除 ON' : '自動削除 OFF'],
      ]
    : [['status', '—', '読み込み中…']];
  for (const [k, v, sub] of cards) stats.append(el('div', { class: 'hs' }, [el('div', { class: 'k', text: k }), el('div', { class: 'v', text: v }), el('div', { class: 's', text: sub })]));
}

function openFromHero(input) {
  const tab = activeTab() || newTab('');
  loadTab(tab, input);
}

/* ------------------------------------------------------------------ */
/* panels                                                            */
/* ------------------------------------------------------------------ */

function togglePanel(name) {
  const next = state.panel === name ? null : name;
  state.panel = next;
  for (const p of ['panelEgress', 'panelThreats', 'panelSettings']) {
    const node = $(`#${p}`);
    if (node) node.hidden = p !== next;
  }
  $$('#shell .nav-group .ico').forEach((b) => b.classList.remove('on'));
  if (next === 'panelEgress') $('#btnEgress').classList.add('on');
  if (next === 'panelThreats') $('#btnThreats').classList.add('on');
  if (next === 'panelSettings') $('#btnSettings').classList.add('on');
  if (next === 'panelEgress') {
    renderCountries();
    renderPoolTable();
  }
  if (next === 'panelThreats') renderThreats();
  if (next === 'panelSettings') renderSettings();
}

/* ---------- egress ---------- */

function renderCountries() {
  const grid = $('#countryGrid');
  const filter = ($('#countryFilter').value || '').trim().toLowerCase();
  grid.textContent = '';
  grid.append(
    el('button', {
      class: 'cc auto',
      'aria-pressed': state.selectedCountry === 'AUTO' ? 'true' : 'false',
      onclick: () => setCountry('AUTO'),
      title: '最も速い出口を自動選択',
    }, [el('span', { class: 'f', text: '🌐' }), el('span', { class: 'n' }, [el('b', { text: t('egressAuto') }), el('i', { text: 'latency + health' })])]),
  );
  const list = state.countries.filter((c) => {
    if (!filter) return true;
    return `${c.country} ${c.name || ''} ${c.region || ''}`.toLowerCase().includes(filter);
  });
  $('#countryCount').textContent = `${list.length} カ国 / ${fmtNum(state.status?.egress?.pool?.size ?? 0)} 生息`;
  for (const c of list.slice(0, 220)) {
    grid.append(
      el(
        'button',
        {
          class: 'cc',
          title: `${c.name || c.country} — healthy ${c.alive}/${c.total}${c.avgLatencyMs ? ` · ${c.avgLatencyMs}ms` : ''}`,
          'aria-pressed': state.selectedCountry === c.country ? 'true' : 'false',
          onclick: () => setCountry(c.country),
        },
        [
          el('span', { class: 'f', text: c.flag || '🏳️' }),
          el('span', { class: 'n' }, [el('b', { text: c.name || c.country }), el('i', { text: `${c.region || ''} ${c.avgLatencyMs ? c.avgLatencyMs + 'ms' : ''}`.trim() })]),
          el('span', { class: 'c', text: `${c.alive || c.total}` }),
        ],
      ),
    );
  }
}

async function setCountry(cc) {
  state.selectedCountry = cc;
  renderCountries();
  try {
    await api('/pool/country', { body: { country: cc }, method: 'POST' });
    toast(`${cc === 'AUTO' ? t('egressAuto') : cc} を出口に指定しました — ${t('reloadNeeded')}`, 'ok', 3200);
  } catch (err) {
    toast(err.message, 'bad');
  }
  refreshStatus();
}

function renderPoolTable() {
  const tb = $('#poolTable tbody');
  tb.textContent = '';
  const items = state.pool.items || [];
  const maxLat = Math.max(...items.map((p) => p.latencyMs || 0), 1);
  for (const p of items.slice(0, 40)) {
    const st = p.banned ? 'st-ban' : p.checked ? (p.latencyMs ? 'st-ok' : 'st-new') : 'st-new';
    tb.append(
      el('tr', {}, [
        el('td', { text: `${p.flag || ''} ${p.country || 'XX'}` }),
        el('td', { html: `<span class="mono">${escapeAttr(p.host)}:${p.port}</span>` }),
        el('td', { text: p.protocol }),
        el('td', { class: 'r' }, [p.latencyMs ? `${p.latencyMs}` : '—', el('div', { class: 'bar', html: `<i style="width:${p.latencyMs ? Math.max(6, Math.round(100 - (p.latencyMs / maxLat) * 100)) : 4}%"></i>` })]),
        el('td', { class: 'r' }, [el('span', { class: `st ${st}`, text: p.banned ? 'BAN' : String(p.score ?? 0) })]),
      ]),
    );
  }
  if (!items.length) {
    tb.append(el('tr', {}, [el('td', { colspan: '5', class: 'muted', text: 'プールが空です — 「リスト更新」を押すか、サーバの取得を待ってください。' })]));
  }
}

/** GitHub から自動取得しているプロキシリストの健全性 (status.lists から作る — 追加リクエスト不要) */
function renderListFeed(lists) {
  const box = $('#listFeed');
  const next = $('#listNext');
  if (!box) return;
  const src = lists?.sources || [];
  if (next) {
    const ms = lists?.nextRefreshInMs;
    next.textContent = lists?.refreshMs
      ? ms > 0 && ms < lists.refreshMs
        ? `次回 ${Math.max(1, Math.round(ms / 60000))}分後`
        : '取得中…'
      : '自動更新 OFF';
  }
  if (!src.length) {
    box.textContent = '';
    box.append(el('div', { class: 'empty', text: 'リストソースが未設定です (MIRAGE_LIST_SOURCES)。同梱シードだけで動いています。' }));
    return;
  }
  const rows = [...src].sort((a, b) => (b.count || 0) - (a.count || 0));
  const frag = document.createDocumentFragment();
  let okN = 0;
  let total = 0;
  for (const it of rows) {
    const st = it.count ? 'ok' : it.last?.error ? 'bad' : 'warn';
    if (it.count) okN++;
    total += it.count || 0;
    const badge = it.count
      ? `${fmtNum(it.count)} 件`
      : it.last?.error
        ? String(it.last.error).slice(0, 24)
        : '未取得';
    frag.append(
      el('div', { class: 'lf', dataset: { st } }, [
        el('span', { class: 'n', text: String(it.label || it.id || '').replace(/-/g, ' · ') }),
        el('span', { class: 'c', text: it.fail ? `${it.ok}✓ ${it.fail}✗` : '' }),
        el('span', { class: 's', text: badge }),
      ]),
    );
  }
  box.textContent = '';
  box.append(frag);
  box.title = `${okN}/${rows.length} ソースが取得成功・合計 ${fmtNum(total)} 件`;
}

async function verifyExit() {
  const btn = $('#btnVerify');
  btn.classList.add('loading');
  try {
    const r = await api(`/egress/verify?sid=${encodeURIComponent(activeTab()?.sid || 'ui')}`);
    state.lastVerify = r;
    const ok = r.ok && r.attempts?.find((a) => a.ok);
    $('#verifyExit').textContent = ok ? `${ok.exitIp || '?'} · ${ok.country || '?'} ${ok.countryName || ''}` : '—';
    $('#verifyExit').className = `v ${ok ? 'ok' : 'bad'}`;
    $('#verifySent').textContent = r.matched ? '秘匿 OK' : '出口 = 自分自身 (direct)';
    $('#verifyNote').textContent = ok ? `${t('verified')} (${ok.via})` : t('notVerified');
    toast(ok ? t('verified') : t('notVerified'), ok ? 'ok' : 'warn');
  } catch (err) {
    $('#verifyNote').textContent = err.message;
    toast(err.message, 'bad');
  } finally {
    btn.classList.remove('loading');
  }
}

/* ---------- threats ---------- */

const SEV_ICON = { danger: '🚨', warn: '⚠️', info: 'ℹ️', good: '✅' };

function renderThreats() {
  const feed = $('#threatFeed');
  const rep = state.threats;
  $('#threatTotal').textContent = rep.totals ? `${rep.totals.events} events` : '';
  const cards = $('#threatCards');
  cards.textContent = '';
  const tot = rep.totals || {};
  for (const [k, v, tone] of [
    ['events', tot.events || 0, ''],
    ['auto-stripped', tot.stripped || 0, 'ok'],
    ['blocked', (tot.blocked || 0) + (tot.quarantined || 0), 'bad'],
    ['hardened', tot.hardened || 0, 'ok'],
    ['warned', tot.warned || 0, 'warn'],
  ]) {
    cards.append(el('div', { class: 'card', dataset: { tone } }, [el('div', { class: 'k', text: k }), el('div', { class: 'v', text: String(v) })]));
  }
  feed.textContent = '';
  const evs = (rep.events || []).slice(0, 60);
  if (!evs.length) feed.append(el('div', { class: 'note', text: '検知はありません 🎉 — 脅威エンジンが URL・DOM・ダウンロード・認証情報の 4 層を常時見張っています。' }));
  for (const e of evs) {
    const pill = e.action?.startsWith('strip') || e.action === 'drop-asset' ? 'pill-strip' : e.action === 'block' || e.action === 'quarantine' ? 'pill-block' : e.color === 'warn' ? 'pill-warn' : 'pill-info';
    const act = e.action ? e.action.replace(/-/g, ' ') : '記録のみ';
    feed.append(
      el('div', { class: 'ev', dataset: { color: e.color || 'info' } }, [
        el('div', { text: SEV_ICON[e.color] || 'ℹ️' }),
        el('div', { class: 'body' }, [
          el('div', { class: 'lbl' }, [e.label || e.code, el('span', { class: 'score', text: `score ${e.score}` })]),
          el('div', { class: 'host', text: `${e.host || ''}${e.sid ? ` · tab ${e.sid.slice(0, 6)}` : ''}` }),
          e.evidence ? el('div', { class: 'evd', text: String(e.evidence).slice(0, 200) }) : null,
        ]),
        el('div', { class: 'act' }, [
          el('span', { class: `pill ${pill}`, text: act }),
          e.sid && e.host
            ? el('button', {
                class: 'mini',
                text: 'このホストを常に許可',
                onclick: async () => {
                  await api('/shields/domain', { body: { domain: e.host, allow: false }, method: 'POST' }).catch(() => {});
                  await api('/threats/purge', { body: { codes: [e.code], sid: e.sid }, method: 'POST' }).catch(() => {});
                  toast(t('allowed', e.host), 'ok');
                  refreshStatus();
                },
              })
            : null,
        ]),
      ]),
    );
  }
  const rules = $('#threatRules');
  rules.textContent = '';
  const top = (rep.topRules || []).slice(0, 8);
  if (top.length) {
    rules.append(el('h3', { class: 'panel-sub', text: 'ルール別ヒット' }));
    const max = top[0].hits || 1;
    for (const r of top) {
      rules.append(
        el('div', { class: 'rule' }, [
          el('span', { class: 'nowrap', text: r.rule.slice(0, 34) }),
          el('span', { class: 'bar', html: `<i style="width:${Math.max(8, Math.round((r.hits / max) * 100))}%"></i>` }),
          el('span', { class: 'n', text: String(r.hits) }),
        ]),
      );
    }
  }
}

/* ---------- settings ---------- */

const SETTING_ROWS = [
  {
    group: 'transport',
    items: [
      { key: 'mode', label: '転送モード', hint: 'UV=既定(高速) / WISP=多重トンネル / auto=自動', type: 'select', options: [['uv', 'UV (fast · 既定)'], ['wisp', 'WISP (multiplexed)'], ['auto', 'auto (能力判定)']] },
      { key: 'advanced.cache', label: 'アセットキャッシュ', hint: '改写済みの js/css をメモリに保持', type: 'bool' },
    ],
  },
  {
    group: 'shields',
    items: [
      { key: 'shields.enabled', label: 'シールド (広告/トラッカー遮断)', hint: 'Brave と同じ発想のネットワーク遮断', type: 'bool' },
      { key: 'shields.level', label: 'レベル', hint: 'aggressive は 3 者 beacon も止める', type: 'select', options: [['standard', 'standard'], ['aggressive', 'aggressive'], ['off', 'off']] },
      { key: 'shields.cosmetic', label: '要素の非表示化 (cosmetic)', hint: '広告枠そのものを CSS で消す', type: 'bool' },
    ],
  },
  {
    group: 'threats',
    items: [
      { key: 'threats.enabled', label: '脅威検知', hint: 'URL / DOM / Asset / Download の 4 層', type: 'bool' },
      { key: 'threats.autoDelete', label: '危険要素の自動削除', hint: 'sanitizeScore 以上でその場で除去', type: 'bool' },
      { key: 'threats.sanitizeScore', label: '自動削除の閾値', hint: '0-100 (既定 40)', type: 'range', min: 0, max: 100 },
      { key: 'threats.blockScore', label: '遮断の閾値', hint: '0-100 (既定 80)', type: 'range', min: 0, max: 100 },
      { key: 'threats.credentialGuard', label: '認証情報の漏洩ガード', hint: '偽フォームへの POST を止める', type: 'bool' },
      { key: 'threats.blockDangerousDownloads', label: '危険なファイル形式を止める', hint: '.exe/.jar など', type: 'bool' },
    ],
  },
  {
    group: 'privacy',
    items: [
      { key: 'privacy.containTop', label: 'フレーム内封じ込め', hint: 'proxy 画面が top window を乗っ取れないようにする', type: 'bool' },
      { key: 'privacy.isolateStorage', label: 'サイトごとに localStorage を分離', hint: 'タブ/サイト毎に隔離', type: 'bool' },
      { key: 'privacy.blockNotifications', label: '通知をブロック', type: 'bool' },
      { key: 'privacy.blockServiceWorker', label: 'サイトの ServiceWorker を禁止', type: 'bool' },
      { key: 'privacy.blockGeolocation', label: '位置情報をブロック', type: 'bool' },
      { key: 'privacy.stripCredentials', label: 'URL 内のユーザー名/パスワードを除去', type: 'bool' },
    ],
  },
  {
    group: 'appearance',
    items: [
      { key: 'ui.theme', label: 'テーマ', type: 'select', options: [['aurora', 'aurora (dark)'], ['light', 'light']] },
      { key: 'ui.lang', label: '言語', type: 'select', options: [['ja', '日本語'], ['en', 'English']] },
      { key: 'ui.showThreatTicker', label: '脅威トーストを表示', type: 'bool' },
    ],
  },
];

const getPath = (obj, p) => p.split('.').reduce((a, k) => (a == null ? a : a[k]), obj);
const setPath = (obj, p, v) => {
  const keys = p.split('.');
  let cur = obj;
  while (keys.length > 1) cur = cur[keys.shift()] ??= {};
  cur[keys[0]] = v;
};

function renderSettings() {
  const body = $('#settingsBody');
  body.textContent = '';
  const s = state.settings || {};
  for (const g of SETTING_ROWS) {
    const group = el('div', { class: 'set-group' }, [el('h3', { text: g.group })]);
    for (const item of g.items) {
      const val = getPath(s, item.key);
      let control;
      if (item.type === 'bool') {
        control = el('button', {
          class: 'sw',
          role: 'switch',
          'aria-checked': val === false ? 'false' : 'true',
          'aria-label': item.label,
          onclick: async (e) => {
            const next = e.currentTarget.getAttribute('aria-checked') !== 'true';
            e.currentTarget.setAttribute('aria-checked', next ? 'true' : 'false');
            await saveSetting(item.key, next);
          },
        });
      } else if (item.type === 'select') {
        control = el(
          'select',
          {
            onchange: (e) => saveSetting(item.key, e.target.value),
          },
          item.options.map(([v, label]) => el('option', { value: v, selected: String(val ?? '') === v, text: label })),
        );
      } else if (item.type === 'range') {
        control = el('input', {
          type: 'range',
          min: item.min ?? 0,
          max: item.max ?? 100,
          value: val ?? 50,
          onchange: (e) => saveSetting(item.key, Number(e.target.value)),
        });
      }
      group.append(el('div', { class: 'row' }, [el('div', { class: 'txt' }, [el('b', { text: item.label }), item.hint ? el('span', { text: item.hint }) : null]), control]));
    }
    body.append(group);
  }
  body.append(
    el('div', { class: 'set-group' }, [
      el('h3', { text: 'session' }),
      el('div', { class: 'row' }, [
        el('div', { class: 'txt' }, [el('b', { text: 'パニック' }), el('span', { text: '全タブ・クッキー・レポート履歴を破棄' })]),
        el('button', { class: 'btn danger', text: '今すぐ破棄', onclick: panic }),
      ]),
      el('div', { class: 'row' }, [
        el('div', { class: 'txt' }, [el('b', { text: 'ショートカット' }), el('span', { text: 'Tab / 検索 / パニックキーの一覧' })]),
        el('button', {
          class: 'btn',
          text: '表示',
          onclick: () =>
            modal(
              'ショートカット',
              el('div', { class: 'kv' }, [
                el('dt', { text: '新規タブ' }),
                el('dd', { html: '<span class="kbd">Ctrl/⌘ T</span>' }),
                el('dt', { text: 'タブを閉じる' }),
                el('dd', { html: '<span class="kbd">Ctrl/⌘ W</span>' }),
                el('dt', { text: 'アドレスへ' }),
                el('dd', { html: '<span class="kbd">Ctrl/⌘ L</span>' }),
                el('dt', { text: 'タブ切替' }),
                el('dd', { html: '<span class="kbd">Ctrl/⌘ 1..9</span>' }),
                el('dt', { text: 'シールド切替' }),
                el('dd', { html: '<span class="kbd">Ctrl/⌘ Shift B</span>' }),
                el('dt', { text: 'パニック (全破棄)' }),
                el('dd', { html: '<span class="kbd">Shift+Esc</span> / <span class="kbd">Ctrl/⌘ Shift K</span>' }),
              ]),
            ),
        }),
      ]),
    ]),
  );
}

async function saveSetting(key, value) {
  const patch = {};
  setPath(patch, key, value);
  try {
    await api('/settings', { method: 'PATCH', body: patch });
    Object.assign(state.settings || {}, patch);
    if (key === 'mode') {
      localStorage.setItem(LS.mode, value);
      notifySwMode(value);
      toast(t('modeSet', value.toUpperCase()), 'ok', 2600);
    }
    if (key === 'ui.theme') applyTheme(value);
    if (key === 'ui.lang') {
      localStorage.setItem(LS.lang, value);
      location.reload();
    }
    refreshStatus();
  } catch (err) {
    toast(err.message, 'bad');
  }
}

function notifySwMode(mode) {
  for (const tab of state.tabs) {
    const f = $(`#iframe-${tab.sid}`);
    try {
      f?.contentWindow?.postMessage?.({ type: 'mirage:mode', sid: tab.sid, mode }, '*');
    } catch (e) {
      /* ignore */
    }
  }
  navigator.serviceWorker?.ready
    ?.then((reg) => reg.active?.postMessage({ type: 'mirage:mode', mode }))
    .catch(() => {});
}

/* ------------------------------------------------------------------ */
/* address bar / suggestions                                          */
/* ------------------------------------------------------------------ */

const SEARCH_HINTS = [
  { kind: 'search', label: 'duckduckgo', url: '!ddg ' },
  { kind: 'search', label: 'wikipedia', url: '!wiki ' },
  { kind: 'search', label: 'brave', url: '!brave ' },
];

function renderSuggest(q) {
  const box = $('#suggest');
  if (!q) {
    box.hidden = true;
    box.textContent = '';
    return;
  }
  const items = [];
  const recent = (() => {
    try {
      return JSON.parse(localStorage.getItem(LS.recent) || '[]');
    } catch {
      return [];
    }
  })().filter((r) => !q || r.url.toLowerCase().includes(q.toLowerCase())).slice(0, 5);
  for (const r of recent) items.push({ kind: 'recent', label: r.title || hostOf(r.url), value: r.url });
  for (const h of SEARCH_HINTS) items.push({ kind: h.kind, label: `${h.label}: ${q}`, value: h.url + q });
  if (!/^[a-z]+:\/\//i.test(q) && !/^[\w.-]+$/.test(q.replace(/\s/g, ''))) items.push({ kind: 'search', label: `Web search: ${q}`, value: q });
  if (!items.length) {
    box.hidden = true;
    return;
  }
  box.textContent = '';
  box.hidden = false;
  box.setAttribute('role', 'listbox');
  items.slice(0, 8).forEach((it, i) => {
    const node = el('button', {
      role: 'option',
      class: i === 0 ? 'sel' : '',
      onclick: () => {
        $('#address').value = it.value;
        box.hidden = true;
        submitAddress(it.value);
      },
    }, [el('span', { class: 'kind', text: it.kind }), el('span', { class: 'lbl', text: it.label })]);
    box.append(node);
  });
}

function submitAddress(value) {
  const tab = activeTab() || newTab('');
  loadTab(tab, value);
}

/* ------------------------------------------------------------------ */
/* status polling / rendering                                        */
/* ------------------------------------------------------------------ */

let statusRefreshInFlight = false;
async function refreshStatus() {
  if (statusRefreshInFlight) return;
  statusRefreshInFlight = true;
  try {
    const s = await api('/status', { timeoutMs: 10000 });
    state.status = s;
    // Render server health independently; a slow settings endpoint must not hide a valid status.
    state.settings = await mergeClientSettings();
    state.selectedCountry = s.egress.country || 'AUTO';
    state.strategy = s.egress.strategy || 'auto';
    $('#engineBadge').textContent = `pool ${fmtNum(s.egress.pool.size)} · ${fmtNum(s.shields.rules)} rules`;
    $('#engineBadge').dataset.state = s.egress.pool.size > 50 ? 'ok' : 'warn';
    $('#modePill').textContent = s.transport.mode.toUpperCase();
    $('#modePill').dataset.mode = s.transport.mode;
    $('#sbTransport').textContent = s.transport.mode.toUpperCase() + (s.capabilities.wisp ? '+wisp' : '');
    $('#sbEgress').textContent = `${s.egress.strategy}${s.egress.country && s.egress.country !== 'AUTO' ? ':' + s.egress.country : ''}`;
    $('#sbPool').innerHTML = `pool <b>${fmtNum(s.egress.pool.size)}</b> healthy <b>${fmtNum(s.egress.pool.healthy)}</b>${s.egress.pool.avgLatencyMs ? ` <b>${s.egress.pool.avgLatencyMs}ms</b>` : ''}`;
    $('#sbShields').innerHTML = `shields <b>${fmtNum(s.shields.blocked)}</b> / ${fmtNum(s.shields.rules)}`;
    $('#sbShields').dataset.tone = s.shields.enabled ? 'ok' : 'warn';
    $('#sbThreats').innerHTML = `threats <b>${fmtNum(s.threats.events)}</b>${s.threats.autoDelete ? '' : ' (readonly)'}`;
    $('#sbThreats').dataset.tone = s.threats.enabled ? '' : 'warn';
    $('#sbCache').innerHTML = `cache <b>${fmtNum(s.transport.cache.size)}</b>`;
    $('#sbVersion').textContent = `${s.app.name} v${s.app.version} "${s.app.codename}"${s.serverless ? ' · serverless' : ''}`;
    $('#egressFlag').textContent = s.egress.clientCountry?.flag || '🌐';
    $('#verifySent').textContent = s.egress.spoof ? 'XFF 偽装 ON' : 'そのまま';
    $('#shieldCount').textContent = String(s.shields.blocked || 0);
    $('#shieldCount').dataset.zero = s.shields.blocked ? '0' : '1';
    $('#shieldToggle').setAttribute('aria-pressed', s.shields.enabled ? 'true' : 'false');
    // per-tab badges from live sessions
    for (const tab of state.tabs) {
      const live = (s.sessions || []).find((x) => x.sid === tab.sid);
      if (!live) continue;
      tab.blocked = (live.blocked || 0) + (live.clientBlocked || 0);
      tab.threat = live.threat || 0;
      if (live.title) tab.title = String(live.title).slice(0, 90);
      if (live.url) tab.url = live.url;
    }
    renderTabs();
    if (state.panel === 'panelEgress') {
      renderCountries();
      renderListFeed(s.lists);
    }
    if (state.panel === 'panelSettings') renderSettings();
    if (!state.countries.length) loadCountries();
    if (!state.pool.items.length) loadPool();
  } catch (err) {
    const badge = $('#engineBadge');
    badge.textContent = 'offline · 再接続中';
    badge.dataset.state = 'warn';
    badge.title = err?.message || 'API に接続できません';
  } finally {
    statusRefreshInFlight = false;
  }
}

async function mergeClientSettings() {
  try {
    const r = await api('/settings');
    return r.settings || {};
  } catch {
    return state.settings || {};
  }
}

async function loadCountries() {
  try {
    const r = await api('/countries?min=1');
    state.countries = r.countries || [];
    if (state.panel === 'panelEgress') renderCountries();
  } catch (e) {
    /* retry next poll */
  }
}

async function loadPool() {
  try {
    const q = state.selectedCountry !== 'AUTO' ? `&country=${state.selectedCountry}` : '';
    const r = await api(`/pool?limit=40&sort=score${q}`);
    state.pool = r;
    if (state.panel === 'panelEgress') renderPoolTable();
  } catch (e) {
    /* ignore */
  }
}

async function pollThreats() {
  try {
    const r = await api('/threats?limit=60');
    const fresh = (r.events || []).filter((e) => e.id && !state.threats.seen.has(e.id));
    for (const e of r.events || []) if (e.id) state.threats.seen.add(e.id);
    state.threats.events = r.events || [];
    state.threats.totals = r.totals;
    state.threats.topRules = r.topRules;
    if (fresh.length) {
      $('#threatDot').hidden = false;
      const s = state.settings || {};
      if (s.ui?.showThreatTicker !== false) {
        for (const e of fresh.slice(0, 2)) {
          const isBlock = e.action === 'block' || e.action === 'quarantine';
          toast(`${isBlock ? t('threatBlock', e.label || e.code) : t('threatFound', e.label || e.code)} — ${e.host || ''}`.trim(), isBlock ? 'bad' : 'warn', 5200);
        }
      }
    }
    if (state.panel === 'panelThreats') renderThreats();
  } catch (e) {
    /* ignore */
  }
}

async function pollMetrics() {
  try {
    const m = await api('/metrics');
    state.metrics = m;
    drawSpark(m.series || []);
    $('#sbRate').querySelector('b').textContent = m.rate ? `${fmtBps((m.rate.kbPerSec || 0) * 1024)} · ${m.rate.reqPerSec}/s` : '—';
  } catch (e) {
    /* ignore */
  }
}

function drawSpark(series) {
  const c = $('#spark');
  if (!c?.getContext) return;
  const ctx = c.getContext('2d');
  const w = c.width;
  const h = c.height;
  ctx.clearRect(0, 0, w, h);
  const vals = series.map((s) => s.kb || 0);
  const max = Math.max(1, ...vals);
  const cs = getComputedStyle(document.documentElement);
  ctx.fillStyle = withAlpha(cs.getPropertyValue('--brand').trim() || '#5c86ff', 0.85);
  const bw = w / Math.max(10, series.length || 10);
  series.slice(-Math.floor(w / bw)).forEach((s, i) => {
    const v = (s.kb || 0) / max;
    const bh = Math.max(1, Math.round(v * (h - 2)));
    ctx.fillRect(i * bw, h - bh, Math.max(1, bw - 1), bh);
  });
}

function withAlpha(hex, a) {
  const m = /^#?([0-9a-f]{6})$/i.exec(hex);
  if (!m) return hex;
  const n = parseInt(m[1], 16);
  return `rgba(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255}, ${a})`;
}

/* ------------------------------------------------------------------ */
/* actions: shields / mode / panic                                    */
/* ------------------------------------------------------------------ */

async function toggleGlobalShields() {
  const on = state.status?.shields?.enabled;
  try {
    await api('/shields', { body: { enabled: !on }, method: 'POST' });
    await saveSetting('shields.enabled', !on);
    toast(`シールドを ${on ? 'OFF' : 'ON'} にしました`, on ? 'warn' : 'ok', 2600);
    refreshStatus();
  } catch (err) {
    toast(err.message, 'bad');
  }
}

function syncShieldToggle() {
  const tab = activeTab();
  const btn = $('#shieldToggle');
  if (!tab || !tab.host) {
    btn.title = 'シールドを ON/OFF (このページ)';
    return;
  }
  const relaxed = (state.status?.shields?.disabledFor || []).includes(hostDomain(tab.host));
  btn.classList.toggle('relaxed', relaxed);
  btn.title = relaxed ? `${tab.host}: 解除中 — クリックで再有効化` : `${tab.host}: シールド切替`;
}

const hostDomain = (h) => {
  const parts = String(h).split('.');
  return parts.length <= 2 ? h : parts.slice(-2).join('.');
};

async function toggleSiteShields() {
  const tab = activeTab();
  const globalOn = state.status?.shields?.enabled;
  if (tab?.host) {
    const relaxed = (state.status?.shields?.disabledFor || []).includes(hostDomain(tab.host));
    try {
      await api('/shields/domain', { body: { domain: hostDomain(tab.host), allow: relaxed }, method: 'POST' });
      toast(relaxed ? t('blockedSite', hostDomain(tab.host)) : t('allowed', hostDomain(tab.host)), 'ok', 3200);
      if (!relaxed && state.status) state.status.shields.disabledFor = [...(state.status.shields.disabledFor || []), hostDomain(tab.host)];
      else if (state.status) state.status.shields.disabledFor = (state.status.shields.disabledFor || []).filter((d) => d !== hostDomain(tab.host));
      syncShieldToggle();
      reloadActive();
    } catch (err) {
      toast(err.message, 'bad');
    }
    return;
  }
  toggleGlobalShields();
}

function reloadActive() {
  const tab = activeTab();
  if (!tab) return;
  const f = $(`#iframe-${tab.sid}`);
  if (f && f.src && f.src !== location.href) f.contentWindow?.location?.replace(f.src);
  else if (tab.url) loadTab(tab, tab.url);
}

async function panic() {
  const doIt = () => {
    for (const tab of [...state.tabs]) closeTab(tab.id);
    state.threats.seen.clear();
    localStorage.removeItem(LS.recent);
    api('/threats/purge', { body: {}, method: 'POST' }).catch(() => {});
    api('/cookies/clear', { body: {}, method: 'POST' }).catch(() => {});
    toast(t('panic'), 'ok');
  };
  if (!state.tabs.length) return doIt();
  modal(
    'パニック — 全部破棄しますか?',
    el('div', {}, [
      el('p', { class: 'note', text: '開いているタブ、上流クッキーのジャー、脅威レポート履歴をまとめて消します。この操作は取り消せません。' }),
      el('div', { class: 'verify-actions', style: 'margin-top:14px' }, [
        el('button', { class: 'btn', text: 'キャンセル', onclick: () => ($('#modal').hidden = true) }),
        el('button', { class: 'btn primary', text: '破棄する', onclick: () => { $('#modal').hidden = true; doIt(); } }),
      ]),
    ]),
  );
}

async function cycleMode() {
  const order = ['uv', 'wisp', 'auto'];
  const caps = state.status?.capabilities || {};
  const cur = state.settings?.mode || 'uv';
  let next = order[(order.indexOf(cur) + 1) % order.length];
  if (next === 'wisp' && !caps.wisp) next = order[(order.indexOf(next) + 1) % order.length];
  await saveSetting('mode', next);
}

/* ------------------------------------------------------------------ */
/* speed test                                                         */
/* ------------------------------------------------------------------ */

async function measureSpeed() {
  const kb = 4096;
  const t0 = performance.now();
  try {
    const res = await fetch(`${API}/speedtest?kb=${kb}&_=${Date.now()}`, { cache: 'no-store' });
    const blob = await res.blob();
    const secs = (performance.now() - t0) / 1000;
    const bps = Math.round((blob.size / secs) * 1000);
    state.speed = bps;
    toast(t('speedMeasured', fmtBps(bps)), 'ok', 4200);
    $('#sbRate').querySelector('b').textContent = fmtBps(bps);
  } catch (err) {
    toast(`速度測定失敗: ${err.message}`, 'bad');
  }
}

/* ------------------------------------------------------------------ */
/* service worker                                                     */
/* ------------------------------------------------------------------ */

async function registerSW() {
  if (!('serviceWorker' in navigator)) return false;
  try {
    let cfg = { swPath: '/mirage/sw.js', swScope: '/' };
    try {
      cfg = { ...cfg, ...(await fetch('/mirage/client-config', { signal: AbortSignal.timeout(4000) }).then((r) => r.json())) };
    } catch (e) {
      /* default */
    }
    const reg = await navigator.serviceWorker.register(cfg.swPath, { scope: cfg.swScope || '/' });
    return reg;
  } catch (err) {
    console.warn('SW register failed:', err?.message);
    return false;
  }
}

/* ------------------------------------------------------------------ */
/* theme / boot                                                       */
/* ------------------------------------------------------------------ */

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme === 'light' ? 'light' : 'aurora';
  localStorage.setItem(LS.theme, theme || 'aurora');
}

function wire() {
  $('#btnNewTab').onclick = () => newTab('');
  $('#tabAdd').onclick = () => newTab('');
  $('#btnHome').onclick = () => {
    state.active = null;
    renderFrames();
    $('#hero').hidden = false;
    renderHero();
  };
  $('#btnReload').onclick = reloadActive;
  $('#btnBack').onclick = () => activeTabIframe()?.contentWindow?.history?.back?.();
  $('#btnFwd').onclick = () => activeTabIframe()?.contentWindow?.history?.forward?.();
  $('#shieldToggle').onclick = toggleSiteShields;
  $('#modePill').onclick = cycleMode;
  $('#btnEgress').onclick = () => togglePanel('panelEgress');
  $('#btnThreats').onclick = () => togglePanel('panelThreats');
  $('#btnSettings').onclick = () => togglePanel('panelSettings');
  $$('[data-close]').forEach((b) => {
    b.onclick = () => togglePanel(b.dataset.close);
  });
  $('#btnVerify').onclick = verifyExit;
  $('#btnRefreshPool').onclick = async (e) => {
    e.target.classList.add('loading');
    try {
      const r = await api('/pool/refresh', { body: {}, method: 'POST' });
      toast(`${t('poolUpdated')} — +${r.added || 0} / 合計 ${fmtNum(r.size || state.status?.egress?.pool?.size)}`, 'ok');
      state.pool = { items: [], total: 0 };
      state.countries = [];
      await Promise.all([refreshStatus(), loadCountries(), loadPool()]);
      renderPoolTable();
    } catch (err) {
      toast(`${t('poolUpdated')} に失敗: ${err.message}`, 'bad', 6000);
    } finally {
      e.target.classList.remove('loading');
    }
  };
  $('#btnProbePool').onclick = async (e) => {
    e.target.classList.add('loading');
    try {
      const r = await api('/pool/probe', { body: { limit: 60, country: state.selectedCountry !== 'AUTO' ? state.selectedCountry : undefined }, method: 'POST' });
      toast(`${t('poolProbed')} — alive ${r.alive}/${r.checked || r.alive || '?'}`, 'ok');
      await Promise.all([loadPool(), loadCountries(), refreshStatus()]);
      renderPoolTable();
    } catch (err) {
      toast(err.message, 'bad');
    } finally {
      e.target.classList.remove('loading');
    }
  };
  $('#countryFilter').oninput = () => renderCountries();
  $('#btnThreatExport').onclick = async () => {
    try {
      const r = await fetch(`${API}/threats/report.json`, { credentials: 'same-origin' });
      const blob = await r.blob();
      const a = el('a', { href: URL.createObjectURL(blob), download: `mirage-threat-report-${new Date().toISOString().slice(0, 10)}.json` });
      document.body.append(a);
      a.click();
      a.remove();
    } catch (err) {
      toast(err.message, 'bad');
    }
  };
  $('#btnThreatPurge').onclick = async () => {
    await api('/threats/purge', { body: {}, method: 'POST' }).catch(() => {});
    state.threats.seen.clear();
    toast(t('cleared'), 'ok');
    pollThreats();
    refreshStatus();
  };
  $$('.segbar .seg').forEach((b) => {
    b.setAttribute('aria-pressed', b.dataset.strategy === (state.status?.egress?.strategy || 'auto') ? 'true' : 'false');
    b.onclick = async () => {
      state.strategy = b.dataset.strategy;
      $$('.segbar .seg').forEach((x) => x.setAttribute('aria-pressed', x === b ? 'true' : 'false'));
      await saveSetting('egress.strategy', b.dataset.strategy);
      toast(`出口戦略を ${b.dataset.strategy.toUpperCase()} にしました`, 'ok', 2600);
    };
  });
  $('#protoSel').onchange = (e) => {
    state.protocols = e.target.value;
    saveSetting('egress.protocols', e.target.value ? [e.target.value] : null);
    loadPool();
  };
  $('#heroSearch').onsubmit = (e) => {
    e.preventDefault();
    const v = $('#heroInput').value.trim();
    if (v) {
      const tab = newTab(v);
      $('#heroInput').value = '';
    }
  };
  $('#addressForm').onsubmit = (e) => {
    e.preventDefault();
    $('#suggest').hidden = true;
    submitAddress($('#address').value);
  };
  $('#address').oninput = (e) => renderSuggest(e.target.value.trim());
  $('#address').onblur = () => setTimeout(() => ($('#suggest').hidden = true), 160);
  $('#address').onkeydown = (e) => {
    const box = $('#suggest');
    if (box.hidden) return;
    const opts = $$('[role="option"]', box);
    let i = opts.findIndex((o) => o.classList.contains('sel'));
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      opts[i]?.classList.remove('sel');
      i = (i + (e.key === 'ArrowDown' ? 1 : opts.length - 1)) % opts.length;
      opts[i]?.classList.add('sel');
      opts[i]?.scrollIntoView({ block: 'nearest' });
    } else if (e.key === 'Enter' && i >= 0 && e.inputType !== 'insertLineBreak') {
      e.preventDefault();
      opts[i].click();
    } else if (e.key === 'Escape') {
      box.hidden = true;
    }
  };
  $('#sbRate').onclick = measureSpeed;

  // keyboard
  window.addEventListener('keydown', (e) => {
    const mod = e.ctrlKey || e.metaKey;
    if (e.shiftKey && e.key === 'Escape') {
      e.preventDefault();
      panic();
      return;
    }
    if (mod && e.shiftKey && (e.key === 'K' || e.key === 'k')) {
      e.preventDefault();
      panic();
      return;
    }
    if (mod && e.shiftKey && (e.key === 'B' || e.key === 'b')) {
      e.preventDefault();
      toggleGlobalShields();
      return;
    }
    if (mod && (e.key === 't' || e.key === 'T')) {
      e.preventDefault();
      const tab = newTab('');
      $('#address').focus();
      void tab;
      return;
    }
    if (mod && (e.key === 'w' || e.key === 'W')) {
      e.preventDefault();
      if (state.active) closeTab(state.active);
      return;
    }
    if (mod && (e.key === 'l' || e.key === 'L')) {
      e.preventDefault();
      $('#address').focus();
      $('#address').select();
      return;
    }
    if (mod && /^[1-9]$/.test(e.key)) {
      e.preventDefault();
      const tab = state.tabs[Number(e.key) - 1];
      if (tab) activateTab(tab.id);
      return;
    }
    if (e.key === 'F5') {
      e.preventDefault();
      reloadActive();
    }
    if (e.altKey && e.key === 'ArrowLeft') {
      e.preventDefault();
      activeTabIframe()?.contentWindow?.history?.back?.();
    }
    if (e.altKey && e.key === 'ArrowRight') {
      e.preventDefault();
      activeTabIframe()?.contentWindow?.history?.forward?.();
    }
  });
  window.addEventListener('message', (ev) => {
    const d = ev.data;
    if (!d || typeof d !== 'object') return;
    const tab = state.tabs.find((x) => x.sid === d.sid);
    if (!tab) return;
    if (d.type === 'mirage:title') tab.title = String(d.title || '').slice(0, 90);
    if (d.type === 'mirage:url') tab.url = String(d.url || tab.url);
    if (d.type === 'mirage:stats') {
      tab.blocked = d.blocked || 0;
      tab.threat = d.threat || 0;
    }
    renderTabs();
  });
  // hash routing (#sid) so a reload returns to the same tab set is intentionally not done:
  // tabs are ephemeral by design (privacy).
}

const activeTabIframe = () => {
  const tab = activeTab();
  return tab ? $(`#iframe-${tab.sid}`) : null;
};

/* ------------------------------------------------------------------ */
/* boot                                                              */
/* ------------------------------------------------------------------ */

async function boot() {
  applyTheme(localStorage.getItem(LS.theme) || 'aurora');
  if (!localStorage.getItem(LS.mode)) localStorage.setItem(LS.mode, 'uv');
  wire();
  renderHero();
  // Service worker installation is optional for rendering; don't let it block dashboard startup.
  registerSW().catch((err) => console.warn('SW setup skipped:', err?.message));
  await refreshStatus();
  pollThreats();
  pollMetrics();
  setInterval(refreshStatus, 2500);
  setInterval(pollThreats, 2000);
  setInterval(pollMetrics, 2000);
  // 起動時に URI があればそのタブを開く (?open=)
  const q = new URLSearchParams(location.search);
  if (q.get('open')) {
    newTab(q.get('open'));
    history.replaceState(null, '', location.pathname);
  }
}

boot();
