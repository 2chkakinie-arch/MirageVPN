/**
 * /mirage/api/aimode/* — Google AI Mode を API として叩く
 * ---------------------------------------------------------------
 *   GET    /mirage/api/aimode/status           … 設定・予算・直近の失敗
 *   GET    /mirage/api/aimode/query?q=...      … 単発問い合わせ
 *   POST   /mirage/api/aimode/query  {q}       … 同上 (body)
 *   POST   /mirage/api/aimode/chat   {messages}… 同上 (会話の最後の user を投げる)
 *   DELETE /mirage/api/aimode/cache            … キャッシュ全掃除
 *   GET    /mirage/api/aimode/debug/html?q=    … 生 HTML (MIRAGE_AIMODE_DEBUG=1 のみ)
 *
 *   POST   /mirage/v1/chat/completions         … OpenAI 互換 (Open WebUI / LangChain 対応)
 *   GET    /mirage/v1/models                   … OpenAI 互換のモデル一覧
 *
 * 認証: MIRAGE_AIMODE_TOKEN を設定すると Bearer / ?key= が必須になる
 * (公開デプロイでは Google のブロックを招くので設定を強く推奨)。
 *
 * @module routes/aimode
 */

import express from 'express';
import { Buffer } from 'node:buffer';
import { log } from '../log.js';

const ns = log.child('aimode-api');

/**
 * @param {ReturnType<import('../app.js').createContext>} ctx
 */
export function createAiModeRouter(ctx) {
  const { config, engine } = ctx;
  const client = engine.aimode;
  const r = express.Router();
  r.use(express.json({ limit: '1mb' }));

  const apiBase = `${config.basePath}${config.url.apiPrefix}/aimode`;

  /* ---------------- 認証 (任意) ---------------- */
  const token = config.aimode.token;
  const authed = (req) => {
    if (!token) return true;
    const h = String(req.headers.authorization || '');
    if (h === `Bearer ${token}`) return true;
    const q = String(req.query.key || '');
    return q === token;
  };

  /* ---------------- status ---------------- */
  r.get(`${apiBase}/status`, (req, res) => {
    res.json({ ok: true, ...client.status() });
  });

  /* ---------------- query ---------------- */
  const handleQuery = async (req, res) => {
    if (!authed(req)) return res.status(401).json({ ok: false, error: 'unauthorized', hint: 'Authorization: Bearer <MIRAGE_AIMODE_TOKEN>' });
    const body = req.method === 'POST' ? req.body || {} : {};
    const q = String(body.q ?? body.query ?? body.prompt ?? req.query.q ?? req.query.query ?? '').trim();
    if (!q) return res.status(400).json({ ok: false, error: 'q が必要です' });
    const out = await client.ask({
      q,
      lang: String(body.lang ?? req.query.lang ?? '').trim() || undefined,
      country: String(body.country ?? req.query.country ?? '').trim().toUpperCase() || undefined,
      provider: String(body.provider ?? req.query.provider ?? '').trim() || undefined,
      resolveCitations: body.resolveCitations ?? undefined,
      sid: req.mirage?.sid || undefined,
      clientId: req.mirage?.clientId,
      settings: req.mirage?.settings,
    });
    res.status(out.ok ? 200 : out.reason?.startsWith('quota:') ? 429 : 502).json(out);
  };
  r.get(`${apiBase}/query`, handleQuery);
  r.post(`${apiBase}/query`, handleQuery);

  /* ---------------- chat (単純なラッパ) ---------------- */
  r.post(`${apiBase}/chat`, async (req, res) => {
    if (!authed(req)) return res.status(401).json({ ok: false, error: 'unauthorized' });
    const messages = Array.isArray(req.body?.messages) ? req.body.messages : [];
    const lastUser = [...messages].reverse().find((m) => m?.role === 'user');
    const system = messages.filter((m) => m?.role === 'system').map((m) => m.content);
    const q = String(lastUser?.content || req.body?.q || '').trim();
    if (!q) return res.status(400).json({ ok: false, error: 'messages に user の発話が必要です' });
    const out = await client.ask({
      q: [...system, q].filter(Boolean).join('\n\n'),
      sid: req.mirage?.sid || undefined,
      clientId: req.mirage?.clientId,
      settings: req.mirage?.settings,
    });
    res.status(out.ok ? 200 : 502).json(out);
  });

  /* ---------------- cache ---------------- */
  r.delete(`${apiBase}/cache`, (req, res) => {
    if (!authed(req)) return res.status(401).json({ ok: false, error: 'unauthorized' });
    res.json({ ok: true, cleared: client.clearCache() });
  });

  /* ---------------- debug: 生 HTML ---------------- */
  r.get(`${apiBase}/debug/html`, async (req, res) => {
    if (!authed(req)) return res.status(401).json({ ok: false, error: 'unauthorized' });
    if (!config.aimode.debug) return res.status(403).json({ ok: false, error: 'MIRAGE_AIMODE_DEBUG=1 で有効化してください' });
    const q = String(req.query.q || '').trim();
    if (!q) return res.status(400).json({ ok: false, error: 'q が必要です' });
    const out = await client.ask({
      q,
      sid: req.mirage?.sid || undefined,
      clientId: req.mirage?.clientId,
      settings: req.mirage?.settings,
      debug: true,
    });
    res.json({ ok: out.ok, reason: out.reason, meta: out.meta, html: out.__html || null });
  });

  /* ---------------- OpenAI 互換 ---------------- */
  const modelId = config.aimode.openaiModelId;

  r.get(`${config.basePath}/mirage/v1/models`, (req, res) => {
    if (!authed(req)) return res.status(401).json({ ok: false, error: 'unauthorized' });
    res.json({
      object: 'list',
      data: [
        {
          id: modelId,
          object: 'model',
          created: Math.floor(Date.now() / 1000),
          owned_by: 'miragevpn',
        },
      ],
    });
  });

  r.post(`${config.basePath}/mirage/v1/chat/completions`, async (req, res) => {
    if (!authed(req)) return res.status(401).json({ ok: false, error: 'unauthorized' });
    const messages = Array.isArray(req.body?.messages) ? req.body.messages : [];
    const lastUser = [...messages].reverse().find((m) => m?.role === 'user');
    const system = messages.filter((m) => m?.role === 'system').map((m) => String(m.content || ''));
    const q = String(lastUser?.content || '').trim();
    if (!q) return res.status(400).json({ error: { message: 'messages に user の発話が必要です', type: 'invalid_request_error' } });

    const out = await client.ask({
      q: [...system, q].filter(Boolean).join('\n\n'),
      sid: req.mirage?.sid || undefined,
      clientId: req.mirage?.clientId,
      settings: req.mirage?.settings,
    });

    if (!out.ok) {
      const status = out.reason?.startsWith('quota:') ? 429 : 502;
      return res.status(status).json({
        error: {
          message: out.error || out.reason || 'AI Mode 問い合わせに失敗しました',
          type: out.reason?.startsWith('quota:') ? 'rate_limit_error' : 'upstream_error',
          retry_after_ms: out.retryAfterMs || null,
          reason: out.reason,
        },
      });
    }

    const created = Math.floor(Date.now() / 1000);
    const promptText = [...system, q].filter(Boolean).join('\n\n');
    if (req.body?.stream) {
      res.writeHead(200, {
        'content-type': 'text/event-stream; charset=utf-8',
        'cache-control': 'no-cache, no-transform',
        connection: 'keep-alive',
        'x-accel-buffering': 'no',
      });
      const id = `chatcmpl-${Date.now().toString(36)}`;
      const chunk = (delta, finish = null) =>
        res.write(
          `data: ${JSON.stringify({
            id,
            object: 'chat.completion.chunk',
            created,
            model: modelId,
            choices: [{ index: 0, delta, finish_reason: finish }],
          })}\n\n`,
        );
      // プロバイダは一括取得なので、既存の断片を順に流す (SSE 形状だけ合わせる)
      chunk({ role: 'assistant' });
      for (const piece of splitForStream(out.answer)) chunk({ content: piece });
      chunk({}, 'stop');
      res.write('data: [DONE]\n\n');
      return res.end();
    }

    res.json({
      id: `chatcmpl-${Date.now().toString(36)}`,
      object: 'chat.completion',
      created,
      model: modelId,
      choices: [
        {
          index: 0,
          message: { role: 'assistant', content: out.answer },
          finish_reason: 'stop',
        },
      ],
      usage: {
        prompt_tokens: estimateTokens(promptText),
        completion_tokens: estimateTokens(out.answer),
        total_tokens: estimateTokens(promptText) + estimateTokens(out.answer),
      },
      mirage: {
        provider: out.meta?.provider,
        citations: out.citations,
        sources: out.sources,
        followUps: out.followUps,
        confidence: out.confidence,
        warnings: out.warnings,
        meta: out.meta,
      },
    });
  });

  ns.info(`AI Mode API: ${apiBase} (provider=${client.status().provider}, enabled=${client.status().enabled})`);
  return r;
}

/** 超概算 (日本語は 1 文字≒1 token 扱い) */
function estimateTokens(s) {
  return Math.max(1, Math.round(String(s || '').length * 0.75));
}

/** ストリームっぽく見せるための分割 (句点・改行・最大幅) */
function splitForStream(text, width = 120) {
  const s = String(text || '');
  if (!s) return [];
  const parts = [];
  let buf = '';
  for (const line of s.split(/(\n\n)/)) {
    if ((buf + line).length >= width) {
      if (buf) parts.push(buf);
      buf = line;
    } else {
      buf += line;
    }
  }
  if (buf) parts.push(buf);
  return parts.filter(Boolean);
}

export default createAiModeRouter;
