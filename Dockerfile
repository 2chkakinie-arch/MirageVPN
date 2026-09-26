# MirageVPN — 依存ほぼゼロ (express + ws) なのでイメージは小さい
FROM node:22-alpine AS base
WORKDIR /app
ENV NODE_ENV=production

FROM base AS deps
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

FROM base AS runtime
# curl は HEALTHCHECK 用。appuser は非特権 (port 8080 は 1024 以上なのでOK)
RUN apk add --no-cache curl tini && adduser -D -H -u 10001 appuser
COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY server ./server
COPY public ./public
COPY api ./api
COPY data ./data
COPY README.md LICENSE .env.example docker-compose.yml ./
RUN mkdir -p /app/data/state && chown -R appuser:appuser /app
USER appuser
EXPOSE 8080
ENV PORT=8080 HOSTNAME_BIND=0.0.0.0 MIRAGE_STATE_DIR=/app/data/state
HEALTHCHECK --interval=30s --timeout=6s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:${PORT}/mirage/api/health || exit 1
ENTRYPOINT ["/sbin/tini","--"]
CMD ["node","server/index.js"]
