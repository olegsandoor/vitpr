# =============================================================================
# Dockerfile — VitEnergo backend
#
# Двухэтапная сборка: deps копируются отдельно, чтобы Docker мог кешировать слой
# с node_modules и пересобирать только при изменении package*.json.
# =============================================================================

FROM node:20-alpine AS deps

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev || npm install --omit=dev


FROM node:20-alpine AS runtime

# DejaVu — кириллический TTF для PDF-генерации (заменяет системный Arial из Windows).
# tini — корректно обрабатывает SIGTERM/SIGINT (без него в Docker процессы становятся
# «init», и сигналы могут не доходить до Node).
RUN apk add --no-cache tini ttf-dejavu

WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3000

COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Папки для рантайм-данных. В Compose они монтируются как volumes —
# здесь только создаём дефолтные пустые на случай запуска без compose.
RUN mkdir -p uploads logs && \
    addgroup -S app && adduser -S app -G app && \
    chown -R app:app /app

USER app
EXPOSE 3000

# Healthcheck читает /api/health (uptime + статус БД).
# 30s между проверками, 5s timeout, 3 неудачи подряд — контейнер unhealthy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://localhost:3000/api/health || exit 1

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "server.js"]
