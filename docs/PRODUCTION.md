# Production deployment checklist — VitEnergo

Документ для DevOps. Проверять при выкатывании на боевой контур (intranet
РУП «Витебскэнерго» или staging-стенд под нагрузочное тестирование).

---

## 1. Обязательные переменные окружения

| Переменная | Значение для prod | Default | Замечания |
|---|---|---|---|
| `NODE_ENV` | `production` | `development` | Включает дополнительные boot-time guards (см. §3) |
| `DB_USER` | сильный логин | `VitEnergoUser` | НЕ использовать `sa` |
| `DB_PASSWORD` | случайные 24+ символа | — | После ротации обязательно `ALTER LOGIN ... WITH PASSWORD = ...` в БД |
| `DB_SERVER` | hostname/IP БД | `localhost` | Если БД на отдельном хосте |
| `DB_DATABASE` | `VitEnergoProject` | `VitEnergoProject` | |
| `PORT` | `3000` | `3000` | За nginx обычно тот же |
| `JWT_SECRET` | 64-байт hex (`crypto.randomBytes(64)`) | — | Минимум 32 символа, без `\r\n` |
| `REFRESH_TOKEN_SECRET` | 64-байт hex (другой!) | — | **Должен отличаться** от `JWT_SECRET` |
| `ALLOWED_ORIGINS` | `https://intranet.vitebskenergo.by` | пусто | CSRF / origin guard. Без нього только same-origin |
| `BEHIND_PROXY` | `true` если за nginx/traefik | пусто | Иначе атакующий через `X-Forwarded-For` подменит IP |
| `DB_TRUST_SERVER_CERT` | `false` для СУБД с валидным cert, `true` для self-signed | пусто (в prod = валидация cert) | В docker-compose выставлен `true`: контейнерная mssql отдаёт самоподписанный сертификат |

## 2. Rate-limit caps (production hard-fail)

В `production` сервер **не стартует**, если значение превышает потолок (защита
от случайного копирования dev-`.env` в прод). Дефолты применяются если переменная
не задана.

| Переменная | Default (prod) | Hard-fail если выше | Окно | Назначение |
|---|---|---|---|---|
| `AUTH_LIMITER_MAX` | `10` | `30` | 15 мин | POST /api/login + /api/refresh-token |
| `UPLOAD_LIMITER_MAX` | `3` | `10` | 1 мин | Multipart-uploads (защита от OOM через memoryStorage) |
| `REQUEST_CREATE_MAX` | `30` | `100` | 1 час | Per-user POST /api/requests |
| `COMMENT_CREATE_MAX` | `120` | `300` | 1 час | Per-user POST /api/requests/:id/comments |

**Симптом «забыли убрать dev-cap»:** в логах при старте — `process.exit(1)` с сообщением
`AUTH_LIMITER_MAX=200 в production (max 30). Похоже dev-.env попал в прод.`

## 3. Boot-time guards

Сервер падает с `process.exit(1)` на старте при:

1. `JWT_SECRET === REFRESH_TOKEN_SECRET` — defence-in-depth.
2. Длина `JWT_SECRET` или `REFRESH_TOKEN_SECRET` < 32 символов.
3. `\r` или `\n` в любом из секретов (newline-injection через `.env`).
4. Любое из rate-limit caps выше потолка (см. §2) при `NODE_ENV=production`.
5. Отсутствие `JWT_SECRET` или `REFRESH_TOKEN_SECRET`.

## 4. БД: чек-лист перед выходом

База разворачивается из снимка `db/backup/VitEnergoProject.bak` (схема плюс
демонстрационные данные). В Docker это делает init-контейнер автоматически; при
ручной установке выполните RESTORE и перемапьте логин приложения:

```bash
# 1. Восстановить БД из снимка:
sqlcmd -S $DB_SERVER -U sa -P "$MSSQL_SA_PASSWORD" -C \
  -Q "RESTORE DATABASE VitEnergoProject FROM DISK = N'/abs/path/db/backup/VitEnergoProject.bak' WITH REPLACE, RECOVERY;"

# 2. Логин приложения. После RESTORE пользователь VitEnergoUser уже есть в базе,
#    но привязан к SID исходной машины (orphaned), поэтому перемапить обязательно:
sqlcmd -S $DB_SERVER -U sa -P "$MSSQL_SA_PASSWORD" -d VitEnergoProject -C \
  -Q "IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name='VitEnergoUser') CREATE LOGIN VitEnergoUser WITH PASSWORD=N'$DB_PASSWORD', CHECK_POLICY=OFF; ALTER USER VitEnergoUser WITH LOGIN = VitEnergoUser; ALTER ROLE db_owner ADD MEMBER VitEnergoUser;"

# 3. Recovery model FULL (point-in-time backup'ы, см. docs/BACKUP.md):
sqlcmd -Q "ALTER DATABASE VitEnergoProject SET RECOVERY FULL;"
```

## 5. Smoke-тесты после деплоя

```bash
# 1. /api/health должен вернуть 200 + db: ok
curl -s http://localhost:3000/api/health | jq .

# 2. Login с реальным юзером:
curl -s -X POST http://localhost:3000/api/login \
  -H 'Content-Type: application/json' \
  -d '{"login":"admin@vitebskenergo.by","password":"<actual-prod-password>"}' \
  -w '\nstatus: %{http_code}\n'

# 3. Login с несуществующим юзером (проверка постоянного времени ответа):
# Должно отвечать ~300мс (timingFloor) для обоих случаев. Разница <10мс.
time curl -s -X POST http://localhost:3000/api/login \
  -H 'Content-Type: application/json' -d '{"login":"none@x.ru","password":"x"}' >/dev/null

# 4. Запросить /api/requests без токена → 401, не 500.
curl -s http://localhost:3000/api/requests -w 'status: %{http_code}\n'
```

## 6. Логи и retention

| Файл | Что в нём | Retention |
|---|---|---|
| `logs/access-YYYY-MM-DD.log` | Все HTTP-запросы, scrubQuery маскирует sensitive query-params | 30 дней (cleanupOldLogFiles) |
| `logs/security-YYYY-MM-DD.log` | uncaughtException, unhandledRejection, wss errors, file-violations | 90 дней |
| `logs/admin-YYYY-MM-DD.log` | logAdminEvent (login/logout/смена ролей/удаление юзеров) | 90 дней |
| MSSQL `AccessAudit` | PII-touch события (закон РБ №99-З) | 1 год (cleanupOldAuditRecords) |
| MSSQL `LoginHistory` | История логинов | 90 дней |

Сейчас ротация **только по дате**. При burst-нагрузке файлы могут расти до десятков
ГБ за день — рекомендуется поверх настроить `logrotate` по размеру, либо мигрировать
на Pino + daily-rotating-file.

## 7. Restart policy

- **Docker**: `restart: unless-stopped` уже в `docker-compose.yml`.
- **PM2**: `pm2 start server.js --name vitenergo --max-memory-restart 1G`.
- **systemd** (под Linux):
  ```
  [Service]
  Restart=on-failure
  RestartSec=5
  Type=simple
  ```

Обработчики `process.on('uncaughtException' / 'unhandledRejection')` при
невпойманной Promise-ошибке делают graceful shutdown (`gracefulShutdown`) и
`process.exit(1)`. Restart policy подхватывает.

## 8. Observability

`/api/health` возвращает:
- `status`: `ok` / `degraded`
- `uptime`: секунд
- `db`: ok/down
- `pool`: `{ size, available, borrowed, pending }` — мониторить рост `borrowed` без
  освобождения (utечка connections).
- `wss`: `{ clients }` — мониторить рост после disconnect'ов (фантомы).
- `memory`: `{ rss, heapUsed, heapTotal }` в МБ.

Рекомендуемые алерты:
- `db: down` — уведомление на on-call.
- `pool.borrowed > 15` (при max=20) — приближение к exhaust.
- `memory.rss > 1024 МБ` — утечка или peak от multer.memoryStorage.

## 9. Безопасность секретов

- **`.env` НИКОГДА не коммитить** (`.gitignore` запись `.env` есть).
- Если `.env` уже в истории — `git filter-repo --path .env --invert-paths` + force-push, либо принять компромис и **сменить ВСЕ секреты** (JWT × 2 + DB).
- На prod-хосте `.env` принадлежит UID процесса (`chown vitenergo:vitenergo .env`),
  права `0600`.
- Бэкапы файлов БД должны шифроваться (Transparent Data Encryption + резервный
  ключ в HSM или vault).

## 10. Известные ограничения

- **Single-process Node**: нет cluster/PM2-cluster mode. Для интранета РУП хватает,
  публичный domain потребует upgrade.
- **In-memory rate-limit storage**: после restart лимиты сбрасываются. Для multi-instance
  потребуется Redis-backed `rate-limit-redis`.
- **Логи дублируются**: `console.error` уходит в stdout (Docker journals), а параллельно
  `writeFileLog` пишет на диск. Для prod-grade рекомендуется единый Pino + transport.
- **Memory cache `tokenVersionCache`** ограничен 10k записей (LRU). При >10k активных
  юзеров увеличить лимит в `server.js` (поиском `LRU_MAX = 10000`).
