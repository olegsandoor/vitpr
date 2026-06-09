# Backup и восстановление — VitEnergo

Документ описывает процедуры резервного копирования и восстановления
информационной системы согласования заявок РУП «Витебскэнерго».

---

## Объекты резервирования

| Объект | Размер (типовой) | Критичность | Частота backup |
|---|---|---|---|
| База данных `VitEnergoProject` (MSSQL) | 50 МБ — 5 ГБ | Критично | **Ежедневно** + transaction-log каждые 30 мин |
| Папка `uploads/` (документы заявок) | 100 МБ — 50 ГБ | Критично | **Ежедневно** |
| Папка `logs/` (access/security/admin) | 10 МБ/день | Средне (compliance) | Раз в неделю, ротация 90 дней |
| Файл `.env` (JWT-секреты, DB-пароли) | < 1 КБ | **Высоко** | При смене секретов; шифровать |
| Папка `assets/fonts/` | 1 МБ | Низко (входит в репозиторий) | — |

Папка `node_modules/` — НЕ резервируется (восстанавливается через `npm ci`).

Для первичного развёртывания репозиторий уже содержит снимок БД
`db/backup/VitEnergoProject.bak` (схема плюс демо-данные). Описанные ниже SQL Agent
jobs относятся к регулярному резервированию на боевом контуре, а не к разовому seed.

---

## RPO и RTO

Это целевые значения. Они достигаются только после настройки SQL Agent jobs из
раздела ниже. На момент ревизии TLog-backup ещё не настроен (см. блок «ВАЖНО»),
поэтому фактический RPO сейчас равен интервалу между ручными бэкапами.

- **RPO (Recovery Point Objective)**, допустимая потеря данных: **30 минут** за
  счёт transaction-log backup каждые 30 минут.
- **RTO (Recovery Time Objective)**, время восстановления: **2 часа** на
  восстановление БД, копирование `uploads/`, `npm ci` и старт.

---

## Что бэкапим: автоматизация

> **ВАЖНО (на момент этой ревизии)**: проверка `log_reuse_wait_desc`
> в БД показывает `LOG_BACKUP`. Это означает что БД находится в `RECOVERY FULL`,
> но **TLog backup не настроен** — лог транзакций (.ldf) растёт без очистки и
> через 2-3 месяца упрётся в полку диска. Перед production-деплоем **обязательно**
> либо настройте SQL Agent jobs из этого файла, либо переключите БД на
> `RECOVERY SIMPLE` (если RPO 24ч устраивает):
>
> ```sql
> -- Вариант "просто и работает": SIMPLE — лог авто-truncate, RPO=24h.
> ALTER DATABASE VitEnergoProject SET RECOVERY SIMPLE;
>
> -- Вариант "RPO=30мин": FULL + TLog backup каждые 30 мин (см. ниже).
> -- Если выбираете FULL — обязательно настройте оба job'а Daily+TLog,
> -- иначе .ldf будет расти бесконечно.
> ```
>
> Проверить факт настройки после деплоя:
> ```sql
> SELECT name, recovery_model_desc, log_reuse_wait_desc
> FROM sys.databases WHERE name = 'VitEnergoProject';
> -- Норма: log_reuse_wait_desc = NOTHING (FULL+TLog работает)
> --        ИЛИ recovery_model_desc = SIMPLE
> ```

### 1. БД — MSSQL Server Agent

```sql
-- Полный backup ежедневно в 02:00 (расписание SQL Agent)
USE master;
EXEC sp_add_job @job_name = N'VitEnergo_Daily_Full_Backup';
EXEC sp_add_jobstep
    @job_name = N'VitEnergo_Daily_Full_Backup',
    @step_name = N'Full Backup',
    @subsystem = N'TSQL',
    @command = N'
        DECLARE @file NVARCHAR(500) = N''\\backup-server\vitenergo\full\'' +
                                      CONVERT(NVARCHAR(10), GETDATE(), 112) + N''.bak'';
        BACKUP DATABASE VitEnergoProject TO DISK = @file
            WITH COMPRESSION, CHECKSUM, FORMAT, INIT;';
EXEC sp_add_schedule
    @schedule_name = N'Daily 02:00',
    @freq_type = 4,
    @freq_interval = 1,
    @active_start_time = 020000;
EXEC sp_attach_schedule @job_name = N'VitEnergo_Daily_Full_Backup', @schedule_name = N'Daily 02:00';

-- Transaction log backup каждые 30 минут (для recovery point ≤ 30 мин)
-- БД должна быть в Recovery Model = FULL:
ALTER DATABASE VitEnergoProject SET RECOVERY FULL;

EXEC sp_add_job @job_name = N'VitEnergo_TLog_Backup_30min';
EXEC sp_add_jobstep
    @job_name = N'VitEnergo_TLog_Backup_30min',
    @step_name = N'TLog Backup',
    @subsystem = N'TSQL',
    @command = N'
        DECLARE @file NVARCHAR(500) = N''\\backup-server\vitenergo\tlog\'' +
                                      CONVERT(NVARCHAR(20), GETDATE(), 120) + N''.trn'';
        SET @file = REPLACE(REPLACE(@file, N'':'', N''-''), N'' '', N''_'');
        BACKUP LOG VitEnergoProject TO DISK = @file
            WITH COMPRESSION, CHECKSUM, NOFORMAT, NOINIT;';
EXEC sp_add_schedule
    @schedule_name = N'Every 30 min',
    @freq_type = 4,
    @freq_interval = 1,
    @freq_subday_type = 4,
    @freq_subday_interval = 30;
EXEC sp_attach_schedule @job_name = N'VitEnergo_TLog_Backup_30min', @schedule_name = N'Every 30 min';
```

Хранение: 30 дней — full, 7 дней — t-log. Старше — архивировать на холодное
хранилище (LTO/S3 Glacier).

### 2. Папка `uploads/` — robocopy mirror

Скрипт `scripts/backup_uploads.bat` (Windows):

```bat
@echo off
set SRC=D:\nevitenergo\VitEnergo\uploads
set DST=\\backup-server\vitenergo\uploads
set LOG=D:\nevitenergo\VitEnergo\logs\backup-uploads-%date:~6,4%-%date:~3,2%-%date:~0,2%.log

robocopy %SRC% %DST% /MIR /R:3 /W:5 /MT:8 /XO /LOG:%LOG% /NP
```

Расписание: Windows Task Scheduler, ежедневно в 02:30 (после backup'а БД).

Linux/Docker — `cron` + `rsync`:

```bash
# /etc/cron.d/vitenergo-uploads
30 2 * * *  appuser  rsync -a --delete /opt/vitenergo/uploads/ backup-server::vitenergo-uploads/
```

### 3. `.env` — отдельно, зашифрованный

Не кладём в общий backup-volume. Лучше:
- хранить вручную в **сейфе** (физически распечатать секреты)
- или использовать `gpg --symmetric` с паролем, известным только админу

Никогда не отправлять `.env` в shared-storage без шифрования.

---

## Восстановление: пошаговый runbook

### Сценарий A: упала БД, нужно вернуться к последнему backup'у

```sql
USE master;
ALTER DATABASE VitEnergoProject SET SINGLE_USER WITH ROLLBACK IMMEDIATE;

RESTORE DATABASE VitEnergoProject
    FROM DISK = N'\\backup-server\vitenergo\full\20260505.bak'
    WITH NORECOVERY, REPLACE;

-- Накатываем все t-log'и от последнего full до нужной точки
RESTORE LOG VitEnergoProject FROM DISK = N'\\backup-server\vitenergo\tlog\2026-05-05_02-30-00.trn' WITH NORECOVERY;
RESTORE LOG VitEnergoProject FROM DISK = N'\\backup-server\vitenergo\tlog\2026-05-05_03-00-00.trn' WITH NORECOVERY;
-- ... все доступные t-log'и
RESTORE LOG VitEnergoProject FROM DISK = N'\\backup-server\vitenergo\tlog\2026-05-05_14-30-00.trn' WITH RECOVERY;

ALTER DATABASE VitEnergoProject SET MULTI_USER;
```

После восстановления БД — перезапустить приложение (`pm2 restart vitenergo`
или `docker compose restart app`) — оно перечитает кэш справочников.

### Сценарий B: пропали файлы из `uploads/`

```bat
robocopy \\backup-server\vitenergo\uploads D:\nevitenergo\VitEnergo\uploads /MIR /R:3 /W:5
```

Никаких изменений в БД не нужно — записи `Documents.file_path` указывают
на восстановленные файлы.

### Сценарий C: полная смерть сервера, переезд на новое железо

1. Подготовить новую машину: Windows Server / Linux + MSSQL 2022 + Node.js 20.
2. Создать пустую БД `VitEnergoProject` + пользователя `VitEnergoUser`.
3. Восстановить БД из последнего full + t-log'и (см. сценарий A).
4. Скопировать `.env` (с расшифровкой пароля) → корень проекта.
5. `git clone` репо или скопировать исходники.
6. `npm ci --omit=dev` (production-deps).
7. Скопировать `uploads/` из backup'а.
8. Применить миграции, которых ещё не было: `sqlcmd -i db/NN_*.sql`.
9. `npm start` или `docker compose up -d`.
10. Smoke-тест: `curl http://localhost:3000/api/health` → 200.

---

## Регулярная проверка

### Sanity-check: job'ы реально работают

`docs/BACKUP.md` — это **спецификация**. Чтобы убедиться что job'ы действительно
выполняются (а не просто описаны), регулярно проверяй `msdb.dbo.backupset`:

```sql
-- Когда был последний FULL backup и его статус
SELECT TOP 5
    bs.database_name,
    bs.type AS backup_type,    -- D=full, I=diff, L=tlog
    bs.backup_start_date,
    bs.backup_finish_date,
    DATEDIFF(MINUTE, bs.backup_finish_date, GETDATE()) AS minutes_ago,
    CAST(bs.backup_size / 1024.0 / 1024.0 AS DECIMAL(10,2)) AS size_mb
FROM msdb.dbo.backupset bs
WHERE bs.database_name = 'VitEnergoProject'
ORDER BY bs.backup_start_date DESC;
```

**Что должно быть видно** при здоровой системе:
- FULL — не старше 24 часов
- DIFF (если используется) — не старше 24 часов
- LOG — не старше 30 минут (наш RPO)

```sql
-- Failed-jobs за последние 7 дней
SELECT j.name, h.run_date, h.run_time, h.message
FROM msdb.dbo.sysjobs j
JOIN msdb.dbo.sysjobhistory h ON h.job_id = j.job_id
WHERE j.name LIKE 'VitEnergo_%'
  AND h.run_status = 0   -- 0=failed
  AND msdb.dbo.agent_datetime(h.run_date, h.run_time) > DATEADD(DAY, -7, GETDATE())
ORDER BY h.run_date DESC, h.run_time DESC;
```

Если результат непустой — есть проблема, разбираться с `h.message`.

```sql
-- Recovery model должен быть FULL (иначе TLog backup невозможен)
SELECT name, recovery_model_desc, log_reuse_wait_desc
FROM sys.databases
WHERE name = 'VitEnergoProject';
-- Ожидаемо: recovery_model_desc = FULL, log_reuse_wait_desc = LOG_BACKUP или NOTHING
-- Если log_reuse_wait_desc = NOTHING долгое время — значит TLog не делается!
```

```sql
-- Размер log-файла. Если растёт без backup-truncation — проблема.
SELECT
    DB_NAME(database_id) AS db,
    name AS logical_name,
    type_desc,
    size * 8 / 1024 AS size_mb,
    CAST(FILEPROPERTY(name, 'SpaceUsed') AS BIGINT) * 8 / 1024 AS used_mb
FROM sys.master_files
WHERE database_id = DB_ID('VitEnergoProject');
```

### Test-restore раз в квартал

Backup без проверки восстановления — миф о backup'е. Раз в 3 месяца:

1. На отдельной testing-машине поднимаем MSSQL.
2. Накатываем последний полный backup из production.
3. Проверяем:
   - `SELECT COUNT(*) FROM Requests` совпадает с prod
   - `SELECT MAX(timestamp) FROM History` — близко к моменту backup'а
   - `SELECT COUNT(*) FROM AccessAudit` — записи compliance на месте
4. Документируем в `docs/BACKUP_TESTS.log`.

### Application-level retention (НЕ заменяет backup)

Сервер автоматически чистит журналы (см. `server.js` cleanup-jobs):
- `History` — старше 365 дней удаляются
- `LoginHistory`, `FileUploadAttempts`, `Notifications` — старше 90 дней
- `AccessAudit` — старше 365 дней (compliance закон РБ №99-З)
- `logs/*.log` — старше 30 дней

Это **не замена** backup'а, а контроль роста. Backup сохраняет «снимок»
до cleanup'а — если в нём нужны данные старше retention, их можно достать
из старого backup'а.

### Monitoring

- SQL Agent должен слать письма при failed-job'ах (`sp_send_dbmail`).
- robocopy /LOG проверять еженедельно — что не растёт количество ошибок.
- Disk space на backup-сервере — alert при < 20% свободного.
- **Disk space сервера БД** — alert при росте `*.ldf` (sign'ал что TLog
  backup не работает и лог не truncate'ится).

---

## Какие данные мы НЕ сможем восстановить

Честный список того, что теряется при восстановлении:
- Активные WS-соединения — клиенты переподключатся через 1-30 сек.
- In-memory счётчики rate-limit и tokenVersionCache — обнуляются.
- Файлы из `uploads/`, загруженные **между** последним rsync'ом и моментом
  падения — потеряны (RPO для файлов ~24ч). Если критично — увеличить
  частоту rsync'а.

## Дрейф БД ↔ uploads/

БД и `uploads/` бэкапятся **независимо**: SQL Agent делает FULL+TLog в 02:00,
robocopy mirror'ит `uploads/` в 02:30. При восстановлении на момент **до** 02:30
получим записи в `Documents` без файлов на диске (или наоборот).

Что делать:
1. **Никогда не делать hard-restore только БД** без согласования времени с
   `uploads/` — будут 404 при попытке скачать документ.
2. Либо использовать **VSS snapshot** (Windows) или **btrfs/zfs snapshot**
   (Linux) для атомарного снимка обоих ресурсов одновременно.
3. Application-level: при `/api/documents/:id/download` если файла нет на
   диске → 410 Gone с понятным сообщением «Файл утерян, обратитесь к
   администратору». Сейчас просто 500 — стоит улучшить (см. server.js
   `res.download()` callback).

---

## Контакты при инциденте

В записке для РУП:
- Администратор системы: ФИО, телефон, email
- Резервный администратор: ФИО, телефон, email
- Поставщик MSSQL-лицензии (для восстановления подписки): контакт

В дипломной работе оставлены placeholder'ы.
