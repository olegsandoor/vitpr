#!/bin/bash
# Однократный init при первом `docker compose up`:
# восстанавливает БД из /backup/VitEnergoProject.bak, если её ещё нет.
set -e

# Используем sqlcmd 18 (-No = no encrypt prompt, -C = trust cert)
SQLCMD="/opt/mssql-tools18/bin/sqlcmd -S mssql -U sa -P ${MSSQL_SA_PASSWORD} -No -C"

echo "[db-init] Проверяем наличие БД VitEnergoProject..."

# Ждём пока mssql ответит на ping (несмотря на healthcheck в compose,
# первая sqlcmd-сессия иногда фейлится в первые секунды после healthy).
for i in 1 2 3 4 5 6 7 8 9 10; do
    if $SQLCMD -Q "SELECT 1" > /dev/null 2>&1; then
        break
    fi
    echo "[db-init] mssql не отвечает, попытка $i/10..."
    sleep 2
done

# Проверяем существует ли БД
DB_EXISTS=$($SQLCMD -h -1 -Q "SET NOCOUNT ON; SELECT CASE WHEN DB_ID('VitEnergoProject') IS NULL THEN 0 ELSE 1 END" | head -1 | tr -d '[:space:]')

if [ "$DB_EXISTS" = "1" ]; then
    echo "[db-init] БД VitEnergoProject уже существует — RESTORE пропущен."
    exit 0
fi

if [ ! -f /backup/VitEnergoProject.bak ]; then
    echo "[db-init] ОШИБКА: /backup/VitEnergoProject.bak не найден."
    echo "[db-init] Проверьте что db/backup/VitEnergoProject.bak присутствует в репо."
    exit 1
fi

echo "[db-init] БД отсутствует. Восстанавливаем из /backup/VitEnergoProject.bak..."
$SQLCMD -Q "
RESTORE DATABASE VitEnergoProject
   FROM DISK = N'/backup/VitEnergoProject.bak'
   WITH MOVE N'VitEnergoProject_data' TO N'/var/opt/mssql/data/VitEnergoProject.mdf',
        MOVE N'VitEnergoProject_log'  TO N'/var/opt/mssql/data/VitEnergoProject_log.ldf',
        REPLACE, RECOVERY;
"

# Пароль app-логина из env DB_PASSWORD (должен совпадать с app-контейнером).
APP_DB_PASSWORD="${DB_PASSWORD:-VitEnergo123!}"

echo "[db-init] Создаём/чиним логин и пользователя VitEnergoUser..."
$SQLCMD -d VitEnergoProject -Q "
SET NOCOUNT ON;

-- 1) Логин уровня сервера. Создаём, либо приводим пароль к значению из env
--    (на случай повторного запуска с изменённым DB_PASSWORD).
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'VitEnergoUser')
    CREATE LOGIN VitEnergoUser WITH PASSWORD = N'${APP_DB_PASSWORD}', CHECK_POLICY = OFF;
ELSE
    ALTER LOGIN VitEnergoUser WITH PASSWORD = N'${APP_DB_PASSWORD}';

-- 2) Пользователь БД из .bak привязан к SID логина другой машины (orphaned).
--    Перемапливаем на свежесозданный логин, иначе app не получит доступ к базе.
IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'VitEnergoUser' AND type = 'S')
    ALTER USER VitEnergoUser WITH LOGIN = VitEnergoUser;
ELSE
    CREATE USER VitEnergoUser FOR LOGIN VitEnergoUser;

-- 3) Гарантируем членство в db_owner (идемпотентно).
IF NOT EXISTS (
    SELECT 1
    FROM sys.database_role_members rm
    JOIN sys.database_principals r ON r.principal_id = rm.role_principal_id AND r.name = N'db_owner'
    JOIN sys.database_principals u ON u.principal_id = rm.member_principal_id AND u.name = N'VitEnergoUser'
)
    ALTER ROLE db_owner ADD MEMBER VitEnergoUser;
"

echo "[db-init] Готово. Приложение может стартовать."
