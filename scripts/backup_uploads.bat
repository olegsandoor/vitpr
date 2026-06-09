@echo off
REM ============================================================================
REM backup_uploads.bat — еженощное mirror-копирование папки uploads/ на backup-сервер
REM
REM Запуск: Task Scheduler, ежедневно 02:30 (после full-backup'а БД).
REM Лог: logs/backup-uploads-YYYY-MM-DD.log
REM
REM Перед использованием:
REM  1. Заменить SRC и DST на реальные пути
REM  2. Проверить наличие сетевого ресурса \\backup-server\vitenergo\uploads
REM  3. Если backup-сервер требует учётку — добавить `net use` перед robocopy
REM ============================================================================

set SRC=D:\nevitenergo\VitEnergo\uploads
set DST=\\backup-server\vitenergo\uploads
set LOGDIR=D:\nevitenergo\VitEnergo\logs

REM Дата в формате YYYY-MM-DD (locale-independent)
for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value') do set datetime=%%I
set DATE_TAG=%datetime:~0,4%-%datetime:~4,2%-%datetime:~6,2%

set LOG=%LOGDIR%\backup-uploads-%DATE_TAG%.log

if not exist %LOGDIR% mkdir %LOGDIR%

echo [%date% %time%] Старт backup uploads/ >> %LOG%
robocopy %SRC% %DST% /MIR /R:3 /W:5 /MT:8 /XO /LOG+:%LOG% /NP

REM robocopy exit codes:
REM  0 — нет изменений; 1 — скопировано; 2 — лишние удалены; 4 — несовпадения; 8+ — ошибки
set RC=%ERRORLEVEL%
echo [%date% %time%] robocopy exit code: %RC% >> %LOG%

if %RC% GEQ 8 (
    echo [%date% %time%] ОШИБКА: robocopy вернул код %RC% — backup не завершён >> %LOG%
    REM TODO: отправить email/Telegram-уведомление администратору
    exit /b 1
)

exit /b 0
