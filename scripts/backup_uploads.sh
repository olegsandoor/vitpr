#!/usr/bin/env bash
# =============================================================================
# backup_uploads.sh — еженощное rsync-копирование uploads/ на backup-сервер.
#
# Для Linux/Docker-окружения. Запуск через cron:
#     30 2 * * *  appuser  /opt/vitenergo/scripts/backup_uploads.sh
#
# Перед использованием:
#  1. Заменить SRC и DST на реальные пути
#  2. На backup-сервере должен быть rsync-демон или SSH-доступ
#  3. SSH-ключи без passphrase (если SSH-вариант)
# =============================================================================

set -euo pipefail

SRC="/opt/vitenergo/uploads/"
DST="backup-server::vitenergo-uploads/"     # rsync-daemon
# DST="backup@backup-server:/srv/vitenergo/uploads/"  # SSH вариант
LOGDIR="/opt/vitenergo/logs"
DATE_TAG=$(date +%Y-%m-%d)
LOG="$LOGDIR/backup-uploads-$DATE_TAG.log"

mkdir -p "$LOGDIR"

echo "[$(date)] Старт backup uploads/" >> "$LOG"

if rsync -a --delete --partial --stats "$SRC" "$DST" >> "$LOG" 2>&1; then
    echo "[$(date)] OK" >> "$LOG"
    exit 0
else
    rc=$?
    echo "[$(date)] FAIL: rsync exit $rc" >> "$LOG"
    # TODO: отправить email/Telegram администратору
    exit $rc
fi
