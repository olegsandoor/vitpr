# VitEnergo

Информационная система автоматизации согласования заявок на проведение
корпоративных мероприятий. Разработана для РУП «Витебскэнерго» в рамках
дипломного проекта.

Полный цикл документооборота: подача заявки сотрудником, модерация,
согласование ответственным лицом, формирование PDF-протокола, прикрепление
подписанной копии.

## Возможности

* Ролевая модель: Сотрудник, Модератор, Согласующий, Администратор
* Жизненный цикл заявки через 7 статусов с матрицей переходов, хранящейся в БД
* Real-time обновление списка, чата и ленты событий через WebSocket
* Загрузка файлов с многоступенчатой проверкой: whitelist расширений, magic-bytes
  через `file-type`, опциональная интеграция с ClamAV
* Генерация PDF-протоколов согласования (бланк к подписи, итоговый,
  протокол отказа) с водяным знаком для черновых статусов
* Календарь мероприятий с публичной витриной (`/events`), архивом за год
  и экспортом событий в формате iCalendar
* Аналитический дашборд с разбивкой KPI по статусам, динамикой по месяцам,
  фильтрацией по категориям и филиалам
* Журналирование всех действий пользователей с поиском по типу события, дате,
  заявке. Audit-trail для compliance закона РБ № 99-З о персональных данных
* OpenAPI 3.0 спецификация (доступна по `/api-docs` для администратора)

## Стек

| Слой         | Технология                                       |
|--------------|--------------------------------------------------|
| Backend      | Node.js 20, Express 5                            |
| База данных  | Microsoft SQL Server 2022                        |
| Frontend     | Vanilla JavaScript, без бандлера                 |
| Realtime     | WebSocket (`ws`) с handshake-аутентификацией     |
| PDF          | pdfkit                                           |
| Документация | swagger-jsdoc                                    |
| Контейнеры   | Docker, Docker Compose                           |

## Быстрый запуск через Docker

Требуется только Docker Desktop. Полное окружение, включая БД с
демонстрационными данными, поднимается одной командой.

```bash
git clone <repo-url> vitenergo
cd vitenergo

cp .env.example .env

# Сгенерируйте два разных секрета и впишите в JWT_SECRET и REFRESH_TOKEN_SECRET:
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

docker compose up -d
```

Через минуту приложение доступно по адресу `http://localhost:3000`.

При первом запуске вспомогательный init-контейнер восстанавливает базу из
`db/backup/VitEnergoProject.bak`. Это снимок готовой БД: схема со всеми
применёнными миграциями (00..37) и демонстрационные данные. Повторные запуски
используют сохранённое состояние из docker volume.

Остановка:
```bash
docker compose stop
```

Полная очистка, включая удаление volume с данными:
```bash
docker compose down -v
```

## Локальная установка для разработки

Требования: Node.js 20+, MS SQL Server 2022, `sqlcmd` в PATH.

```bash
git clone <repo-url> vitenergo
cd vitenergo
npm install
cp .env.example .env
```

Заполните `.env` параметрами подключения и JWT-секретами. Для локального MSSQL
с самоподписанным сертификатом оставьте `DB_TRUST_SERVER_CERT=true` (значение по
умолчанию в `.env.example`). Восстановите БД из `db/backup/VitEnergoProject.bak`
через SSMS или sqlcmd:

```sql
RESTORE DATABASE VitEnergoProject
   FROM DISK = 'C:\path\to\db\backup\VitEnergoProject.bak'
   WITH REPLACE, RECOVERY;
```

Создайте логин приложения. После RESTORE пользователь `VitEnergoUser` уже есть
в базе, но привязан к SID логина исходной машины, поэтому его нужно перемапить
через `ALTER USER ... WITH LOGIN`, иначе вход не сработает:

```sql
CREATE LOGIN VitEnergoUser WITH PASSWORD = 'VitEnergo123!';
USE VitEnergoProject;
IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'VitEnergoUser')
    ALTER USER VitEnergoUser WITH LOGIN = VitEnergoUser;
ELSE
    CREATE USER VitEnergoUser FOR LOGIN VitEnergoUser;
ALTER ROLE db_owner ADD MEMBER VitEnergoUser;
```

Запуск:
```bash
npm start
```

## Учётные записи для демонстрации

Единый пароль для всех ролей: `X12345678!`

| Роль          | Логин                          | ФИО                          |
|---------------|--------------------------------|------------------------------|
| Администратор | admin@vitebskenergo.by         | Власенко Игорь Леонидович    |
| Модератор     | t.kovaleva@vitebskenergo.by    | Ковалёва Татьяна Михайловна  |
| Согласующий   | e.morozova@vitebskenergo.by    | Морозова Елена Игоревна      |
| Сотрудник     | a.bondarenko@vitebskenergo.by  | Бондаренко Алексей Викторович |

Полный список из 24 сотрудников по 17 филиалам виден в админ-центре, раздел «Пользователи».

## Тестирование

```bash
npm test
```

Команда запускает около 90 интеграционных smoke-сценариев против работающего
сервера. Скрипт автоматически поднимает локальный инстанс на время выполнения
и останавливает его после.

Проверка стиля:
```bash
npm run lint
```

## API документация

После запуска приложения: `http://localhost:3000/api-docs` (требуется логин
администратора).

Эндпоинты сгруппированы в 10 разделов: Auth, Profile, Requests, Comments,
Documents, Notifications, Stats, Reference, Admin, Health.

Чистый JSON формата OpenAPI 3.0 для импорта в Postman или Insomnia доступен
по адресу `/api-docs.json` с Bearer-токеном.

## Структура проекта

```
server.js              основной серверный файл, 55 эндпоинтов
config/                доменные константы, OpenAPI-спецификация
db/backup/             бэкап БД (схема + демо-данные) для развёртывания
pdf/                   генератор PDF-протоколов согласования
public/                клиентская часть (HTML, CSS, JavaScript)
scripts/               вспомогательные скрипты (бэкап файлов, restore БД)
tests/                 интеграционные smoke-тесты
docs/                  runbook по бэкапам и развёртыванию
```

## Безопасность

Реализованы следующие меры:

* JWT-аутентификация с разделением access (15 мин) и refresh (7 дней) токенов
* Ротация refresh-токена при каждом обращении к `/api/refresh-token`
* Constant-time сравнение хешей через `crypto.timingSafeEqual`
* CSRF-защита через проверку Origin и Referer на мутирующих запросах
* BREACH-mitigation: отключение compression на auth-эндпоинтах
* Многоуровневые rate-limiters: per-user, per-IP, специальные для аутентификации
  и загрузки файлов
* IDOR-защита через единый `requireAccessToRequest` во всех эндпоинтах `/api/requests/*`
* Soft-delete пользователей и комментариев с сохранением целостности FK
* Аудит доступа к персональным данным (закон РБ № 99-З), retention 1 год
* Эскалация при подозрительной активности: временный лок при 3+ нарушениях
  MIME-валидации, постоянный при 5+ за сутки

Подробности по архитектурным решениям и принятым trade-off см. в `HANDOFF.md`.

## Производственное развёртывание

Чек-лист выкатки на боевой контур (переменные окружения, boot-time guards,
rate-limit caps, наблюдаемость) собран в `docs/PRODUCTION.md`. Резервное
копирование и восстановление БД и файлов описаны в `docs/BACKUP.md`.

## Лицензия

Учебный проект для дипломной работы. Используется в рамках сотрудничества
с РУП «Витебскэнерго».
