require('dotenv').config();

const express = require('express');
const path = require('path');
const http = require('http');
const WebSocket = require('ws');
const fs = require('fs').promises;
const crypto = require('crypto');

const sql = require('mssql');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const archiver = require('archiver');
const cookieParser = require('cookie-parser');
const compression = require('compression');
const ExcelJS = require('exceljs');
const swaggerUi = require('swagger-ui-express');
const { swaggerSpec } = require('./config/swagger');

// Доменные константы загружаются из БД при старте сервера (см. config/constants.js).
const {
    ROLES, ROLE_NAMES,
    STATUSES, STATUS_NAMES,
    loadConstants,
    activeStatusList,
    isTransitionAllowed,
    getRoleIdByName,
    getAllowedTargetsForRole,
    PDF_PROTOCOL_CONFIG,
    getPdfProtocolAccess
} = require('./config/constants');

// Корневая директория для физических файлов загрузок.
// БД хранит только filename — полный путь строится через resolveUploadPath().
const UPLOADS_DIR = path.join(__dirname, 'uploads');

// Глобальный mssql ConnectionPool (в v12 нет модульного sql.pool, держим ссылку сами).
// Нужен для /api/health pool-метрик и fast-fail middleware.
let dbPool = null;

/**
 * Защита от path traversal (defense-in-depth):
 *   `Documents.file_path` берётся из БД, путь склеивается с UPLOADS_DIR.
 *   Если кто-то изменит file_path на `../../etc/passwd` (через будущий
 *   баг в админ-CRUD'е, инсайдер DBA, SQL injection в новом эндпоинте) —
 *   `path.join` нормализует, но НЕ блокирует выход из корневой папки.
 *   `path.resolve(UPLOADS_DIR, rel).startsWith(UPLOADS_DIR + sep)` —
 *   единственная корректная проверка.
 *
 * @returns {string|null} абсолютный путь внутри UPLOADS_DIR, или null если выход.
 */
function resolveUploadPath(relPath) {
    if (typeof relPath !== 'string' || !relPath) return null;
    const abs = path.resolve(UPLOADS_DIR, relPath);
    const root = UPLOADS_DIR + path.sep;
    if (abs !== UPLOADS_DIR && !abs.startsWith(root)) {
        console.error(`[security] path traversal попытка: relPath=${relPath}, resolved=${abs}`);
        return null;
    }
    return abs;
}

const helmet = require('helmet');
const { rateLimit, ipKeyGenerator } = require('express-rate-limit');

/**
 * Ошибка отклонения файла. severity определяет реакцию системы:
 *   - 'soft'   — формат не поддерживается, но безопасен (mp4, heic, psd…). Без штрафа.
 *   - 'medium' — содержимое не соответствует заявленному типу (битый файл / необычный формат).
 *   - 'high'   — попытка загрузить опасный файл (.exe, .bat, скрипт) или мимикрия под PDF.
 */
class InvalidFileTypeError extends Error {
    constructor(fileName, severity = 'medium', category = 'mime_mismatch') {
        super(`Файл "${fileName}" отклонён.`);
        this.name = 'InvalidFileTypeError';
        this.fileName = fileName;
        this.severity = severity;
        this.category = category;
    }
}

/* =============================================================================
   Классификация файлов: разрешённые / неподдерживаемые / опасные.
   ============================================================================= */

// 🟢 Разрешённые MIME (документы, изображения, архивы) — пропускаются на magic-check.
const SAFE_MIMES = new Set([
    // Документы
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.oasis.opendocument.text',
    'application/rtf',
    'text/rtf',
    // Таблицы
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.oasis.opendocument.spreadsheet',
    'text/csv',
    // Презентации
    'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'application/vnd.oasis.opendocument.presentation',
    // Изображения
    'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/bmp', 'image/tiff',
    'image/svg+xml',
    // Архивы
    'application/zip', 'application/x-zip-compressed',
    'application/x-rar-compressed', 'application/vnd.rar',
    'application/x-7z-compressed',
    // Текст
    'text/plain'
]);

// 🔴 Опасные расширения — попытка такой загрузки = security incident.
const DANGEROUS_EXTENSIONS = new Set([
    // Исполняемые
    'exe', 'bat', 'cmd', 'com', 'msi', 'scr', 'pif', 'dll', 'sys', 'drv',
    // Скрипты
    'sh', 'ps1', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'mjs',
    'py', 'rb', 'pl', 'lua',
    // Web (потенциальный XSS / RCE)
    'php', 'phtml', 'php3', 'php4', 'php5', 'asp', 'aspx', 'jsp', 'cgi',
    'html', 'htm', 'xhtml',
    // Java / .NET
    'jar', 'class', 'war', 'ear',
    // Office с макросами
    'docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'potm', 'xlam', 'xll',
    // Установщики
    'apk', 'ipa', 'app', 'deb', 'rpm', 'dmg', 'iso', 'img'
]);

// 🔴 Опасные MIME-типы (определяются по magic-bytes file-type).
const DANGEROUS_MIMES = new Set([
    'application/x-msdownload',
    'application/x-msdos-program',
    'application/x-executable',
    'application/x-elf',
    'application/x-mach-binary',
    'application/x-bat',
    'application/x-sh',
    'application/x-perl',
    'application/x-python',
    'application/x-php',
    'application/javascript',
    'application/x-javascript',
    'text/javascript',
    'text/html',
    'application/xhtml+xml',
    'application/java-archive',
    'application/x-java-applet'
]);

/**
 * Классифицирует файл на 3 уровня. Возвращает { kind, severity, category, message }.
 * @param {Object} args
 * @param {string} args.fileName    — имя файла (после sanitize)
 * @param {string} args.claimedMime — то, что заявил браузер (Content-Type)
 * @param {string|null} args.actualMime — то, что определил file-type (или null если не определимо)
 */
function classifyFile({ fileName, claimedMime, actualMime }) {
    const ext = (fileName.split('.').pop() || '').toLowerCase();

    // Уровень 1: явно опасное расширение
    if (DANGEROUS_EXTENSIONS.has(ext)) {
        return {
            kind: 'rejected',
            severity: 'high',
            category: 'dangerous_extension',
            message: `Файл «${fileName}» относится к категории потенциально опасных (.${ext}). Загрузка таких файлов запрещена политикой безопасности.`
        };
    }

    // Уровень 2: опасный заявленный MIME
    if (DANGEROUS_MIMES.has(claimedMime)) {
        return {
            kind: 'rejected',
            severity: 'high',
            category: 'dangerous_mime',
            message: `Файл «${fileName}» имеет тип, запрещённый политикой безопасности.`
        };
    }

    // Уровень 3: реальное содержимое — исполняемое или скриптовое
    if (actualMime && DANGEROUS_MIMES.has(actualMime)) {
        return {
            kind: 'rejected',
            severity: 'high',
            category: 'dangerous_content',
            message: `Содержимое файла «${fileName}» определено как ${actualMime} — это исполняемый/скриптовый код. Попытка зарегистрирована.`
        };
    }

    // Уровень 4: разрешённый формат — но проверим mismatch magic-bytes
    if (SAFE_MIMES.has(claimedMime)) {
        if (actualMime && !SAFE_MIMES.has(actualMime)) {
            // Magic-bytes показал что-то совсем другое (не safe и не dangerous, но в любом случае не совпадает)
            return {
                kind: 'rejected',
                severity: 'medium',
                category: 'mime_mismatch',
                message: `Содержимое файла «${fileName}» не соответствует заявленному типу (${claimedMime} ≠ ${actualMime}).`
            };
        }
        return { kind: 'accepted' };
    }

    // Уровень 5: не в whitelist, но и не опасное — soft reject
    return {
        kind: 'rejected',
        severity: 'soft',
        category: 'unsupported_format',
        message: `Формат «.${ext || claimedMime}» не поддерживается. Загружайте документы (PDF, DOCX, XLSX, PPTX), изображения (PNG, JPG) или архивы (ZIP, RAR).`
    };
}

const app = express();
// trust proxy ВКЛЮЧАЕМ только за обратным прокси (nginx, traefik, ALB).
// Если включить безусловно при прямом deploy — атакующий шлёт заголовок
// `X-Forwarded-For: 1.2.3.4` и подменяет IP во всех логах + байпасит
// per-IP rate-limit. Управляется через .env: BEHIND_PROXY=true.
if (process.env.BEHIND_PROXY === 'true') {
    app.set('trust proxy', 1);
}

const PORT = process.env.PORT || 3000;
const dbConfig = {
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    server: process.env.DB_SERVER,
    database: process.env.DB_DATABASE,
    options: {
        encrypt: true,
        // dev: доверяем cert; prod: валидируем, кроме явного DB_TRUST_SERVER_CERT=true
        // (нужно для контейнерной mssql с self-signed сертификатом).
        trustServerCertificate: process.env.DB_TRUST_SERVER_CERT === 'true' || process.env.NODE_ENV !== 'production',
        // Все DATETIME2 без TZ читаются как UTC, при записи new Date() конвертируется
        // в UTC. Критично для «окна редактирования 24ч» и для кросс-TZ-окружений
        // (Linux-контейнер vs Windows-разработка могут быть в разных TZ).
        useUTC: true
    },
    // Connection pool под одновременную работу 50+ пользователей.
    // max=20 параллельных соединений достаточно для сценария 5 одновременных WS + 30 активных REST-запросов.
    pool: {
        max: 20,
        min: 2,
        idleTimeoutMillis: 30000,
        acquireTimeoutMillis: 15000
    }
};

// Helmet с явно настроенной Content Security Policy.
// 'self' для скриптов и стилей: всё подаётся с нашего же сервера.
// 'unsafe-inline' для style-src нужен из-за inline `style="..."` атрибутов
// (цветовая разметка категорий) — общепринятая практика для UI-приложений.
// Внешние ресурсы: только Google Fonts и data: URI для иконок/шрифтов.
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc:  ["'self'"],
            styleSrc:   ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc:    ["'self'", "https://fonts.gstatic.com", "data:"],
            imgSrc:     ["'self'", "data:"],
            // убрано `ws:`/`wss:` — CSP `'self'` (since ~Chrome M86 / FF M99)
            // покрывает WebSocket к тому же origin'у с любым ws/wss-протоколом.
            // Раньше широкий список разрешал exfiltration через любой WS-эндпоинт
            // в случае stored XSS. Теперь — только same-origin.
            connectSrc: ["'self'"],
            objectSrc:  ["'none'"],
            frameAncestors: ["'none'"],
            baseUri:    ["'self'"],
            formAction: ["'self'"]
        }
    },
    crossOriginEmbedderPolicy: false  // не блокировать наши локальные шрифты/PDF
}));

// Permissions-Policy — helmet 8 не выставляет автоматически.
// Без него iframe/embed может получить доступ к geolocation/microphone/camera
// если каким-то образом окажется на нашем origin (через injection / future bug).
// Whitelist пустой — для нашего приложения эти браузерные APIs не используются.
app.use((req, res, next) => {
    res.setHeader(
        'Permissions-Policy',
        'geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=(), midi=()'
    );
    next();
});

// CSRF guard: для мутирующих запросов проверяем Origin/Referer против whitelist.
// Whitelist собирается из:
// - текущего Host заголовка (тот же ориджин — всегда OK)
// - ALLOWED_ORIGINS из .env (запятая-разделённый список) — для прод-доменов
// Запросы БЕЗ Origin/Referer пропускаются ТОЛЬКО для не-браузерных клиентов:
// Sec-Fetch-Site отсутствует ⇒ это curl/Postman (а они должны иметь валидный
// Bearer-токен, который проверит authenticateToken дальше). Браузер всегда
// проставляет Sec-Fetch-Site, и если он есть, а Origin нет — это аномалия,
// мы её отклоняем.
const EXTRA_ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
    .split(',').map(s => s.trim()).filter(Boolean);

app.use((req, res, next) => {
    if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();
    if (!req.path.startsWith('/api/')) return next();

    const origin = req.headers.origin || req.headers.referer || '';
    const host = req.headers.host;
    const secFetchSite = req.headers['sec-fetch-site'];

    if (!origin) {
        // Браузер всегда шлёт Sec-Fetch-Site. Его наличие при пустом Origin —
        // подозрение на атаку (старый/специально кастомный браузер).
        if (secFetchSite) {
            return res.status(403).json({ message: 'Origin missing from browser request.' });
        }
        // Не-браузерный клиент (curl/Postman/тест) — пропускаем; ниже сработает
        // authenticateToken и без него ничего не получится.
        return next();
    }

    try {
        const u = new URL(origin);
        if (u.host === host) return next();
        if (EXTRA_ALLOWED_ORIGINS.includes(`${u.protocol}//${u.host}`)) return next();
    } catch (_) { /* не URL — отклоняем */ }
    return res.status(403).json({ message: 'Cross-origin запрос отклонён.' });
});

/* =============================================================================
   Многоуровневое журналирование в файлы.
   Категории:
     access   — каждый HTTP-запрос (метод, URL, статус, время, юзер, IP)
     security — нарушения политики, блокировки, неудачные логины
     admin    — действия администраторов (изменения юзеров, разблокировки)
   Файлы именуются: logs/{category}-YYYY-MM-DD.log (авто-ротация по дате).
   ============================================================================= */

const LOGS_DIR = path.join(__dirname, 'logs');
(async () => {
    try { await fs.mkdir(LOGS_DIR, { recursive: true }); }
    catch (e) { console.error('Не удалось создать папку logs/:', e.message); }
})();

// rate-limit per (category, event-type) для защиты диска.
// Без этого если broken proxy шлёт мусор и `wss.on('error')` фиксирует 1000
// ошибок/сек — fs.appendFile отправляет 1000 syscall'ов/сек, security-{date}.log
// растёт до GB за минуту. Token-bucket: max 60 событий/мин на ключ.
// Ключ = `${category}:${event}` (event опционально из payload.event), при
// превышении первый «overflow» пишется со счётчиком, далее silent skip
// до окна. Аудит-категории (admin) НЕ rate-limit'ятся — там explicit user
// actions, не бесконтрольный burst.
const FILELOG_RATE_BUDGET = 60;        // events per window
const FILELOG_RATE_WINDOW_MS = 60000;  // 1 min
const _fileLogBuckets = new Map();
function _consumeFileLogBudget(key) {
    const now = Date.now();
    const b = _fileLogBuckets.get(key);
    if (!b || (now - b.windowStart) >= FILELOG_RATE_WINDOW_MS) {
        _fileLogBuckets.set(key, { windowStart: now, count: 1, dropped: 0 });
        return { allow: true, droppedBeforeReset: b ? b.dropped : 0 };
    }
    if (b.count < FILELOG_RATE_BUDGET) {
        b.count++;
        return { allow: true, droppedBeforeReset: 0 };
    }
    b.dropped++;
    // Раз в каждые BUDGET drop'ов — всё-таки пишем заметку об overflow.
    if (b.dropped === 1 || b.dropped % FILELOG_RATE_BUDGET === 0) {
        return { allow: true, overflow: true, droppedSoFar: b.dropped };
    }
    return { allow: false };
}
function writeFileLog(category, payload) {
    // E2/H-5: admin И security категории — БЕЗ rate-limit'а.
    // Раньше security попадал в общий бюджет, и атакующий через 60+
    // failed-login'ов с одной IP за минуту вытеснял собственные записи
    // из forensic-журнала — именно эпизод атаки терялся. Теперь:
    // - admin: явные user-actions, низкая частота → не лимитим.
    // - security: критично сохранить ВСЕ инциденты для post-mortem
    // (закон РБ №99-З требует audit retention 1 год, см. mig 19).
    // - access (HTTP-логи): potentially burst-able → лимитим.
    // - другие категории: лимитим по дефолту.
    if (category !== 'admin' && category !== 'security') {
        const event = (payload && payload.event) || '_unknown';
        const verdict = _consumeFileLogBudget(`${category}:${event}`);
        if (!verdict.allow) return;
        if (verdict.overflow) {
            payload = { ...payload, _overflow_dropped: verdict.droppedSoFar };
        }
    }
    // E2/H-5: payload в spread'е первым — наш `ts` всегда выигрывает.
    // Раньше payload.ts мог затереть наш timestamp (post-mortem timeline сломан).
    const entry = JSON.stringify({ ...payload, ts: new Date().toISOString() }) + '\n';
    const date = new Date().toISOString().slice(0, 10);
    const filename = path.join(LOGS_DIR, `${category}-${date}.log`);
    fs.appendFile(filename, entry, 'utf8').catch(err =>
        console.error(`writeFileLog(${category}) error:`, err.message)
    );
}

// маскируем чувствительные query-параметры перед записью в access-log.
// Сейчас в URL'ах нет sensitive (search/page/status) — но логи живут 30 дней,
// и любой будущий endpoint с `?token=` / `?reset=` сразу попадёт в архив.
// Whitelist значений по regex имени параметра — keys with token/password/secret/
// code/hash/key заменяем на `***`, остальные оставляем для отладки фильтров.
const SENSITIVE_QUERY_KEY_RE = /(token|password|secret|code|hash|key|auth)/i;
function scrubQuery(originalUrl) {
    if (typeof originalUrl !== 'string') return originalUrl;
    const qIdx = originalUrl.indexOf('?');
    if (qIdx === -1) return originalUrl;
    const path = originalUrl.slice(0, qIdx);
    const query = originalUrl.slice(qIdx + 1);
    const scrubbed = query.split('&').map(pair => {
        const eqIdx = pair.indexOf('=');
        if (eqIdx === -1) return pair;
        const key = pair.slice(0, eqIdx);
        // URL-encoded sensitive keys с malformed %-sequence
        // обходили scrub через fallback на raw bytes. Например `?%70%61ssword%E0=...`:
        // decodeURIComponent бросает на `%E0` (truncated UTF-8) → fallback на raw
        // `%70%61ssword%E0` → regex `/password/i` НЕ сматчит литерала "password"
        // → значение уходит в access-log незамасакированным.
        // Paranoid default: при любой ошибке декодирования — scrub'аем безусловно.
        let decoded, decodeOk = true;
        try { decoded = decodeURIComponent(key); }
        catch (e) {
            if (e instanceof URIError) decodeOk = false;
            else throw e;
        }
        if (!decodeOk || SENSITIVE_QUERY_KEY_RE.test(decoded)) {
            return `${key}=***`;
        }
        return pair;
    }).join('&');
    return `${path}?${scrubbed}`;
}

// Middleware: пишет каждый осмысленный запрос в access.log.
// Игнорирует статические ресурсы (vendor/, .css/.js/.png и т.п.) — они спамят.
app.use((req, res, next) => {
    const skip = req.path.startsWith('/vendor/')
              || /\.(css|js|mjs|map|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|otf|eot|json)$/i.test(req.path);
    if (skip) return next();

    const start = Date.now();
    res.on('finish', () => {
        writeFileLog('access', {
            method: req.method,
            url:    scrubQuery(req.originalUrl),
            status: res.statusCode,
            ms:     Date.now() - start,
            ip:     req.ip || req.socket.remoteAddress,
            userId: req.user?.id || null,
            role:   req.user?.role || null
        });
    });
    next();
});

/**
 * JWT hardening: единый issuer + audience + явный whitelist алгоритма.
 * Без этого:
 *  - Если разработчик случайно поделит JWT_SECRET с другим dev-проектом,
 *    токены сработают везде где совпал секрет (нет привязки к нашему домену).
 *  - jsonwebtoken 9+ блокирует alg:none, но whitelist — defence-in-depth.
 *
 * `aud` различается для access/refresh, чтобы access-токен нельзя было
 * предъявить как refresh и наоборот.
 */
const JWT_ISSUER = 'vitenergo';
const JWT_AUD_ACCESS = 'vitenergo-access';
const JWT_AUD_REFRESH = 'vitenergo-refresh';
const JWT_AUD_DOCS = 'vitenergo-docs';
const JWT_ALG = 'HS256';

// bcrypt cost-factor для всех новых хешей. NIST/OWASP 2026
// рекомендуют ≥12 (предпочтительно 13-14). Cost 10 на современном CPU — ~100мс,
// специализированное железо может перебирать 10⁵+ guesses/sec — слишком быстро.
// Backward-compat: существующие хеши (`$2b$10$...`) НЕ меняются — bcrypt сам
// читает cost из строки при verify. Меняется только cost для новых паролей.
const BCRYPT_COST = 12;

// refreshToken cookie ограничен path'ом эндпоинта /api/refresh-token.
// До фикса cookie шёл на КАЖДЫЙ запрос (включая статику /css/*.css, /vendor/*.js):
// расширяет surface CSRF / cookie-leak'а через mismatched same-site sub-resources.
// Теперь браузер шлёт cookie ТОЛЬКО на единственный эндпоинт, который её читает.
// Важно: clearCookie тоже обязан передавать тот же path — иначе браузер не удалит
// cookie (другая (name, domain, path)-тройка).
const REFRESH_COOKIE_PATH = '/api/refresh-token';
const REFRESH_COOKIE_OPTS = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: REFRESH_COOKIE_PATH,
    maxAge: 7 * 24 * 60 * 60 * 1000
};
const REFRESH_COOKIE_CLEAR_OPTS = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: REFRESH_COOKIE_PATH
};

function signAccess(payload) {
    return jwt.sign(payload, process.env.JWT_SECRET, {
        expiresIn: '15m', algorithm: JWT_ALG,
        issuer: JWT_ISSUER, audience: JWT_AUD_ACCESS
    });
}
function signRefresh(payload) {
    return jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, {
        expiresIn: '7d', algorithm: JWT_ALG,
        issuer: JWT_ISSUER, audience: JWT_AUD_REFRESH
    });
}
function verifyAccess(token, cb) {
    return jwt.verify(token, process.env.JWT_SECRET, {
        algorithms: [JWT_ALG], issuer: JWT_ISSUER, audience: JWT_AUD_ACCESS
    }, cb);
}
function verifyRefresh(token) {
    return jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, {
        algorithms: [JWT_ALG], issuer: JWT_ISSUER, audience: JWT_AUD_REFRESH
    });
}

// Лимит /api/login + /api/refresh-token. Стандартный 10/15м. Поднять можно
// через .env (AUTH_LIMITER_MAX) — нужно для smoke-тестов, где много login'ов
// идут с одного IP.
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: Math.max(1, parseInt(process.env.AUTH_LIMITER_MAX, 10) || 10),
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        message: 'Слишком много попыток. Пожалуйста, попробуйте снова через 15 минут.'
    }
});

/**
 * Soft-decode middleware: если в запросе есть валидный access-токен —
 * декодирует и кладёт user в req.user. НЕ отвергает запрос при отсутствии
 * или невалидности — это работа authenticateToken дальше по стеку.
 *
 * Зачем: apiLimiter монтируется на префикс /api/ до per-route auth-middleware,
 * и его skip-функция должна знать роль текущего юзера. Раньше мы дублировали
 * jwt.verify внутри skip — это два полных HMAC-расчёта на каждый запрос.
 * Теперь верифицируем один раз тут, дальше переиспользуем.
 */
function softDecodeToken(req, _res, next) {
    const auth = req.headers['authorization'];
    const token = auth && auth.split(' ')[1];
    if (!token) return next();
    verifyAccess(token, async (err, user) => {
        if (err || !user) return next();
        // Проверяем tokenVersion — иначе отозванный (через bumpTokenVersion)
        // админ всё равно получит skip от apiLimiter. Если версия не совпала
        // — игнорируем токен, дальше authenticateToken вернёт 401.
        // токен БЕЗ tv-claim (pre-mig-16 / forged) тоже игнорируем
        // — раньше `user.tv ?? 1` принимал такой токен как tv=1 и пропускал
        // soft-decode. Теперь все валидные токены сервера содержат tv явно.
        try {
            if (user.id) {
                const expected = await getTokenVersion(user.id);
                if (typeof user.tv !== 'number' || user.tv < expected) return next();
            }
        } catch (_) { /* при ошибке БД — пропускаем soft-decode */ }
        req.user = user;
        next();
    });
}

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20000,
    standardHeaders: true,
    legacyHeaders: false,
    // Per-user ключ: один авторизованный юзер не может съесть всю квоту IP
    // (например, через NAT 100 юзеров за одним внешним IP). У анонимов ключ
    // остаётся IP, но через ipKeyGenerator() — чтобы IPv6 правильно нормализовался
    // (иначе в /128 каждый адрес — отдельное ведро, и атакующий с /48 может
    // обойти лимит).
    keyGenerator: (req, res) => req.user?.id ? `u:${req.user.id}` : `ip:${ipKeyGenerator(req, res)}`,
    // Админ освобождён от общего лимита (для импорта/выгрузок).
    skip: (req) => req.user?.role === 'Администратор'
});

// Второй слой защиты — лимитер строго по IP, поверх per-user. Закрывает
// NAT-amplification: 100 авторизованных юзеров за одним внешним IP × 20000
// per-user = 2 млн запросов/15м = ~2200 RPS на ту же саму БД. Ограничиваем
// агрегированный трафик с одного IP. Цифра 60000/15м = 67 RPS, что в десятки
// раз больше нормальной офисной нагрузки (100 юзеров × 0.1 RPS среднее).
// Админа НЕ скипаем — этот слой против ботнета, не против юзера-роли.
const ipHeavyLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 60000,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req, res) => `ip:${ipKeyGenerator(req, res)}`,
    message: { message: 'Слишком много запросов с этого IP. Подождите 15 минут.' }
});

// Excel-экспорт — отдельный, ещё более жёсткий лимит per IP. Каждый экспорт это
// fetch всех заявок в скоупе + ExcelJS-сериализация. 100 экспортов/15м/IP =
// ~7 в минуту — больше чем любому реальному юзеру нужно. Бот привязан.
const ipExportLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req, res) => `ip:${ipKeyGenerator(req, res)}`,
    message: { message: 'Слишком много экспортов с этого IP.' }
});

// upload rate-limiter — multipart-запросы в минуту на юзера. Главный
// OOM-вектор: `multer.memoryStorage()` + 10 файлов × 15 МБ = 150 МБ heap на
// один запрос. 50 одновременных = 7.5 ГБ → Node OOM. Реальный человек редко
// делает >3 upload-сессий в минуту; бот привязан к лимиту.
// Применяется к POST /api/requests и POST /api/requests/:id/documents.
// Дефолт 3/мин на проде; в dev/smoke поднимается через UPLOAD_LIMITER_MAX
// (smoke создаёт много заявок подряд).
const uploadLimiter = rateLimit({
    windowMs: 60 * 1000,
    // Math.max clamp — `parseInt('-1', 10) || 3` возвращает -1 (truthy),
    // и express-rate-limit интерпретирует max=-1 как unlimited → обход лимита
    // через misconfig env. Явно требуем ≥1.
    max: Math.max(1, parseInt(process.env.UPLOAD_LIMITER_MAX, 10) || 3),
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => `upload:${req.user?.id || 'anon'}`,
    message: { message: 'Слишком много загрузок подряд. Подождите минуту.' }
});

// per-user rate-limit на создание заявок и комментариев. Один юзер
// без semantic cap'а может через apiLimiter (20k/15м) создать 1000 заявок/мин
// или флудить комментариями — DB bloat, notification storm на подписчиков
// канала. Реальный человек редко создаёт >20 заявок в час и >100 комментариев
// в час; cap'ы покрывают любое разумное использование.
const requestCreationLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: Math.max(1, parseInt(process.env.REQUEST_CREATE_MAX, 10) || 30),
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => `req-create:${req.user?.id || 'anon'}`,
    message: { message: 'Достигнут лимит создания заявок (30 в час). Подождите.' }
});
const commentCreationLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: Math.max(1, parseInt(process.env.COMMENT_CREATE_MAX, 10) || 120),
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => `cmt-create:${req.user?.id || 'anon'}`,
    message: { message: 'Слишком много комментариев. Подождите.' }
});

// Reactions toggle: каждое срабатывание шлёт `detail_update` всем подписчикам
// канала. Юзер с 30 подписчиками + цикл toggle 100/сек = 3000 WS-сообщений/сек.
// Ограничиваем 30 toggle/мин на (user, comment), что покрывает любую разумную
// модель использования (даже самый эмоциональный юзер не клацает каждые 2 сек
// на одно сообщение). Бот тоже не сможет спамить — ключ включает comment_id,
// поэтому атакующий не обойдёт меняя коммент-id (придётся искать живые
// сообщения в выборке, что само по себе ограничивает сценарий).
const reactionsLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => `react:${req.user?.id || 'anon'}:${req.params?.id || '?'}`,
    message: { message: 'Слишком частые реакции на это сообщение.' }
});

// Gzip-сжатие всех текстовых ответов (HTML/JS/CSS/JSON) — даёт 5-10× уменьшение трафика.
// Бинарные ответы (PDF, изображения) compression игнорирует автоматически.
//
// BREACH-mitigation: при HTTPS + compression + reflected user-input в response
// злоумышленник может извлечь auth-секреты по compression-ratio (CVE-2013-3587).
// Не сжимаем ТОЛЬКО реально чувствительные endpoint'ы:
// - /api/login, /api/refresh-token, /api/logout — содержат tokens
// - /api/profile/* — личный профиль (ФИО, email, история входов)
// - /api/admin/users, /api/admin/logs, /api/admin/file-attempts,
// /api/admin/pii-audit — списки с ПДн других юзеров
// Категории, KPI-сводки, типы событий — без ПДн, сжимаются нормально.
const COMPRESSION_SKIP_PATHS = [
    '/api/login',
    '/api/refresh-token',
    '/api/logout',
    '/api/profile/',
    '/api/admin/users',
    '/api/admin/logs',
    '/api/admin/file-attempts',
    '/api/admin/pii-audit'
];
app.use(compression({
    threshold: 1024,                     // не сжимать ответы < 1 KB
    filter: (req, res) => {
        if (req.headers['x-no-compression']) return false;
        // BREACH-mitigation: chunky опасные endpoint'ы — без gzip.
        if (COMPRESSION_SKIP_PATHS.some(p => req.path === p || req.path.startsWith(p + '/') || req.path.startsWith(p + '?'))) return false;
        return compression.filter(req, res);
    }
}));

// Vendor-библиотеки (FullCalendar, Chart.js, шрифты) и шрифты — immutable, кэшируем 30 дней.
app.use('/vendor', express.static(path.join(__dirname, 'public', 'vendor'), {
    maxAge: '30d',
    immutable: true,
    etag: true
}));

// Чистые URL для HTML-страниц без расширения .html.
// Эти роуты ОБЯЗАНЫ стоять ПЕРЕД express.static — иначе serve-static, не находя
// файла «/events» (без .html), выставляет статус 404 + CSP `default-src 'none'`,
// и хотя последующий fallback-handler отправляет правильное тело, заголовки
// уже испорчены. Сценарий мы наблюдали в Эшелоне 3.5 — фикс этого бага.
//
// Используем `{ root: ... }` вместо абсолютного пути в первом аргументе.
// Send 1.x по умолчанию `dotfiles: 'ignore'` ⇒ если __dirname сам содержит
// dot-prefixed segment (`.claude/worktrees/...` при отладке через worktree),
// проверка `containsDotFile` отдаёт 404 ещё до stat'а файла. С `root` send
// проверяет только относительный путь от root'а — корень не участвует.
const PUBLIC_ROOT = path.join(__dirname, 'public');
app.get('/login',  (req, res) => res.sendFile('login.html',  { root: PUBLIC_ROOT }));
app.get('/events', (req, res) => res.sendFile('events.html', { root: PUBLIC_ROOT }));

// Остальная статика — кэш на 1 час, ETag-валидация (re-validate если контент изменился).
app.use(express.static(path.join(__dirname, 'public'), {
    maxAge: '1h',
    etag: true
}));
// Безопасность: папка uploads НЕ раздаётся как static — доступ к файлам только
// через /api/documents/:id/download с проверкой авторизации и принадлежности заявке.
//
// Body-parser limit: явный 256 КБ (default body-parser даёт 100 КБ, но недокументировано).
// Реальные нужды: comment_text 5000 символов (~10 КБ), batch-status до 100 ids (~1 КБ),
// admin-форма создания юзера (~1 КБ). 256 КБ — с большим запасом, но ставит потолок
// для DoS через гигантский JSON. Файлы идут через multer (не json), у них свой лимит.
app.use(express.json({ limit: '256kb' }));
app.use(cookieParser());

const upload = multer({
    storage: multer.memoryStorage(),
    fileFilter: (req, file, cb) => {
        // 1-я линия: классификация на стадии приёма (по заявленному MIME и расширению).
        // Сюда ещё не попадают magic-bytes — это будет в validateAndSaveFiles.
        const sanitizedName = path.basename(
            Buffer.from(file.originalname, 'latin1').toString('utf8')
        ).replace(/[<>:"/\\|?*\x00-\x1F]/g, '_') || ('file_' + Date.now());

        const verdict = classifyFile({
            fileName: sanitizedName,
            claimedMime: file.mimetype,
            actualMime: null
        });

        if (verdict.kind === 'accepted') {
            cb(null, true);
        } else {
            const err = new InvalidFileTypeError(sanitizedName, verdict.severity, verdict.category);
            err.claimedMime = file.mimetype;
            err.actualMime = null;
            err.userMessage = verdict.message;
            cb(err, false);
        }
    },
    limits: {
        fileSize: 15 * 1024 * 1024
    }
});

async function validateAndSaveFiles(files, ctx = {}) {
    if (!files || files.length === 0) return [];

    const {
        fileTypeFromBuffer
    } = await import('file-type');
    const filesToProcess = [];

    for (const file of files) {
        // Безопасность: декодируем имя из latin1→utf8, затем sanitize:
        // - path.basename защищает от path traversal (../../etc/passwd)
        // - regex выбрасывает управляющие символы и зарезервированные на Windows/Unix
        let originalname = Buffer.from(file.originalname, 'latin1').toString('utf8');
        originalname = path.basename(originalname).replace(/[<>:"/\\|?*\x00-\x1F]/g, '_');
        if (!originalname || originalname === '.' || originalname === '..') {
            originalname = 'file_' + Date.now();
        }
        if (originalname.length > 200) originalname = originalname.slice(0, 200);

        // На уровне multer fileFilter заявленный MIME уже проверен. Здесь — magic-bytes.
        let actualMime = null;
        if (file.mimetype !== 'text/plain') {
            const typeInfo = await fileTypeFromBuffer(file.buffer);
            actualMime = typeInfo ? typeInfo.mime : null;
        }

        const verdict = classifyFile({
            fileName: originalname,
            claimedMime: file.mimetype,
            actualMime
        });

        if (verdict.kind !== 'accepted') {
            const err = new InvalidFileTypeError(originalname, verdict.severity, verdict.category);
            err.claimedMime = file.mimetype;
            err.actualMime = actualMime;
            err.userMessage = verdict.message;
            throw err;
        }

        const fileHash = crypto.createHash('sha256').update(file.buffer).digest('hex');
        const result = await new sql.Request()
            .input('hash', sql.NVarChar, fileHash)
            .query `SELECT TOP 1 file_path FROM Documents WHERE file_hash = @hash`;

        // В БД храним только relative-имя файла (без префикса uploads/).
        // Полный путь к физическому файлу вычисляется в коде через UPLOADS_DIR.
        let relativePath;       // то, что будет записано в Documents.file_path
        let absolutePath;       // куда писать буфер на диск
        let isDuplicate = false;
        if (result.recordset.length > 0) {
            relativePath = result.recordset[0].file_path;
            absolutePath = path.join(UPLOADS_DIR, relativePath);
            isDuplicate = true;
        } else {
            const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
            relativePath = uniqueSuffix + '-' + originalname;
            absolutePath = path.join(UPLOADS_DIR, relativePath);
        }

        filesToProcess.push({ ...file,
            originalname,
            path: relativePath,         // в БД пойдёт это
            absolutePath,                // на диск пойдёт сюда
            hash: fileHash,
            isDuplicate,
            claimedMime: file.mimetype,
            actualMime
        });
    }

    // H2/H3: пишем во временный путь `<final>.tmp` → fs.rename (atomic в одной FS).
    // Это закрывает 2 проблемы:
    // 1) ENOSPC/EIO посреди fs.writeFile оставлял partial-файл по финальному
    // пути → Documents.file_path ссылался на повреждённый файл.
    // 2) Если процесс упал между writeFile и transaction.commit (см. POST
    // /api/requests), файл оставался orphan'ом.
    // Финальный rename выполняется ниже (после `transaction.commit`) через
    // commitWritesAtomically(filesToProcess).
    await Promise.all(
        filesToProcess
        .filter(file => !file.isDuplicate)
        .map(file => fs.writeFile(file.absolutePath + '.tmp', file.buffer))
    );

    // Опциональное антивирусное сканирование (3-я линия обороны).
    // По умолчанию выключено; включается через ENABLE_CLAMAV=true в .env.
    // Сканируем .tmp-файлы — финальный путь будет создан только после
    // успешного transaction.commit через commitWritesAtomically.
    if (process.env.ENABLE_CLAMAV === 'true') {
        for (const f of filesToProcess.filter(f => !f.isDuplicate)) {
            const av = await scanWithClamAV(f.absolutePath + '.tmp');
            if (!av.clean) {
                try { await fs.unlink(f.absolutePath + '.tmp'); } catch (e) {}
                const err = new InvalidFileTypeError(f.originalname);
                err.claimedMime = f.claimedMime;
                err.actualMime = 'application/x-malware-detected';
                throw err;
            }
        }
    }

    // Аудит успешных загрузок (если контекст передан).
    // Сбрасываем счётчик нарушений у пользователя — он успешно загружает «чистый» файл.
    if (ctx.userId) {
        for (const f of filesToProcess) {
            await recordFileUploadAttempt({
                userId: ctx.userId,
                ip: ctx.ip,
                fileName: f.originalname,
                claimedMime: f.claimedMime,
                actualMime: f.actualMime,
                wasClean: true,
                reason: f.isDuplicate ? 'дубликат — переиспользован существующий файл' : null
            });
        }
        try {
            await new sql.Request()
                .input('userId', sql.Int, ctx.userId)
                .query('UPDATE Users SET failed_uploads_count = 0 WHERE id = @userId AND failed_uploads_count > 0');
        } catch (e) {
            // Не критично для основного флоу (счётчик неудачных загрузок),
            // но молчать нельзя — повторяющиеся ошибки могут сигналить о
            // деградации БД. R6: логируем для observability.
            console.error('Не удалось обнулить failed_uploads_count для', ctx.userId, ':', e.message);
        }
    }

    return filesToProcess;
}

/**
 * H2/H3: финализация загруженных файлов после успешного `transaction.commit`.
 * Переименовывает каждый `<final>.tmp` в `<final>` атомарно (rename в одной
 * FS — atomic syscall на POSIX/NTFS). Дубликаты пропускаем — они не писались
 * на диск, а ссылаются на существующий путь.
 *
 * При ошибке rename одной из частей — НЕ откатываем уже переименованные;
 * возвращаем массив несостоявшихся путей. Caller видит частичный успех и
 * принимает решение (в текущем коде — после commit'а БД эта ошибка только
 * логируется, потому что commit уже произошёл и логически файл "существует").
 */
/* =============================================================================
   H5: Idempotency-Key для критичных POST'ов.

   Мотивация: тяжёлый multipart POST /api/requests может тайм-аутиться у
   клиента ПОСЛЕ успешного `transaction.commit` на сервере. Retry создаёт
   дубликат заявки (хеш-проверка спасает только файлы). Контракт: клиент шлёт
   `Idempotency-Key` header с уникальным UUID. Сервер дедуплицирует через
   таблицу `IdempotencyKeys` (mig 27).

   Жизненный цикл записи:
     1. checkIdempotency() в начале handler'а:
        - Нет header'а → возвращает null, handler работает как обычно.
        - Есть header — INSERT row { key, user_id, status=NULL }. PK conflict
          означает повторный запрос: SELECT по ключу,
            * status_code IS NULL → 409 «retry shortly» (in-flight)
            * status_code != NULL → 200/201 с сохранённым response_json
            * created_at > 24ч назад → старый ключ, обрабатываем как новый
              (UPDATE row).
        - Возвращает 'sent' если ответ уже отправлен (caller делает return).
     2. saveIdempotency() в success-path: UPDATE row с финальным
        status_code + response_json.

   Cleanup: записи старше 24ч удаляются в cleanupJournals.
   ============================================================================= */

const IDEMPOTENCY_KEY_RE = /^[A-Za-z0-9_-]{8,64}$/;
const IDEMPOTENCY_TTL_HOURS = 24;

// / H-2: scope — POST + path. Без endpoint-scope клиент,
// случайно reuse'ивший один UUID для разных endpoint'ов, получал чужой кеш
// (`{ requestId: 123 }` вместо `{ newCommentId: 456 }` → JSON-структура
// ломала фронт). Теперь PK = (idempotency_key, endpoint), пересечения нет.
// Используем `req.method + ':' + (req.route?.path || req.path)` — req.route
// доступен внутри handler'а, имеет шаблон ('/api/requests/:id/comments').
function getIdempotencyEndpoint(req) {
    const routePath = (req.route && req.route.path) || req.path;
    // 64 NVARCHAR cap (см. mig 33). Урезаем на всякий случай.
    return (req.method + ':' + routePath).slice(0, 64);
}

async function checkIdempotency(req, res) {
    const key = req.headers['idempotency-key'];
    if (!key) return null;
    if (!IDEMPOTENCY_KEY_RE.test(key)) {
        res.status(400).json({ message: 'Idempotency-Key должен быть 8-64 символа из [A-Za-z0-9_-].' });
        return 'sent';
    }
    const endpoint = getIdempotencyEndpoint(req);
    try {
        await new sql.Request()
            .input('key', sql.NVarChar, key)
            .input('endpoint', sql.NVarChar, endpoint)
            .input('userId', sql.Int, req.user.id)
            .query(`INSERT INTO IdempotencyKeys (idempotency_key, endpoint, user_id)
                    VALUES (@key, @endpoint, @userId)`);
        return key; // успешный INSERT — handler работает дальше
    } catch (e) {
        if (e.number !== 2627 && e.number !== 2601) {
            console.error('checkIdempotency unexpected error:', e.message);
            return key; // не блокируем — пусть handler выполнится; defense-in-depth
        }
        // PK conflict — есть старая запись для (key, endpoint).
        const r = await new sql.Request()
            .input('key', sql.NVarChar, key)
            .input('endpoint', sql.NVarChar, endpoint)
            .input('hours', sql.Int, IDEMPOTENCY_TTL_HOURS)
            .query(`SELECT user_id, status_code, response_json,
                           DATEDIFF(SECOND, created_at, SYSUTCDATETIME()) AS age_sec
                    FROM IdempotencyKeys
                    WHERE idempotency_key = @key AND endpoint = @endpoint
                      AND created_at > DATEADD(HOUR, -@hours, SYSUTCDATETIME())`);
        const row = r.recordset[0];
        if (!row) {
            // conditional UPDATE — только если запись действительно старше TTL.
            const updRes = await new sql.Request()
                .input('key', sql.NVarChar, key)
                .input('endpoint', sql.NVarChar, endpoint)
                .input('userId', sql.Int, req.user.id)
                .input('hours', sql.Int, IDEMPOTENCY_TTL_HOURS)
                .query(`UPDATE IdempotencyKeys
                        SET user_id = @userId, status_code = NULL, response_json = NULL,
                            created_at = SYSUTCDATETIME()
                        WHERE idempotency_key = @key AND endpoint = @endpoint
                          AND created_at < DATEADD(HOUR, -@hours, SYSUTCDATETIME())`);
            if ((updRes.rowsAffected[0] || 0) === 0) {
                // Между SELECT и UPDATE другой запрос успел занять ключ.
                res.status(409).json({ message: 'Запрос ещё обрабатывается. Повторите через несколько секунд.' });
                return 'sent';
            }
            return key;
        }
        if (row.user_id !== req.user.id) {
            res.status(409).json({ message: 'Idempotency-Key конфликтует с другим пользователем.' });
            return 'sent';
        }
        if (row.status_code === null) {
            res.status(409).json({ message: 'Запрос ещё обрабатывается. Повторите через несколько секунд.' });
            return 'sent';
        }
        // Completed — отдаём сохранённый response.
        res.status(row.status_code);
        try {
            res.json(safeJsonParseServer(row.response_json));
        } catch (parseErr) {
            res.json({ message: 'Сохранённый ответ повреждён, повторите запрос с новым Idempotency-Key.' });
        }
        return 'sent';
    }
}

async function saveIdempotency(req, key, statusCode, body) {
    if (!key || key === 'sent') return;
    const endpoint = getIdempotencyEndpoint(req);
    try {
        // D2/H-2: UPDATE WHERE (key, endpoint, user_id) — защита
        // от race с reset/rotation: если cleanup-job или параллельный запрос
        // переиначил ключ другому юзеру, мы не перетрём чужой response.
        await new sql.Request()
            .input('key', sql.NVarChar, key)
            .input('endpoint', sql.NVarChar, endpoint)
            .input('userId', sql.Int, req.user.id)
            .input('status', sql.Int, statusCode)
            .input('body', sql.NVarChar, JSON.stringify(body || {}))
            .query(`UPDATE IdempotencyKeys
                    SET status_code = @status, response_json = @body
                    WHERE idempotency_key = @key AND endpoint = @endpoint AND user_id = @userId`);
    } catch (e) {
        // Не блокируем основной success-path. Логируем для разбора.
        console.error('saveIdempotency error:', e.message);
    }
}

// Безопасный JSON.parse на сервере (на случай повреждённого response_json в БД).
function safeJsonParseServer(s) {
    try { return JSON.parse(s); } catch (_) { return null; }
}

async function commitWritesAtomically(files) {
    const failed = [];
    for (const f of files) {
        if (f.isDuplicate) continue;
        try {
            await fs.rename(f.absolutePath + '.tmp', f.absolutePath);
        } catch (err) {
            failed.push({ file: f.absolutePath, err: err.message });
            console.error('commitWritesAtomically rename failed:', f.absolutePath, err.message);
        }
    }
    return failed;
}

/**
 * Cleanup помощник для catch'а: чистим как `.tmp`, так и финальные имена
 * (если что-то уже успело переименоваться). Вызывается при rollback'е
 * транзакции / ошибке после writeFile'а.
 */
async function cleanupTempUploads(files) {
    if (!Array.isArray(files)) return;
    for (const f of files) {
        if (f.isDuplicate) continue;
        const abs = f.absolutePath || (f.path ? path.join(UPLOADS_DIR, f.path) : null);
        if (!abs) continue;
        for (const candidate of [abs + '.tmp', abs]) {
            try { await fs.unlink(candidate); } catch (_) { /* нет файла — норм */ }
        }
    }
}

/* =============================================================================
   JWT token versioning — отзыв активных access-токенов.

   JWT по своей природе stateless и не отзывается. После принудительной смены
   пароля / soft-delete юзера access-токен живёт ещё до 15 минут — это окно
   риска при увольнении. Решение:
     1. Каждый JWT содержит claim `tv` (token version).
     2. На каждом authenticated-запросе сверяем `tv` из токена с актуальной
        версией в БД (Users.token_version).
     3. Чтобы не делать SQL на каждый запрос — кешируем версию в RAM Map.
     4. При увольнении / reset-password — bumpTokenVersion(userId) увеличивает
        версию в БД и в кеше → все active access-токены этого юзера моментально
        перестают работать.

   Cache fallback: если userId нет в кеше (после рестарта) — лениво подгружаем
   из БД и кладём в кеш.
   ============================================================================= */

// bounded LRU на tokenVersionCache. Без cap'а Map растёт линейно с числом
// уникальных userId (после старта процесса каждый login/refresh добавляет
// запись). На 1k юзеров — 50 КБ, OK; на 100k — 5 МБ + усиливает M10. LRU
// держит самых горячих: при превышении max выселяем первый (самый старый
// по insertion-order — Map это гарантирует) entry.
const TOKEN_VERSION_CACHE_MAX = 10000;
const _tokenVersionCacheBacking = new Map();
const tokenVersionCache = {
    has: (k) => _tokenVersionCacheBacking.has(k),
    get: (k) => {
        if (!_tokenVersionCacheBacking.has(k)) return undefined;
        const v = _tokenVersionCacheBacking.get(k);
        // LRU touch: переставляем в конец через delete+set.
        _tokenVersionCacheBacking.delete(k);
        _tokenVersionCacheBacking.set(k, v);
        return v;
    },
    set: (k, v) => {
        if (_tokenVersionCacheBacking.has(k)) _tokenVersionCacheBacking.delete(k);
        _tokenVersionCacheBacking.set(k, v);
        if (_tokenVersionCacheBacking.size > TOKEN_VERSION_CACHE_MAX) {
            // Удаляем самую старую запись (первый ключ Map по insertion-order).
            const oldest = _tokenVersionCacheBacking.keys().next().value;
            _tokenVersionCacheBacking.delete(oldest);
        }
    },
    delete: (k) => _tokenVersionCacheBacking.delete(k)
};

async function getTokenVersion(userId) {
    if (tokenVersionCache.has(userId)) return tokenVersionCache.get(userId);
    try {
        const r = await new sql.Request()
            .input('id', sql.Int, userId)
            .query('SELECT token_version FROM Users WHERE id = @id');
        const v = r.recordset[0]?.token_version ?? 1;
        tokenVersionCache.set(userId, v);
        return v;
    } catch (e) {
        // Если БД недоступна — не ломаем доступ, считаем что токен валиден.
        // Иначе любой временный гитч в БД вырубит всех юзеров системы.
        console.error('getTokenVersion: error fetching for user', userId, e.message);
        return 1;
    }
}

/**
 * Audit log доступа к ПДн (compliance закон РБ №99-З).
 * Fire-and-forget: ошибка записи не должна ронять основной запрос.
 */
function auditPiiAccess({ userId, action, targetType = null, targetId = null, ip = null, userAgent = null, extraMeta = null }) {
    if (!userId) return;
    new sql.Request()
        .input('userId',     sql.Int,      userId)
        .input('action',     sql.NVarChar, String(action || '').slice(0, 50))
        .input('targetType', sql.NVarChar, targetType ? String(targetType).slice(0, 40) : null)
        .input('targetId',   sql.Int,      Number.isInteger(targetId) ? targetId : null)
        .input('ip',         sql.NVarChar, ip ? String(ip).slice(0, 45) : null)
        .input('ua',         sql.NVarChar, userAgent ? String(userAgent).slice(0, 255) : null)
        .input('meta',       sql.NVarChar, extraMeta ? String(extraMeta).slice(0, 500) : null)
        .query(`INSERT INTO AccessAudit (user_id, action, target_type, target_id, ip_address, user_agent, extra_meta)
                VALUES (@userId, @action, @targetType, @targetId, @ip, @ua, @meta)`)
        .catch(err => console.error('auditPiiAccess error:', err.message));
}

/**
 * Multi-word search builder. Разбивает поисковый запрос на слова и формирует
 * SQL-условие, где КАЖДОЕ слово должно встретиться хотя бы в одном из
 * указанных полей (AND по словам, OR по полям).
 *
 * Пример: search="антикоррупция Орша" → найдёт заявки где «антикоррупция»
 * есть в title/description/location, И «Орша» есть в title/description/location.
 *
 * Это значительно умнее dumb-LIKE'а на всю фразу. На свежей MSSQL Full-Text
 * Search дал бы ranking + морфологию (без него остаётся substring-match).
 *
 * @param {sql.Request} dbReq — куда добавляем .input() для параметров
 * @param {string}      term  — пользовательский ввод
 * @param {string[]}    fields — SQL-выражения полей, например ['r.title', 'r.description']
 * @param {string}      paramPrefix — префикс для имён параметров (избегаем коллизий)
 * @returns {string} SQL-фрагмент `(... AND ... AND ...)`, готовый для WHERE
 */
/**
 * LIKE-wildcard escape. Юзер с поисковым запросом «50%» или «test_admin»
 * раньше получал full-table-scan через wildcard-побочный эффект. Теперь
 * экранируем `%`, `_`, `[` через ESCAPE-клаузу — пользовательский ввод трактуется
 * буквально. Параметризация (sql.NVarChar) защищает от инъекций SQL,
 * но не от wildcard-инъекций — это разные слои.
 */
function escapeLikeWildcards(s) {
    return String(s).replace(/[\\%_[]/g, '\\$&');
}

/**
 * Валидация ISO/YYYY-MM-DD строки даты с фильтрами в /api/requests.
 * Раньше невалидное `?createdFrom=2025-13-99` биндилось в `sql.Date` →
 * mssql throw → outer catch → 500 + засоренные логи. Теперь pre-check
 * даёт чистый 400 с полем `field`, удобный фронту для подсветки.
 *
 * @returns {boolean} true если строка пустая/null (фильтр не задан) либо валидна
 */
function isValidDateFilter(s) {
    if (s === undefined || s === null || s === '') return true;
    if (typeof s !== 'string') return false;
    // Базовый формат YYYY-MM-DD или ISO с временем — оба парсятся в Date.
    const d = new Date(s);
    if (isNaN(d.getTime())) return false;
    // Защита от 2025-13-99 (Date конструктор переполняет в 2026-2-7).
    // Сравниваем YYYY-MM-DD из исходной строки с результатом toISOString.
    const m = String(s).match(/^(\d{4})-(\d{2})-(\d{2})/);
    if (!m) return true; // полная ISO-строка с T — Date уже её провалидировал
    const [year, month, day] = [parseInt(m[1], 10), parseInt(m[2], 10), parseInt(m[3], 10)];
    if (year < 1900 || year > 2100) return false;
    if (month < 1 || month > 12) return false;
    if (day < 1 || day > 31) return false;
    // Финальный sanity: что Date не «откатил» переполненный day обратно.
    return d.getUTCFullYear() === year
        && (d.getUTCMonth() + 1) === month
        && d.getUTCDate() === day;
}

function buildSearchCondition(dbReq, term, fields, paramPrefix = 'q') {
    // cap общей длины search-строки до 200 символов. Без cap'а юзер может
    // прислать 100 КБ single-token → строка `%...%` шириной 100 КБ улетит в SQL,
    // плюс `escapeLikeWildcards` пройдётся по всему. Реальный поиск не превышает
    // 50 символов; 200 — с большим запасом для русских ФИО и составных названий.
    const capped = String(term || '').slice(0, 200);
    const words = capped
        .trim()
        .split(/\s+/)
        .filter(w => w.length >= 2)
        .slice(0, 6); // защита от DoS — не больше 6 слов
    if (words.length === 0) return null;

    const wordClauses = words.map((w, i) => {
        const paramName = `${paramPrefix}_${i}`;
        dbReq.input(paramName, sql.NVarChar, `%${escapeLikeWildcards(w)}%`);
        const fieldOrs = fields.map(f => `${f} LIKE @${paramName} ESCAPE '\\'`).join(' OR ');
        return `(${fieldOrs})`;
    });
    return `(${wordClauses.join(' AND ')})`;
}

/**
 * Принудительно инвалидирует все активные access-токены пользователя.
 * Используется при: soft-delete, reset-password, смене собственного пароля.
 *
 * Реализация: отдельный UPDATE token_version+1 + сброс кеша версии. Не объединено
 * с composite update (delete_user / reset_pwd) — оверхед один лишний round-trip,
 * но логика владения проще: helper работает в одной точке, а вызывающие routes
 * остаются читаемыми.
 *
 * Если основной composite-update прошёл, а bump упал — refresh_token_hash уже
 * был обнулён, юзер всё равно разлогинен на следующем refresh; access — живёт
 * до 15 минут (стандартный JWT-tradeoff). Полная согласованность не нужна.
 */
async function bumpTokenVersion(userId) {
    if (!Number.isInteger(userId) || userId <= 0) return;
    try {
        await bumpTokenVersionInTx(null, userId);
    } catch (e) {
        console.error('bumpTokenVersion error:', e.message);
    }
}

/**
 * / CRIT-1+2: tx-aware bump. Используется в multi-step admin-flow
 * (DELETE /admin/users/:id, POST /admin/users/:id/reset-password) для атомарности
 * UPDATE Users + UPDATE token_version. Возвращает callback `() => doWsRevoke()`,
 * caller обязан вызвать его ПОСЛЕ commit'а — чтобы при rollback WS-каналы
 * не закрылись (юзер не должен видеть «session revoked» для несостоявшегося
 * delete).
 *
 * Без tx (tx=null) — поведение совместимое с прежним bumpTokenVersion: UPDATE +
 * cache.set + WS revoke немедленно.
 */
async function bumpTokenVersionInTx(tx, userId) {
    // атомарно увеличиваем token_version и сразу обновляем кеш на
    // полученное значение через OUTPUT inserted (см. оригинальный комментарий).
    const r = await new sql.Request(tx || undefined)
        .input('id', sql.Int, userId)
        .query(`UPDATE Users SET token_version = token_version + 1
                OUTPUT inserted.token_version AS tv
                WHERE id = @id`);
    const newTv = r.recordset[0]?.tv;
    const doWsRevoke = () => {
        if (Number.isInteger(newTv)) {
            tokenVersionCache.set(userId, newTv);
        } else {
            tokenVersionCache.delete(userId);
        }
        if (wss && wss.clients) {
            for (const client of wss.clients) {
                if (client.user && client.user.id === userId &&
                    client.readyState === WebSocket.OPEN) {
                    try {
                        client.send(JSON.stringify({ type: 'auth_revoked', message: 'session revoked' }));
                    } catch (_) { /* best-effort */ }
                    try { client.close(1008, 'Token revoked'); } catch (_) {}
                }
            }
        }
    };
    if (tx) {
        // Caller сам дёрнет doWsRevoke() после commit'а.
        return doWsRevoke;
    }
    // Без tx — auto-commit, можно сразу.
    doWsRevoke();
    return () => {};
}

// / H-4: обработчик ошибок транзакций. На SQL error 1205
// (deadlock victim) отдаём 503 с `Retry-After: 1` — клиентский `secureFetch`
// (Block W раунд 7) умеет автоматически ретраить на 503 ≤5 сек.
// 40001 — serialization failure (теоретически тоже retry'able под snapshot).
// Любой другой error — 500 с переданным fallback-сообщением.
//
// Используется во всех 7 tx-handler'ах: status-change, batch-status,
// comment-create, document-finalize, delete-user, reset-password.
// Без этого helper'а sporadic deadlock'и под нагрузкой давали юзеру
// 500 «Внутренняя ошибка», хотя ситуация легитимно ретрайтся.
function replyOnTxError(res, txErr, fallbackMsg) {
    if (txErr && (txErr.number === 1205 || txErr.number === 40001)) {
        if (!res.headersSent) {
            res.set('Retry-After', '1');
            return res.status(503).json({
                message: 'Временный конфликт транзакции, повторите запрос.'
            });
        }
        return;
    }
    if (!res.headersSent) {
        return res.status(500).json({ message: fallbackMsg });
    }
}

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    verifyAccess(token, async (err, user) => {
        if (err) return res.sendStatus(403);
        // Валидация версии токена — защита от не-отозванных JWT после
        // delete user / reset password / role change.
        if (user.id) {
            // токен БЕЗ tv-claim — отказ. Все валидные access-токены,
            // подписанные нашим signAccess, содержат tv. Отсутствие = forged либо
            // legacy pre-mig-16 (быстро вымоется за 15 мин TTL access).
            if (typeof user.tv !== 'number') {
                return res.status(401).json({
                    message: 'Токен невалиден (нет token_version). Войдите заново.'
                });
            }
            const expectedVersion = await getTokenVersion(user.id);
            if (user.tv < expectedVersion) {
                return res.status(401).json({
                    message: 'Токен отозван. Войдите заново.'
                });
            }
        }
        req.user = user;
        next();
    });
}

function isAdmin(req, res, next) {
    if (req.user.role !== 'Администратор') {
        return res.status(403).json({
            message: 'Доступ запрещен.'
        });
    }
    next();
}

function optionalAuthenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return next();

    verifyAccess(token, (err, user) => {
        if (!err) {
            req.user = user;
        }
        next();
    });
}

const server = http.createServer(app);

// / H-1: защита от slow-HTTP DDOS. Без этих таймаутов:
// - headersTimeout default 60с — атакующий шлёт headers по байту, держит сокет;
// - requestTimeout default 5 мин (Node 18+) — slow-body атакующий держит 5 мин;
// - timeout default 0 — нет idle-limit'а, FD утекают.
// На дефолтном Linux ulimit 1024 атакующий с 1100 IP'шек выкачивает все FD.
// Установка трёх таймаутов закрывает атаку. Multipart-uploads с PDF-протоколом
// укладываются в 60с, headers — стандартно <1с. Идle keep-alive — 5с (Node default).
server.headersTimeout  = 10000;   // 10с — на всё headers
server.requestTimeout  = 60000;   // 60с — полный request включая body
server.timeout         = 120000;  // 2 мин — hard idle limit на connection
// per-IP cooldown на upgrade. Без него злой клиент может циклить
// connect → close → connect и каждый раз получать новый 5-сек grace, держа
// FD'ы и RAM. Окно 10 сек, лимит 10 попыток с одного IP. Реальный legitimate
// reconnect (через `dashboard.js` exp-backoff) даже на flaky-сети не превышает
// 5 попыток за 10 сек.
const WS_UPGRADE_WINDOW_MS = 10 * 1000;
const WS_UPGRADE_MAX_PER_IP = 10;
const _wsUpgradeAttemptsByIp = new Map(); // ip → number[] (timestamps)

function _checkWsUpgradeRate(ip) {
    if (!ip) return true;
    const now = Date.now();
    const cutoff = now - WS_UPGRADE_WINDOW_MS;
    let arr = _wsUpgradeAttemptsByIp.get(ip);
    if (!arr) { arr = []; _wsUpgradeAttemptsByIp.set(ip, arr); }
    // Чистим старые попытки за окном
    while (arr.length && arr[0] < cutoff) arr.shift();
    if (arr.length >= WS_UPGRADE_MAX_PER_IP) {
        // даже при превышении лимита проверяем — если массив пустой
        // (только что чистили), удаляем entry полностью (cleanup).
        if (arr.length === 0) _wsUpgradeAttemptsByIp.delete(ip);
        return false;
    }
    arr.push(now);
    return true;
}

// периодическая «уборка» пустых entries. Без этого Map медленно растёт
// с каждым уникальным IP, который когда-либо коннектился (после прохода
// окна arr пустой, но Map.delete никогда не вызывается). Раз в 10 минут
// обходим Map и сносим entries с empty arr или массивом, в котором все
// timestamps старше окна.
setInterval(() => {
    const cutoff = Date.now() - WS_UPGRADE_WINDOW_MS;
    for (const [ip, arr] of _wsUpgradeAttemptsByIp) {
        while (arr.length && arr[0] < cutoff) arr.shift();
        if (arr.length === 0) _wsUpgradeAttemptsByIp.delete(ip);
    }
}, 10 * 60 * 1000).unref?.();

const wss = new WebSocket.Server({
    server,
    // 64 КБ — с запасом для legitimate-сообщений (auth, subscribe, messages_read).
    // Любое сообщение крупнее этого закрывается с ошибкой 1009 Too Large.
    // Защита от DoS-сообщений на 100 МБ JSON, которые ws по умолчанию принимает.
    maxPayload: 64 * 1024,
    // Origin guard на уровне upgrade. Open handshake-аутентификация защищает
    // от использования открытого соединения, но без verifyClient злой сайт может
    // открыть тысячи анонимных подключений и удерживать порт/RAM до grace-таймаута.
    verifyClient: (info) => {
        // rate-limit на сами upgrade-запросы с одного IP. Применяется ДО
        // Origin-проверки, потому что злой бот может слать корректный Origin.
        const ip = info.req.socket?.remoteAddress;
        if (!_checkWsUpgradeRate(ip)) return false;

        const origin = info.origin || info.req.headers.origin || '';
        const host = info.req.headers.host;
        if (!origin) return true; // не-браузерные клиенты (тесты, мониторинг) пропускаем
        try {
            const u = new URL(origin);
            if (u.host === host) return true;
            if (EXTRA_ALLOWED_ORIGINS.includes(`${u.protocol}//${u.host}`)) return true;
        } catch (_) { /* битый Origin — отклоняем */ }
        return false;
    }
});

// Множества типов событий для определения куда писать в файлах
const SECURITY_EVENT_TYPES = new Set([
    'Неудачный вход', 'Временная блокировка', 'Постоянная блокировка',
    'Опасный файл отклонён', 'Нарушение безопасности', 'Снятие блокировки',
    'Блокировка пользователя'
]);
const ADMIN_EVENT_TYPES = new Set([
    'Изменение пользователя', 'Снятие блокировки', 'Блокировка пользователя',
    'Постоянная блокировка', 'Временная блокировка', 'Регистрация пользователя'
]);

async function logAdminEvent(eventType, details, userId, userName, requestId = null) {
    try {
        await new sql.Request()
            .input('action', sql.NVarChar, eventType)
            .input('details', sql.NVarChar, details)
            .input('user_id', sql.Int, userId)
            .input('request_id', sql.Int, requestId)
            .query(`INSERT INTO History (request_id, user_id, action, details) VALUES (@request_id, @user_id, @action, @details)`);

        const logData = {
            event_time: new Date().toISOString(),
            user_name: userName,
            event_type: eventType,
            details: details,
            request_id: requestId
        };
        broadcastToAdmins({
            type: 'admin_log_update',
            log: logData
        });

        // Дополнительная запись в файлы — security и/или admin категории.
        const filePayload = {
            event: eventType,
            userId, userName, requestId,
            details
        };
        if (SECURITY_EVENT_TYPES.has(eventType)) {
            writeFileLog('security', filePayload);
        }
        if (ADMIN_EVENT_TYPES.has(eventType)) {
            writeFileLog('admin', filePayload);
        }
    } catch (e) {
        console.error("Критическая ошибка при логировании события:", e);
    }
}

// transaction-aware вариант logAdminEvent. Используется в multi-step
// flow где смена статуса + audit + comment + notifications должны быть атомарны.
// Контракт: выполняет INSERT в History внутри переданной транзакции; broadcast
// в админ-канал и file-log выполняются ПОСЛЕ commit'а — caller получает
// колбэк `commit()` и обязан вызвать его после успешного transaction.commit().
async function logAdminEventInTx(tx, eventType, details, userId, userName, requestId = null) {
    await new sql.Request(tx)
        .input('action', sql.NVarChar, eventType)
        .input('details', sql.NVarChar, details)
        .input('user_id', sql.Int, userId)
        .input('request_id', sql.Int, requestId)
        .query(`INSERT INTO History (request_id, user_id, action, details) VALUES (@request_id, @user_id, @action, @details)`);
    return () => {
        const logData = {
            event_time: new Date().toISOString(),
            user_name: userName,
            event_type: eventType,
            details: details,
            request_id: requestId
        };
        broadcastToAdmins({ type: 'admin_log_update', log: logData });
        const filePayload = { event: eventType, userId, userName, requestId, details };
        if (SECURITY_EVENT_TYPES.has(eventType)) writeFileLog('security', filePayload);
        if (ADMIN_EVENT_TYPES.has(eventType)) writeFileLog('admin', filePayload);
    };
}

/* =============================================================================
   Многоуровневая защита от вредоносной загрузки.
   Линии обороны:
     1. ALLOWED_MIME_TYPES whitelist                  — отсекает по заявленному MIME
     2. file-type magic-bytes                         — отсекает по реальному содержимому
     3. (опционально) ClamAV через child_process     — антивирусная проверка
     4. Скользящее окно нарушений (3 за 30 минут)    — временная блокировка на 1 час
     5. Постоянная блокировка при 5+ нарушениях/24ч  — требует ручного вмешательства
     6. WS-уведомления админам в реальном времени    — сразу со 2-й попытки
     7. Аудит в FileUploadAttempts                    — IP, время, файл, mime
   ============================================================================= */

const VIOLATION_WINDOW_MIN = 30;     // окно подсчёта нарушений
const VIOLATION_TEMP_LOCK  = 3;      // нарушений → временная блокировка
const VIOLATION_HARD_LOCK  = 5;      // нарушений за 24ч → постоянная блокировка
const TEMP_LOCK_HOURS      = 1;      // длительность временной блокировки

async function recordFileUploadAttempt({ userId, ip, fileName, claimedMime, actualMime, wasClean, reason }) {
    try {
        await new sql.Request()
            .input('userId', sql.Int, userId)
            .input('ip', sql.NVarChar, ip || null)
            .input('fileName', sql.NVarChar, fileName)
            .input('claimedMime', sql.NVarChar, claimedMime || null)
            .input('actualMime', sql.NVarChar, actualMime || null)
            .input('wasClean', sql.Bit, wasClean ? 1 : 0)
            .input('reason', sql.NVarChar, reason || null)
            .query(`INSERT INTO FileUploadAttempts (user_id, ip_address, file_name, claimed_mime, actual_mime, was_clean, reason)
                    VALUES (@userId, @ip, @fileName, @claimedMime, @actualMime, @wasClean, @reason)`);
    } catch (e) {
        console.error('Ошибка записи в FileUploadAttempts:', e);
    }
}

/**
 * Регистрирует нарушение и применяет градацию мер.
 * @returns {{ tempLocked: boolean, hardLocked: boolean, count: number, lockedUntil: Date|null }}
 */
async function recordFileViolation({ userId, userName, ip, fileName, claimedMime, actualMime, severity = 'medium', category = 'mime_mismatch' }) {
    // 1. Запись в журнал попыток с пометкой severity
    const reason = `[${severity}/${category}] MIME заявлен ${claimedMime || '?'}, фактически ${actualMime || '?'}`;
    await recordFileUploadAttempt({
        userId, ip, fileName, claimedMime, actualMime, wasClean: false, reason
    });

    // 1b. Сами нарушения попадают в History — они должны быть видны в журнале админки.
    // Тип события зависит от severity, чтобы можно было фильтровать.
    const eventType = severity === 'high' ? 'Опасный файл отклонён' : 'Нарушение безопасности';
    const detailsText = `[${category}] Файл «${fileName}». MIME заявлен ${claimedMime || '?'}, фактически ${actualMime || '?'}. IP: ${ip || '?'}.`;
    await logAdminEvent(eventType, detailsText, userId, userName);

    // 1c. Подробная запись в security.log — для последующего forensic-анализа
    writeFileLog('security', {
        event: 'file_violation',
        severity, category,
        userId, userName, ip,
        fileName, claimedMime, actualMime
    });

    // 2. Обновление счётчика нарушений с учётом скользящего окна
    const updateResult = await new sql.Request()
        .input('userId', sql.Int, userId)
        .input('windowMin', sql.Int, VIOLATION_WINDOW_MIN)
        .query(`
            UPDATE Users
            SET failed_uploads_count = CASE
                    WHEN last_failed_at IS NULL
                      OR DATEDIFF(MINUTE, last_failed_at, SYSUTCDATETIME()) > @windowMin
                    THEN 1
                    ELSE failed_uploads_count + 1
                END,
                last_failed_at = SYSUTCDATETIME()
            OUTPUT INSERTED.failed_uploads_count
            WHERE id = @userId`);

    const violationsInWindow = updateResult.recordset[0]?.failed_uploads_count || 1;

    // 3. Подсчёт нарушений за 24 часа (для жёсткой блокировки)
    const dayResult = await new sql.Request()
        .input('userId', sql.Int, userId)
        .query(`
            SELECT COUNT(*) AS qty FROM FileUploadAttempts
            WHERE user_id = @userId
              AND was_clean = 0
              AND attempted_at >= DATEADD(HOUR, -24, SYSUTCDATETIME())`);
    const violationsIn24h = dayResult.recordset[0].qty;

    let tempLocked = false;
    let hardLocked = false;
    let lockedUntil = null;

    // high (замаскированный опасный файл) блокируем с первой попытки; medium держит
    // окно из 3 попыток, т.к. там бывают ложные срабатывания и битые файлы.
    const tempLockThreshold = severity === 'high' ? 1 : VIOLATION_TEMP_LOCK;

    // 4. Постоянная блокировка при 5+ нарушений за 24 часа
    // hard-lock = soft-delete. Раньше ставился только
    // `is_active=0`, без `deleted_at` — что нарушало CLAUDE.md правило #22
    // (orphan-state: юзер не помечен как удалённый, но не может войти).
    // 31 такой row уже накопился за 9 раундов smoke-тестов (включая тестовый
    // bondarenko id=3). Теперь стандартный soft-delete с deleted_at —
    // mig 35 filtered UNIQUE освободит email/login slot, админ сможет
    // пересоздать учётку при необходимости.
    if (violationsIn24h >= VIOLATION_HARD_LOCK) {
        await new sql.Request()
            .input('userId', sql.Int, userId)
            .query(`UPDATE Users
                    SET is_active = 0,
                        deleted_at = SYSUTCDATETIME(),
                        refresh_token_hash = NULL
                    WHERE id = @userId`);
        hardLocked = true;
        await logAdminEvent(
            'Постоянная блокировка',
            `Превышен лимит нарушений (${violationsIn24h} за 24 часа). Файл: "${fileName}". IP: ${ip || '?'}.`,
            userId, userName
        );
    }
    // 5. Временная блокировка: high сразу (порог 1), medium при 3 за 30 минут
    else if (violationsInWindow >= tempLockThreshold) {
        const result = await new sql.Request()
            .input('userId', sql.Int, userId)
            .input('hours', sql.Int, TEMP_LOCK_HOURS)
            .query(`
                UPDATE Users SET locked_until = DATEADD(HOUR, @hours, SYSUTCDATETIME())
                OUTPUT INSERTED.locked_until
                WHERE id = @userId`);
        lockedUntil = result.recordset[0].locked_until;
        tempLocked = true;
        await logAdminEvent(
            'Временная блокировка',
            `${violationsInWindow} нарушений за ${VIOLATION_WINDOW_MIN} мин. Файл: "${fileName}". Доступ восстановится в ${new Date(lockedUntil).toLocaleString('ru-RU')}.`,
            userId, userName
        );
    }

    // 6. WS-уведомление админам:
    // — при severity='high' (опасный файл, попытка обхода) — СРАЗУ, даже на 1-й попытке
    // — при severity='medium' — со 2-й попытки в окне
    if (severity === 'high' || violationsInWindow >= 2) {
        broadcastToAdmins({
            type: 'security_alert',
            level: hardLocked ? 'critical' : (severity === 'high' ? 'high' : (tempLocked ? 'high' : 'medium')),
            severity,
            category,
            user: { id: userId, name: userName },
            ip,
            fileName,
            claimedMime,
            actualMime,
            violationsInWindow,
            violationsIn24h,
            tempLocked,
            hardLocked,
            timestamp: new Date().toISOString()
        });
    }

    return { tempLocked, hardLocked, count: violationsInWindow, count24h: violationsIn24h, lockedUntil };
}

/**
 * Универсальный обработчик ошибки InvalidFileTypeError.
 * Реакция зависит от severity:
 *   - 'soft'   — файл просто не поддерживается (mp4, heic…). Ответ 415 без штрафа.
 *   - 'medium' — содержимое не соответствует заявленному MIME. +1 в счётчик нарушений.
 *   - 'high'   — попытка загрузить опасный файл. +1 в счётчик + WS-алерт админу с пометкой.
 */
async function handleInvalidFileError(err, req, res) {
    const ip = req.ip || req.socket.remoteAddress;
    const severity = err.severity || 'medium';
    const userMsg  = err.userMessage || `Файл «${err.fileName}» отклонён системой безопасности.`;

    // SOFT: формат не поддерживается, но безвреден — просто отказываем без штрафа
    if (severity === 'soft') {
        await recordFileUploadAttempt({
            userId: req.user.id,
            ip,
            fileName: err.fileName,
            claimedMime: err.claimedMime,
            actualMime: err.actualMime,
            wasClean: false,
            reason: `unsupported_format (${err.category})`
        });
        return res.status(415).json({
            message: userMsg,
            severity: 'soft',
            category: err.category
        });
    }

    // MEDIUM / HIGH: регистрируем нарушение в счётчике
    const v = await recordFileViolation({
        userId: req.user.id,
        userName: req.user.fullName,
        ip,
        fileName: err.fileName,
        claimedMime: err.claimedMime,
        actualMime: err.actualMime,
        severity,
        category: err.category
    });

    if (v.hardLocked) {
        res.clearCookie('refreshToken', REFRESH_COOKIE_CLEAR_OPTS);
        return res.status(403).json({
            message: `Превышен лимит нарушений за сутки (${v.count24h}). Аккаунт заблокирован до решения администратора.`,
            severity: 'high',
            category: err.category
        });
    }
    if (v.tempLocked) {
        res.clearCookie('refreshToken', REFRESH_COOKIE_CLEAR_OPTS);
        const until = new Date(v.lockedUntil).toLocaleString('ru-RU');
        return res.status(403).json({
            message: `Слишком много нарушений (${v.count} за ${VIOLATION_WINDOW_MIN} мин). Аккаунт временно заблокирован до ${until}.`,
            locked_until: v.lockedUntil,
            severity: 'high',
            category: err.category
        });
    }

    const remaining = VIOLATION_TEMP_LOCK - v.count;
    const status = severity === 'high' ? 403 : 400;
    return res.status(status).json({
        message: `${userMsg} Осталось попыток до временной блокировки: ${remaining}.`,
        severity,
        category: err.category
    });
}

/**
 * Архитектурный задел под антивирусное сканирование (ClamAV).
 * В production развёртывании достаточно установить clamd и активировать через env.
 * Сейчас работает в no-op режиме (флаг ENABLE_CLAMAV не выставлен).
 */
async function scanWithClamAV(filePath) {
    if (process.env.ENABLE_CLAMAV !== 'true') {
        return { scanned: false, clean: true, output: 'AV scanning disabled' };
    }
    return new Promise((resolve) => {
        const { execFile } = require('child_process');
        // execFile без shell: имя файла идёт аргументом, инъекция через имя невозможна.
        execFile('clamscan', ['--no-summary', filePath], { timeout: 30000 }, (err, stdout, stderr) => {
            // Коды clamscan: 0 чисто, 1 вирус, 2+ ошибка. fail-closed: при ошибке сканера
            // не считаем файл чистым (иначе AV молча пропускает заражённое).
            if (err && err.code !== 1) {
                console.error('[clamav] scan failed:', err.code || err.message);
                resolve({ scanned: false, clean: false, output: String(stderr || err.message || 'clamav error') });
                return;
            }
            const isClean = !String(stdout).includes('FOUND');
            resolve({ scanned: true, clean: isClean, output: stdout || stderr });
        });
    });
}

function broadcastToAdmins(data, excludeClient = null) {
    const channel = 'admin-logs';
    wss.clients.forEach((client) => {
        if (client !== excludeClient && client.readyState === WebSocket.OPEN && client.user?.role === 'Администратор' && client.subscriptions.has(channel)) {
            client.send(JSON.stringify(data));
        }
    });
}

function broadcastToRequest(requestId, data, excludeClient = null) {
    const channel = `request-${requestId}`;
    // каждый event автоматически снабжается `requestId` — клиент при
    // быстром переключении A→B сравнивает с currently-open request и игнорит
    // stale events (раньше detail_update от A приходил когда hash уже B и
    // обновлял UI данными от чужой заявки).
    //
    // caller priority — `requestId` ставится ПЕРВЫМ, чтобы
    // `...data` мог его перекрыть. До этого spread шёл первым, и любой будущий
    // caller с `data.requestId = X` молча терял своё значение в пользу
    // канального requestId. Текущие callers не передают requestId явно —
    // поведение идентично, но защищаем от будущих regression'ов.
    const ridNum = parseInt(requestId, 10);
    const payload = JSON.stringify({
        requestId: Number.isFinite(ridNum) ? ridNum : requestId,
        ...data
    });
    wss.clients.forEach((client) => {
        if (client !== excludeClient && client.readyState === WebSocket.OPEN && client.subscriptions.has(channel)) {
            client.send(payload);
        }
    });
}

/**
 * После смены статуса заявки видимость для разных ролей могла поменяться.
 * Subscribe-time проверка через `requireAccessToRequest` отработала ОДИН РАЗ
 * на момент подписки — после этого `broadcastToRequest` доверяет
 * `client.subscriptions`. Без prune'а возникает leak: APPROVER подписался на
 * APPROVAL-заявку → админ перевёл в WITHDRAWN → APPROVER её больше не видит,
 * но продолжает получать `detail_update` / `typing` / комментарии-реакции
 * (broadcast их шлёт по subscription).
 *
 * Пройдёмся по всем live-WS-клиентам с этим каналом и через `canUserSeeRequest`
 * (sync, без БД — проверка по роли + creator_id + status) выкорчуем stale-
 * подписки. На клиента с отозванной подпиской отправляем `subscribe_revoked` —
 * фронт сможет показать тост / закрыть открытую карточку чужой заявки.
 *
 * Проход целиком sync, без I/O — ~5–50 клиентов на типовой нагрузке.
 *
 * @param {number|string} requestId
 * @param {object} request — должен содержать creator_id, status_id, status
 */
function pruneStaleSubscriptionsForRequest(requestId, request) {
    if (!wss?.clients || !request) return;
    const channel = `request-${requestId}`;
    let pruned = 0;
    for (const client of wss.clients) {
        if (client.readyState !== WebSocket.OPEN) continue;
        if (!client.subscriptions || !client.subscriptions.has(channel)) continue;
        if (!canUserSeeRequest(client.user, request)) {
            client.subscriptions.delete(channel);
            try {
                client.send(JSON.stringify({ type: 'subscribe_revoked', channel }));
            } catch (_) { /* best-effort */ }
            pruned++;
        }
    }
    return pruned;
}

/**
 * Проверяет, может ли пользователь видеть заявку в списке. Дублирует логику
 * фильтрации /api/requests, чтобы WS-обновления не утекали к юзерам, у которых
 * этой заявки нет в видимом скоупе. Это:
 *   - снижает трафик WS (особенно при большом количестве клиентов)
 *   - закрывает потенциальный leak бизнес-данных через WS
 */
function canUserSeeRequest(user, request) {
    if (!user || !request) return false;
    if (user.role === ROLE_NAMES[ROLES.ADMIN]) return true;
    if (user.role === ROLE_NAMES[ROLES.MODERATOR]) return true;
    if (user.role === ROLE_NAMES[ROLES.APPROVER]) {
        // Согласующий видит заявки начиная со «На согласовании».
        // Источник истины — approverVisibleStatusIds() (см. ниже).
        const visibleIds = approverVisibleStatusIds();
        return visibleIds.some(id => STATUS_NAMES[id] === request.status);
    }
    if (user.role === ROLE_NAMES[ROLES.EMPLOYEE]) {
        return request.creator_id === user.id;
    }
    return false;
}

/**
 * IDOR-guard: единая точка проверки доступа к заявке для всех эндпоинтов
 * `/api/requests/:id*` и `/api/documents/:id*`. Делает SELECT базовых полей
 * заявки и прогоняет через `canUserSeeRequest`. Возвращает row при доступе,
 * null при отсутствии заявки ИЛИ отказе в доступе (намеренно одинаковый
 * исход — чтобы по коду ответа нельзя было определить существование чужой
 * заявки). Эндпоинт обязан отвечать 404 на null.
 *
 * Для документ-эндпоинтов (download, archive) сначала вытаскивается
 * `request_id` документа, потом проверяется доступ к этой заявке.
 *
 * @param {number|string} requestId
 * @param {object} user — req.user из authenticateToken
 * @returns {Promise<object|null>} row { id, creator_id, status_id, status } или null
 */
/**
 * Список status_id, которые видит роль «Согласующий». Используется и в HTTP-
 * фильтрах (список заявок, календарь, экспорт), и в `canUserSeeRequest`,
 * и для defence-in-depth в WS-broadcast'е. Извлечено в одно место чтобы
 * изменение скоупа (например, добавление нового статуса) не требовало
 * правок в 4-5 разных SQL-секциях.
 */
function approverVisibleStatusIds() {
    return [
        STATUSES.APPROVAL,
        STATUSES.APPROVED,
        STATUSES.REJECTED,
        STATUSES.REWORK
    ];
}

/**
 * Возвращает SQL-фрагмент для WHERE/ON, ограничивающий выборку заявок
 * по роли пользователя. CALLER должен заранее забиндить `@userId` через
 * `.input('userId', sql.Int, userId)` если ожидается роль EMPLOYEE
 * (mssql драйвер бросит «parameter already declared» если бинд повторный,
 * поэтому не делаем его внутри хелпера). Все 4 callsite уже биндят userId
 * безусловно — это стандартный паттерн.
 *
 * @returns {string|null} фрагмент или null если роль не требует ограничения
 *                        (Admin / Модератор видят всё)
 */
function applyRoleScope(role, _userId, _sqlReq, prefix = 'r') {
    if (role === ROLE_NAMES[ROLES.APPROVER]) {
        return `${prefix}.status_id IN (${approverVisibleStatusIds().join(',')})`;
    }
    if (role === ROLE_NAMES[ROLES.EMPLOYEE]) {
        return `${prefix}.creator_id = @userId`;
    }
    return null;
}

async function requireAccessToRequest(requestId, user) {
    const id = Number(requestId);
    if (!Number.isInteger(id) || id <= 0) return null;
    try {
        const r = await new sql.Request()
            .input('id', sql.Int, id)
            .query(`
                SELECT r.id, r.creator_id, r.status_id, rs.name AS status
                FROM Requests r
                JOIN RequestStatuses rs ON rs.id = r.status_id
                WHERE r.id = @id`);
        const row = r.recordset[0];
        if (!row) return null;
        if (!canUserSeeRequest(user, row)) return null;
        return row;
    } catch (e) {
        console.error('requireAccessToRequest error:', e.message);
        return null;
    }
}

async function broadcastListUpdate(requestId) {
    try {
        const data = await new sql.Request()
            .input('requestId', sql.Int, requestId)
            .query(`SELECT r.id, r.title, rs.name as status, r.created_at, u.full_name as creator_name,
                           r.creator_id, r.updated_at, r.planned_date, r.category_id,
                           ec.name as category_name, ec.color_hex as category_color,
                           (SELECT COUNT(*) FROM Documents WHERE request_id = r.id) AS docs_count,
                           (SELECT COUNT(*) FROM Comments WHERE request_id = r.id) AS comments_count
                    FROM Requests r
                    JOIN RequestStatuses rs ON r.status_id = rs.id
                    JOIN Users u ON r.creator_id = u.id
                    LEFT JOIN EventCategories ec ON ec.id = r.category_id
                    WHERE r.id = @requestId`);

        if (!data.recordset[0]) return;
        const request = data.recordset[0];

        wss.clients.forEach((client) => {
            if (client.readyState !== WebSocket.OPEN) return;
            // Фильтрация по доступу: не отправляем обновление тем, кто эту заявку не видит
            if (!canUserSeeRequest(client.user, request)) return;
            client.send(JSON.stringify({
                type: 'list_item_update',
                request
            }));
        });
    } catch (error) {
        console.error("Ошибка при вещании обновления списка:", error);
    }
}

/* =============================================================================
   Подсистема пользовательских уведомлений (Notifications).

   В отличие от broadcastToAdmins(security_alert) — это уведомления для ВСЕХ
   ролей: «ваша заявка одобрена», «новый комментарий», «прикреплён документ».
   Записываются в таблицу Notifications (миграция 09) и одновременно
   рассылаются через WebSocket онлайн-клиентам.
   ============================================================================= */

const NOTIFICATION_TYPES = Object.freeze({
    STATUS_CHANGED: 'status_changed',
    NEW_COMMENT:    'new_comment',
    NEW_DOCUMENT:   'new_document',
    RETURNED:       'returned_for_rework'
});

/**
 * Возвращает userId-получателей уведомления по событию заявки:
 * автор + все, кто оставил хоть один комментарий, исключая инициатора события.
 *
 * принимает опциональный tx (sql.Transaction) — для snapshot
 * consistency внутри multi-step write-flow (status-change, comment-create,
 * document-upload). Без tx работает поверх auto-commit pool.
 */
async function getNotificationRecipients(requestId, excludeUserId, tx = null) {
    // Получатели = автор заявки + участники чата (НЕ удалённые сообщения),
    // минус инициатор события, минус удалённые пользователи. Удалённые юзеры
    // не могут залогиниться, и засорять им Notifications бессмысленно.
    //
    // ФИЛЬТР ПО VISIBILITY. Раньше любой кто комментировал заявку
    // оставался получателем уведомлений навсегда — даже если потерял доступ
    // (роль изменилась / статус ушёл из visible-set / Сотрудник теперь не creator).
    // Юзер получал toast «новое сообщение в №31», кликал → 404 «доступ отозван».
    //
    // Логика visibility (синхронно с canUserSeeRequest):
    // ADMIN, MODERATOR → видит ВСЕ → recipient всегда.
    // APPROVER → видит только status IN approverVisibleStatusIds().
    // EMPLOYEE → видит только если creator_id = u.id.
    const approverIds = approverVisibleStatusIds().join(',');
    const r = await new sql.Request(tx || undefined)
        .input('requestId', sql.Int, parseInt(requestId, 10))
        .input('excludeId', sql.Int, excludeUserId || 0)
        .input('roleAdmin', sql.Int, ROLES.ADMIN)
        .input('roleMod',   sql.Int, ROLES.MODERATOR)
        .input('roleAppr',  sql.Int, ROLES.APPROVER)
        .input('roleEmp',   sql.Int, ROLES.EMPLOYEE)
        .query(`
            SELECT DISTINCT t.user_id
            FROM (
                SELECT creator_id AS user_id FROM Requests WHERE id = @requestId
                UNION
                SELECT user_id FROM Comments
                 WHERE request_id = @requestId AND deleted_at IS NULL
            ) t
            JOIN Users u ON u.id = t.user_id
            JOIN Requests r ON r.id = @requestId
            WHERE t.user_id IS NOT NULL
              AND t.user_id <> @excludeId
              AND u.deleted_at IS NULL
              AND u.is_active = 1
              AND (
                u.role_id = @roleAdmin
                OR u.role_id = @roleMod
                OR (u.role_id = @roleAppr AND r.status_id IN (${approverIds}))
                OR (u.role_id = @roleEmp  AND r.creator_id = u.id)
              )`);
    return r.recordset.map(row => row.user_id);
}

/**
 * Шлёт WS-сообщение всем подключениям одного пользователя
 * (один юзер может быть открыт в нескольких вкладках).
 */
function broadcastToUser(userId, payload) {
    wss.clients.forEach(client => {
        if (client.readyState !== WebSocket.OPEN) return;
        if (client.user?.id !== userId) return;
        client.send(JSON.stringify(payload));
    });
}

/**
 * Создаёт уведомления в БД bulk-инсертом и тут же шлёт WS онлайн-клиентам.
 */
async function createNotifications({ recipientIds, requestId, actorId, type, message }) {
    if (!recipientIds || recipientIds.length === 0) return;
    try {
        const reqDb = new sql.Request()
            .input('requestId', sql.Int, requestId ? parseInt(requestId, 10) : null)
            .input('actorId',   sql.Int, actorId || null)
            .input('type',      sql.NVarChar, type)
            .input('message',   sql.NVarChar, (message || '').slice(0, 500));

        const valuesSql = recipientIds
            .map((uid, i) => {
                reqDb.input(`u${i}`, sql.Int, uid);
                return `(@u${i}, @requestId, @actorId, @type, @message, SYSUTCDATETIME())`;
            })
            .join(',');

        const result = await reqDb.query(`
            INSERT INTO Notifications (user_id, request_id, actor_id, type, message, created_at)
            OUTPUT INSERTED.id, INSERTED.user_id, INSERTED.request_id, INSERTED.actor_id,
                   INSERTED.type, INSERTED.message, INSERTED.is_read, INSERTED.created_at
            VALUES ${valuesSql}`);

        for (const row of result.recordset) {
            broadcastToUser(row.user_id, {
                type: 'user_notification',
                notification: row
            });
        }
    } catch (e) {
        console.error('Ошибка createNotifications:', e);
    }
}

// transaction-aware вариант. Выполняет INSERT'ы Notifications
// внутри переданной транзакции, возвращает () => doBroadcasts() для
// post-commit вызова. Если tx сделает rollback — broadcasts не отправятся,
// юзеры не увидят уведомлений о действиях которых не было.
async function createNotificationsInTx(tx, { recipientIds, requestId, actorId, type, message }) {
    if (!recipientIds || recipientIds.length === 0) return () => {};

    // rolling-merge для new_comment (и new_document) — если у
    // recipient'а уже есть НЕпрочитанное уведомление с тем же
    // (user_id, request_id, type, actor_id), обновляем его message + created_at
    // вместо нового INSERT'а. Иначе bell за час чата пухнет до 30 записей
    // от одного автора, теряется навигация. Для status_changed и
    // returned_for_rework — всегда INSERT (важные ивенты, не должны mergiться).
    const MERGEABLE = new Set(['new_comment', 'new_document']);
    const merge = MERGEABLE.has(type);

    const trimmedMessage = (message || '').slice(0, 500);
    const allRows = [];

    for (const uid of recipientIds) {
        let row = null;
        if (merge && actorId) {
            // Попытка UPDATE existing unread с тем же (user_id, request_id, type, actor_id).
            const upd = await new sql.Request(tx)
                .input('uid',  sql.Int, uid)
                .input('rid',  sql.Int, requestId ? parseInt(requestId, 10) : null)
                .input('aid',  sql.Int, actorId)
                .input('type', sql.NVarChar, type)
                .input('msg',  sql.NVarChar, trimmedMessage)
                .query(`
                    UPDATE Notifications
                    SET message = @msg, created_at = SYSUTCDATETIME()
                    OUTPUT INSERTED.id, INSERTED.user_id, INSERTED.request_id, INSERTED.actor_id,
                           INSERTED.type, INSERTED.message, INSERTED.is_read, INSERTED.created_at
                    WHERE user_id = @uid
                      AND request_id = @rid
                      AND type = @type
                      AND actor_id = @aid
                      AND is_read = 0`);
            if (upd.recordset && upd.recordset[0]) {
                row = { ...upd.recordset[0], _merged: true };
            }
        }
        if (!row) {
            // Стандартный INSERT.
            const ins = await new sql.Request(tx)
                .input('uid',  sql.Int, uid)
                .input('rid',  sql.Int, requestId ? parseInt(requestId, 10) : null)
                .input('aid',  sql.Int, actorId || null)
                .input('type', sql.NVarChar, type)
                .input('msg',  sql.NVarChar, trimmedMessage)
                .query(`
                    INSERT INTO Notifications (user_id, request_id, actor_id, type, message, created_at)
                    OUTPUT INSERTED.id, INSERTED.user_id, INSERTED.request_id, INSERTED.actor_id,
                           INSERTED.type, INSERTED.message, INSERTED.is_read, INSERTED.created_at
                    VALUES (@uid, @rid, @aid, @type, @msg, SYSUTCDATETIME())`);
            row = ins.recordset[0];
        }
        if (row) allRows.push(row);
    }

    return () => {
        for (const row of allRows) {
            broadcastToUser(row.user_id, { type: 'user_notification', notification: row });
        }
    };
}

// Фейковый bcrypt-хеш для timing-safe сравнения с несуществующими юзерами.
// Защищает от account enumeration через измерение времени ответа.
// timing-safe защита enumeration. ТРЕБОВАНИЯ:
// 1) Это валидный bcrypt-хеш (длина 60), иначе bcrypt.compare → ранний return false (~0мс)
// и timing leak'ает существование email (atak: ~0мс vs ~250мс на cost-12).
// 2) Cost FAKE_HASH должен совпадать с BCRYPT_COST для всех новых хешей —
// иначе timing разъезжается (cost-10 ~60мс vs cost-12 ~250мс).
// Сгенерировано через `bcrypt.hash('random-string', 12)`. Содержание не важно —
// важна форма ($2b$12$<22-char-salt><31-char-hash>) и cost. Регенерировать
// при изменении BCRYPT_COST.
const FAKE_PASSWORD_HASH = '$2b$12$oWvLiUe42Fn/zTBlqeAyDuj0pUT7wNxrKGJebLCvxh0eZnHl7xu5G';

// нижний потолок времени любого failure-path /api/login.
// Без него enumeration атакуется через timing: legacy-юзеры с cost-10 хешем
// дают ~80мс bcrypt.compare, FAKE_HASH (cost-12) даёт ~250мс. Атакующий по
// разнице 170мс надёжно отделяет existing/non-existing email.
//
// Решение: всегда паддить до 300мс (запас над cost-12 ~250мс с дисперсией).
// Когда ВСЕ юзеры перейдут на cost-12 (через bcrypt rehash on login —
// follow-up задача группы C #14), padding станет no-op для всех путей.
const LOGIN_FAILURE_FLOOR_MS = 300;
async function timingFloor(t0, floorMs) {
    const elapsed = Date.now() - t0;
    if (elapsed < floorMs) {
        await new Promise(r => setTimeout(r, floorMs - elapsed));
    }
}

/**
 * Email-валидатор. Более строгий, чем «^[^\s@]+@[^\s@]+\.[^\s@]+$»:
 *   - локальная часть из букв/цифр/.+_- длиной 1..64
 *   - домен из меток с буквами/цифрами/дефисами, разделённых точками,
 *     каждая метка 1..63, общая длина ≤ 253, TLD ≥ 2 символа
 *   - регистр игнорируется при последующем сравнении (toLowerCase)
 * Одна централизованная функция вместо двух копий regexa в коде.
 */
const EMAIL_REGEX = /^(?=.{1,254}$)(?=.{1,64}@)[A-Za-z0-9._%+\-]+@[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+$/;
function isValidEmail(s) {
    return typeof s === 'string' && EMAIL_REGEX.test(s);
}

const LOGIN_VIOLATION_WINDOW_MIN = 15;
//
// Escalating temp-lock без hard-lock'а:
// hard-lock (`is_active = 0`) был DoS-вектором — атакующий, зная email,
// мог намеренно ввести 10 неверных паролей и заблокировать жертву (особенно
// опасно для админов: разблокировать может только другой админ).
// Теперь блокировки только временные, юзер сам разблокируется по таймеру.
// Для роли «Администратор» лимит фиксированно 1 час (макс) — чтобы
// атакующий не мог удерживать админа в lock'е сутками.
//
const LOGIN_LOCK_TIERS = [
    { threshold: 5,  hours: 1  },  // 5 неудач за 15 мин → 1 час
    { threshold: 10, hours: 6  },  // 10 неудач → 6 часов
    { threshold: 15, hours: 24 }   // 15+ неудач → сутки
];
const ADMIN_MAX_LOCK_HOURS = 1;    // Админу никогда не больше часа

function pickLockHours(count, roleName) {
    let hours = 0;
    for (const tier of LOGIN_LOCK_TIERS) {
        if (count >= tier.threshold) hours = tier.hours;
    }
    if (roleName === 'Администратор' && hours > ADMIN_MAX_LOCK_HOURS) {
        hours = ADMIN_MAX_LOCK_HOURS;
    }
    return hours;
}

async function recordFailedLogin(userId, userName, roleName, ip) {
    // Скользящее окно: если последняя неудача давно — счётчик сбрасываем.
    const upd = await new sql.Request()
        .input('userId', sql.Int, userId)
        .input('windowMin', sql.Int, LOGIN_VIOLATION_WINDOW_MIN)
        .query(`
            UPDATE Users
            SET failed_login_count = CASE
                    WHEN last_failed_login_at IS NULL
                      OR DATEDIFF(MINUTE, last_failed_login_at, SYSUTCDATETIME()) > @windowMin
                    THEN 1
                    ELSE failed_login_count + 1
                END,
                last_failed_login_at = SYSUTCDATETIME()
            OUTPUT INSERTED.failed_login_count
            WHERE id = @userId`);
    const count = upd.recordset[0]?.failed_login_count || 1;

    const hours = pickLockHours(count, roleName);
    let lockedUntil = null;

    if (hours > 0) {
        const r = await new sql.Request()
            .input('userId', sql.Int, userId)
            .input('hours', sql.Int, hours)
            .query(`UPDATE Users
                    SET locked_until = DATEADD(HOUR, @hours, SYSUTCDATETIME())
                    OUTPUT INSERTED.locked_until
                    WHERE id = @userId`);
        lockedUntil = r.recordset[0].locked_until;
        await logAdminEvent('Временная блокировка',
            `${count} неудачных попыток входа за ${LOGIN_VIOLATION_WINDOW_MIN} мин. ` +
            `Блокировка на ${hours} ч. Роль: ${roleName || '?'}. IP: ${ip || '?'}.`,
            userId, userName);
    }

    return { count, lockedUntil, lockHours: hours };
}

/**
 * @openapi
 * /api/login:
 *   post:
 *     tags: [Auth]
 *     summary: Вход по email/логину и паролю
 *     security: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema: { $ref: '#/components/schemas/LoginRequest' }
 *     responses:
 *       200:
 *         description: Успешный вход. Refresh-токен ставится в httpOnly cookie.
 *         content:
 *           application/json:
 *             schema: { $ref: '#/components/schemas/LoginResponse' }
 *       401: { description: 'Неверные учётные данные', content: { application/json: { schema: { $ref: '#/components/schemas/Error' } } } }
 *       403: { description: 'Аккаунт заблокирован', content: { application/json: { schema: { $ref: '#/components/schemas/Error' } } } }
 *       429: { description: 'Превышен лимит попыток входа (10 за 15 минут)' }
 */
app.post('/api/login', authLimiter, async (req, res) => {
    const t0 = Date.now();   // CRIT-2 раунд 7: для timingFloor на failure-path'ах
    const { login, password } = req.body;
    const ip = req.ip || req.socket.remoteAddress;

    try {
        const result = await sql.query`
            SELECT u.*, r.name as role_name FROM Users u
            JOIN Roles r ON u.role_id = r.id
            WHERE (u.email = ${login} OR u.login = ${login})
              AND u.deleted_at IS NULL`;

        // === Несуществующий пользователь ===
        // ВАЖНО: всё равно вызываем bcrypt.compare для timing-safe сравнения,
        // иначе атакующий может определить существование email по времени ответа.
        if (result.recordset.length === 0) {
            await bcrypt.compare(password || '', FAKE_PASSWORD_HASH);
            await logAdminEvent('Неудачный вход',
                `Попытка входа для несуществующего: ${login}. IP: ${ip}`,
                null, 'Система');
            await timingFloor(t0, LOGIN_FAILURE_FLOOR_MS);
            return res.status(401).json({ message: 'Неверные учётные данные' });
        }

        const user = result.recordset[0];

        // CPU-shield для ботнет-атаки. Если у юзера hard-lock (15+ fails →
        // 24 часа), значит это уже точно атака, не забывчивый пользователь.
        // Прогон bcrypt против реального hash съедает ~100мс CPU за попытку;
        // 10к IP × 10 попыток = 100k bcrypt'ов = ~3 часа CPU на одном email.
        // раунд 7: убрали `setTimeout(100)` — теперь timing нормализуется
        // через единый LOGIN_FAILURE_FLOOR_MS (см. ниже).
        // UX-trade-off: при hard-lock даже правильный пароль вернёт 401 generic
        // вместо 403 «заблокирован до X». Это приемлемо: юзер с 15 неудачами
        // подряд и так зашёл не туда — пусть подождёт unlock и попробует.
        const isHardLocked = user.locked_until
            && new Date(user.locked_until) > new Date()
            && (user.failed_login_count || 0) >= 15;
        if (isHardLocked) {
            await logAdminEvent('Неудачный вход (CPU-shield)',
                `Bot-shield: попытка входа в hard-locked аккаунт (count=${user.failed_login_count}, до ${user.locked_until}). IP: ${ip}.`,
                user.id, user.full_name);
            await timingFloor(t0, LOGIN_FAILURE_FLOOR_MS);
            return res.status(401).json({ message: 'Неверные учётные данные' });
        }

        // === Account-enumeration защита ===
        // Раньше is_active=0 / locked_until возвращали 403 ДО проверки пароля.
        // Атакующий через различие 401↔403 определял существование email.
        // Теперь сначала ВСЕГДА проверяем пароль (timing-safe). Раскрытие
        // состояний lock/inactive — только тем, кто знает правильный пароль.
        const isPasswordCorrect = await bcrypt.compare(password || '', user.password_hash);

        if (!isPasswordCorrect) {
            // Атакующий или забывчивый юзер — отдаём generic 401 без leak'а.
            const v = await recordFailedLogin(user.id, user.full_name, user.role_name, ip);
            await logAdminEvent('Неудачный вход',
                `Неверный пароль. Попыток за окно: ${v.count}. IP: ${ip}.`,
                user.id, user.full_name);
            // Даже если только что выставился lock — не показываем его до
            // успешной парольной проверки. Юзер увидит lock-сообщение в
            // следующем логине с правильным паролем.
            await timingFloor(t0, LOGIN_FAILURE_FLOOR_MS);
            return res.status(401).json({ message: 'Неверные учётные данные' });
        }

        // Пароль верен — теперь можем безопасно раскрыть состояния аккаунта.
        if (!user.is_active) {
            return res.status(403).json({
                message: 'Аккаунт неактивен. Обратитесь к администратору.'
            });
        }
        if (user.locked_until && new Date(user.locked_until) > new Date()) {
            const lockedUntilLocal = new Date(user.locked_until).toLocaleString('ru-RU');
            return res.status(403).json({
                message: `Аккаунт временно заблокирован до ${lockedUntilLocal} из-за подозрительной активности.`,
                locked_until: user.locked_until
            });
        }

        // === Успешный логин ===
        // Сбрасываем счётчик неудач и сохраняем хеш refresh-токена в БД,
        // чтобы при logout/refresh можно было его инвалидировать.
        // tv (token_version) добавляется в payload — это claim для отзыва
        // активных access-токенов при принудительном выходе админом.
        const tv = user.token_version ?? 1;
        tokenVersionCache.set(user.id, tv);
        const payload = { id: user.id, fullName: user.full_name, role: user.role_name, tv };
        const accessToken  = signAccess(payload);
        // tv в refresh-токене тоже — чтобы edge-case «delete user + восстановить
        // is_active» не позволил старому refresh пройти (при delete bumpTokenVersion
        // увеличивает tv, рестор не инкрементит → старый refresh не сматчит).
        const refreshToken = signRefresh({ id: user.id, tv });
        const refreshHash  = crypto.createHash('sha256').update(refreshToken).digest('hex');

        // постепенная миграция cost-10 → cost-12. Block U поднял
        // BCRYPT_COST=12 для новых паролей, но существующие хеши в БД оставались
        // cost-10 (timing leak, см. CRIT-2). Block V закрыл leak через timingFloor,
        // но это лишь нормализация. Реальная защита — пересохранить хеш с cost=12
        // у юзеров когда они логинятся с правильным паролем (мы только что
        // подтвердили — `isPasswordCorrect=true` — значит пароль в открытом виде
        // у нас в `password`). Через несколько недель все активные юзеры
        // мигрируют, через 6 месяцев — практически все. После полной миграции
        // FAKE_PASSWORD_HASH cost=12 даст естественный timing match без floor'а.
        let rehashedHash = null;
        try {
            const hashCost = parseInt((user.password_hash || '').slice(4, 6), 10);
            if (Number.isFinite(hashCost) && hashCost < BCRYPT_COST) {
                rehashedHash = await bcrypt.hash(password, BCRYPT_COST);
            }
        } catch (rhErr) {
            // Не критично — оставляем старый хеш, юзер войдёт. Логируем для
            // диагностики (если массово фейлится — что-то с bcrypt).
            console.error('bcrypt rehash failed for user', user.id, ':', rhErr.message);
        }

        // UPDATE refresh_token_hash + failed_login_count — всегда (наш login
        // должен зафиксировать refresh-сессию независимо от race с reset-password).
        await new sql.Request()
            .input('userId', sql.Int, user.id)
            .input('hash', sql.NVarChar, refreshHash)
            .query(`UPDATE Users
                    SET refresh_token_hash = @hash,
                        failed_login_count = 0,
                        last_failed_login_at = NULL
                    WHERE id = @userId`);

        // отдельный conditional UPDATE для password rehash
        // с WHERE password_hash = @originalHash. Если параллельно admin через
        // /api/admin/users/:id/reset-password сменил пароль между нашим
        // bcrypt.compare и этим UPDATE — наш UPDATE с rowsAffected=0 будет
        // no-op (не перетрём admin'ский новый пароль на rehashed-cost-12 от
        // старого). bumpTokenVersion в reset-password всё равно tv-инвалидирует
        // наш access (next request → 401), но password в БД останется правильный.
        if (rehashedHash) {
            await new sql.Request()
                .input('userId', sql.Int, user.id)
                .input('newPasswordHash', sql.NVarChar, rehashedHash)
                .input('originalHash', sql.NVarChar, user.password_hash)
                .query(`UPDATE Users SET password_hash = @newPasswordHash
                        WHERE id = @userId AND password_hash = @originalHash`);
        }

        await logAdminEvent('Вход в систему', `IP: ${ip}`, user.id, user.full_name);
        try {
            await sql.query`INSERT INTO LoginHistory (user_id, ip_address) VALUES (${user.id}, ${ip})`;
        } catch (e) {
            // история логинов — не блокирующая для входа функциональность,
            // но молчаливо игнорировать нельзя: повторяющиеся ошибки = индикатор
            // проблем с БД (диск, lock, schema-drift). Кладём в error-канал.
            console.error('Не удалось записать LoginHistory для user', user.id, ':', e.message);
        }

        res.cookie('refreshToken', refreshToken, REFRESH_COOKIE_OPTS);
        res.json({ message: 'Вход успешен', accessToken });

    } catch (err) {
        console.error('Ошибка входа:', err);
        res.status(500).json({ message: 'Внутренняя ошибка сервера' });
    }
});

// H6 grace-window ОТКАЧЕН как security regress.
// Прежняя реализация запоминала выданные tokens на 5 сек и возвращала их
// клиенту, чей refresh не сматчил current_hash — задумано было защитить
// parallel-tabs от false-positive breach-detection. Но grace-check был
// keyed только по `user.id`, БЕЗ валидации что requester владеет prev-hash:
//
// атакующий украл cookie victim'а
// victim делает refresh → hash ротирован → grace заполнен
// атакующий с украденной cookie делает refresh → hash не сматчит →
// grace lookup hits → СЕРВЕР ОТДАЁТ АТАКУЮЩЕМУ свежие access+refresh
//
// Использовать prev_hash для дискриминации не помогает: атакующий и
// legitimate parallel-tab держат ОДНУ И ТУ ЖЕ cookie, prev_hash для них
// совпадает. Невозможно отличить replay от parallel-tab без дополнительной
// аутентификации (browser fingerprint — ненадёжно).
//
// Корректное решение parallel-tabs UX — client-side mutex через
// BroadcastChannel или localStorage `storage`-event: одна вкладка ждёт
// результат refresh другой через cross-tab signal. Это меняет dashboard.js,
// сервер же остаётся со строгим 403+bumpTokenVersion при replay.

/**
 * @openapi
 * /api/refresh-token:
 *   post:
 *     tags: [Auth]
 *     summary: Обновление access-токена через refresh-cookie
 *     description: |
 *       Ротация refresh-токена на каждом вызове (one-time-use). При повторном
 *       использовании ТОГО ЖЕ refresh-токена — 403 + bumpTokenVersion (отзыв
 *       всех живых access-токенов юзера, защита от replay при компрометации).
 *     security: []
 *     responses:
 *       200:
 *         description: Новый access-токен. Refresh обновлён в httpOnly cookie.
 *         content: { application/json: { schema: { $ref: '#/components/schemas/RefreshResponse' } } }
 *       401: { description: 'Refresh-cookie отсутствует' }
 *       403: { description: 'Refresh отозван (replay / logout / смена пароля / token_version mismatch)' }
 *       429: { $ref: '#/components/responses/TooManyRequests' }
 */
app.post('/api/refresh-token', authLimiter, async (req, res) => {
    const { refreshToken } = req.cookies;
    if (!refreshToken) {
        return res.status(401).json({ message: 'Refresh токен не предоставлен' });
    }

    try {
        const decoded = verifyRefresh(refreshToken);
        const result = await sql.query`
            SELECT u.*, r.name as role_name FROM Users u
            JOIN Roles r ON u.role_id = r.id
            WHERE u.id = ${decoded.id} AND u.is_active = 1 AND u.deleted_at IS NULL`;

        if (result.recordset.length === 0) {
            res.clearCookie('refreshToken', REFRESH_COOKIE_CLEAR_OPTS);
            return res.status(403).json({ message: 'Пользователь не найден или неактивен' });
        }
        const user = result.recordset[0];

        // tv-check: refresh-токен подписан с фиксированным token_version.
        // Если админ через delete-user / reset-password сделал bumpTokenVersion,
        // current user.token_version вырос, а tv в payload остался старым.
        // Edge-case: юзера удалили (bump), потом восстановили is_active=1 — без
        // tv-check старый refresh снова бы сработал. С check'ом — нет.
        // refresh-токен БЕЗ tv-claim — отказ. Все валидные refresh
        // подписываются нашим signRefresh с tv; отсутствие = forged/legacy.
        const expectedTv = user.token_version ?? 1;
        if (typeof decoded.tv !== 'number' || decoded.tv < expectedTv) {
            res.clearCookie('refreshToken', REFRESH_COOKIE_CLEAR_OPTS);
            return res.status(403).json({ message: 'Refresh токен отозван (token_version mismatch).' });
        }

        // === Серверная проверка refresh-токена ===
        // Сравниваем хеш предъявленного токена с тем, что записан в БД при login.
        // Если не совпадает — токен либо отозван (logout, login на другом устройстве),
        // либо украден и подменён ротацией. В обоих случаях — отказ + bumpTokenVersion
        // (мгновенно гасим все живые access-токены этого юзера).
        //
        // timing-safe compare через crypto.timingSafeEqual.
        // Раньше использовался `!==` который short-circuit'ит на первом несовпавшем
        // символе → теоретический timing side-channel (восстановление хеша по
        // RTT, 1 символ за раз). Эксплуатация вычислительно невозможна (нужен
        // preimage-attack на SHA-256), но defense-in-depth: оба хеша равной
        // длины, переходим на constant-time compare через Buffer'ы.
        const presentedHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
        let hashMatches = false;
        if (user.refresh_token_hash && user.refresh_token_hash.length === presentedHash.length) {
            try {
                const stored = Buffer.from(user.refresh_token_hash, 'hex');
                const presented = Buffer.from(presentedHash, 'hex');
                // Доп. защита: timingSafeEqual бросает если длины различаются.
                // Проверили выше через .length но Buffer.from с битым hex может
                // вернуть короче — оставляем try/catch как страховку.
                hashMatches = stored.length === presented.length
                    && crypto.timingSafeEqual(stored, presented);
            } catch (_) { /* битый hex в БД — считаем mismatch */ }
        }
        if (!hashMatches) {
            res.clearCookie('refreshToken', REFRESH_COOKIE_CLEAR_OPTS);
            // Подозрение на компрометацию: либо replay украденного токена, либо
            // юзер уже разлогинился. В обоих случаях — мгновенно инвалидируем
            // активные access-токены, чтобы атакующий не пользовался ими 15 мин.
            bumpTokenVersion(user.id).catch(e => console.error('bumpTokenVersion failed for user', user.id, ':', e.message));
            return res.status(403).json({ message: 'Refresh токен отозван. Войдите заново.' });
        }

        if (user.locked_until && new Date(user.locked_until) > new Date()) {
            return res.status(403).json({
                message: 'Аккаунт временно заблокирован из-за подозрительной активности.',
                locked_until: user.locked_until
            });
        }

        // === Ротация refresh-токена (best practice) ===
        // На каждый refresh выдаём НОВЫЙ refresh-токен и инвалидируем старый.
        const tv = user.token_version ?? 1;
        const payload = { id: user.id, fullName: user.full_name, role: user.role_name, tv };
        const newAccessToken  = signAccess(payload);
        const newRefreshToken = signRefresh({ id: user.id, tv });
        const newRefreshHash  = crypto.createHash('sha256').update(newRefreshToken).digest('hex');

        // Optimistic concurrency: UPDATE проходит ТОЛЬКО если БД всё ещё хранит
        // тот же хеш, что мы только что прочитали. Если rowsAffected=0 — значит
        // другой запрос (вторая вкладка ИЛИ атакующий с украденным cookie)
        // успел ротировать первым. Это сигнал на breach-detection: bumpTokenVersion
        // отзывает все живые access-токены, юзер вынужден перелогиниться.
        const upd = await new sql.Request()
            .input('userId', sql.Int, user.id)
            .input('newHash', sql.NVarChar, newRefreshHash)
            .input('oldHash', sql.NVarChar, presentedHash)
            .query(`UPDATE Users
                    SET refresh_token_hash = @newHash
                    WHERE id = @userId AND refresh_token_hash = @oldHash`);
        if (upd.rowsAffected[0] === 0) {
            res.clearCookie('refreshToken', REFRESH_COOKIE_CLEAR_OPTS);
            bumpTokenVersion(user.id).catch(e => console.error('bumpTokenVersion failed for user', user.id, ':', e.message));
            return res.status(403).json({
                message: 'Параллельный refresh обнаружен — сессия отозвана. Войдите заново.'
            });
        }
        tokenVersionCache.set(user.id, tv);

        res.cookie('refreshToken', newRefreshToken, REFRESH_COOKIE_OPTS);
        res.json({ accessToken: newAccessToken });
    } catch (err) {
        res.clearCookie('refreshToken', REFRESH_COOKIE_CLEAR_OPTS);
        return res.status(403).json({ message: 'Невалидный refresh токен' });
    }
});

// Soft-decode: верифицируем токен один раз, чтобы apiLimiter мог быстро
// освободить админа от квот без повторного jwt.verify. Дальше по стеку
// authenticateToken на отдельных роутах валидирует наличие req.user.
// Публичные эндпоинты (/api/public/*) пропускают soft-decode — там нет
// смысла тратить CPU на JWT-верификацию для анонимных запросов.
app.use('/api/', (req, res, next) => {
    if (req.path.startsWith('/public/')) return next();
    return softDecodeToken(req, res, next);
}, apiLimiter);

// fast-fail при перегрузке mssql pool. Pool max=20 — если очередь
// `pending` запросов превышает 50, новые запросы будут ждать до
// `acquireTimeoutMillis: 15000` и потом отвалятся 500. На стороне клиента
// это выглядит как «сервер тормозит» с retry-storm. Лучше вернуть 503 сразу,
// чтобы клиент применил backoff/circuit-breaker, чем держать ему слот.
// Применяется ТОЛЬКО к /api/ — статика и публичные не зависят от БД.
const POOL_PENDING_FAST_FAIL_THRESHOLD = 50;
app.use('/api/', (req, res, next) => {
    if (req.path.startsWith('/public/') || req.path === '/health') return next();
    const pending = dbPool?.pending || 0;
    if (pending >= POOL_PENDING_FAST_FAIL_THRESHOLD) {
        res.set('Retry-After', '5');
        return res.status(503).json({
            message: 'Сервис временно перегружен. Повторите запрос через несколько секунд.'
        });
    }
    next();
});

/**
 * @openapi
 * /api/logout:
 *   post:
 *     tags: [Auth]
 *     summary: Выход из системы
 *     description: |
 *       Обнуляет refresh_token_hash в БД + bumpTokenVersion — все живые
 *       access-токены юзера моментально становятся невалидными. Закрывает
 *       все live-WS-каналы этого пользователя.
 *     responses:
 *       200:
 *         description: Выход выполнен. Refresh-cookie очищена.
 *         content: { application/json: { schema: { type: 'object', properties: { message: { type: 'string' } } } } }
 */
app.post('/api/logout', optionalAuthenticateToken, async (req, res) => {
    if (req.user) {
        // Серверная инвалидация refresh-токена: обнуляем хеш в БД.
        // Любая попытка использовать старый токен — 403 «Refresh токен отозван».
        try {
            await new sql.Request()
                .input('userId', sql.Int, req.user.id)
                .query('UPDATE Users SET refresh_token_hash = NULL WHERE id = @userId');
        } catch (e) { console.error('Не удалось обнулить refresh_token_hash:', e); }

        // bumpTokenVersion: без него access-токен жертвы продолжает работать
        // до 15 мин после logout. Если cookie/access были украдены через XSS
        // — атакующий ходит как ни в чём не бывало. Bump инвалидирует все
        // active access-токены этого юзера + закрывает live WS-каналы.
        // Также защищает от race logout+refresh: если refresh успел провернуться
        // между чтением cookie и обнулением hash, новый access всё равно получит
        // tv++ и не пройдёт.
        await bumpTokenVersion(req.user.id);

        await logAdminEvent('Выход из системы', 'Пользователь вышел из системы.',
            req.user.id, req.user.fullName);
    }
    res.clearCookie('refreshToken', REFRESH_COOKIE_CLEAR_OPTS);
    res.status(200).json({ message: 'Выход выполнен успешно' });
});

// Открытая регистрация отключена. Корпоративная политика: учётные записи
// создаются администратором централизованно через POST /api/admin/users.
// Старый эндпоинт оставлен заглушкой, чтобы фронт получил понятный ответ.
/**
 * @openapi
 * /api/register:
 *   post:
 *     tags: [Auth]
 *     summary: 'ОТКЛЮЧЁН — открытая регистрация запрещена'
 *     description: |
 *       Корпоративная политика: учётные записи создаются только администратором
 *       через `POST /api/admin/users`. Эндпоинт оставлен заглушкой для понятной
 *       ошибки на клиенте.
 *     security: []
 *     responses:
 *       403:
 *         description: Регистрация недоступна
 *         content: { application/json: { schema: { $ref: '#/components/schemas/Error' } } }
 */
app.post('/api/register', (req, res) => {
    return res.status(403).json({
        message: 'Открытая регистрация отключена. Обратитесь к администратору системы для создания учётной записи.'
    });
});

// Создание пользователя администратором через админ-центр.
// Использует ту же password policy, проверяет уникальность email/login,
// логирует действие и пишет в admin.log.
/**
 * @openapi
 * /api/admin/users:
 *   post:
 *     tags: [Admin]
 *     summary: Создание пользователя администратором
 *     description: |
 *       Корпоративная альтернатива открытой регистрации. Применяет ту же политику
 *       пароля. Дубликаты email/login проверяются только среди живых юзеров.
 *       Создание роли «Администратор» через UI запрещено (требует SQL).
 *     requestBody:
 *       required: true
 *       content: { application/json: { schema: { $ref: '#/components/schemas/AdminUserCreate' } } }
 *     responses:
 *       201:
 *         description: Создан
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message: { type: string }
 *                 userId:  { type: integer }
 *       400: { description: 'Невалидные поля (ФИО, email, пароль, role_id)' }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 *       403: { description: 'Попытка создать админа' }
 *       409: { description: 'Email или login уже занят' }
 */
app.post('/api/admin/users', authenticateToken, isAdmin, async (req, res) => {
    const { fio, email, login, branch_id, role_id, password } = req.body;

    if (!fio || !email || !password) {
        return res.status(400).json({ message: 'ФИО, email и пароль обязательны.' });
    }
    if (typeof fio !== 'string' || fio.trim().length < 5 || fio.length > 200) {
        return res.status(400).json({ message: 'ФИО должно быть от 5 до 200 символов.' });
    }
    // defense-in-depth XSS — запрет HTML-метасимволов в ФИО.
    // Frontend экранирует на render, но dataset-атрибуты декодируются
    // браузером, и при innerHTML без повторного escape — XSS на роли
    // согласующего/модератора. Реальные ФИО таких символов не содержат.
    if (FIO_BAD_CHARS.test(fio)) {
        return res.status(400).json({ message: 'ФИО не может содержать символы < > " \' & =.' });
    }
    if (!isValidEmail(email) || email.length > 200) {
        return res.status(400).json({ message: 'Некорректный email.' });
    }
    // upper bound 72. bcrypt усекает пароль на 72 байтах
    // молчаливо — юзер с 100-символьной passphrase реально проверяет первые
    // 72, последние 28 не учитываются. Для русских символов (UTF-8 ~2 байта)
    // лимит 72 байта = ~36 русских chars. Граница 72 chars в regex —
    // консервативно: ASCII-only password ≤72 chars гарантированно <=72 байт.
    // Mixed-charset (русский + латиница) тоже укладывается в большинстве
    // случаев. Если юзер хочет длиннее — explicit error лучше silent truncation.
    const passwordRegex = /^(?=.*[A-Za-zА-Яа-я])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-zА-Яа-я\d@$!%*#?&]{10,72}$/;
    if (!passwordRegex.test(password)) {
        return res.status(400).json({
            message: 'Пароль: 10–72 символа, минимум буква, цифра и спецсимвол (@$!%*#?&). Длиннее 72 — bcrypt усекает.'
        });
    }
    const parsedRoleId   = role_id   ? parseInt(role_id, 10) : 2;   // дефолт — Сотрудник
    const parsedBranchId = branch_id ? parseInt(branch_id, 10) : null;
    if (isNaN(parsedRoleId)) return res.status(400).json({ message: 'Некорректная роль.' });

    // whitelist role_id (симметрично PUT /api/admin/users/:id из Block A3).
    // Раньше POST принимал любое число — role_id=99 проваливалось в FK 500.
    const ALLOWED_CREATE_ROLES = [ROLES.EMPLOYEE, ROLES.MODERATOR, ROLES.APPROVER];
    if (!ALLOWED_CREATE_ROLES.includes(parsedRoleId)) {
        return res.status(400).json({ message: 'Некорректный role_id (создание Администратора запрещено).' });
    }

    try {
        // Не разрешаем админу создавать через эту форму ещё одного админа —
        // это требует прямого доступа к БД (дополнительная преграда).
        const adminRoleRow = await sql.query`SELECT id FROM Roles WHERE name = 'Администратор'`;
        const adminRoleId = adminRoleRow.recordset[0]?.id;
        if (parsedRoleId === adminRoleId) {
            return res.status(403).json({ message: 'Создание администратора через UI запрещено.' });
        }

        // Дубликат проверяем только среди живых юзеров — освободившийся email
        // удалённого можно использовать заново.
        const existing = await sql.query`SELECT id FROM Users
            WHERE (email = ${email} OR login = ${login || email})
              AND deleted_at IS NULL`;
        if (existing.recordset.length > 0) {
            return res.status(409).json({ message: 'Пользователь с таким email или логином уже существует.' });
        }

        const salt = await bcrypt.genSalt(BCRYPT_COST);
        const passwordHash = await bcrypt.hash(password, salt);
        const userLogin = login && login.trim() ? login.trim() : email;

        const result = await sql.query`
            INSERT INTO Users (full_name, login, password_hash, email, role_id, branch_id, is_active)
            OUTPUT INSERTED.id
            VALUES (${fio.trim()}, ${userLogin}, ${passwordHash}, ${email}, ${parsedRoleId}, ${parsedBranchId}, 1)`;

        const newUserId = result.recordset[0].id;
        await logAdminEvent(
            'Регистрация пользователя',
            `Администратор ${req.user.fullName} создал учётную запись: ${fio} (${email}). ID: ${newUserId}.`,
            req.user.id, req.user.fullName
        );

        res.status(201).json({ message: 'Пользователь создан.', userId: newUserId });
    } catch (err) {
        console.error('Ошибка создания пользователя:', err);
        res.status(500).json({ message: 'Ошибка сервера' });
    }
});

/* =============================================================================
   In-memory кэш справочных данных.
   Используется для редко изменяющихся справочников (Branches, EventCategories,
   Roles), которые запрашиваются клиентами часто (при заходе на каждую страницу).

   TTL = 10 минут. Если админ изменит справочник через прямой SQL — изменения
   проявятся максимум через 10 минут. Для UI-управления категориями (когда
   будет реализовано) — invalidateCache(key) вручную после мутаций.
   ============================================================================= */
const _cache = new Map();
async function cached(key, ttlMs, fetcher) {
    const c = _cache.get(key);
    if (c && c.expiresAt > Date.now()) return c.value;
    const value = await fetcher();
    _cache.set(key, { value, expiresAt: Date.now() + ttlMs });
    return value;
}
function invalidateCache(key) { _cache.delete(key); }
const CACHE_TTL = 10 * 60 * 1000; // 10 минут

/**
 * @openapi
 * /api/branches:
 *   get:
 *     tags: [Reference]
 *     summary: Список филиалов
 *     description: |
 *       Доступен без аутентификации (используется в форме регистрации, если она
 *       была бы открыта, и в админ-форме создания юзера). In-memory кэш 10мин.
 *     security: []
 *     responses:
 *       200:
 *         description: Филиалы
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items: { $ref: '#/components/schemas/Branch' }
 */
app.get('/api/branches', async (req, res) => {
    try {
        const data = await cached('branches', CACHE_TTL, async () => {
            const r = await sql.query`SELECT id, name FROM Branches ORDER BY name`;
            return r.recordset;
        });
        // HTTP-кэш: браузер тоже может закэшировать на минуту
        res.set('Cache-Control', 'public, max-age=60');
        res.json(data);
    } catch (err) {
        res.status(500).json({ message: 'Не удалось загрузить список филиалов' });
    }
});

// Доменные константы для фронтенда — отдаются один раз при загрузке UI.
// Содержат маппинги ROLE_KEY → id, STATUS_KEY → id и обратные. Это позволяет
// фронту обращаться к статусам через STATUSES.NEW вместо «1», что устраняет
// рассинхронизацию с серверной частью при изменении справочников.
/**
 * @openapi
 * /api/system-constants:
 *   get:
 *     tags: [Reference]
 *     summary: Доменные константы для фронтенда
 *     description: |
 *       Карты `ROLE_KEY → id`, `STATUS_KEY → id` и обратные. Раздаётся один
 *       раз при загрузке UI, кэшируется на 5 минут на клиенте (`Cache-Control`).
 *       Позволяет фронту обращаться к статусам через `STATUSES.NEW` вместо
 *       числовых литералов.
 *     responses:
 *       200:
 *         description: Константы
 *         content: { application/json: { schema: { $ref: '#/components/schemas/SystemConstants' } } }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 */
app.get('/api/system-constants', authenticateToken, (req, res) => {
    res.set('Cache-Control', 'private, max-age=300');
    res.json({
        roles: ROLES, roleNames: ROLE_NAMES,
        statuses: STATUSES, statusNames: STATUS_NAMES,
        // единая матрица доступа к PDF-протоколу. Фронт скрывает
        // кнопку для запрещённых сочетаний (статус × роль), backend дублирует
        // проверку через getPdfProtocolAccess(). Источник истины — config/constants.js.
        pdfProtocol: PDF_PROTOCOL_CONFIG
    });
});

/**
 * @openapi
 * /api/event-categories:
 *   get:
 *     tags: [Reference]
 *     summary: Активные категории мероприятий
 *     description: |
 *       Возвращает только `is_active = 1`. Полный список (включая неактивные)
 *       — через `GET /api/admin/categories` (admin only). In-memory кэш 10мин.
 *     responses:
 *       200:
 *         description: Список категорий
 *         content: { application/json: { schema: { type: array, items: { $ref: '#/components/schemas/Category' } } } }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 */
app.get('/api/event-categories', authenticateToken, async (req, res) => {
    try {
        const data = await cached('event-categories', CACHE_TTL, async () => {
            const r = await sql.query`SELECT id, name, color_hex FROM EventCategories WHERE is_active = 1 ORDER BY id`;
            return r.recordset;
        });
        res.set('Cache-Control', 'public, max-age=60');
        res.json(data);
    } catch (err) {
        console.error('Ошибка получения категорий мероприятий:', err);
        res.status(500).json({ message: 'Не удалось загрузить категории мероприятий' });
    }
});

/**
 * @openapi
 * /api/templates/{categoryId}:
 *   get:
 *     tags: [Reference]
 *     summary: Шаблон формы заявки для категории
 *     description: |
 *       Возвращает пред-заполненные значения title/description/location/responsible
 *       /attendees для выбранной категории мероприятия. Используется фронтом при
 *       создании заявки — пользователь не пишет с нуля.
 *     parameters:
 *       - { in: path, name: categoryId, required: true, schema: { type: integer } }
 *     responses:
 *       200: { description: Шаблон (или null если не настроен) }
 */
/**
 * @openapi
 * /api/templates/{categoryId}:
 *   get:
 *     tags: [Reference]
 *     summary: Шаблоны заявок для категории
 *     description: |
 *       Возвращает предустановленные шаблоны (заголовок + описание) для быстрого
 *       заполнения формы создания заявки определённой категории.
 *     parameters:
 *       - in: path
 *         name: categoryId
 *         required: true
 *         schema: { type: integer }
 *     responses:
 *       200:
 *         description: Список шаблонов
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:          { type: integer }
 *                   title:       { type: string }
 *                   description: { type: string, nullable: true }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 */
app.get('/api/templates/:categoryId', authenticateToken, async (req, res) => {
    const categoryId = parseInt(req.params.categoryId, 10);
    if (isNaN(categoryId)) return res.status(400).json({ message: 'Некорректный categoryId.' });
    try {
        // JOIN на EventCategories с фильтром `ec.is_active = 1` — если
        // категория soft-deleted'нута (CRUD категорий деактивирует через
        // is_active=0, а не hard-delete), её шаблон тоже не должен всплывать
        // в UI как валидный prefill. Раньше шаблон возвращался пока сам
        // RequestTemplates.is_active=1, без проверки активности категории.
        const r = await new sql.Request()
            .input('cid', sql.Int, categoryId)
            .query(`SELECT rt.default_title, rt.default_description, rt.default_location,
                           rt.default_responsible, rt.default_attendees
                    FROM RequestTemplates rt
                    JOIN EventCategories ec ON ec.id = rt.category_id
                    WHERE rt.category_id = @cid AND rt.is_active = 1 AND ec.is_active = 1`);
        res.json(r.recordset[0] || null);
    } catch (err) {
        console.error('Ошибка /api/templates:', err);
        res.status(500).json({ message: 'Не удалось загрузить шаблон' });
    }
});

/**
 * @openapi
 * /api/stats:
 *   get:
 *     tags: [Stats]
 *     summary: Аналитический дашборд (KPI + графики)
 *     description: |
 *       Видимость данных по ролям:
 *         - Сотрудник → только свои заявки (`scope: personal`)
 *         - Согласующий → заявки в статусах 3–6 (`scope: approval`)
 *         - Модератор/Админ → весь корпоративный объём (`scope: enterprise`)
 *     parameters:
 *       - in: query
 *         name: months
 *         description: 'Период для графика «Активность по месяцам». Допустимые: 3, 6, 12 (default 6) или 0 (всё время)'
 *         schema: { type: integer, enum: [3, 6, 12, 0], default: 6 }
 *     responses:
 *       200:
 *         description: Статистика
 *         content: { application/json: { schema: { $ref: '#/components/schemas/StatsResponse' } } }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 */
app.get('/api/stats', authenticateToken, async (req, res) => {
    const { role, id: userId } = req.user;
    // Период для графика «Активность по месяцам». Допустимые: 3, 6, 12 (default 6).
    // 0 = «всё время» — выбираем последние 24 месяца чтобы графику было что показать.
    const allowedPeriods = [3, 6, 12, 0];
    let months = parseInt(req.query.months, 10);
    if (!allowedPeriods.includes(months)) months = 6;
    const monthsBack    = months === 0 ? 24 : Math.ceil(months / 2);
    const monthsForward = months === 0 ? 24 : Math.ceil(months / 2);

    // Видимость данных аналитики совпадает с правилами /api/requests:
    // - Сотрудник → только его собственные заявки
    // - Согласующий → заявки в статусах 3-6
    // - Модератор/Администратор → весь корпоративный объём
    let scopeWhere = '';                  // условие, которое навешивается на r.* в WHERE
    let joinScope  = '';                  // то же условие, навешиваемое в LEFT JOIN ON
    let scopeTitle;
    // Список статусов, видимых согласующему — единая точка с applyRoleScope().
    const APPROVER_STATUSES = approverVisibleStatusIds().join(',');

    if (role === ROLE_NAMES[ROLES.EMPLOYEE]) {
        scopeWhere = 'r.creator_id = @userId';
        joinScope  = 'AND r.creator_id = @userId';
        scopeTitle = 'personal';
    } else if (role === ROLE_NAMES[ROLES.APPROVER]) {
        scopeWhere = `r.status_id IN (${APPROVER_STATUSES})`;
        joinScope  = `AND r.status_id IN (${APPROVER_STATUSES})`;
        scopeTitle = 'approval';
    } else {
        scopeTitle = 'enterprise';
    }
    const whereClause = scopeWhere ? `WHERE ${scopeWhere}` : '';

    try {
        // Каждый запрос — со своим `sql.Request` (один экземпляр нельзя использовать
        // повторно для разных query). Параметр @userId передаём только тем, где он нужен.
        const newReq = () => new sql.Request().input('userId', sql.Int, userId);

        const [kpiRes, byCategoryRes, byBranchRes, byMonthRes, byStatusRes] = await Promise.all([
            newReq().query(`
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN r.status_id = ${STATUSES.APPROVED} THEN 1 ELSE 0 END) AS approved,
                    SUM(CASE WHEN r.status_id = ${STATUSES.REJECTED} THEN 1 ELSE 0 END) AS rejected,
                    SUM(CASE WHEN r.status_id IN (${activeStatusList()})
                             THEN 1 ELSE 0 END) AS in_progress,
                    AVG(CAST(CASE WHEN r.status_id = ${STATUSES.APPROVED}
                                  THEN DATEDIFF(hour, r.created_at, r.updated_at)
                             END AS FLOAT)) AS avg_approval_hours
                FROM Requests r
                ${whereClause}`),

            newReq().query(`
                SELECT ec.id, ec.name, ec.color_hex,
                       ISNULL(COUNT(r.id), 0) AS qty
                FROM EventCategories ec
                LEFT JOIN Requests r ON r.category_id = ec.id ${joinScope}
                WHERE ec.is_active = 1
                GROUP BY ec.id, ec.name, ec.color_hex
                ORDER BY qty DESC, ec.id`),

            // для Сотрудника убираем personal-scope в этом
            // графике — показываем ВСЕ филиалы (top-10) для конкурентной
            // картины. Раньше Сотрудник видел только столбец своего филиала
            // (бесполезно). Согласующий по-прежнему scope'ится по статусам
            // (он видит активность по согласуемым заявкам — это релевантно).
            // Админ/Модератор — без scope как и раньше.
            newReq().query(`
                SELECT TOP 10 b.id, b.name, COUNT(r.id) AS qty
                FROM Branches b
                JOIN Users u ON u.branch_id = b.id
                JOIN Requests r ON r.creator_id = u.id
                ${role === ROLE_NAMES[ROLES.EMPLOYEE] ? '' : whereClause}
                GROUP BY b.id, b.name
                ORDER BY qty DESC`),

            newReq()
                .input('back',    sql.Int, monthsBack)
                .input('forward', sql.Int, monthsForward)
                .query(`
                SELECT YEAR(r.planned_date) AS yr,
                       MONTH(r.planned_date) AS mn,
                       COUNT(*) AS qty
                FROM Requests r
                WHERE r.planned_date >= DATEADD(month, -@back, GETUTCDATE())
                  AND r.planned_date <  DATEADD(month, @forward, GETUTCDATE())
                  ${scopeWhere ? `AND ${scopeWhere}` : ''}
                GROUP BY YEAR(r.planned_date), MONTH(r.planned_date)
                ORDER BY yr, mn`),

            newReq().query(`
                SELECT rs.id, rs.name, COUNT(r.id) AS qty
                FROM RequestStatuses rs
                LEFT JOIN Requests r ON r.status_id = rs.id ${joinScope}
                GROUP BY rs.id, rs.name
                ORDER BY rs.id`)
        ]);

        res.json({
            scope: scopeTitle,            // подсказка фронту: показать заголовок «Ваша / Корпоративная аналитика»
            months,                       // период, за который вернулась динамика
            kpi: {
                total:              kpiRes.recordset[0].total              || 0,
                approved:           kpiRes.recordset[0].approved           || 0,
                rejected:           kpiRes.recordset[0].rejected           || 0,
                in_progress:        kpiRes.recordset[0].in_progress        || 0,
                avg_approval_hours: kpiRes.recordset[0].avg_approval_hours
                    ? Math.round(kpiRes.recordset[0].avg_approval_hours * 10) / 10
                    : null
            },
            byCategory: byCategoryRes.recordset,
            byBranch:   byBranchRes.recordset,
            byMonth:    byMonthRes.recordset,
            byStatus:   byStatusRes.recordset
        });
    } catch (err) {
        console.error('Ошибка получения статистики:', err);
        res.status(500).json({ message: 'Не удалось загрузить статистику' });
    }
});

/**
 * @openapi
 * /api/roles:
 *   get:
 *     tags: [Admin]
 *     summary: Список ролей системы
 *     responses:
 *       200:
 *         description: Роли
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:   { type: integer }
 *                   name: { type: string, example: 'Сотрудник' }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 *       403: { $ref: '#/components/responses/Forbidden' }
 */
app.get('/api/roles', authenticateToken, isAdmin, async (req, res) => {
    try {
        const data = await cached('roles', CACHE_TTL, async () => {
            const r = await sql.query`SELECT id, name FROM Roles ORDER BY name`;
            return r.recordset;
        });
        res.set('Cache-Control', 'private, max-age=60');
        res.json(data);
    } catch (err) {
        res.status(500).json({ message: 'Не удалось загрузить список ролей' });
    }
});

/**
 * @openapi
 * /api/admin/users:
 *   get:
 *     tags: [Admin]
 *     summary: Список пользователей с пагинацией и поиском
 *     description: |
 *       Каждый запрос журналируется в `AccessAudit` (compliance закон РБ №99-З).
 *       По умолчанию скрывает soft-deleted, опционально включается через
 *       `?includeDeleted=true`.
 *     parameters:
 *       - in: query
 *         name: page
 *         schema: { type: integer, default: 1 }
 *       - in: query
 *         name: pageSize
 *         schema: { type: integer, default: 50, maximum: 500 }
 *       - in: query
 *         name: search
 *         description: 'Поиск по ФИО, email, логину'
 *         schema: { type: string }
 *       - in: query
 *         name: includeDeleted
 *         schema: { type: boolean, default: false }
 *     responses:
 *       200:
 *         description: Пагинированный список
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 items:      { type: array, items: { $ref: '#/components/schemas/AdminUserListItem' } }
 *                 totalItems: { type: integer }
 *                 page:       { type: integer }
 *                 pageSize:   { type: integer }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 *       403: { $ref: '#/components/responses/Forbidden' }
 */
app.get('/api/admin/users', authenticateToken, isAdmin, async (req, res) => {
    // Опциональная пагинация и поиск.
    // Если параметры не переданы — возвращается полный список (старое поведение,
    // совместимо со всеми существующими местами фронта). При page/pageSize/search
    // — пагинированный ответ { users, totalItems, page, pageSize }.
    const hasPagination = req.query.page || req.query.pageSize || req.query.search;
    // Math.max(1, ...) на pageSize тоже — без него ?pageSize=-50
    // → SQL `FETCH NEXT -50 ROWS` → 500 с обнажённым SQL-сообщением. Аналогично
    // в /api/admin/logs (2888) и /api/admin/file-attempts (2984).
    const page     = Math.max(1, parseInt(req.query.page, 10) || 1);
    const pageSize = Math.min(500, Math.max(1, parseInt(req.query.pageSize, 10) || 50));
    const offset   = (page - 1) * pageSize;
    const search   = (req.query.search || '').trim();

    // Удалённых юзеров скрываем по умолчанию. Опциональный ?includeDeleted=true
    // для админ-кейсов «вспомнить кто это был».
    const includeDeleted = req.query.includeDeleted === 'true';

    try {
        const reqQ = new sql.Request();
        const where = [];
        if (!includeDeleted) {
            where.push('u.deleted_at IS NULL');
        }
        if (search) {
            reqQ.input('search', sql.NVarChar, `%${escapeLikeWildcards(search)}%`);
            where.push(`(u.full_name LIKE @search ESCAPE '\\' OR u.email LIKE @search ESCAPE '\\' OR u.login LIKE @search ESCAPE '\\')`);
        }
        const whereClause = where.length ? `WHERE ${where.join(' AND ')}` : '';

        const baseQuery = `
            FROM Users u
            JOIN Roles r ON u.role_id = r.id
            LEFT JOIN Branches b ON u.branch_id = b.id
            ${whereClause}`;

        const selectFields = `
            SELECT u.id, u.full_name, u.email, u.login, u.is_active, u.role_id,
                   r.name as role_name, u.branch_id, b.name as branch_name,
                   u.failed_uploads_count, u.locked_until, u.deleted_at,
                   (SELECT COUNT(*) FROM FileUploadAttempts a
                      WHERE a.user_id = u.id AND a.was_clean = 0
                        AND a.attempted_at >= DATEADD(HOUR, -24, SYSUTCDATETIME())
                   ) AS violations_24h`;

        // Журналируем доступ к ПДн (compliance закон РБ №99-З) — ОБА пути:
        // и legacy (без пагинации) и новый. Раньше аудит был только в новом
        // пути и большинство реальных просмотров (UI ходит без пагинации)
        // не журналировались — баг.
        auditPiiAccess({
            userId: req.user.id,
            action: 'list_users',
            targetType: 'users',
            ip: req.ip,
            userAgent: req.headers['user-agent'],
            extraMeta: `search=${search || ''}, hasPagination=${!!hasPagination}`
        });

        if (!hasPagination) {
            // Старое поведение для обратной совместимости
            const r = await reqQ.query(`${selectFields} ${baseQuery} ORDER BY u.id`);
            return res.json(r.recordset);
        }

        // Новый формат с пагинацией
        const countResult = await reqQ.query(`SELECT COUNT(*) AS total ${baseQuery}`);
        const totalItems = countResult.recordset[0].total;

        const r = await reqQ.query(`
            ${selectFields} ${baseQuery}
            ORDER BY u.id
            OFFSET ${offset} ROWS FETCH NEXT ${pageSize} ROWS ONLY`);
        res.json({ users: r.recordset, totalItems, page, pageSize });
    } catch (err) {
        console.error("Ошибка получения пользователей:", err);
        res.status(500).json({ message: 'Ошибка сервера' });
    }
});

/**
 * @openapi
 * /api/admin/logs:
 *   get:
 *     tags: [Admin]
 *     summary: Журнал событий системы (admin event log)
 *     description: |
 *       Все записи `History` (входы, смены статусов, загрузки, нарушения,
 *       admin-действия) с фильтрами и пагинацией. Forensic-инструмент.
 *     parameters:
 *       - in: query
 *         name: page
 *         schema: { type: integer, default: 1 }
 *       - in: query
 *         name: pageSize
 *         schema: { type: integer, default: 50 }
 *       - in: query
 *         name: eventType
 *         description: 'CSV типов событий для фильтрации'
 *         schema: { type: string, example: 'Неудачный вход,Временная блокировка' }
 *       - in: query
 *         name: dateFrom
 *         schema: { type: string, format: date-time }
 *       - in: query
 *         name: dateTo
 *         schema: { type: string, format: date-time }
 *       - in: query
 *         name: search
 *         description: 'Поиск по `details` и `action`'
 *         schema: { type: string }
 *       - in: query
 *         name: requestId
 *         schema: { type: integer }
 *     responses:
 *       200:
 *         description: Журнал
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 logs:       { type: array, items: { $ref: '#/components/schemas/AdminLogItem' } }
 *                 totalItems: { type: integer }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 *       403: { $ref: '#/components/responses/Forbidden' }
 */
app.get('/api/admin/logs', authenticateToken, isAdmin, async (req, res) => {
    // Math.max(1, ...) clamp — без него ?page=-1 / pageSize=-50
    // даёт OFFSET/FETCH NEXT отрицательное значение → 500 с SQL-сообщением.
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const pageSize = Math.min(200, Math.max(1, parseInt(req.query.pageSize, 10) || 50));
    const offset = (page - 1) * pageSize;

    const actions = Array.isArray(req.query.action) ? req.query.action
                  : (req.query.action ? [req.query.action] : []);
    const userIds = Array.isArray(req.query.userId) ? req.query.userId
                  : (req.query.userId ? [req.query.userId] : []);
    const { dateFrom, dateTo, search, requestId } = req.query;

    try {
        const reqQ = new sql.Request();
        const where = [];

        if (actions.length > 0) {
            const params = actions.map((_, i) => `@act${i}`);
            actions.forEach((a, i) => reqQ.input(`act${i}`, sql.NVarChar, a));
            where.push(`h.action IN (${params.join(',')})`);
        }
        if (userIds.length > 0) {
            const params = userIds.map((_, i) => `@uid${i}`);
            userIds.forEach((id, i) => reqQ.input(`uid${i}`, sql.Int, parseInt(id, 10)));
            where.push(`h.user_id IN (${params.join(',')})`);
        }
        if (dateFrom) {
            reqQ.input('dateFrom', sql.DateTime2, new Date(dateFrom));
            where.push('h.timestamp >= @dateFrom');
        }
        if (dateTo) {
            reqQ.input('dateTo', sql.DateTime2, new Date(dateTo));
            where.push('h.timestamp <= @dateTo');
        }
        if (search) {
            reqQ.input('search', sql.NVarChar, `%${escapeLikeWildcards(search)}%`);
            where.push(`(h.details LIKE @search ESCAPE '\\' OR h.action LIKE @search ESCAPE '\\')`);
        }
        if (requestId) {
            reqQ.input('reqId', sql.Int, parseInt(requestId, 10));
            where.push('h.request_id = @reqId');
        }

        const whereClause = where.length > 0 ? 'WHERE ' + where.join(' AND ') : '';

        const countResult = await reqQ.query(`SELECT COUNT(*) AS total FROM History h ${whereClause}`);
        const totalItems = countResult.recordset[0].total;

        const dataResult = await reqQ.query(`
            SELECT h.id, h.timestamp AS event_time,
                   ISNULL(u.full_name, 'Система') AS user_name,
                   h.user_id,
                   h.action AS event_type, h.details, h.request_id
            FROM History h
            LEFT JOIN Users u ON h.user_id = u.id
            ${whereClause}
            ORDER BY h.timestamp DESC
            OFFSET ${offset} ROWS FETCH NEXT ${pageSize} ROWS ONLY`);

        // compliance — закон РБ №99-З требует журналировать
        // доступ к ПДн. Эндпоинт возвращает History.details (свободный текст
        // содержащий ФИО + действия + IP) и JOIN'ит Users.full_name. Это самый
        // PII-богатый admin-endpoint, при этом единственный который раньше
        // НЕ вызывал auditPiiAccess() — все остальные (admin/users,
        // admin/file-attempts, requests/:id, documents/:id/download,
        // requests/export.xlsx) уже журналировали.
        auditPiiAccess({
            userId: req.user.id,
            action: 'view_admin_logs',
            targetType: 'history',
            ip: req.ip,
            userAgent: req.headers['user-agent'],
            extraMeta: `actions=[${actions.join(',')}],userIds=[${userIds.join(',')}],dateFrom=${dateFrom||''},dateTo=${dateTo||''},rows=${dataResult.recordset.length}`
        });
        res.json({ logs: dataResult.recordset, totalItems });
    } catch (err) {
        console.error("Ошибка получения логов:", err);
        res.status(500).json({ message: "Ошибка сервера" });
    }
});

// Список уникальных типов событий (для multi-select фильтра в UI)
/**
 * @openapi
 * /api/admin/log-event-types:
 *   get:
 *     tags: [Admin]
 *     summary: Список уникальных типов событий для фильтра журнала
 *     description: Используется в UI как опции multiselect-фильтра журнала событий.
 *     responses:
 *       200:
 *         description: Типы событий
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items: { type: string, example: 'Вход в систему' }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 *       403: { $ref: '#/components/responses/Forbidden' }
 */
app.get('/api/admin/log-event-types', authenticateToken, isAdmin, async (req, res) => {
    try {
        const result = await sql.query`
            SELECT action AS name, COUNT(*) AS qty
            FROM History
            GROUP BY action
            ORDER BY qty DESC, action`;
        res.json(result.recordset);
    } catch (err) {
        console.error("Ошибка получения типов событий:", err);
        res.status(500).json({ message: "Ошибка сервера" });
    }
});

// Журнал попыток загрузки файлов (FileUploadAttempts) с фильтрами
/**
 * @openapi
 * /api/admin/file-attempts:
 *   get:
 *     tags: [Admin]
 *     summary: Журнал попыток загрузки файлов
 *     description: |
 *       Все попытки upload (включая отклонённые из-за MIME-mismatch / clamav).
 *       Полезно для forensic-анализа атак на upload и compliance-аудита.
 *     parameters:
 *       - in: query
 *         name: page
 *         schema: { type: integer, default: 1 }
 *       - in: query
 *         name: pageSize
 *         schema: { type: integer, default: 50 }
 *       - in: query
 *         name: userIds
 *         description: 'CSV id юзеров для фильтра'
 *         schema: { type: string }
 *       - in: query
 *         name: severity
 *         schema: { type: string, enum: [all, soft, medium, high] }
 *       - in: query
 *         name: wasClean
 *         description: 'true=показать только чистые, false=только отклонённые'
 *         schema: { type: boolean }
 *       - in: query
 *         name: dateFrom
 *         schema: { type: string, format: date-time }
 *       - in: query
 *         name: dateTo
 *         schema: { type: string, format: date-time }
 *       - in: query
 *         name: search
 *         description: 'Поиск по имени файла и reason'
 *         schema: { type: string }
 *     responses:
 *       200:
 *         description: Журнал попыток
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 attempts: { type: array, items: { type: object } }
 *                 totalItems: { type: integer }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 *       403: { $ref: '#/components/responses/Forbidden' }
 */
app.get('/api/admin/file-attempts', authenticateToken, isAdmin, async (req, res) => {
    // Math.max(1, ...) clamp — см. /api/admin/logs.
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const pageSize = Math.min(200, Math.max(1, parseInt(req.query.pageSize, 10) || 50));
    const offset = (page - 1) * pageSize;

    const userIds = Array.isArray(req.query.userId) ? req.query.userId
                  : (req.query.userId ? [req.query.userId] : []);
    const { severity, wasClean, dateFrom, dateTo, search } = req.query;

    try {
        const reqQ = new sql.Request();
        const where = [];

        if (userIds.length > 0) {
            const params = userIds.map((_, i) => `@uid${i}`);
            userIds.forEach((id, i) => reqQ.input(`uid${i}`, sql.Int, parseInt(id, 10)));
            where.push(`a.user_id IN (${params.join(',')})`);
        }
        if (severity && severity !== 'all') {
            // severity сохранён как часть строки reason: [soft/...] / [medium/...] / [high/...]
            // `[` экранируем как `[[]`: в LIKE это метасимвол, иначе не матчит reason.
            reqQ.input('sev', sql.NVarChar, `[[]${severity}/%`);
            where.push('a.reason LIKE @sev');
        }
        if (wasClean === 'true' || wasClean === '1') where.push('a.was_clean = 1');
        if (wasClean === 'false' || wasClean === '0') where.push('a.was_clean = 0');
        if (dateFrom) {
            reqQ.input('dateFrom', sql.DateTime2, new Date(dateFrom));
            where.push('a.attempted_at >= @dateFrom');
        }
        if (dateTo) {
            reqQ.input('dateTo', sql.DateTime2, new Date(dateTo));
            where.push('a.attempted_at <= @dateTo');
        }
        if (search) {
            reqQ.input('search', sql.NVarChar, `%${escapeLikeWildcards(search)}%`);
            where.push(`(a.file_name LIKE @search ESCAPE '\\' OR a.reason LIKE @search ESCAPE '\\')`);
        }

        const whereClause = where.length > 0 ? 'WHERE ' + where.join(' AND ') : '';

        const countResult = await reqQ.query(`SELECT COUNT(*) AS total FROM FileUploadAttempts a ${whereClause}`);
        const totalItems = countResult.recordset[0].total;

        const dataResult = await reqQ.query(`
            SELECT a.id, a.attempted_at, a.user_id,
                   ISNULL(u.full_name, 'Удалён') AS user_name,
                   a.ip_address, a.file_name, a.claimed_mime, a.actual_mime,
                   a.was_clean, a.reason
            FROM FileUploadAttempts a
            LEFT JOIN Users u ON u.id = a.user_id
            ${whereClause}
            ORDER BY a.attempted_at DESC
            OFFSET ${offset} ROWS FETCH NEXT ${pageSize} ROWS ONLY`);

        auditPiiAccess({
            userId: req.user.id,
            action: 'view_file_attempts',
            targetType: 'file_attempts',
            ip: req.ip,
            userAgent: req.headers['user-agent'],
            extraMeta: `count=${dataResult.recordset.length}`
        });
        res.json({ attempts: dataResult.recordset, totalItems });
    } catch (err) {
        console.error("Ошибка получения file-attempts:", err);
        res.status(500).json({ message: "Ошибка сервера" });
    }
});

/**
 * @openapi
 * /api/admin/pii-audit:
 *   get:
 *     tags: [Admin]
 *     summary: Журнал доступа к персональным данным (compliance закон РБ №99-З)
 *     description: |
 *       Возвращает кто, когда и к каким данным обращался — обязательная
 *       составляющая для оператора ПДн. Только администратор. Пагинация
 *       page/pageSize, опциональный фильтр userId.
 *     parameters:
 *       - { in: query, name: page,     schema: { type: integer, default: 1 } }
 *       - { in: query, name: pageSize, schema: { type: integer, default: 50 } }
 *       - { in: query, name: userId,   schema: { type: integer } }
 *     responses:
 *       200: { description: 'Список аудит-записей' }
 */
/**
 * @openapi
 * /api/admin/pii-audit:
 *   get:
 *     tags: [Admin]
 *     summary: Журнал доступа к персональным данным (compliance закон РБ №99-З)
 *     description: |
 *       Каждый запрос к эндпоинтам, отдающим чужие ПДн (`GET /api/admin/users`,
 *       профили и т.п.), фиксируется в `AccessAudit`. Этот эндпоинт показывает
 *       историю «кто, когда, какие ПДн смотрел».
 *       Retention: 1 год (cron-cleanup автоматически чистит старые записи).
 *     parameters:
 *       - in: query
 *         name: page
 *         schema: { type: integer, default: 1 }
 *       - in: query
 *         name: pageSize
 *         schema: { type: integer, default: 50 }
 *     responses:
 *       200:
 *         description: Журнал PII-доступа
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 items: { type: array, items: { type: object } }
 *                 totalItems: { type: integer }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 *       403: { $ref: '#/components/responses/Forbidden' }
 */
app.get('/api/admin/pii-audit', authenticateToken, isAdmin, async (req, res) => {
    const page     = Math.max(1, parseInt(req.query.page, 10) || 1);
    // Math.max(1, ...) на pageSize.
    const pageSize = Math.min(200, Math.max(1, parseInt(req.query.pageSize, 10) || 50));
    const offset   = (page - 1) * pageSize;
    const userId   = parseInt(req.query.userId, 10);

    try {
        const reqQ = new sql.Request();
        const where = [];
        if (Number.isInteger(userId)) {
            reqQ.input('uid', sql.Int, userId);
            where.push('a.user_id = @uid');
        }
        const whereClause = where.length ? `WHERE ${where.join(' AND ')}` : '';

        const total = await reqQ.query(`SELECT COUNT(*) AS c FROM AccessAudit a ${whereClause}`);
        const data  = await reqQ.query(`
            SELECT a.id, a.user_id, u.full_name AS user_name,
                   a.action, a.target_type, a.target_id,
                   a.ip_address, a.user_agent, a.extra_meta, a.accessed_at
            FROM AccessAudit a
            LEFT JOIN Users u ON u.id = a.user_id
            ${whereClause}
            ORDER BY a.accessed_at DESC
            OFFSET ${offset} ROWS FETCH NEXT ${pageSize} ROWS ONLY`);

        res.json({ items: data.recordset, totalItems: total.recordset[0].c, page, pageSize });
    } catch (err) {
        console.error('Ошибка /api/admin/pii-audit:', err);
        res.status(500).json({ message: 'Не удалось загрузить журнал' });
    }
});

// Сводка для главной вкладки админки (KPI)
/**
 * @openapi
 * /api/admin/security-summary:
 *   get:
 *     tags: [Admin]
 *     summary: Сводка по безопасности за последние 24 часа
 *     description: |
 *       Quick-overview для админ-дашборда: кол-во неудачных входов, активных
 *       lock'ов, нарушений upload по severity. Используется для визуальной
 *       проверки «всё ли спокойно» без открытия полных журналов.
 *     responses:
 *       200:
 *         description: Сводка
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 failedLogins24h:    { type: integer }
 *                 lockedUsers:        { type: integer }
 *                 violationsHigh24h:  { type: integer }
 *                 violationsMedium24h: { type: integer }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 *       403: { $ref: '#/components/responses/Forbidden' }
 */
app.get('/api/admin/security-summary', authenticateToken, isAdmin, async (req, res) => {
    try {
        const r = await sql.query`
            SELECT
                (SELECT COUNT(*) FROM Users) AS total_users,
                (SELECT COUNT(*) FROM Users WHERE is_active = 1
                    AND (locked_until IS NULL OR locked_until <= SYSUTCDATETIME())) AS active_users,
                (SELECT COUNT(*) FROM Users WHERE is_active = 1
                    AND locked_until IS NOT NULL AND locked_until > SYSUTCDATETIME()) AS temp_locked,
                (SELECT COUNT(*) FROM Users WHERE is_active = 0) AS hard_locked,
                (SELECT COUNT(*) FROM FileUploadAttempts
                    WHERE was_clean = 0 AND attempted_at >= DATEADD(HOUR, -24, SYSUTCDATETIME())) AS violations_24h,
                (SELECT COUNT(*) FROM FileUploadAttempts
                    WHERE was_clean = 0 AND attempted_at >= DATEADD(DAY, -7, SYSUTCDATETIME())) AS violations_7d,
                (SELECT COUNT(*) FROM FileUploadAttempts
                    WHERE attempted_at >= DATEADD(HOUR, -24, SYSUTCDATETIME())) AS uploads_24h,
                (SELECT COUNT(*) FROM History
                    WHERE timestamp >= DATEADD(HOUR, -24, SYSUTCDATETIME())) AS events_24h`;

        const recentAlerts = await sql.query`
            SELECT TOP 10 a.id, a.attempted_at,
                   ISNULL(u.full_name, 'Удалён') AS user_name,
                   a.ip_address, a.file_name, a.reason
            FROM FileUploadAttempts a
            LEFT JOIN Users u ON u.id = a.user_id
            WHERE a.was_clean = 0
              AND (a.reason LIKE '[[]high/%' OR a.reason LIKE '[[]medium/%')
            ORDER BY a.attempted_at DESC`;

        // recentAlerts содержит u.full_name + a.ip_address +
        // a.file_name — PII даже если KPI-агрегаты не считаются. Логируем
        // только если есть recentAlerts (KPI без аудита допустим — это просто
        // counts, не персонализированные данные).
        if (recentAlerts.recordset.length > 0) {
            auditPiiAccess({
                userId: req.user.id,
                action: 'view_security_summary',
                targetType: 'file_upload_attempts',
                ip: req.ip,
                userAgent: req.headers['user-agent'],
                extraMeta: `recent_alerts=${recentAlerts.recordset.length}`
            });
        }
        res.json({
            kpi: r.recordset[0],
            recentAlerts: recentAlerts.recordset
        });
    } catch (err) {
        console.error("Ошибка security-summary:", err);
        res.status(500).json({ message: "Ошибка сервера" });
    }
});

// Снять временную блокировку с пользователя
/**
 * @openapi
 * /api/admin/users/{id}/unlock:
 *   post:
 *     tags: [Admin]
 *     summary: Снять временную блокировку с пользователя
 *     description: |
 *       Сбрасывает `locked_until` и `failed_uploads_count` (счётчики violations).
 *       Применяется когда юзер запустил temp-lock через 3+ нарушения MIME за 30
 *       минут или 5+ неудачных входов и админ хочет дать ему доступ обратно
 *       без ожидания auto-unlock.
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer }
 *     responses:
 *       200: { description: 'Блокировка снята' }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 *       403: { $ref: '#/components/responses/Forbidden' }
 *       404: { $ref: '#/components/responses/NotFound' }
 */
app.post('/api/admin/users/:id/unlock', authenticateToken, isAdmin, async (req, res) => {
    const userId = parseInt(req.params.id, 10);
    if (isNaN(userId)) return res.status(400).json({ message: 'Неверный ID' });

    try {
        const target = await new sql.Request()
            .input('id', sql.Int, userId)
            .query`SELECT id, full_name, locked_until, failed_uploads_count FROM Users WHERE id = @id`;
        if (target.recordset.length === 0) {
            return res.status(404).json({ message: 'Пользователь не найден' });
        }
        const t = target.recordset[0];
        await new sql.Request()
            .input('id', sql.Int, userId)
            .query`UPDATE Users SET locked_until = NULL, failed_uploads_count = 0 WHERE id = @id`;

        await logAdminEvent(
            'Снятие блокировки',
            `Администратор ${req.user.fullName} снял блокировку пользователя ${t.full_name}.`,
            req.user.id, req.user.fullName
        );

        res.json({ message: 'Блокировка снята.' });
    } catch (err) {
        console.error('Ошибка снятия блокировки:', err);
        res.status(500).json({ message: 'Ошибка сервера' });
    }
});

app.put('/api/admin/users/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const userIdToChange = parseInt(req.params.id, 10);
        if (isNaN(userIdToChange)) return res.status(400).json({ message: 'Некорректный id.' });

        const { role_id, branch_id, is_active, full_name, email } = req.body;

        // Самого себя админ не может выключить — иначе системе не останется ни одного активного админа.
        if (userIdToChange === req.user.id && is_active === false) {
            return res.status(403).json({ message: 'Нельзя деактивировать собственную учётную запись.' });
        }

        const adminRoleId = ROLES.ADMIN;

        const userToChangeResult = await new sql.Request()
            .input('id', sql.Int, userIdToChange)
            .query('SELECT role_id, full_name, email FROM Users WHERE id = @id');
        if (userToChangeResult.recordset.length === 0) {
            return res.status(404).json({ message: 'Пользователь не найден.' });
        }
        const current = userToChangeResult.recordset[0];

        // Whitelist role_id: разрешены только реальные значения. Раньше можно
        // было прислать role_id=99 — попадало в UPDATE и роняло FK violation 500.
        const newRoleId = parseInt(role_id, 10);
        const ALLOWED_ROLES = [ROLES.ADMIN, ROLES.EMPLOYEE, ROLES.MODERATOR, ROLES.APPROVER];
        if (!ALLOWED_ROLES.includes(newRoleId)) {
            return res.status(400).json({ message: 'Некорректный role_id.' });
        }

        if ((current.role_id === adminRoleId && newRoleId !== adminRoleId) ||
            (newRoleId === adminRoleId && current.role_id !== adminRoleId)) {
            return res.status(403).json({ message: 'Запрещено изменять роль "Администратор".' });
        }

        // Whitelist branch_id: должен существовать (или быть null/undefined).
        let branchValue = null;
        if (branch_id !== null && branch_id !== undefined && branch_id !== '') {
            const bid = parseInt(branch_id, 10);
            if (!Number.isInteger(bid) || bid <= 0) {
                return res.status(400).json({ message: 'Некорректный branch_id.' });
            }
            const bExists = await new sql.Request()
                .input('bid', sql.Int, bid)
                .query('SELECT 1 AS x FROM Branches WHERE id = @bid');
            if (bExists.recordset.length === 0) {
                return res.status(400).json({ message: 'Филиал не найден.' });
            }
            branchValue = bid;
        }

        // Last-active-admin guard: если деактивируем чужого админа — должен
        // остаться хотя бы один активный. Раньше через 2 шага (А деактивирует
        // Б, потом А разлогинивается) система могла остаться без админа.
        if (current.role_id === adminRoleId &&
            (is_active === false || newRoleId !== adminRoleId)) {
            const r = await new sql.Request()
                .input('uid', sql.Int, userIdToChange)
                .query(`SELECT COUNT(*) AS cnt FROM Users
                        WHERE role_id = ${adminRoleId}
                          AND is_active = 1
                          AND deleted_at IS NULL
                          AND id <> @uid`);
            if ((r.recordset[0].cnt || 0) < 1) {
                return res.status(409).json({
                    message: 'Нельзя деактивировать или понизить последнего активного администратора.'
                });
            }
        }

        // Валидация необязательных полей full_name / email — изменяем только если переданы.
        let nextFullName = current.full_name;
        let nextEmail    = current.email;
        const changedFields = [];

        if (typeof full_name === 'string') {
            const fn = full_name.trim();
            if (fn.length < 5 || fn.length > 200) {
                return res.status(400).json({ message: 'ФИО должно быть от 5 до 200 символов.' });
            }
            if (FIO_BAD_CHARS.test(fn)) {
                return res.status(400).json({ message: 'ФИО не может содержать символы < > " \' & =.' });
            }
            if (fn !== current.full_name) { nextFullName = fn; changedFields.push('ФИО'); }
        }

        if (typeof email === 'string') {
            const em = email.trim().toLowerCase();
            if (!isValidEmail(em) || em.length > 200) {
                return res.status(400).json({ message: 'Некорректный email.' });
            }
            if (em !== (current.email || '').toLowerCase()) {
                // Проверка уникальности.
                // F1/H-1: фильтр `deleted_at IS NULL` — синхронно с
                // filtered UQ_Users_Email_Active (mig 35) и с INSERT в
                // /api/admin/users:2620. Раньше pre-check блокировал email
                // soft-deleted'а, хотя БД-индекс уже разрешает переиспользование.
                const dup = await new sql.Request()
                    .input('email', sql.NVarChar, em)
                    .input('id',    sql.Int, userIdToChange)
                    .query('SELECT 1 AS x FROM Users WHERE email = @email AND id <> @id AND deleted_at IS NULL');
                if (dup.recordset.length > 0) {
                    return res.status(409).json({ message: 'Пользователь с таким email уже существует.' });
                }
                nextEmail = em;
                changedFields.push('email');
            }
        }

        // is_active нормализуем в boolean — иначе sql.Bit получит truthy
        // строку «false» и интерпретирует как 1.
        const isActiveBool = is_active === true || is_active === 1 || is_active === '1' || is_active === 'true';

        // E1/H-2: транзакция UPDATE Users + bumpTokenVersion + History.
        // Раньше 3 независимые query — UPDATE прошёл, bumpTokenVersion упал на
        // deadlock/connection drop → юзер с новой ролью, но старый JWT с
        // прежними правами валиден до 15 мин (privilege escalation window).
        // Аналогичный паттерн уже применён в DELETE /admin/users/:id (Block Y).
        // Privilege-revocation logic: при изменении роли или деактивации
        // не самого себя — bump token_version. Не вызываем при правке
        // собственного ФИО — иначе админ вылетит из своей сессии.
        const roleChanged = current.role_id !== newRoleId;
        const becameInactive = isActiveBool === false;
        const shouldBump = (roleChanged || becameInactive) && userIdToChange !== req.user.id;
        const detailsSuffix = changedFields.length ? ` (изменено: ${changedFields.join(', ')})` : '';

        const transaction = new sql.Transaction();
        let txStarted = false;
        let wsRevoke = null;
        let logBroadcast = null;
        try {
            await transaction.begin();
            txStarted = true;

            await new sql.Request(transaction)
                .input('id',         sql.Int, userIdToChange)
                .input('role_id',    sql.Int, newRoleId)
                .input('branch_id',  sql.Int, branchValue)
                .input('is_active',  sql.Bit, isActiveBool)
                .input('full_name',  sql.NVarChar, nextFullName)
                .input('email',      sql.NVarChar, nextEmail)
                .query(`UPDATE Users
                        SET role_id    = @role_id,
                            branch_id  = @branch_id,
                            is_active  = @is_active,
                            full_name  = @full_name,
                            email      = @email
                        WHERE id = @id`);

            if (shouldBump) {
                wsRevoke = await bumpTokenVersionInTx(transaction, userIdToChange);
            }

            logBroadcast = await logAdminEventInTx(
                transaction,
                'Изменение пользователя',
                `Пользователем ${req.user.fullName} обновлены данные для ID: ${userIdToChange}${detailsSuffix}.`,
                req.user.id, req.user.fullName
            );

            await transaction.commit();
            txStarted = false;
        } catch (txErr) {
            if (txStarted) await transaction.rollback().catch(() => {});
            console.error('Транзакция PUT /admin/users/:id упала:', txErr);
            return replyOnTxError(res, txErr, 'Ошибка сервера');
        }

        // POST-COMMIT: WS-revoke + admin-log broadcast + PII-аудит.
        if (wsRevoke) {
            try { wsRevoke(); } catch (e) { console.error('wsRevoke failed:', e.message); }
        }
        try { logBroadcast(); } catch (e) { console.error('logBroadcast failed:', e.message); }
        auditPiiAccess({
            userId: req.user.id,
            action: 'update_user',
            targetType: 'users',
            targetId: userIdToChange,
            ip: req.ip,
            userAgent: req.headers['user-agent'],
            extraMeta: `fields=[${changedFields.join(',')}]`
        });
        res.json({ message: 'Данные пользователя обновлены.' });
    } catch (err) {
        console.error("Ошибка обновления пользователя:", err);
        res.status(500).json({
            message: 'Ошибка сервера'
        });
    }
});

/**
 * Принудительный сброс пароля. Генерирует новый пароль по той же политике,
 * что и при создании юзера, обнуляет refresh_token_hash (выгоняет со всех
 * устройств), возвращает новый пароль один раз — админ передаёт его юзеру
 * по защищённому каналу.
 */
/* =============================================================================
   API управления категориями мероприятий (только админ).
   - GET    /api/admin/categories          — список с usage_count
   - POST   /api/admin/categories          — создание
   - PUT    /api/admin/categories/:id      — обновление имени/цвета
   - DELETE /api/admin/categories/:id      — soft-delete (is_active = 0)
   После каждой мутации — invalidateCache('event-categories'), чтобы
   фронт получил свежие данные при следующем GET.
   ============================================================================= */

const HEX_COLOR_RE = /^#([0-9A-Fa-f]{6})$/;

/**
 * @openapi
 * /api/admin/categories:
 *   get:
 *     tags: [Admin]
 *     summary: Список всех категорий с usage_count (только админ)
 *     responses:
 *       200:
 *         description: Категории
 *         content:
 *           application/json:
 *             schema: { type: array, items: { $ref: '#/components/schemas/Category' } }
 *   post:
 *     tags: [Admin]
 *     summary: Создание новой категории
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [name, color_hex]
 *             properties:
 *               name:      { type: string, minLength: 2, maxLength: 100 }
 *               color_hex: { type: string, pattern: '^#[0-9A-Fa-f]{6}$' }
 *     responses:
 *       201: { description: Создано }
 *       409: { description: Категория с таким именем уже есть }
 */
/**
 * @openapi
 * /api/admin/categories:
 *   get:
 *     tags: [Admin]
 *     summary: Полный список категорий (включая неактивные)
 *     description: |
 *       Отличается от публичного `GET /api/event-categories` тем, что возвращает
 *       и `is_active = 0` (для управления). Также добавлено поле `usage_count` —
 *       сколько заявок ссылается на категорию (для запрета удаления используемых).
 *     responses:
 *       200:
 *         description: Категории
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 allOf:
 *                   - $ref: '#/components/schemas/Category'
 *                   - type: object
 *                     properties:
 *                       usage_count: { type: integer }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 *       403: { $ref: '#/components/responses/Forbidden' }
 */
app.get('/api/admin/categories', authenticateToken, isAdmin, async (req, res) => {
    try {
        const r = await sql.query`
            SELECT ec.id, ec.name, ec.color_hex, ec.is_active,
                   (SELECT COUNT(*) FROM Requests WHERE category_id = ec.id) AS usage_count
            FROM EventCategories ec
            ORDER BY ec.is_active DESC, ec.id`;
        res.json(r.recordset);
    } catch (err) {
        console.error('Ошибка /api/admin/categories:', err);
        res.status(500).json({ message: 'Не удалось загрузить категории' });
    }
});

// Запрет HTML-метасимволов в имени категории (defense-in-depth поверх
// frontend-escapeHtml). Реальные русские названия категорий в этих символах
// не нуждаются.
const CATEGORY_NAME_BAD_CHARS = /[<>"'&]/;
// То же для ФИО юзера — плюс `=` для CSV-injection защиты в Excel-export
// (footer строки `Пользователь: ${fullName}`).
const FIO_BAD_CHARS = /[<>"'&=]/;

/**
 * @openapi
 * /api/admin/categories:
 *   post:
 *     tags: [Admin]
 *     summary: Создание категории
 *     requestBody:
 *       required: true
 *       content: { application/json: { schema: { $ref: '#/components/schemas/CategoryUpsert' } } }
 *     responses:
 *       201:
 *         description: Создана
 *         content: { application/json: { schema: { $ref: '#/components/schemas/Category' } } }
 *       400: { description: 'Невалидные поля (длина name, формат цвета, запрещённые символы)' }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 *       403: { $ref: '#/components/responses/Forbidden' }
 *       409: { description: 'Категория с таким именем уже существует' }
 */
app.post('/api/admin/categories', authenticateToken, isAdmin, async (req, res) => {
    const name = (req.body?.name || '').trim();
    const color = (req.body?.color_hex || '').trim();

    if (name.length < 2 || name.length > 100) {
        return res.status(400).json({ message: 'Название должно быть от 2 до 100 символов.' });
    }
    if (CATEGORY_NAME_BAD_CHARS.test(name)) {
        return res.status(400).json({ message: 'Название не может содержать символы < > " \' &.' });
    }
    if (!HEX_COLOR_RE.test(color)) {
        return res.status(400).json({ message: 'Цвет должен быть в формате #RRGGBB.' });
    }

    try {
        const dup = await new sql.Request()
            .input('name', sql.NVarChar, name)
            .query('SELECT 1 AS x FROM EventCategories WHERE name = @name');
        if (dup.recordset.length > 0) {
            return res.status(409).json({ message: 'Категория с таким названием уже существует.' });
        }

        const r = await new sql.Request()
            .input('name',  sql.NVarChar, name)
            .input('color', sql.NVarChar, color)
            .query(`
                DECLARE @Out TABLE (ID INT);
                INSERT INTO EventCategories (name, color_hex, is_active)
                OUTPUT INSERTED.id INTO @Out(ID)
                VALUES (@name, @color, 1);
                SELECT ID FROM @Out;`);

        invalidateCache('event-categories');
        await logAdminEvent('Создание категории',
            `Администратор ${req.user.fullName} создал категорию «${name}».`,
            req.user.id, req.user.fullName);
        res.status(201).json({ id: r.recordset[0].ID, name, color_hex: color, is_active: 1 });
    } catch (err) {
        console.error('Ошибка создания категории:', err);
        res.status(500).json({ message: 'Не удалось создать категорию' });
    }
});

/**
 * @openapi
 * /api/admin/categories/{id}:
 *   put:
 *     tags: [Admin]
 *     summary: Обновление категории (имя, цвет, активность)
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer }
 *     requestBody:
 *       required: true
 *       content: { application/json: { schema: { $ref: '#/components/schemas/CategoryUpsert' } } }
 *     responses:
 *       200:
 *         description: Обновлена
 *         content: { application/json: { schema: { $ref: '#/components/schemas/Category' } } }
 *       400: { description: 'Невалидные поля' }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 *       403: { $ref: '#/components/responses/Forbidden' }
 *       404: { description: 'Категория не найдена' }
 *       409: { description: 'Конфликт имени с другой категорией' }
 */
app.put('/api/admin/categories/:id', authenticateToken, isAdmin, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) return res.status(400).json({ message: 'Некорректный id.' });

    const name = (req.body?.name || '').trim();
    const color = (req.body?.color_hex || '').trim();
    const isActive = req.body?.is_active;

    if (name.length < 2 || name.length > 100) {
        return res.status(400).json({ message: 'Название должно быть от 2 до 100 символов.' });
    }
    if (CATEGORY_NAME_BAD_CHARS.test(name)) {
        return res.status(400).json({ message: 'Название не может содержать символы < > " \' &.' });
    }
    if (!HEX_COLOR_RE.test(color)) {
        return res.status(400).json({ message: 'Цвет должен быть в формате #RRGGBB.' });
    }

    try {
        const dup = await new sql.Request()
            .input('name', sql.NVarChar, name)
            .input('id',   sql.Int, id)
            .query('SELECT 1 AS x FROM EventCategories WHERE name = @name AND id <> @id');
        if (dup.recordset.length > 0) {
            return res.status(409).json({ message: 'Другая категория с таким названием уже существует.' });
        }

        const upd = await new sql.Request()
            .input('id',        sql.Int, id)
            .input('name',      sql.NVarChar, name)
            .input('color',     sql.NVarChar, color)
            .input('is_active', sql.Bit, isActive ? 1 : 0)
            .query('UPDATE EventCategories SET name = @name, color_hex = @color, is_active = @is_active WHERE id = @id');
        if (upd.rowsAffected[0] === 0) {
            return res.status(404).json({ message: 'Категория не найдена.' });
        }

        invalidateCache('event-categories');
        await logAdminEvent('Обновление категории',
            `Администратор ${req.user.fullName} обновил категорию #${id}.`,
            req.user.id, req.user.fullName);
        res.json({ id, name, color_hex: color, is_active: isActive ? 1 : 0 });
    } catch (err) {
        console.error('Ошибка обновления категории:', err);
        res.status(500).json({ message: 'Не удалось обновить категорию' });
    }
});

/**
 * Soft-delete категории: is_active = 0.
 * Hard-delete не делаем — на категорию могут ссылаться Requests, и потеря FK
 * сломает данные. Категории с usage_count > 0 не удаляются вовсе — при попытке
 * возвращаем 409 с подсказкой «деактивируйте, чтобы скрыть из выпадающих».
 */
/**
 * @openapi
 * /api/admin/categories/{id}:
 *   delete:
 *     tags: [Admin]
 *     summary: Удаление неиспользуемой категории
 *     description: |
 *       Hard-delete возможен ТОЛЬКО если ни одна заявка не ссылается на категорию.
 *       Иначе 409 с подсказкой «деактивируйте через PUT, чтобы скрыть из выпадающих».
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer }
 *     responses:
 *       200: { description: 'Удалена' }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 *       403: { $ref: '#/components/responses/Forbidden' }
 *       404: { description: 'Категория не найдена' }
 *       409: { description: 'Категория используется в заявках (надо деактивировать)' }
 */
app.delete('/api/admin/categories/:id', authenticateToken, isAdmin, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) return res.status(400).json({ message: 'Некорректный id.' });
    try {
        const usage = await new sql.Request()
            .input('id', sql.Int, id)
            .query('SELECT COUNT(*) AS cnt FROM Requests WHERE category_id = @id');
        if (usage.recordset[0].cnt > 0) {
            return res.status(409).json({
                message: `Эта категория используется в ${usage.recordset[0].cnt} заявках. Удаление запрещено — деактивируйте её, чтобы скрыть.`
            });
        }
        const r = await new sql.Request()
            .input('id', sql.Int, id)
            .query('DELETE FROM EventCategories WHERE id = @id');
        if (r.rowsAffected[0] === 0) return res.status(404).json({ message: 'Категория не найдена.' });

        invalidateCache('event-categories');
        await logAdminEvent('Удаление категории',
            `Администратор ${req.user.fullName} удалил неиспользуемую категорию #${id}.`,
            req.user.id, req.user.fullName);
        res.json({ message: 'Категория удалена.' });
    } catch (err) {
        console.error('Ошибка удаления категории:', err);
        res.status(500).json({ message: 'Не удалось удалить категорию' });
    }
});

/**
 * @openapi
 * /api/admin/users/{id}:
 *   delete:
 *     tags: [Admin]
 *     summary: Soft-delete пользователя
 *     description: |
 *       Помечает пользователя как удалённого (deleted_at = now). Hard-delete не
 *       выполняется никогда — на пользователя ссылаются заявки, комментарии и
 *       история. Удалённый юзер не может войти в систему, не появляется в
 *       выпадающих списках и в админ-таблице (если не запросить ?includeDeleted=true).
 *       Все его исторические данные сохраняются.
 *     parameters:
 *       - { in: path, name: id, required: true, schema: { type: integer } }
 *     responses:
 *       200: { description: 'Пользователь помечен как удалённый' }
 *       403: { description: 'Запрещено: удаление администратора или самого себя' }
 *       404: { description: 'Пользователь не найден' }
 */
app.delete('/api/admin/users/:id', authenticateToken, isAdmin, async (req, res) => {
    const userId = parseInt(req.params.id, 10);
    if (isNaN(userId)) return res.status(400).json({ message: 'Некорректный id.' });
    if (userId === req.user.id) {
        return res.status(403).json({ message: 'Нельзя удалить собственную учётную запись.' });
    }

    try {
        const u = await new sql.Request()
            .input('id', sql.Int, userId)
            .query('SELECT id, full_name, role_id, deleted_at FROM Users WHERE id = @id');
        if (u.recordset.length === 0) return res.status(404).json({ message: 'Пользователь не найден.' });
        if (u.recordset[0].role_id === ROLES.ADMIN) {
            return res.status(403).json({ message: 'Удаление администратора через UI запрещено.' });
        }
        if (u.recordset[0].deleted_at) {
            return res.status(409).json({ message: 'Пользователь уже удалён.' });
        }

        // транзакция UPDATE Users (soft-delete) +
        // UPDATE token_version. Раньше две независимые query — если bumpTokenVersion
        // падал после soft-delete, юзер был помечен deleted_at, но token_version
        // не инкрементнут → активные access-токены жили ещё до 15 мин, удалённый
        // юзер делал API-запросы. WS-revoke и admin-event broadcast выполняются
        // ПОСЛЕ commit (rollback не должен показывать «session revoked» для
        // несостоявшегося delete).
        const transaction = new sql.Transaction();
        let txStarted = false;
        let wsRevoke = null;
        let logBroadcast = null;
        try {
            await transaction.begin();
            txStarted = true;

            // Soft-delete: deleted_at + is_active=0 + сброс refresh-токена.
            await new sql.Request(transaction)
                .input('id', sql.Int, userId)
                .query(`UPDATE Users
                        SET deleted_at = SYSUTCDATETIME(),
                            is_active = 0,
                            refresh_token_hash = NULL
                        WHERE id = @id`);

            // bumpTokenVersionInTx: UPDATE token_version в той же tx + готовит
            // WS-revoke callback (не дёрнет до commit).
            wsRevoke = await bumpTokenVersionInTx(transaction, userId);

            // History (admin-event) тоже в tx — без неё запись о удалении
            // могла не попасть в журнал, нарушив compliance-аудит.
            logBroadcast = await logAdminEventInTx(
                transaction,
                'Удаление пользователя',
                `Администратор ${req.user.fullName} удалил учётную запись ${u.recordset[0].full_name} (ID: ${userId}). Soft-delete: данные сохранены.`,
                req.user.id, req.user.fullName
            );

            await transaction.commit();
            txStarted = false;
        } catch (txErr) {
            if (txStarted) await transaction.rollback().catch(() => {});
            console.error('Транзакция delete-user упала:', txErr);
            return replyOnTxError(res, txErr, 'Не удалось удалить пользователя');
        }

        // POST-COMMIT: WS-revoke + admin-log broadcast.
        try { wsRevoke(); } catch (e) { console.error('wsRevoke failed:', e.message); }
        try { logBroadcast(); } catch (e) { console.error('logBroadcast failed:', e.message); }

        res.json({ message: 'Пользователь удалён. Его данные (заявки, комментарии, история) сохранены.' });
    } catch (err) {
        console.error('Ошибка soft-delete пользователя:', err);
        res.status(500).json({ message: 'Не удалось удалить пользователя' });
    }
});

/**
 * @openapi
 * /api/admin/users/{id}/reset-password:
 *   post:
 *     tags: [Admin]
 *     summary: Сброс пароля пользователя
 *     description: |
 *       Генерирует случайный пароль 14 символов (буквы+цифры+спецсимвол),
 *       сохраняет хеш + обнуляет refresh_token_hash + `bumpTokenVersion` (отзыв
 *       всех живых access-токенов). Новый пароль возвращается ОДИН РАЗ в ответе —
 *       администратор должен передать его юзеру через защищённый канал.
 *       Сброс пароля админа через UI запрещён.
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer }
 *     responses:
 *       200:
 *         description: Пароль сброшен
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:     { type: string }
 *                 newPassword: { type: string, example: 'Xa9R7$pQm2nJk' }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 *       403: { description: 'Запрет: сброс собственного пароля или администратора' }
 *       404: { description: 'Пользователь не найден' }
 */
app.post('/api/admin/users/:id/reset-password', authenticateToken, isAdmin, async (req, res) => {
    const userId = parseInt(req.params.id, 10);
    if (isNaN(userId)) return res.status(400).json({ message: 'Некорректный id.' });
    if (userId === req.user.id) {
        return res.status(403).json({ message: 'Свой пароль меняйте через профиль (не через сброс).' });
    }

    try {
        const u = await new sql.Request()
            .input('id', sql.Int, userId)
            .query('SELECT id, full_name, role_id FROM Users WHERE id = @id');
        if (u.recordset.length === 0) return res.status(404).json({ message: 'Пользователь не найден.' });
        if (u.recordset[0].role_id === ROLES.ADMIN) {
            return res.status(403).json({ message: 'Сброс пароля администратора через UI запрещён.' });
        }

        // Генерация: 14 символов, гарантированно содержит все 4 группы.
        const groups = [
            'ABCDEFGHJKLMNPQRSTUVWXYZ',
            'abcdefghjkmnpqrstuvwxyz',
            '23456789',
            '@$!%*#?&'
        ];
        const all = groups.join('');
        const pickRand = (s) => s[crypto.randomInt(0, s.length)];
        const chars = groups.map(pickRand);
        for (let i = 0; i < 10; i++) chars.push(pickRand(all));
        // Перемешаем безопасным шафлом
        for (let i = chars.length - 1; i > 0; i--) {
            const j = crypto.randomInt(0, i + 1);
            [chars[i], chars[j]] = [chars[j], chars[i]];
        }
        const newPassword = chars.join('');
        const newHash = await bcrypt.hash(newPassword, BCRYPT_COST);

        // транзакция UPDATE password + UPDATE token_version
        // + History. Раньше: UPDATE password успел → bumpTokenVersion упал →
        // 500 → admin не видит newPassword (res.json не дошёл) → юзер заблокирован
        // (старый пароль не работает, нового никто не знает) → DoS на учётку.
        // Теперь rollback откатит UPDATE password, юзер продолжает работать со
        // старым, admin видит 500 и retry'ит.
        const transaction = new sql.Transaction();
        let txStarted = false;
        let wsRevoke = null;
        let logBroadcast = null;
        try {
            await transaction.begin();
            txStarted = true;

            await new sql.Request(transaction)
                .input('id',   sql.Int, userId)
                .input('hash', sql.NVarChar, newHash)
                .query(`UPDATE Users
                        SET password_hash = @hash,
                            refresh_token_hash = NULL,
                            failed_login_count = 0,
                            last_failed_login_at = NULL
                        WHERE id = @id`);

            wsRevoke = await bumpTokenVersionInTx(transaction, userId);

            logBroadcast = await logAdminEventInTx(
                transaction,
                'Сброс пароля',
                `Администратор ${req.user.fullName} сбросил пароль пользователю ${u.recordset[0].full_name} (ID: ${userId}).`,
                req.user.id, req.user.fullName
            );

            await transaction.commit();
            txStarted = false;
        } catch (txErr) {
            if (txStarted) await transaction.rollback().catch(() => {});
            console.error('Транзакция reset-password упала:', txErr);
            return replyOnTxError(res, txErr, 'Не удалось сбросить пароль');
        }

        // POST-COMMIT
        try { wsRevoke(); } catch (e) { console.error('wsRevoke failed:', e.message); }
        try { logBroadcast(); } catch (e) { console.error('logBroadcast failed:', e.message); }

        res.json({ message: 'Пароль сброшен.', newPassword });
    } catch (err) {
        console.error('Ошибка сброса пароля:', err);
        res.status(500).json({ message: 'Не удалось сбросить пароль' });
    }
});


/**
 * @openapi
 * /api/requests:
 *   get:
 *     tags: [Requests]
 *     summary: Пагинированный список заявок (с учётом роли)
 *     description: |
 *       Сотрудник видит только свои заявки. Согласующий видит заявки в
 *       статусах «На согласовании» и более поздних. Модератор и администратор
 *       видят весь корпоративный объём.
 *     parameters:
 *       - { in: query, name: page,         schema: { type: integer, default: 1 } }
 *       - { in: query, name: pageSize,     schema: { type: integer, default: 20 } }
 *       - { in: query, name: search,       schema: { type: string }, description: 'Полнотекстовый поиск по №/названию/описанию/месту/ответственному' }
 *       - { in: query, name: status,       schema: { type: array, items: { type: string } }, style: form, explode: true }
 *       - { in: query, name: authorId,     schema: { type: array, items: { type: integer } }, style: form, explode: true }
 *       - { in: query, name: createdFrom,  schema: { type: string, format: date } }
 *       - { in: query, name: createdTo,    schema: { type: string, format: date } }
 *     responses:
 *       200:
 *         description: Список заявок и метаданные
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 requests:       { type: array, items: { $ref: '#/components/schemas/Request' } }
 *                 totalItems:     { type: integer }
 *                 uniqueCreators: { type: array, items: { type: object } }
 *   post:
 *     tags: [Requests]
 *     summary: Создание новой заявки (с прикреплением файлов через multipart/form-data)
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             allOf:
 *               - $ref: '#/components/schemas/CreateRequest'
 *               - type: object
 *                 properties:
 *                   documentFiles:
 *                     type: array
 *                     items: { type: string, format: binary }
 *     responses:
 *       201: { description: Заявка создана }
 *       400: { description: Ошибка валидации }
 *       403: { description: Файл отклонён политикой безопасности }
 */
app.get('/api/requests', authenticateToken, ipHeavyLimiter, async (req, res) => {
    // Cap'ы pageSize/page: без них EMPLOYEE через ?pageSize=1000000 материализует
    // всю scoped-выборку → memory blow + многосекундный SQL. 200 строк/страницу —
    // больше чем нужно UI (он показывает 20), но честный потолок для batch-действий.
    const page = Math.min(10000, Math.max(1, parseInt(req.query.page, 10) || 1));
    const pageSize = Math.min(200, Math.max(1, parseInt(req.query.pageSize, 10) || 20));
    const offset = (page - 1) * pageSize;
    const {
        search,
        createdFrom,
        createdTo,
        updatedFrom,
        updatedTo
    } = req.query;
    const statuses = Array.isArray(req.query.status) ? req.query.status : (req.query.status ? [req.query.status] : []);
    const authorIds = Array.isArray(req.query.authorId) ? req.query.authorId : (req.query.authorId ? [req.query.authorId] : []);
    // фильтр по категориям. Принимаем массив id'ов
    // через ?categoryId=N (повторяющийся параметр) или ?categoryId[]=N.
    const categoryIds = Array.isArray(req.query.categoryId) ? req.query.categoryId : (req.query.categoryId ? [req.query.categoryId] : []);
    // фильтр по филиалам — только для Admin/Mod/Approver.
    // Для Сотрудника игнорируем (видит только свои заявки, branch-фильтр бессмыслен).
    const branchIds = Array.isArray(req.query.branchId) ? req.query.branchId : (req.query.branchId ? [req.query.branchId] : []);

    // pre-validate date filters → 400 вместо 500 при кривом вводе.
    for (const [field, value] of [['createdFrom', createdFrom], ['createdTo', createdTo],
                                   ['updatedFrom', updatedFrom], ['updatedTo', updatedTo]]) {
        if (!isValidDateFilter(value)) {
            return res.status(400).json({ message: `Некорректная дата в фильтре ${field}.`, field });
        }
    }

    try {
        const {
            role,
            id: userId
        } = req.user;
        const requestPool = new sql.Request();
        const baseQuery = ` FROM Requests r JOIN RequestStatuses rs ON r.status_id = rs.id JOIN Users u ON r.creator_id = u.id LEFT JOIN EventCategories ec ON ec.id = r.category_id `;
        const whereConditions = [];
        requestPool.input('userId', sql.Int, userId);

        const scopeFragment = applyRoleScope(role, userId, requestPool);
        if (scopeFragment) {
            whereConditions.push(scopeFragment);
        } else if (![ROLE_NAMES[ROLES.ADMIN], ROLE_NAMES[ROLES.MODERATOR]].includes(role)) {
            // Неизвестная роль — fallback на «только свои»
            whereConditions.push(`r.creator_id = @userId`);
        }

        if (search) {
            // Если введён только id (число или префикс «#») — точечный поиск,
            // иначе — multi-word smart-search.
            const idMatch = String(search).trim().match(/^#?(\d+)$/);
            if (idMatch) {
                requestPool.input('searchId', sql.Int, parseInt(idMatch[1], 10));
                whereConditions.push('r.id = @searchId');
            } else {
                const cond = buildSearchCondition(requestPool, search, [
                    'r.title', 'r.description', 'r.location', 'r.responsible_person'
                ]);
                if (cond) whereConditions.push(cond);
            }
        }
        if (statuses.length > 0) {
            const statusParams = statuses.map((s, i) => `@status${i}`);
            statuses.forEach((s, i) => requestPool.input(`status${i}`, sql.NVarChar, s));
            whereConditions.push(`rs.name IN (${statusParams.join(',')})`);
        }
        if (authorIds.length > 0) {
            const authorParams = authorIds.map((id, i) => `@authorId${i}`);
            authorIds.forEach((id, i) => requestPool.input(`authorId${i}`, sql.Int, id));
            whereConditions.push(`r.creator_id IN (${authorParams.join(',')})`);
        }
        if (categoryIds.length > 0) {
            const validCatIds = categoryIds
                .map(id => parseInt(id, 10))
                .filter(n => Number.isInteger(n) && n > 0)
                .slice(0, 50);   // защита от gigantic IN-list
            if (validCatIds.length > 0) {
                const catParams = validCatIds.map((id, i) => `@catId${i}`);
                validCatIds.forEach((id, i) => requestPool.input(`catId${i}`, sql.Int, id));
                whereConditions.push(`r.category_id IN (${catParams.join(',')})`);
            }
        }
        // branch-фильтр. Только для Admin/Mod/Approver — Сотрудник
        // видит только свои заявки (creator_id = userId) и фильтр по филиалам
        // ему не нужен. Сотрудник всё равно увидит только свой филиал, поэтому
        // server-side игнорируем его branchId без error'а (не security issue).
        const isPrivilegedRole = [ROLE_NAMES[ROLES.ADMIN], ROLE_NAMES[ROLES.MODERATOR], ROLE_NAMES[ROLES.APPROVER]].includes(role);
        if (branchIds.length > 0 && isPrivilegedRole) {
            const validBranchIds = branchIds
                .map(id => parseInt(id, 10))
                .filter(n => Number.isInteger(n) && n > 0)
                .slice(0, 50);
            if (validBranchIds.length > 0) {
                const branchParams = validBranchIds.map((id, i) => `@brId${i}`);
                validBranchIds.forEach((id, i) => requestPool.input(`brId${i}`, sql.Int, id));
                // Filter по branch'у создателя заявки. JOIN Users u ON r.creator_id=u.id уже есть.
                whereConditions.push(`u.branch_id IN (${branchParams.join(',')})`);
            }
        }
        if (createdFrom) {
            whereConditions.push(`r.created_at >= @createdFrom`);
            requestPool.input('createdFrom', sql.Date, createdFrom);
        }
        if (createdTo) {
            whereConditions.push(`r.created_at <= @createdTo`);
            requestPool.input('createdTo', sql.Date, createdTo);
        }
        if (updatedFrom) {
            whereConditions.push(`r.updated_at >= @updatedFrom`);
            requestPool.input('updatedFrom', sql.Date, updatedFrom);
        }
        if (updatedTo) {
            whereConditions.push(`r.updated_at <= @updatedTo`);
            requestPool.input('updatedTo', sql.Date, updatedTo);
        }

        const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(' AND ')}` : '';
        const countResult = await requestPool.query(`SELECT COUNT(*) as total ${baseQuery} ${whereClause}`);
        const totalItems = countResult.recordset[0].total;

        const unreadActivitySubquery = `
            CASE WHEN EXISTS (
                SELECT 1 FROM History h
                WHERE h.request_id = r.id
                AND h.action NOT IN ('Скачивание файла', 'Новый комментарий', 'Просмотр заявки')
                AND NOT EXISTS (
                    SELECT 1 FROM HistoryReadStatus hrs
                    WHERE hrs.history_id = h.id AND hrs.user_id = @userId
                )
            ) THEN 1 ELSE 0 END`;

        const unreadCommentsSubquery = `
            CASE WHEN EXISTS (
                SELECT 1 FROM Comments c
                WHERE c.request_id = r.id AND c.user_id != @userId AND NOT EXISTS (
                    SELECT 1 FROM CommentReadStatus crs
                    WHERE crs.comment_id = c.id AND crs.user_id = @userId
                )
            ) THEN 1 ELSE 0 END`;

        // OUTER APPLY вместо двух scalar-subqueries в SELECT-листе:
        // план SQL Server склонен превращать subquery-в-select в RID lookup
        // на каждую строку (N seek'ов на N заявок). APPLY заставляет
        // оптимизатор использовать stream-aggregate с index-seek по
        // (request_id) → одно sortless-обращение вместо N.
        const dataQuery = `
            SELECT r.id, r.title, rs.name as status, r.created_at, u.full_name as creator_name, r.creator_id, r.updated_at,
                   r.planned_date, r.category_id, ec.name as category_name, ec.color_hex as category_color,
                   ISNULL(dc.cnt, 0) AS docs_count,
                   ISNULL(cc.cnt, 0) AS comments_count,
                   ${unreadActivitySubquery} AS has_unread_activity,
                   ${unreadCommentsSubquery} AS has_unread_comments
            ${baseQuery}
            OUTER APPLY (SELECT COUNT(*) AS cnt FROM Documents d WHERE d.request_id = r.id) dc
            OUTER APPLY (SELECT COUNT(*) AS cnt FROM Comments  c WHERE c.request_id = r.id) cc
            ${whereClause}
            ORDER BY r.updated_at DESC
            OFFSET ${offset} ROWS FETCH NEXT ${pageSize} ROWS ONLY`;

        const result = await requestPool.query(dataQuery);
        const creatorsResult = await sql.query(`
            SELECT DISTINCT creator_id, u.full_name as creator_name
            FROM Requests JOIN Users u ON Requests.creator_id = u.id
            ORDER BY u.full_name`);

        res.json({
            requests: result.recordset,
            totalItems: totalItems,
            uniqueCreators: creatorsResult.recordset
        });
    } catch (err) {
        console.error('Ошибка получения заявок:', err);
        res.status(500).json({
            message: 'Не удалось загрузить заявки'
        });
    }
});


/* =============================================================================
   Excel-экспорт заявок (xlsx).
   Принимает те же query-параметры, что и /api/requests (search, status, authorId,
   createdFrom/To, updatedFrom/To), но без пагинации — выгружает
   все строки. Уважает scope роли (Сотрудник видит только свои и т.д.).
   ============================================================================= */
/**
 * @openapi
 * /api/requests/export.xlsx:
 *   get:
 *     tags: [Requests]
 *     summary: Экспорт текущего отфильтрованного списка заявок в Excel
 *     description: Принимает те же query-параметры, что и `GET /api/requests`. Без пагинации — отдаёт всё, что подходит под фильтры.
 *     responses:
 *       200:
 *         description: Файл .xlsx
 *         content:
 *           application/vnd.openxmlformats-officedocument.spreadsheetml.sheet:
 *             schema: { type: string, format: binary }
 */
/**
 * @openapi
 * /api/requests/export.xlsx:
 *   get:
 *     tags: [Requests]
 *     summary: Экспорт списка заявок в Excel (.xlsx)
 *     description: |
 *       Применяются те же фильтры что и в `GET /api/requests`. Per-IP rate-limit
 *       100 экспортов / 15 минут (защита от amplification).
 *     parameters:
 *       - in: query
 *         name: search
 *         schema: { type: string }
 *       - in: query
 *         name: statuses
 *         description: 'CSV имён статусов'
 *         schema: { type: string }
 *       - in: query
 *         name: createdFrom
 *         schema: { type: string, format: date }
 *       - in: query
 *         name: createdTo
 *         schema: { type: string, format: date }
 *     responses:
 *       200:
 *         description: Excel-файл
 *         content:
 *           application/vnd.openxmlformats-officedocument.spreadsheetml.sheet:
 *             schema: { type: string, format: binary }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 *       429: { $ref: '#/components/responses/TooManyRequests' }
 */
app.get('/api/requests/export.xlsx', authenticateToken, ipExportLimiter, async (req, res) => {
    const { search, createdFrom, createdTo, updatedFrom, updatedTo } = req.query;
    const statuses = Array.isArray(req.query.status) ? req.query.status : (req.query.status ? [req.query.status] : []);
    const authorIds = Array.isArray(req.query.authorId) ? req.query.authorId : (req.query.authorId ? [req.query.authorId] : []);
    // те же фильтры что в /api/requests.
    const categoryIds = Array.isArray(req.query.categoryId) ? req.query.categoryId : (req.query.categoryId ? [req.query.categoryId] : []);
    const branchIds = Array.isArray(req.query.branchId) ? req.query.branchId : (req.query.branchId ? [req.query.branchId] : []);

    // те же date-фильтры, та же pre-validation что и в /api/requests.
    for (const [field, value] of [['createdFrom', createdFrom], ['createdTo', createdTo],
                                   ['updatedFrom', updatedFrom], ['updatedTo', updatedTo]]) {
        if (!isValidDateFilter(value)) {
            return res.status(400).json({ message: `Некорректная дата в фильтре ${field}.`, field });
        }
    }

    try {
        const { role, id: userId, fullName } = req.user;
        const r = new sql.Request().input('userId', sql.Int, userId);
        const where = [];

        const xlsxScope = applyRoleScope(role, userId, r);
        if (xlsxScope) {
            where.push(xlsxScope);
        } else if (![ROLE_NAMES[ROLES.ADMIN], ROLE_NAMES[ROLES.MODERATOR]].includes(role)) {
            // симметрично с /api/requests — для неизвестной роли fallback
            // на «только свои». Без этого добавление новой роли в БД могло бы
            // молча давать ей полный xlsx-дамп через ничейный applyRoleScope.
            where.push(`r.creator_id = @userId`);
        }

        if (search) {
            const idMatch = String(search).trim().match(/^#?(\d+)$/);
            if (idMatch) {
                r.input('exId', sql.Int, parseInt(idMatch[1], 10));
                where.push('r.id = @exId');
            } else {
                const cond = buildSearchCondition(r, search, [
                    'r.title', 'r.description', 'r.location', 'r.responsible_person'
                ], 'ex');
                if (cond) where.push(cond);
            }
        }
        if (statuses.length) {
            const ps = statuses.map((_, i) => `@s${i}`);
            statuses.forEach((s, i) => r.input(`s${i}`, sql.NVarChar, s));
            where.push(`rs.name IN (${ps.join(',')})`);
        }
        if (authorIds.length) {
            const ps = authorIds.map((_, i) => `@a${i}`);
            authorIds.forEach((a, i) => r.input(`a${i}`, sql.Int, a));
            where.push(`r.creator_id IN (${ps.join(',')})`);
        }
        if (categoryIds.length) {
            const valid = categoryIds.map(id => parseInt(id, 10)).filter(n => Number.isInteger(n) && n > 0).slice(0, 50);
            if (valid.length) {
                const ps = valid.map((_, i) => `@xc${i}`);
                valid.forEach((c, i) => r.input(`xc${i}`, sql.Int, c));
                where.push(`r.category_id IN (${ps.join(',')})`);
            }
        }
        const isPriv = [ROLE_NAMES[ROLES.ADMIN], ROLE_NAMES[ROLES.MODERATOR], ROLE_NAMES[ROLES.APPROVER]].includes(role);
        if (branchIds.length && isPriv) {
            const valid = branchIds.map(id => parseInt(id, 10)).filter(n => Number.isInteger(n) && n > 0).slice(0, 50);
            if (valid.length) {
                const ps = valid.map((_, i) => `@xb${i}`);
                valid.forEach((b, i) => r.input(`xb${i}`, sql.Int, b));
                where.push(`u.branch_id IN (${ps.join(',')})`);
            }
        }
        if (createdFrom) { where.push('r.created_at >= @cf'); r.input('cf', sql.Date, createdFrom); }
        if (createdTo)   { where.push('r.created_at <= @ct'); r.input('ct', sql.Date, createdTo); }
        if (updatedFrom) { where.push('r.updated_at >= @uf'); r.input('uf', sql.Date, updatedFrom); }
        if (updatedTo)   { where.push('r.updated_at <= @ut'); r.input('ut', sql.Date, updatedTo); }

        const whereClause = where.length ? `WHERE ${where.join(' AND ')}` : '';

        const data = await r.query(`
            SELECT r.id, r.title, r.description, r.created_at, r.updated_at, r.planned_date,
                   r.location, r.expected_attendees, r.responsible_person,
                   rs.name AS status_name,
                   u.full_name AS creator_name, b.name AS branch_name,
                   ec.name AS category_name, ec.color_hex AS category_color,
                   ISNULL(dc.cnt, 0) AS docs_count,
                   ISNULL(cc.cnt, 0) AS comments_count
            FROM Requests r
            JOIN RequestStatuses rs ON r.status_id = rs.id
            JOIN Users u ON r.creator_id = u.id
            LEFT JOIN Branches b ON u.branch_id = b.id
            OUTER APPLY (SELECT COUNT(*) AS cnt FROM Documents d WHERE d.request_id = r.id) dc
            OUTER APPLY (SELECT COUNT(*) AS cnt FROM Comments  c WHERE c.request_id = r.id) cc
            LEFT JOIN EventCategories ec ON ec.id = r.category_id
            ${whereClause}
            ORDER BY r.id DESC`);

        const rows = data.recordset;

        // Audit: Excel-выгрузка содержит ФИО + email авторов и ответственных
        // (= ПДн), журналируем доступ.
        auditPiiAccess({
            userId: req.user.id,
            action: 'export_requests_xlsx',
            targetType: 'requests_list',
            ip: req.ip,
            userAgent: req.headers['user-agent'],
            extraMeta: `rows=${rows.length}, search=${search || ''}`
        });

        const wb = new ExcelJS.Workbook();
        wb.creator = 'РУП Витебскэнерго — система согласования заявок';
        wb.created = new Date();

        const ws = wb.addWorksheet('Заявки', {
            views: [{ state: 'frozen', ySplit: 1 }]
        });

        ws.columns = [
            { header: '№',           key: 'id',                width: 6  },
            { header: 'Название',    key: 'title',             width: 40 },
            { header: 'Категория',   key: 'category_name',     width: 22 },
            { header: 'Статус',      key: 'status_name',       width: 18 },
            { header: 'Автор',       key: 'creator_name',      width: 30 },
            { header: 'Филиал',      key: 'branch_name',       width: 25 },
            { header: 'Дата мероп.', key: 'planned_date',      width: 18, style: { numFmt: 'dd.mm.yyyy hh:mm' } },
            { header: 'Место',       key: 'location',          width: 30 },
            { header: 'Участников',  key: 'expected_attendees',width: 12 },
            { header: 'Ответственный', key: 'responsible_person', width: 25 },
            { header: 'Документы',   key: 'docs_count',        width: 11 },
            { header: 'Коммент.',    key: 'comments_count',    width: 11 },
            { header: 'Создана',     key: 'created_at',        width: 18, style: { numFmt: 'dd.mm.yyyy hh:mm' } },
            { header: 'Обновлена',   key: 'updated_at',        width: 18, style: { numFmt: 'dd.mm.yyyy hh:mm' } },
            { header: 'Описание',    key: 'description',       width: 60 }
        ];

        // Заголовок: жирный, белый текст на slate-фоне
        ws.getRow(1).eachCell(cell => {
            cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1E293B' } };
            cell.font = { bold: true, color: { argb: 'FFFFFFFF' }, size: 11 };
            cell.alignment = { vertical: 'middle', horizontal: 'center', wrapText: true };
            cell.border = { bottom: { style: 'medium', color: { argb: 'FF38BDF8' } } };
        });
        ws.getRow(1).height = 26;

        const STATUS_FILL = {
            'Новая':              'FFE0F2FE',
            'На модерации':       'FFFFEDD5',
            'На согласовании':    'FFFEF3C7',
            'Одобрена':           'FFD1FAE5',
            'Отклонена':          'FFFEE2E2',
            'Требует доработки':  'FFFCE7F3'
        };

        // CSV/Formula-injection защита (CWE-1236): Excel выполняет содержимое
        // ячейки как формулу если оно начинается с `=`, `+`, `-`, `@`, `\t`, `\r`.
        // Атакующий, создав заявку с `title = "=cmd|'/c calc.exe'!A1"`, мог бы
        // запустить RCE на машине бухгалтера, открывшего выгрузку.
        // Префикс `'` нейтрализует — Excel не интерпретирует как формулу,
        // саму одинарную кавычку не показывает в ячейке.
        const csvSafe = (v) => {
            if (v === null || v === undefined) return v;
            const s = String(v);
            return /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
        };

        rows.forEach(row => {
            const safeRow = {};
            for (const [k, v] of Object.entries(row)) {
                safeRow[k] = (typeof v === 'string') ? csvSafe(v) : v;
            }
            const added = ws.addRow({
                ...safeRow,
                description: csvSafe((row.description || '').slice(0, 1000))
            });
            // Цветная заливка по статусу
            const fillColor = STATUS_FILL[row.status_name];
            if (fillColor) {
                added.getCell('status_name').fill = {
                    type: 'pattern', pattern: 'solid', fgColor: { argb: fillColor }
                };
            }
            added.alignment = { vertical: 'middle', wrapText: true };
        });

        // Подвал: служебная информация. csvSafe на user-controlled поле
        // (fullName) — defense-in-depth поверх FIO_BAD_CHARS regex (G2):
        // если по какой-то причине в БД попало значение начинающееся с
        // `=`/`+`/`-`/`@` — Excel не выполнит как формулу.
        ws.addRow([]);
        const footerRow = ws.addRow([
            `Сформировано: ${new Date().toLocaleString('ru-RU')}`, '',
            csvSafe(`Пользователь: ${fullName}`), '',
            `Записей: ${rows.length}`
        ]);
        footerRow.font = { italic: true, color: { argb: 'FF64748B' }, size: 10 };

        const filename = `requests-${new Date().toISOString().slice(0, 10)}.xlsx`;
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        await wb.xlsx.write(res);
        res.end();
    } catch (err) {
        console.error('Ошибка экспорта в Excel:', err);
        res.status(500).json({ message: 'Не удалось сформировать файл' });
    }
});


/**
 * @openapi
 * /api/requests/calendar:
 *   get:
 *     tags: [Stats]
 *     summary: События для календаря FullCalendar
 *     description: |
 *       Заявки в виде событий для FullCalendar. Видимость по ролям соответствует
 *       `GET /api/requests`. Дата события — `planned_date`.
 *     parameters:
 *       - in: query
 *         name: from
 *         description: 'Дата начала диапазона (ISO 8601)'
 *         schema: { type: string, format: date-time }
 *       - in: query
 *         name: to
 *         description: 'Дата конца диапазона'
 *         schema: { type: string, format: date-time }
 *     responses:
 *       200:
 *         description: Список событий
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items: { $ref: '#/components/schemas/CalendarEvent' }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 */
app.get('/api/requests/calendar', authenticateToken, async (req, res) => {
    const { from, to } = req.query;
    if (!from || !to) {
        return res.status(400).json({ message: 'Параметры from/to обязательны (ISO-даты).' });
    }
    const fromDate = new Date(from);
    const toDate = new Date(to);
    if (isNaN(fromDate) || isNaN(toDate)) {
        return res.status(400).json({ message: 'Некорректный формат даты.' });
    }
    if ((toDate - fromDate) > 1000 * 60 * 60 * 24 * 366) {
        return res.status(400).json({ message: 'Диапазон не может превышать 12 месяцев.' });
    }

    try {
        const { role, id: userId } = req.user;
        const request = new sql.Request()
            .input('userId', sql.Int, userId)
            .input('fromDate', sql.DateTime2, fromDate)
            .input('toDate', sql.DateTime2, toDate);

        const whereConditions = ['r.planned_date >= @fromDate', 'r.planned_date < @toDate'];

        const calScope = applyRoleScope(role, userId, request);
        if (calScope) {
            whereConditions.push(calScope);
        } else if (![ROLE_NAMES[ROLES.ADMIN], ROLE_NAMES[ROLES.MODERATOR]].includes(role)) {
            whereConditions.push('r.creator_id = @userId');
        }

        const result = await request.query(`
            SELECT r.id, r.title, r.planned_date, r.location, r.expected_attendees,
                   rs.name AS status_name, r.status_id,
                   u.full_name AS creator_name,
                   r.category_id, ec.name AS category_name, ec.color_hex AS category_color
            FROM Requests r
            JOIN RequestStatuses rs ON rs.id = r.status_id
            JOIN Users u ON u.id = r.creator_id
            LEFT JOIN EventCategories ec ON ec.id = r.category_id
            WHERE ${whereConditions.join(' AND ')}
            ORDER BY r.planned_date ASC`);

        res.json(result.recordset);
    } catch (err) {
        console.error('Ошибка получения заявок календаря:', err);
        res.status(500).json({ message: 'Не удалось загрузить календарь.' });
    }
});


app.post('/api/requests', authenticateToken, uploadLimiter, requestCreationLimiter, upload.array('documentFiles', 10), async (req, res) => {
    // idempotency. Если клиент прислал `Idempotency-Key` — проверяем
    // не было ли уже такого запроса. Если был и завершился — отдаём сохранённый
    // ответ, не плодим дубликат заявки. Без header'а ведём себя как раньше.
    const idempKey = await checkIdempotency(req, res);
    if (idempKey === 'sent') return; // ответ уже отправлен (cached / conflict / in-flight)
    let processedFiles = [];
    const transaction = new sql.Transaction();
    // txStarted: rollback() при не-стартовавшей транзакции выбрасывает
    // «Transaction has not begun» — это маскирует исходную ошибку валидации.
    // Флаг даёт rollback'у понять можно ли его вызывать.
    let txStarted = false;
    // E1/H-1: newRequestId объявлен ВНЕ try, чтобы catch имел доступ
    // для partial-response (commit прошёл, post-commit упало → клиент должен
    // знать requestId для отображения в списке).
    let newRequestId;
    try {
        const {
            title,
            description,
            planned_date,
            category_id,
            location,
            expected_attendees,
            responsible_person
        } = req.body;

        if (!title || !planned_date || !category_id || (!description?.trim() && (!req.files || req.files.length === 0))) {
            return res.status(400).json({
                message: "Название, дата, категория и описание (или файл) обязательны."
            });
        }

        // server-side length-caps для title и description. Без cap'ов
        // 250 КБ title попадает в БД (NVARCHAR(255) → mssql truncation 500),
        // в History.details (admin.log bloat), в JSON-ответы list-эндпоинта.
        // Description NVARCHAR(MAX) принимает 2 ГБ, дальше PDF-генерация OOM.
        const titleStr = String(title);
        if (titleStr.trim().length < 3 || titleStr.length > 300) {
            return res.status(400).json({
                message: "Название должно быть от 3 до 300 символов."
            });
        }
        if (description != null && String(description).length > 10000) {
            return res.status(400).json({
                message: "Описание не должно превышать 10 000 символов."
            });
        }

        const parsedCategoryId = parseInt(category_id, 10);
        if (isNaN(parsedCategoryId)) {
            return res.status(400).json({
                message: "Указана некорректная категория мероприятия."
            });
        }

        let parsedAttendees = null;
        if (expected_attendees !== undefined && expected_attendees !== null && String(expected_attendees).trim() !== '') {
            parsedAttendees = parseInt(expected_attendees, 10);
            if (isNaN(parsedAttendees) || parsedAttendees < 1 || parsedAttendees > 100000) {
                return res.status(400).json({
                    message: "Количество участников должно быть положительным целым числом."
                });
            }
        }

        const trimmedLocation = location?.trim() || null;
        if (trimmedLocation && trimmedLocation.length > 255) {
            return res.status(400).json({
                message: "Поле «Место проведения» не должно превышать 255 символов."
            });
        }

        const trimmedResponsible = responsible_person?.trim() || null;
        if (trimmedResponsible && trimmedResponsible.length > 255) {
            return res.status(400).json({
                message: "Поле «Ответственный за проведение» не должно превышать 255 символов."
            });
        }

        processedFiles = await validateAndSaveFiles(req.files, { userId: req.user.id, ip: req.ip || req.socket.remoteAddress });
        await transaction.begin();
        txStarted = true;

        const catCheck = await new sql.Request(transaction)
            .input('cat', sql.Int, parsedCategoryId)
            .query `SELECT 1 AS ok FROM EventCategories WHERE id = @cat AND is_active = 1`;
        if (catCheck.recordset.length === 0) {
            throw new Error('Указанная категория мероприятия не найдена.');
        }

        // Новая заявка стартует в статусе «Новая» (STATUSES.NEW из constants).
        const requestQuery = `
            DECLARE @OutputTbl TABLE (ID INT);
            INSERT INTO Requests (title, description, planned_date, creator_id, status_id, category_id, location, expected_attendees, responsible_person)
            OUTPUT inserted.id INTO @OutputTbl(ID)
            VALUES (@title, @description, @planned_date, @creator_id, ${STATUSES.NEW}, @category_id, @location, @expected_attendees, @responsible_person);
            SELECT ID FROM @OutputTbl;`;

        const requestResult = await new sql.Request(transaction)
            .input('title', sql.NVarChar, title)
            .input('description', sql.NVarChar, description || '')
            .input('planned_date', sql.DateTime2, new Date(planned_date))
            .input('creator_id', sql.Int, req.user.id)
            .input('category_id', sql.Int, parsedCategoryId)
            .input('location', sql.NVarChar, trimmedLocation)
            .input('expected_attendees', sql.Int, parsedAttendees)
            .input('responsible_person', sql.NVarChar, trimmedResponsible)
            .query(requestQuery);

        newRequestId = requestResult.recordset[0].ID;

        if (processedFiles.length > 0) {
            for (const file of processedFiles) {
                await new sql.Request(transaction)
                    .input('request_id', sql.Int, newRequestId)
                    .input('file_name', sql.NVarChar, file.originalname)
                    .input('file_path', sql.NVarChar, file.path)
                    .input('uploaded_by', sql.Int, req.user.id)
                    .input('file_hash', sql.NVarChar, file.hash)
                    .query(`INSERT INTO Documents (request_id, file_name, file_path, uploaded_by, file_hash) VALUES (@request_id, @file_name, @file_path, @uploaded_by, @file_hash)`);
            }
        }
        await transaction.commit();
        // E1/H-1: обязательный сброс txStarted после commit'а.
        // Без него ЛЮБАЯ ошибка ниже (commitWritesAtomically/logAdminEvent/
        // saveIdempotency) попадёт в catch с txStarted=true → попытка rollback
        // зафиксированной транзакции (mssql throw, .catch глотает) + ВЫЗОВ
        // cleanupTempUploads(processedFiles) — а файлы УЖЕ в БД через INSERT
        // Documents. Результат: orphan-ссылки на удалённые файлы.
        txStarted = false;

        // H2/H3: rename всех .tmp → final после успешного commit'а БД.
        // Если упадёт rename — БД уже зафиксирована, файл (с тем же содержимым)
        // лежит как .tmp; janitor подберёт через хеш-сверку. Не падаем здесь.
        await commitWritesAtomically(processedFiles);

        // одна богатая запись вместо двух (trigger дропнут в mig 37).
        await logAdminEvent('Заявка создана', `«${title}» — статус: Новая`, req.user.id, req.user.fullName, newRequestId);
        await broadcastListUpdate(String(newRequestId));
        const successBody = { message: "Заявка успешно создана!", requestId: newRequestId };
        // сохраняем ответ под Idempotency-Key — retry того же ключа в
        // течение TTL (24ч) получит ровно этот же ответ, не создавая дубликата.
        await saveIdempotency(req, idempKey, 201, successBody);
        res.status(201).json(successBody);
    } catch (err) {
        // Откат только если транзакция реально стартовала. Иначе rollback
        // на несуществующей транзакции бросит, маскируя исходную ошибку.
        // E1/H-1: cleanup ТОЖЕ под txStarted-guard. Если commit
        // прошёл (txStarted=false), а потом упал post-commit step — файлы
        // УЖЕ в БД, удалять их нельзя. Janitor разрулит .tmp/final mismatch
        // через 7 дней (хеш-сверка с Documents).
        if (txStarted) {
            await transaction.rollback().catch(rbErr => {
                console.error('Rollback failed (non-fatal):', rbErr.message);
            });
            // H2/H3: чистим временные .tmp-файлы (а заодно final, если уже успели
            // переименоваться через commitWritesAtomically до ошибки). Дубликаты
            // (sha256 совпал с уже существующим) НЕ удаляем — они нужны другим
            // заявкам. cleanupTempUploads пробует оба варианта пути.
            await cleanupTempUploads(processedFiles);
        } else {
            console.error('Post-commit error in POST /api/requests (заявка в БД, файлы НЕ удалены):', err);
        }

        if (err instanceof InvalidFileTypeError) {
            return handleInvalidFileError(err, req, res);
        }
        console.error("Ошибка создания заявки:", err);
        // статичный текст для клиента — `err.message` от mssql может содержать
        // имена indexes / constraints / values (напр. «Violation of UNIQUE KEY ...
        // duplicate key (...)»), что раскрывает схему БД для probing-attack.
        // Полный stack остаётся в console.error для server-side debugging.
        // E1/H-1: если commit прошёл — заявка реально создана, отдаём 201
        // с предупреждением (file-rename / log-event могли не доехать, но
        // основной артефакт есть и юзер должен это видеть).
        if (!txStarted) {
            return res.status(201).json({
                message: 'Заявка создана, но возникла ошибка пост-обработки. Проверьте список заявок.',
                requestId: typeof newRequestId === 'number' ? newRequestId : undefined,
                _partial: true
            });
        }
        res.status(500).json({ message: 'Не удалось создать заявку.' });
    }
});


/**
 * @openapi
 * /api/requests/{id}:
 *   get:
 *     tags: [Requests]
 *     summary: Детали заявки
 *     description: |
 *       Возвращает полные данные заявки. Доступ через `requireAccessToRequest`
 *       (IDOR-guard, 404 при отсутствии доступа). При первом просмотре
 *       логируется в `RequestViewHistory` (dedup-по-юзеру).
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer }
 *     responses:
 *       200:
 *         description: Детали заявки
 *         content: { application/json: { schema: { $ref: '#/components/schemas/RequestDetail' } } }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 *       404: { $ref: '#/components/responses/NotFound' }
 */
app.get('/api/requests/:id', authenticateToken, async (req, res) => {
    const requestId = parseInt(req.params.id, 10);
    const {
        id: userId,
        role,
        fullName
    } = req.user;

    // IDOR-guard: 404 если заявки нет ИЛИ юзеру она не положена.
    // Намеренно одинаковый ответ — чтобы по коду нельзя было определить
    // существование чужой заявки.
    const access = await requireAccessToRequest(requestId, req.user);
    if (!access) {
        return res.status(404).json({ message: 'Заявка не найдена' });
    }

    if (['Администратор', 'Модератор', 'Согласующий'].includes(role)) {
        try {
            const result = await new sql.Request()
                .input('requestId', sql.Int, requestId)
                .input('userId', sql.Int, userId)
                .query(`
                    IF NOT EXISTS (SELECT 1 FROM RequestViewHistory WHERE request_id = @requestId AND user_id = @userId)
                    BEGIN
                        INSERT INTO RequestViewHistory (request_id, user_id) VALUES (@requestId, @userId);
                        SELECT 1 AS WasInserted;
                    END
                    ELSE BEGIN
                        SELECT 0 AS WasInserted;
                    END`);

            if (result.recordset[0].WasInserted === 1) {
                await logAdminEvent('Просмотр заявки', `Пользователем ${fullName}.`, userId, fullName, requestId);
            }
        } catch (viewErr) {
            console.error("Ошибка логирования просмотра заявки:", viewErr);
        }
    }

    try {
        const result = await new sql.Request()
            .input('id', sql.Int, requestId)
            .query `
                SELECT r.*, rs.name as status_name, u.full_name as creator_name, b.name as branch_name,
                       ec.name as category_name, ec.color_hex as category_color
                FROM Requests r
                JOIN RequestStatuses rs ON r.status_id = rs.id
                JOIN Users u ON r.creator_id = u.id
                LEFT JOIN Branches b ON u.branch_id = b.id
                LEFT JOIN EventCategories ec ON ec.id = r.category_id
                WHERE r.id = @id`;
        if (result.recordset.length === 0) {
            return res.status(404).json({
                message: "Заявка не найдена"
            });
        }
        // PII audit: открытие ЧУЖОЙ заявки (заявки содержат creator_id, ФИО,
        // ответственный, описание — это ПДн). Своя — не аудим, иначе шум.
        const row = result.recordset[0];
        if (row.creator_id !== userId) {
            auditPiiAccess({
                userId, action: 'view_request', targetType: 'request', targetId: requestId,
                ip: req.ip, userAgent: req.headers['user-agent'],
                extraMeta: `creator=${row.creator_id}, status=${row.status_name}`
            });
        }
        res.json(row);
    } catch (err) {
        res.status(500).json({
            message: 'Внутренняя ошибка'
        });
    }
});


/**
 * @openapi
 * /api/requests/{id}/status:
 *   put:
 *     tags: [Requests]
 *     summary: Смена статуса заявки (по матрице переходов для текущей роли)
 *     parameters:
 *       - { in: path, name: id, required: true, schema: { type: integer } }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [newStatusId]
 *             properties:
 *               newStatusId: { type: integer, description: '1=Новая, 2=На модерации, 3=На согласовании, 4=Одобрена, 5=Отклонена, 6=Требует доработки, 7=Отозвана (терминальный, доступен только автору из NEW)' }
 *               details:     { type: string,  description: 'Обязательно ≥3 символов при возврате на доработку (статус 6) — становится сообщением в чате заявки' }
 *     responses:
 *       200: { description: 'Статус обновлён' }
 *       400: { description: 'Невалидные данные / нет причины при REWORK' }
 *       403: { description: 'Эта смена статуса запрещена для роли' }
 */
app.put('/api/requests/:id/status', authenticateToken, async (req, res) => {
    const {
        id: requestId
    } = req.params;
    const {
        newStatusId,
        details
    } = req.body;
    const {
        id: userId,
        role,
        fullName
    } = req.user;

    const parsedStatusId = parseInt(newStatusId, 10);
    if (isNaN(parsedStatusId)) {
        return res.status(400).json({
            message: "Некорректный ID статуса."
        });
    }

    try {
        // IDOR-guard: единая 404-политика для несуществующей и недоступной
        // заявки. Без него сотрудник через PUT /:id/status различал
        // «не существует» (404) и «не моя» (403) — enumeration-leak чужих id.
        const access = await requireAccessToRequest(requestId, req.user);
        if (!access) {
            return res.status(404).json({
                message: "Заявка не найдена"
            });
        }
        const { status_id: currentStatusId, creator_id } = access;

        // Матрица переходов теперь в БД (таблица StatusTransitions, миграция 14).
        // Тут проверяем только декларативное правило «можно ли роли R перевести
        // заявку с X на Y». Дополнительное доменное условие — «сотрудник может
        // двигать только свои» — остаётся здесь.
        const roleId = getRoleIdByName(role);
        const allowed = roleId !== null
            && isTransitionAllowed(roleId, currentStatusId, parsedStatusId)
            && !(role === ROLE_NAMES[ROLES.EMPLOYEE] && userId !== creator_id);

        if (!allowed) {
            return res.status(403).json({
                message: "Действие запрещено."
            });
        }

        // При возврате на доработку обязателен текстовый комментарий — это и
        // есть «причина возврата». Без него автору нечего исправлять.
        const isRework = parsedStatusId === STATUSES.REWORK;
        const reworkReason = (details || '').toString().trim();
        if (isRework && reworkReason.length < 3) {
            return res.status(400).json({
                message: "При возврате на доработку обязательно укажите причину (минимум 3 символа)."
            });
        }

        // Бизнес-инвариант: одобрить заявку (APPROVAL → APPROVED) можно только
        // если согласующий приложил подписанный протокол. Юридически
        // «утверждённая» заявка без артефакта-документа не имеет смысла.
        // Проверка дёшево — есть индекс IX_Documents_RequestId.
        //
        // совмещаем check'и в один атомарный UPDATE с EXISTS-подзапросом.
        // Раньше: SELECT протокола → UPDATE статуса в двух разных запросах.
        // Race: между SELECT и UPDATE другой согласующий мог удалить документ →
        // заявка ушла бы в APPROVED без актуального протокола. Теперь EXISTS
        // вычисляется внутри транзакции UPDATE'а — race закрыт. При неудаче
        // различаем «протокол отсутствует» от «статус уже изменён» вторым
        // SELECT'ом для понятного UX.
        const isApprovalToApproved = parsedStatusId === STATUSES.APPROVED && currentStatusId === STATUSES.APPROVAL;

        // атомарность статус-flow. Раньше UPDATE Requests +
        // INSERT History + INSERT Comments (rework-причина) + INSERT Notifications
        // шли как 4 разных query в общем event-loop'е. Если любой из последних
        // трёх падал (CHECK / FK / deadlock) — статус уже сменён, юзер видит
        // grime-state без rationale / уведомлений. Теперь всё в одной tx,
        // с post-commit broadcast'ом (rollback не отправит phantom-WS-events).
        const transaction = new sql.Transaction();
        let txStarted = false;
        const pendingBroadcasts = [];
        let reworkCommentId = null;
        let newStatusName = null;
        try {
            await transaction.begin();
            txStarted = true;

            const updReq = new sql.Request(transaction)
                .input('requestId', sql.Int, parseInt(requestId, 10))
                .input('newStatusId', sql.Int, parsedStatusId)
                .input('expectedFromId', sql.Int, currentStatusId);
            const protoCondition = isApprovalToApproved
                ? `AND EXISTS (SELECT 1 FROM Documents WHERE request_id = @requestId AND is_signed_protocol = 1)`
                : '';
            const upd = await updReq.query(`UPDATE Requests
                        SET status_id = @newStatusId, updated_at = GETUTCDATE()
                        WHERE id = @requestId AND status_id = @expectedFromId ${protoCondition}`);
            if (upd.rowsAffected[0] === 0) {
                await transaction.rollback();
                txStarted = false;
                // Различаем причины: протокол отсутствует или статус успел смениться.
                if (isApprovalToApproved) {
                    const proto = await new sql.Request()
                        .input('rid', sql.Int, parseInt(requestId, 10))
                        .query(`SELECT TOP 1 1 AS x FROM Documents
                                WHERE request_id = @rid AND is_signed_protocol = 1`);
                    if (proto.recordset.length === 0) {
                        return res.status(400).json({
                            message: 'Прежде чем утвердить заявку, прикрепите подписанный протокол.'
                        });
                    }
                }
                return res.status(409).json({
                    message: 'Статус заявки уже изменён другим пользователем. Обновите страницу.'
                });
            }

            const statusResult = await new sql.Request(transaction)
                .input('newStatusId', sql.Int, parsedStatusId)
                .query`SELECT name FROM RequestStatuses WHERE id = @newStatusId`;
            newStatusName = statusResult.recordset[0].name;

            const actionType = 'Смена статуса';
            // details ВСЕГДА содержит имя нового статуса —
            // раньше `details || fallback` перетирал имя статуса, если frontend
            // передавал свой текст (rework-причина, "взята в работу" итд),
            // и лента событий показывала непонятное «Смена статуса: пу-пу-пу».
            // Теперь: «Статус: «<name>». <контекст или ничего>».
            // Для rework — причина НЕ дублируется в feed (она уже идёт
            // отдельным auto-сообщением в чат), только ссылка-подсказка.
            const detailsExtra = (details || '').toString().trim();
            const logDetails = isRework
                ? `Статус: «${newStatusName}». Причина — в сообщении в чате.`
                : (detailsExtra
                    ? `Статус: «${newStatusName}». ${detailsExtra}`
                    : `Статус: «${newStatusName}».`);
            const logBroadcast = await logAdminEventInTx(transaction, actionType, logDetails, userId, fullName, requestId);
            pendingBroadcasts.push(logBroadcast);

            // Если это возврат на доработку — кладём причину отдельным сообщением
            // в чат заявки от имени модератора/согласующего, чтобы автор её увидел
            // в обычной ленте обсуждения, а не «утопил» в системных событиях.
            //
            // формат сообщения = sentinel-prefix + reason.
            // Frontend детектит `__sys__:rework\n` и рендерит как системную
            // event-card (центрированная, без bubble) вместо обычного pop-up.
            // Backwards-compat: старые записи с emoji-префиксом тоже распознаются.
            if (isRework) {
                const reworkText = `__sys__:rework\n${reworkReason}`;
                const cRes = await new sql.Request(transaction)
                    .input('requestId',    sql.Int, parseInt(requestId, 10))
                    .input('userId',       sql.Int, userId)
                    .input('comment_text', sql.NVarChar, reworkText)
                    .query(`
                        DECLARE @Out TABLE (ID INT);
                        INSERT INTO Comments (request_id, user_id, comment_text)
                        OUTPUT INSERTED.id INTO @Out(ID)
                        VALUES (@requestId, @userId, @comment_text);
                        SELECT ID FROM @Out;`);
                reworkCommentId = cRes.recordset[0]?.ID || null;
            }

            // Notifications. Snapshot consistency — выполняем в tx.
            const recipients = await getNotificationRecipients(requestId, userId, transaction);

            const notifType = isRework ? NOTIFICATION_TYPES.RETURNED : NOTIFICATION_TYPES.STATUS_CHANGED;
            const notifMsg = isRework
                ? `${fullName} вернул заявку №${requestId} на доработку: «${reworkReason.length > 80 ? reworkReason.slice(0, 80) + '…' : reworkReason}»`
                : `${fullName} изменил статус заявки №${requestId} на «${newStatusName}»`;
            const notifBroadcast = await createNotificationsInTx(transaction, {
                recipientIds: recipients,
                requestId, actorId: userId,
                type: notifType,
                message: notifMsg
            });
            pendingBroadcasts.push(notifBroadcast);

            await transaction.commit();
            txStarted = false;
        } catch (txErr) {
            if (txStarted) await transaction.rollback().catch(() => {});
            console.error('Транзакция status-change упала:', txErr);
            return replyOnTxError(res, txErr, 'Внутренняя ошибка сервера');
        }

        // === POST-COMMIT: broadcasts. После commit'а и только после него. ===
        // после смены статуса видимость могла измениться — выкорчуем
        // stale-подписки на WS-канал заявки.
        pruneStaleSubscriptionsForRequest(requestId, {
            id: parseInt(requestId, 10),
            creator_id,
            status_id: parsedStatusId,
            status: newStatusName
        });
        broadcastToRequest(String(requestId), {
            type: 'detail_update',
            newCommentId: reworkCommentId
        });
        await broadcastListUpdate(String(requestId));
        for (const fn of pendingBroadcasts) {
            try { fn(); } catch (e) { console.error('post-commit broadcast failed:', e.message); }
        }

        res.json({ message: 'Статус обновлен' });
    } catch (err) {
        console.error('PUT /requests/:id/status outer error:', err);
        res.status(500).json({
            message: 'Внутренняя ошибка сервера'
        });
    }
});


/**
 * Batch-смена статуса для модератора/согласующего/админа.
 * Принимает массив id заявок и новый статус. Атомарно проверяет права на
 * каждую заявку индивидуально (через ту же матрицу переходов, что и singular
 * PUT /api/requests/:id/status). Возвращает per-request результат: что
 * прошло, что отклонено и почему.
 */
/**
 * @openapi
 * /api/requests/batch-status:
 *   post:
 *     tags: [Requests]
 *     summary: Массовая смена статуса (до 100 заявок за один запрос)
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [ids, newStatusId]
 *             properties:
 *               ids:         { type: array, items: { type: integer }, maxItems: 100 }
 *               newStatusId: { type: integer }
 *               details:     { type: string }
 *     responses:
 *       200:
 *         description: Per-request результаты
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:      { type: integer }
 *                 failed:  { type: integer }
 *                 results: { type: array, items: { type: object } }
 */
app.post('/api/requests/batch-status', authenticateToken, async (req, res) => {
    const { ids, newStatusId, details } = req.body || {};
    const { id: userId, role, fullName } = req.user;

    if (!Array.isArray(ids) || ids.length === 0) {
        return res.status(400).json({ message: 'Список id заявок обязателен.' });
    }
    const cleanIds = [...new Set(ids.slice(0, 100).map(x => parseInt(x, 10)).filter(n => Number.isInteger(n) && n > 0))];
    if (cleanIds.length === 0) return res.status(400).json({ message: 'Не передано ни одного валидного id.' });

    const parsedStatusId = parseInt(newStatusId, 10);
    if (isNaN(parsedStatusId)) return res.status(400).json({ message: 'Некорректный newStatusId.' });

    // Batch-возврат на доработку требует общую причину (применяется ко всем).
    const isRework = parsedStatusId === STATUSES.REWORK;
    const reworkReason = (details || '').toString().trim();
    if (isRework && reworkReason.length < 3) {
        return res.status(400).json({ message: 'При возврате на доработку обязательно укажите причину.' });
    }

    // Матрица переходов в БД: проверяем целевой статус среди всех возможных
    // для текущей роли. На уровне индивидуальной заявки в цикле дальше идёт
    // более точная проверка `isTransitionAllowed(role, from, to)`.
    const roleId = getRoleIdByName(role);
    const allTargetsForRole = roleId !== null ? getAllowedTargetsForRole(roleId) : [];
    if (!allTargetsForRole.includes(parsedStatusId)) {
        return res.status(403).json({ message: 'Эта смена статуса недоступна для вашей роли.' });
    }

    try {
        // Загружаем все запрошенные заявки одним запросом
        const reqDb = new sql.Request();
        const idParams = cleanIds.map((id, i) => { reqDb.input(`id${i}`, sql.Int, id); return `@id${i}`; }).join(',');
        const loaded = await reqDb.query(`SELECT id, status_id, creator_id FROM Requests WHERE id IN (${idParams})`);
        const byId = new Map(loaded.recordset.map(r => [r.id, r]));

        const newStatusName = (await new sql.Request()
            .input('s', sql.Int, parsedStatusId)
            .query('SELECT name FROM RequestStatuses WHERE id = @s')).recordset[0]?.name || '';

        const results = [];
        for (const id of cleanIds) {
            const cur = byId.get(id);
            // IDOR-guard: проверяем доступ через canUserSeeRequest на уже
            // загруженных bulk-SELECT'ом данных (не делаем +N селектов).
            // Несуществующий id и недоступный сворачиваем в общий 'forbidden',
            // чтобы перебором нельзя было определить какие чужие id существуют.
            const visible = cur && canUserSeeRequest(req.user, {
                id: cur.id,
                creator_id: cur.creator_id,
                status_id: cur.status_id,
                status: STATUS_NAMES[cur.status_id]
            });
            if (!visible) { results.push({ id, ok: false, reason: 'forbidden' }); continue; }
            const okTransition = isTransitionAllowed(roleId, cur.status_id, parsedStatusId)
                && !(role === ROLE_NAMES[ROLES.EMPLOYEE] && userId !== cur.creator_id);
            if (!okTransition) { results.push({ id, ok: false, reason: 'forbidden_transition' }); continue; }
            if (cur.status_id === parsedStatusId) { results.push({ id, ok: false, reason: 'already_in_status' }); continue; }

            // тот же атомарный UPDATE с EXISTS-подзапросом, что и в singular
            // PUT /:id/status. APPROVAL→APPROVED + наличие протокола проверяется
            // внутри одного UPDATE'а — race с удалением документа закрыт.
            const isApprovalToApprovedBatch = parsedStatusId === STATUSES.APPROVED && cur.status_id === STATUSES.APPROVAL;
            const protoConditionBatch = isApprovalToApprovedBatch
                ? `AND EXISTS (SELECT 1 FROM Documents WHERE request_id = @id AND is_signed_protocol = 1)`
                : '';

            // per-request транзакция в batch. Каждая заявка
            // обрабатывается отдельной tx — если одна упала, остальные не
            // ломаются (что важно для batch-семантики). Внутри tx: UPDATE +
            // History + Comments (rework) + Notifications. Post-commit:
            // pruneStaleSubscriptions + broadcasts.
            const transaction = new sql.Transaction();
            let txStarted = false;
            const pendingBroadcasts = [];
            let reworkCommentId = null;
            try {
                await transaction.begin();
                txStarted = true;

                // Optimistic concurrency: апдейтим только если статус не изменился
                // и (для APPROVAL→APPROVED) подписанный протокол существует.
                const upd = await new sql.Request(transaction)
                    .input('id', sql.Int, id)
                    .input('newStatusId', sql.Int, parsedStatusId)
                    .input('expectedFromId', sql.Int, cur.status_id)
                    .query(`UPDATE Requests SET status_id = @newStatusId, updated_at = GETUTCDATE()
                            WHERE id = @id AND status_id = @expectedFromId ${protoConditionBatch}`);
                if (upd.rowsAffected[0] === 0) {
                    await transaction.rollback();
                    txStarted = false;
                    // Различаем причины: статус сменился vs протокол отсутствует.
                    if (isApprovalToApprovedBatch) {
                        const proto = await new sql.Request()
                            .input('rid', sql.Int, id)
                            .query(`SELECT TOP 1 1 AS x FROM Documents
                                    WHERE request_id = @rid AND is_signed_protocol = 1`);
                        if (proto.recordset.length === 0) {
                            results.push({ id, ok: false, reason: 'no_signed_protocol' });
                            continue;
                        }
                    }
                    results.push({ id, ok: false, reason: 'status_changed' });
                    continue;
                }

                // (см. одиночный flow выше): имя статуса всегда в details,
                // причина rework не дублируется (есть auto-комментарий в чате).
                const logDetails = isRework
                    ? `[batch] Статус: «${newStatusName}». Причина — в сообщении в чате.`
                    : `[batch] Статус: «${newStatusName}».`;
                const logBroadcast = await logAdminEventInTx(transaction, 'Смена статуса', logDetails, userId, fullName, id);
                pendingBroadcasts.push(logBroadcast);

                if (isRework) {
                    // Тот же sentinel-format что и в одиночном flow: `__sys__:rework\n<reason>`.
                    const cRes = await new sql.Request(transaction)
                        .input('requestId',    sql.Int, id)
                        .input('userId',       sql.Int, userId)
                        .input('comment_text', sql.NVarChar, `__sys__:rework\n${reworkReason}`)
                        .query(`
                            DECLARE @Out TABLE (ID INT);
                            INSERT INTO Comments (request_id, user_id, comment_text)
                            OUTPUT INSERTED.id INTO @Out(ID)
                            VALUES (@requestId, @userId, @comment_text);
                            SELECT ID FROM @Out;`);
                    reworkCommentId = cRes.recordset[0]?.ID || null;
                }

                const recipients = await getNotificationRecipients(id, userId, transaction);

                const notifType = isRework ? NOTIFICATION_TYPES.RETURNED : NOTIFICATION_TYPES.STATUS_CHANGED;
                const notifMsg = isRework
                    ? `${fullName} вернул заявку №${id} на доработку: «${reworkReason.length > 80 ? reworkReason.slice(0, 80) + '…' : reworkReason}»`
                    : `${fullName} изменил статус заявки №${id} на «${newStatusName}»`;
                const notifBroadcast = await createNotificationsInTx(transaction, {
                    recipientIds: recipients,
                    requestId: id, actorId: userId,
                    type: notifType,
                    message: notifMsg
                });
                pendingBroadcasts.push(notifBroadcast);

                await transaction.commit();
                txStarted = false;

                // === POST-COMMIT broadcasts ===
                pruneStaleSubscriptionsForRequest(id, {
                    id,
                    creator_id: cur.creator_id,
                    status_id: parsedStatusId,
                    status: newStatusName
                });
                broadcastToRequest(String(id), { type: 'detail_update', newCommentId: reworkCommentId });
                await broadcastListUpdate(String(id));
                for (const fn of pendingBroadcasts) {
                    try { fn(); } catch (e) { console.error('post-commit broadcast failed:', e.message); }
                }

                results.push({ id, ok: true });
            } catch (perErr) {
                if (txStarted) await transaction.rollback().catch(() => {});
                console.error(`Ошибка batch для заявки ${id}:`, perErr);
                // D2/H-4: на deadlock 1205 — batch-семантика отличает
                // ретрайтабельную причину: клиент может повторить целиком батч
                // или фильтровать failed по reason='deadlock' и retry'ить только их.
                const reason = (perErr && (perErr.number === 1205 || perErr.number === 40001))
                    ? 'deadlock'
                    : 'server_error';
                results.push({ id, ok: false, reason });
            }
        }

        const ok = results.filter(r => r.ok).length;
        const failed = results.length - ok;
        res.json({ ok, failed, results });
    } catch (err) {
        console.error('Ошибка batch-status:', err);
        res.status(500).json({ message: 'Ошибка сервера' });
    }
});

/**
 * @openapi
 * /api/requests/{id}/documents:
 *   get:
 *     tags: [Documents]
 *     summary: Список прикреплённых к заявке файлов
 *     description: |
 *       Подписанный протокол (если есть) идёт первым (`is_signed_protocol: true`).
 *       Остальные документы — в порядке загрузки от новых к старым.
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer }
 *     responses:
 *       200:
 *         description: Документы
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items: { $ref: '#/components/schemas/Document' }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 *       404: { $ref: '#/components/responses/NotFound' }
 */
app.get('/api/requests/:id/documents', authenticateToken, async (req, res) => {
    const access = await requireAccessToRequest(req.params.id, req.user);
    if (!access) return res.status(404).json({ message: 'Заявка не найдена' });

    try {
        const result = await new sql.Request()
            .input('request_id', sql.Int, access.id)
            .query(`
                SELECT d.id, d.file_name, d.uploaded_at, u.full_name as uploaded_by_name,
                       d.uploaded_by as uploaded_by_id, d.is_signed_protocol
                FROM Documents d JOIN Users u ON d.uploaded_by = u.id
                WHERE d.request_id = @request_id
                ORDER BY d.is_signed_protocol DESC, d.uploaded_at DESC`);
        res.json(result.recordset);
    } catch (err) {
        res.status(500).json({
            message: "Не удалось загрузить документы"
        });
    }
});


/**
 * @openapi
 * /api/requests/{id}/documents:
 *   post:
 *     tags: [Documents]
 *     summary: Прикрепить документы к заявке (multipart/form-data)
 *     description: |
 *       Загружает один или несколько файлов как обычные документы заявки.
 *       Если query-параметр `signed=true` И роль вызывающего — Согласующий или
 *       Администратор, файл помечается как «подписанный протокол согласования»
 *       (`Documents.is_signed_protocol = 1`) и в UI отображается отдельным
 *       зелёным блоком 📜.
 *     parameters:
 *       - { in: path, name: id, required: true, schema: { type: integer } }
 *       - { in: query, name: signed, schema: { type: boolean }, description: 'Если true — файл = подписанный протокол (только для Согласующего/Админа)' }
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               documentFiles:
 *                 type: array
 *                 items: { type: string, format: binary }
 *     responses:
 *       201: { description: 'Файлы загружены' }
 *       400: { description: 'Не приложено ни одного файла' }
 *       403: { description: 'Файл отклонён политикой безопасности (опасное расширение / mime mismatch)' }
 */
app.post('/api/requests/:id/documents', authenticateToken, uploadLimiter, upload.array('documentFiles', 10), async (req, res) => {
    // IDOR-guard ПЕРВЫМ: иначе 400 «нет файлов» отвечает раньше 404 и
    // leak'ает существование чужой заявки.
    const access = await requireAccessToRequest(req.params.id, req.user);
    if (!access) {
        return res.status(404).json({ message: 'Заявка не найдена' });
    }
    if (!req.files || req.files.length === 0) {
        return res.status(400).json({
            message: 'Файлы не были загружены'
        });
    }
    let processedFiles = [];
    // scope над try/catch — catch handler читает committedFiles чтобы НЕ
    // удалить уже-коммиченные файлы. Если бы переменная жила внутри try,
    // catch бы её не видел.
    const committedFiles = [];
    try {
        processedFiles = await validateAndSaveFiles(req.files, { userId: req.user.id, ip: req.ip || req.socket.remoteAddress });
        const {
            id: requestId
        } = req.params;
        const {
            id: userId,
            fullName,
            role
        } = req.user;

        // Только согласующий или админ может загружать файл с пометкой
        // «подписанный протокол» — реальный сценарий: ген. директор по
        // идеологической работе подписал документ и прикладывает PDF/скан
        // к заявке вместе с одобрением. Дополнительно гейтим по статусу
        // (см. requireSignedProtocolStatus ниже).
        const isSignedProtocol = req.query.signed === 'true' &&
            (role === ROLE_NAMES[ROLES.APPROVER] || role === ROLE_NAMES[ROLES.ADMIN]);

        // ограничение «один файл за signed=true upload». Раньше согласующий
        // мог прислать batch из 10 файлов с ?signed=true и ВСЕ помечались как
        // «подписанный протокол» — UI отображал зелёным блоком 📜 кучу файлов,
        // что бессмысленно (протокол один). Если нужно несколько артефактов
        // — пусть будут грузятся как обычные документы, а protocol — отдельным
        // запросом.
        if (isSignedProtocol && processedFiles.length > 1) {
            await cleanupTempUploads(processedFiles);
            return res.status(400).json({
                message: 'При signed=true можно прикреплять только один файл за раз.'
            });
        }

        // Бизнес-правило: подписанный протокол прикладывается ПОСЛЕ одобрения
        // (статусы «На согласовании» или «Одобрена»). На «Новой»/«Отклонена»
        // /«Отозвана»/«Доработка» — нонсенс, блокируем 400.
        if (isSignedProtocol &&
            access.status_id !== STATUSES.APPROVAL &&
            access.status_id !== STATUSES.APPROVED) {
            return res.status(400).json({
                message: 'Подписанный протокол можно прикреплять только к заявке в статусе «На согласовании» или «Одобрена».'
            });
        }

        const fileNames = processedFiles.map(f => f.originalname).join(', ');
        const actionType = isSignedProtocol ? 'Подписанный протокол' : 'Загрузка файла';
        const logDetails = isSignedProtocol
            ? `Согласующий приложил подписанный протокол: ${fileNames}`
            : `Добавлены файлы: ${fileNames}`;

        // H2/H3: per-file pattern — INSERT в БД autocommit'ится, потом сразу
        // rename `.tmp → final`. Если упадёт INSERT на N-ом файле, первые N-1
        // уже зафиксированы и переименованы, N-й остаётся как `.tmp` → попадёт
        // в catch-cleanup (cleanupTempUploads). Транзакции нет — это by design
        // (handler не атомарный, документы можно прикреплять по одному).
        let skippedDuplicates = 0;
        let signedRejectedByStatus = 0;
        // трекаем какие файлы уже попали в БД и переименовались в финал.
        // catch-cleanup должен НЕ удалять их (там лежат коммиченные документы).
        // committedFiles объявлен ВЫШЕ try/catch (см. начало handler'а).
        for (const file of processedFiles) {
            // для signed-протокола делаем conditional INSERT — INSERT
            // проходит только если статус заявки всё ещё APPROVAL/APPROVED.
            // Раньше: requireAccessToRequest читал статус → INSERT в Documents
            // независимо от того, что произошло между ними. Race: между
            // проверкой и INSERT'ом другой согласующий мог перевести в
            // REJECTED → к отклонённой заявке прилипал «подписанный протокол».
            // Для обычных (signed=false) загрузок такого инварианта нет.
            const insertSql = isSignedProtocol
                ? `INSERT INTO Documents (request_id, file_name, file_path, uploaded_by, file_hash, is_signed_protocol)
                   SELECT @request_id, @file_name, @file_path, @uploaded_by, @file_hash, @is_signed_protocol
                   WHERE EXISTS (SELECT 1 FROM Requests
                                 WHERE id = @request_id
                                   AND status_id IN (${STATUSES.APPROVAL}, ${STATUSES.APPROVED}))`
                : `INSERT INTO Documents (request_id, file_name, file_path, uploaded_by, file_hash, is_signed_protocol)
                   VALUES (@request_id, @file_name, @file_path, @uploaded_by, @file_hash, @is_signed_protocol)`;
            try {
                const ins = await new sql.Request()
                    .input('request_id', sql.Int, requestId)
                    .input('file_name', sql.NVarChar, file.originalname)
                    .input('file_path', sql.NVarChar, file.path)
                    .input('uploaded_by', sql.Int, userId)
                    .input('file_hash', sql.NVarChar, file.hash)
                    .input('is_signed_protocol', sql.Bit, isSignedProtocol ? 1 : 0)
                    .query(insertSql);
                // если signed=true, но conditional EXISTS не сматчил
                // (статус успел смениться) — INSERT прошёл с 0 rowsAffected.
                if (isSignedProtocol && (ins.rowsAffected[0] || 0) === 0) {
                    signedRejectedByStatus++;
                    if (!file.isDuplicate) {
                        try { await fs.unlink(file.absolutePath + '.tmp'); } catch (_) {}
                    }
                    continue;
                }
            } catch (insErr) {
                // 2627/2601 = UNIQUE violation на UQ_Documents_RequestHash.
                // Параллельный запрос успел вставить тот же (request_id, hash)
                // первым. Это race из retry'я / двух вкладок. Пропускаем файл,
                // считаем как duplicate. Физический .tmp выкорчуем — он уже
                // не нужен (БД ссылается на канонический файл первого INSERT'а).
                if (insErr.number === 2627 || insErr.number === 2601) {
                    skippedDuplicates++;
                    if (!file.isDuplicate) {
                        try { await fs.unlink(file.absolutePath + '.tmp'); } catch (_) {}
                    }
                    continue;
                }
                throw insErr;
            }
            // Rename per-file. На дубликатах .tmp не существует — пропускаем.
            if (!file.isDuplicate) {
                try { await fs.rename(file.absolutePath + '.tmp', file.absolutePath); }
                catch (rnErr) { console.error('rename .tmp failed for', file.absolutePath, rnErr.message); }
            }
            // файл закоммичен (INSERT + rename). cleanup в catch не должен
            // его удалять — БД на него ссылается.
            committedFiles.push(file);
        }
        // early-return если ни один файл не закоммитился.
        // ДО фикса: UPDATE updated_at + History + Notifications выполнялись
        // всегда — даже когда все файлы дубликаты / signed-rejected. Юзер
        // получал phantom-broadcast «новый документ» без реального документа.
        // единый guard на «никто не сохранился».
        const totalNotInserted = skippedDuplicates + (isSignedProtocol ? signedRejectedByStatus : 0);
        if (processedFiles.length > 0 && totalNotInserted === processedFiles.length) {
            let msg = 'Ни один файл не был загружен.';
            if (skippedDuplicates === processedFiles.length) {
                msg = 'Все файлы уже были загружены к этой заявке.';
            } else if (isSignedProtocol && signedRejectedByStatus === processedFiles.length) {
                msg = 'Заявка вышла из стадии согласования — подписанный протокол не приложен.';
            }
            return res.status(409).json({ message: msg, skippedDuplicates, signedRejectedByStatus });
        }

        // finalize-часть в одной транзакции. INSERT'ы документов
        // оставлены вне tx (per-file pattern с .tmp→rename — не сочетается с
        // SQL rollback, см. H2/H3). Но UPDATE updated_at + History +
        // Notifications должны быть атомарны: если History упал — нет смысла
        // обновлять updated_at и слать notif о действии, которое не задокументировано.
        const finalizeTx = new sql.Transaction();
        let finalizeStarted = false;
        const pendingBroadcasts = [];
        try {
            await finalizeTx.begin();
            finalizeStarted = true;

            await new sql.Request(finalizeTx)
                .input('id', sql.Int, requestId)
                .query('UPDATE Requests SET updated_at = GETUTCDATE() WHERE id = @id');

            const logBroadcast = await logAdminEventInTx(finalizeTx, actionType, logDetails, userId, fullName, requestId);
            pendingBroadcasts.push(logBroadcast);

            const recipients = await getNotificationRecipients(requestId, userId, finalizeTx);

            const fileWord = processedFiles.length === 1 ? 'документ' : 'документов';
            const msg = `${fullName} добавил ${processedFiles.length} ${fileWord} к заявке №${requestId}`;
            const notifBroadcast = await createNotificationsInTx(finalizeTx, {
                recipientIds: recipients,
                requestId, actorId: userId,
                type: NOTIFICATION_TYPES.NEW_DOCUMENT,
                message: msg
            });
            pendingBroadcasts.push(notifBroadcast);

            await finalizeTx.commit();
            finalizeStarted = false;
        } catch (txErr) {
            if (finalizeStarted) await finalizeTx.rollback().catch(() => {});
            // Файлы УЖЕ закоммичены в Documents (per-file pattern). Даже если
            // finalize-tx упала, БД консистентна — просто updated_at не подёрнут
            // и нет notification. Логируем, отдаём 201 (документы реально есть).
            console.error('Document-upload finalize tx failed:', txErr);
        }

        // POST-COMMIT broadcasts.
        broadcastToRequest(String(requestId), { type: 'detail_update' });
        await broadcastListUpdate(String(requestId));
        for (const fn of pendingBroadcasts) {
            try { fn(); } catch (e) { console.error('post-commit broadcast failed:', e.message); }
        }

        res.status(201).json({
            message: skippedDuplicates > 0
                ? `Файлы загружены (${skippedDuplicates} пропущено как дубликаты).`
                : 'Файлы успешно загружены',
            skippedDuplicates,
            signedRejectedByStatus
        });
    } catch (err) {
        // catch-cleanup НЕ должен трогать файлы, уже попавшие в
        // committedFiles (INSERT + rename прошли — БД ссылается на финал).
        // До исправления `cleanupTempUploads(processedFiles)` для всех 10 файлов
        // ронял также финальные пути первых N коммиченных → орфанные ссылки
        // в БД на удалённые файлы. Теперь чистим только не-коммиченные.
        const committedSet = new Set(committedFiles.map(f => f.absolutePath));
        const toCleanup = processedFiles.filter(f => !committedSet.has(f.absolutePath));
        await cleanupTempUploads(toCleanup);
        if (err instanceof InvalidFileTypeError) {
            return handleInvalidFileError(err, req, res);
        }
        console.error("Ошибка загрузки документов:", err);
        // статичный текст для клиента (см. /api/requests catch).
        res.status(500).json({ message: 'Не удалось загрузить документы.' });
    }
});


/**
 * @openapi
 * /api/documents/{id}/download:
 *   get:
 *     tags: [Documents]
 *     summary: Скачивание одного файла
 *     description: |
 *       Доступ через IDOR-guard: сначала вытаскиваем `request_id` документа,
 *       проверяем доступ юзера к заявке через `requireAccessToRequest`. Если
 *       нет доступа — 404 (намеренно одинаковый код с «нет файла» для anti-enum).
 *       Каждое скачивание логируется в History.
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer }
 *     responses:
 *       200:
 *         description: Файл
 *         content:
 *           application/octet-stream:
 *             schema: { type: string, format: binary }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 *       404: { $ref: '#/components/responses/NotFound' }
 */
app.get('/api/documents/:id/download', authenticateToken, async (req, res) => {
    try {
        const docId = parseInt(req.params.id, 10);
        if (!Number.isInteger(docId) || docId <= 0) {
            return res.status(404).send();
        }
        const result = await new sql.Request()
            .input('id', sql.Int, docId)
            .query('SELECT d.file_name, d.file_path, d.request_id FROM Documents d WHERE d.id = @id');
        if (result.recordset.length === 0) {
            return res.status(404).send();
        }

        const doc = result.recordset[0];
        // IDOR-guard через requireAccessToRequest по request_id документа.
        const access = await requireAccessToRequest(doc.request_id, req.user);
        if (!access) return res.status(404).send();

        await logAdminEvent('Скачивание файла', `Пользователь ${req.user.fullName} скачал файл: "${doc.file_name}"`, req.user.id, req.user.fullName, doc.request_id);
        // PII audit: документ принадлежит конкретной заявке, может содержать
        // личные данные сотрудников (списки участников, сметы и т.п.).
        auditPiiAccess({
            userId: req.user.id,
            action: 'download_document',
            targetType: 'document',
            targetId: parseInt(req.params.id, 10),
            ip: req.ip,
            userAgent: req.headers['user-agent'],
            extraMeta: `request_id=${doc.request_id}, file=${doc.file_name}`
        });

        // doc.file_path — относительный путь. resolveUploadPath гарантирует
        // что результат не покинет UPLOADS_DIR (path traversal defense).
        const absoluteFilePath = resolveUploadPath(doc.file_path);
        if (!absoluteFilePath) {
            return res.status(404).send();
        }
        // res.download сам выставляет Content-Disposition: attachment.
        res.download(absoluteFilePath, doc.file_name, (err) => {
            if (err && !res.headersSent) {
                res.status(500).send();
            }
        });
    } catch (err) {
        if (!res.headersSent) {
            res.status(500).send();
        }
    }
});


/**
 * @openapi
 * /api/documents/download-archive:
 *   get:
 *     tags: [Documents]
 *     summary: Скачать ZIP-архив выбранных документов
 *     description: |
 *       Принимает CSV id'шников документов (`?ids=12,13,14`). Все документы
 *       должны принадлежать одной заявке (защита от cross-request leakage).
 *       Проверка доступа через IDOR-guard на request_id. Лимит 30 файлов.
 *     parameters:
 *       - in: query
 *         name: ids
 *         required: true
 *         description: 'CSV id документов (≤30)'
 *         schema: { type: string, example: '12,13,14' }
 *     responses:
 *       200:
 *         description: ZIP-архив
 *         content:
 *           application/zip:
 *             schema: { type: string, format: binary }
 *       400: { description: 'Документы из разных заявок или некорректный CSV' }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 *       404: { $ref: '#/components/responses/NotFound' }
 */
app.get('/api/documents/download-archive', authenticateToken, async (req, res) => {
    const {
        ids
    } = req.query;
    const documentIds = ids?.split(',').map(id => parseInt(id.trim(), 10)).filter(id => !isNaN(id)) || [];

    if (documentIds.length === 0) {
        return res.status(400).json({
            message: 'ID файлов не указаны'
        });
    }
    // Защита от чрезмерной выборки + DoS через гигантский архив
    if (documentIds.length > 200) {
        return res.status(400).json({
            message: 'Слишком много файлов в одном архиве (макс 200).'
        });
    }
    try {
        const request = new sql.Request();
        const idParameters = documentIds.map((id, i) => `@id${i}`);
        documentIds.forEach((id, i) => request.input(`id${i}`, sql.Int, id));
        const result = await request.query(`SELECT file_name, file_path, request_id FROM Documents WHERE id IN (${idParameters.join(',')})`);

        if (result.recordset.length === 0) {
            return res.status(404).send();
        }

        // IDOR-guard: проверяем доступ к КАЖДОЙ заявке, к которой привязан
        // запрошенный файл. Один отказ = отказ на весь архив (быстрее и
        // безопаснее, чем silent-skip — иначе атакующий через бинарный поиск
        // в id определит границу доступности).
        //
        // batch-проверка доступа одним SELECT'ом + sync canUserSeeRequest.
        // Раньше для архива из 200 файлов с 50 уникальных request_id шло 50
        // sequential SELECT'ов через `requireAccessToRequest` — на холодном
        // pool'е это мог быть существенный hit. Теперь один SELECT вытаскивает
        // status/creator_id для всех уникальных id сразу, дальше pure-function
        // фильтр без I/O.
        const uniqueRequestIds = [...new Set(result.recordset.map(d => d.request_id))];
        if (uniqueRequestIds.length > 0) {
            const accReq = new sql.Request();
            const accParams = uniqueRequestIds.map((id, i) => {
                accReq.input(`r${i}`, sql.Int, id);
                return `@r${i}`;
            }).join(',');
            const accRes = await accReq.query(`
                SELECT r.id, r.creator_id, r.status_id, rs.name AS status
                FROM Requests r JOIN RequestStatuses rs ON rs.id = r.status_id
                WHERE r.id IN (${accParams})`);
            const accRows = new Map(accRes.recordset.map(r => [r.id, r]));
            for (const reqId of uniqueRequestIds) {
                const row = accRows.get(reqId);
                if (!row || !canUserSeeRequest(req.user, row)) {
                    return res.status(404).send();
                }
            }
        }

        const archive = archiver('zip', {
            zlib: {
                level: 9
            }
        });
        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', `attachment; filename="archive-${Date.now()}.zip"`);
        archive.pipe(res);

        for (const doc of result.recordset) {
            const absPath = resolveUploadPath(doc.file_path);
            if (!absPath) continue;   // skip suspicious entry, не падаем
            archive.file(absPath, { name: doc.file_name });
        }
        await archive.finalize();

        await logAdminEvent('Скачивание файла', `Скачан архив из ${result.recordset.length} файлов`, req.user.id, req.user.fullName, result.recordset[0].request_id);
    } catch (err) {
        if (!res.headersSent) {
            res.status(500).send();
        }
    }
});


// PDF-протокол согласования заявки
const { generateProtocolPDF } = require('./pdf/protocol');

/**
 * @openapi
 * /api/requests/{id}/pdf:
 *   get:
 *     tags: [Requests]
 *     summary: PDF-протокол согласования
 *     description: |
 *       Доступ контролируется матрицей `PDF_PROTOCOL_CONFIG` (config/constants.js):
 *         - APPROVAL (`На согласовании`) — «Бланк к подписи» с pre-fill подписанта
 *           (текущий юзер + сегодня). Сотрудник НЕ имеет доступа.
 *         - APPROVED (`Одобрена`) — финальный «Протокол согласования»
 *         - REJECTED (`Отклонена`) — «Протокол отказа»
 *         - Все остальные статусы — 409
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer }
 *     responses:
 *       200:
 *         description: PDF-документ
 *         content:
 *           application/pdf:
 *             schema: { type: string, format: binary }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 *       403: { description: 'Роль не имеет доступа к PDF на этом статусе' }
 *       404: { $ref: '#/components/responses/NotFound' }
 *       409: { description: 'Статус заявки не позволяет генерацию протокола' }
 */
app.get('/api/requests/:id/pdf', authenticateToken, async (req, res) => {
    const requestId = parseInt(req.params.id, 10);
    if (isNaN(requestId)) return res.status(400).json({ message: 'Неверный ID' });

    // IDOR-guard через единый helper. Раньше проверка была: «любой
    // не-Сотрудник видит всё». Это давало Согласующему доступ к PDF
    // заявки в статусе «Новая», что не соответствует canUserSeeRequest.
    const access = await requireAccessToRequest(requestId, req.user);
    if (!access) return res.status(404).json({ message: 'Заявка не найдена' });

    // централизованная access-matrix в config/constants.js.
    // Запрещает PDF для NEW/MODERATION/WITHDRAWN/REWORK (концептуально нет
    // «решения» которое можно зафиксировать — см. PDF_PROTOCOL_CONFIG доку)
    // и для Сотрудника на APPROVAL (бланк к подписи — не для автора).
    // Возвращает isDraft флаг — для APPROVAL PDF идёт с watermark
    // «ПРОЕКТ — НЕ ПОДПИСАН», чтобы распечатку нельзя было выдать за финал.
    const userRoleId = getRoleIdByName(req.user.role);
    const pdfAccess = getPdfProtocolAccess(access.status_id, userRoleId);
    if (!pdfAccess.allowed) {
        if (pdfAccess.reason === 'role_denied_for_status') {
            return res.status(403).json({
                message: 'Просмотр черновика протокола доступен только согласующему и модератору до принятия решения.'
            });
        }
        return res.status(409).json({
            message: 'Протокол доступен только для заявок, прошедших стадию согласования.'
        });
    }

    try {
        // 1. Загружаем полные данные заявки для генерации PDF.
        const reqResult = await new sql.Request()
            .input('id', sql.Int, requestId)
            .query`
                SELECT r.*, rs.name AS status_name, u.full_name AS creator_name, b.name AS branch_name,
                       ec.name AS category_name, ec.color_hex AS category_color
                FROM Requests r
                JOIN RequestStatuses rs ON rs.id = r.status_id
                JOIN Users u ON u.id = r.creator_id
                LEFT JOIN Branches b ON b.id = u.branch_id
                LEFT JOIN EventCategories ec ON ec.id = r.category_id
                WHERE r.id = @id`;

        if (reqResult.recordset.length === 0) {
            return res.status(404).json({ message: 'Заявка не найдена' });
        }
        const requestData = reqResult.recordset[0];

        // 2. Загружаем историю смен статусов (для определения подписантов)
        const histResult = await new sql.Request()
            .input('request_id', sql.Int, requestId)
            .query`
                SELECT h.action, h.details, h.timestamp, u.full_name
                FROM History h
                LEFT JOIN Users u ON h.user_id = u.id
                WHERE h.request_id = @request_id
                  AND h.action = 'Смена статуса'
                ORDER BY h.timestamp ASC`;

        // собираем PDF в Buffer ДО setHeader. Раньше pipe(res) шёл сразу
        // после setHeader → если pdfkit бросал исключение посреди генерации
        // (битый шрифт, переполнение страницы, content-stream error), клиент
        // получал 200 OK + Content-Type: application/pdf + усечённый stream.
        // Теперь любая ошибка генерации даёт чистый 500 с JSON-сообщением.
        // Для «Бланка к подписи» (APPROVAL) PDF делается полноценным с
        // pre-заполненным «потенциальным» подписантом — текущим юзером,
        // открывающим бланк. Согласующий распечатывает уже готовый к подписи
        // документ (ФИО + дата уже стоят), физически расписывается, грузит
        // обратно как signed_protocol. Без watermark — это не черновик,
        // а формальный бланк (рабочий артефакт документооборота).
        const isApprovalBlank = access.status_id === STATUSES.APPROVAL;
        const pdfBuffer = await new Promise((resolve, reject) => {
            const doc = generateProtocolPDF(requestData, histResult.recordset, {
                isDraft: pdfAccess.isDraft,
                // Pre-fill «потенциального» подписанта на APPROVAL: ФИО текущего
                // юзера + сегодняшняя дата. PDF подставит в секцию «Решение»
                // и в строку «Утверждено (согласующий)» если соответствующей
                // записи нет в history.
                presumptiveSigner: isApprovalBlank
                    ? { name: req.user.fullName, date: new Date() }
                    : null
            });
            const chunks = [];
            doc.on('data', chunk => chunks.push(chunk));
            doc.on('error', reject);
            doc.on('end', () => resolve(Buffer.concat(chunks)));
            doc.end();
        });

        const fileSuffix = pdfAccess.isDraft ? '-draft' : '';
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `inline; filename="protocol-${requestId}${fileSuffix}.pdf"`);
        res.setHeader('Cache-Control', 'no-store');
        res.setHeader('Content-Length', pdfBuffer.length);
        res.end(pdfBuffer);

        // 4. Логируем в History. В details — тип (черновик/итоговый) для
        // последующего аудита: «кто и какой документ скачал».
        await logAdminEvent(
            'Печать протокола',
            `Сформирован PDF-протокол заявки № ${requestId} (${pdfAccess.isDraft ? 'черновик: ' + pdfAccess.label : pdfAccess.label}).`,
            req.user.id, req.user.fullName, requestId
        );
    } catch (err) {
        console.error('Ошибка генерации PDF:', err);
        if (!res.headersSent) {
            res.status(500).json({ message: 'Не удалось сформировать PDF' });
        }
    }
});

/**
 * @openapi
 * /api/requests/{id}/history:
 *   get:
 *     tags: [Requests]
 *     summary: Лента событий по заявке
 *     description: |
 *       Все смены статуса, загрузки файлов, просмотры, реакции — упорядочены по
 *       времени. Поле `is_read` отражает прочитано ли событие текущим юзером
 *       (для красной полоски «непрочитанное»).
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer }
 *     responses:
 *       200:
 *         description: Лента событий
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items: { $ref: '#/components/schemas/HistoryItem' }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 *       404: { $ref: '#/components/responses/NotFound' }
 */
app.get('/api/requests/:id/history', authenticateToken, async (req, res) => {
    const access = await requireAccessToRequest(req.params.id, req.user);
    if (!access) return res.status(404).json({ message: 'Заявка не найдена' });

    try {
        const result = await new sql.Request()
            .input('request_id', sql.Int, access.id)
            .input('user_id', sql.Int, req.user.id)
            .query(`
                SELECT h.*, u.full_name,
                       CASE WHEN hrs.id IS NOT NULL THEN 1 ELSE 0 END as is_read
                FROM History h
                LEFT JOIN Users u ON h.user_id = u.id
                LEFT JOIN HistoryReadStatus hrs ON h.id = hrs.history_id AND hrs.user_id = @user_id
                WHERE h.request_id = @request_id AND h.action NOT IN ('Скачивание файла', 'Новый комментарий', 'Просмотр заявки')
                ORDER BY h.timestamp ASC`);
        res.json(result.recordset);
    } catch (err) {
        res.status(500).send();
    }
});


/**
 * @openapi
 * /api/requests/{id}/history/mark-read:
 *   post:
 *     tags: [Requests]
 *     summary: Пометить события заявки как прочитанные
 *     description: |
 *       Bulk-операция: список ID событий, которые юзер увидел (через
 *       IntersectionObserver на фронте). Идемпотентно — повторный mark
 *       уже-прочитанных = no-op.
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [ids]
 *             properties:
 *               ids: { type: array, items: { type: integer }, example: [101, 102, 103] }
 *     responses:
 *       200: { description: 'Помечены прочитанными' }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 *       404: { $ref: '#/components/responses/NotFound' }
 */
app.post('/api/requests/:id/history/mark-read', authenticateToken, async (req, res) => {
    const {
        historyIds
    } = req.body;
    if (!Array.isArray(historyIds) || historyIds.length === 0) {
        return res.status(400).send();
    }

    const access = await requireAccessToRequest(req.params.id, req.user);
    if (!access) return res.status(404).json({ message: 'Заявка не найдена' });

    // Дополнительно отфильтруем historyIds — берём только те, что принадлежат
    // именно этой заявке. Защита от подмены id'шников из чужой заявки.
    const intIds = historyIds.map(x => parseInt(x, 10)).filter(n => Number.isInteger(n) && n > 0);
    if (intIds.length === 0) return res.status(400).send();

    try {
        const reqQ = new sql.Request();
        reqQ.input('request_id', sql.Int, access.id);
        reqQ.input('user_id', sql.Int, req.user.id);
        const placeholders = intIds.map((id, i) => {
            reqQ.input(`hid${i}`, sql.Int, id);
            return `@hid${i}`;
        }).join(',');
        await reqQ.query(`
            INSERT INTO HistoryReadStatus (history_id, user_id)
            SELECT h.id, @user_id FROM History h
            WHERE h.id IN (${placeholders})
              AND h.request_id = @request_id
              AND NOT EXISTS (
                  SELECT 1 FROM HistoryReadStatus hrs
                  WHERE hrs.history_id = h.id AND hrs.user_id = @user_id
              );`);
        res.status(200).send();
    } catch (err) {
        res.status(500).send();
    }
});


/**
 * @openapi
 * /api/requests/{id}/comments:
 *   get:
 *     tags: [Comments]
 *     summary: Список комментариев чата заявки
 *     description: |
 *       Включает reply-цепочку (через `reply_to_id` + поля родителя), реакции
 *       (поле `reactions_raw` парсится на клиенте) и read-receipts (поле `readers`).
 *       Удалённые сообщения возвращаются с `comment_text=null` (плейсхолдер).
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer }
 *     responses:
 *       200:
 *         description: Комментарии
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items: { $ref: '#/components/schemas/Comment' }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 *       404: { $ref: '#/components/responses/NotFound' }
 */
app.get('/api/requests/:id/comments', authenticateToken, async (req, res) => {
    const access = await requireAccessToRequest(req.params.id, req.user);
    if (!access) return res.status(404).json({ message: 'Заявка не найдена' });

    try {
        // Подгружаем reply-цепочку, реакции и read-receipts одним запросом.
        // Контент удалённых комментариев из строки убираем — фронт показывает
        // плейсхолдер «сообщение удалено». Сам факт сообщения сохраняем
        // (важно для подгрузки reply на удалённое родительское).
        const result = await new sql.Request()
            .input('request_id', sql.Int, access.id)
            .query(`
                SELECT c.id, c.user_id, c.created_at, c.edited_at, c.deleted_at,
                       c.reply_to_id,
                       CASE WHEN c.deleted_at IS NULL THEN c.comment_text ELSE NULL END AS comment_text,
                       u.full_name,
                       pc.user_id    AS reply_to_user_id,
                       pu.full_name  AS reply_to_user_name,
                       CASE WHEN pc.deleted_at IS NULL THEN pc.comment_text ELSE NULL END AS reply_to_text,
                       pc.deleted_at AS reply_to_deleted_at,
                       (SELECT STRING_AGG(crs.user_id, ',') FROM CommentReadStatus crs WHERE crs.comment_id = c.id) as readers,
                       (SELECT STRING_AGG(CONCAT(rx.emoji, ':', rx.user_id), ';')
                        FROM CommentReactions rx WHERE rx.comment_id = c.id) AS reactions_raw
                FROM Comments c
                JOIN Users u ON c.user_id = u.id
                LEFT JOIN Comments pc ON pc.id = c.reply_to_id
                LEFT JOIN Users pu    ON pu.id = pc.user_id
                WHERE c.request_id = @request_id
                ORDER BY c.created_at ASC`);
        res.json(result.recordset);
    } catch (err) {
        console.error('Ошибка загрузки комментариев:', err);
        res.status(500).send();
    }
});

/**
 * @openapi
 * /api/comments/{id}/reactions:
 *   post:
 *     tags: [Comments]
 *     summary: Toggle реакции на сообщение
 *     description: |
 *       Если у юзера уже стоит этот emoji на сообщение — он снимается.
 *       Иначе — добавляется. Один пользователь может поставить несколько
 *       разных emoji на одно сообщение.
 *     parameters:
 *       - { in: path, name: id, required: true, schema: { type: integer } }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [emoji]
 *             properties:
 *               emoji: { type: string, enum: ['👍', '❤️', '😂', '😢', '🔥', '👏'] }
 *     responses:
 *       200: { description: 'Реакция обновлена' }
 */
const ALLOWED_REACTIONS = new Set(['👍', '❤️', '😂', '😢', '🔥', '👏']);

/**
 * @openapi
 * /api/comments/{id}/reactions:
 *   post:
 *     tags: [Comments]
 *     summary: Toggle реакции на комментарий
 *     description: |
 *       Если реакции этого юзера с этим emoji ещё нет — добавляем, иначе снимаем
 *       (idempotent toggle). Только из whitelist: 👍 ❤️ 😂 😢 🔥 👏.
 *       Rate-limit: 30 toggle/мин на (user, comment).
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer }
 *     requestBody:
 *       required: true
 *       content: { application/json: { schema: { $ref: '#/components/schemas/ReactionToggle' } } }
 *     responses:
 *       200: { description: 'Реакция установлена/снята' }
 *       400: { description: 'Emoji не в whitelist' }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 *       404: { $ref: '#/components/responses/NotFound' }
 *       429: { $ref: '#/components/responses/TooManyRequests' }
 */
app.post('/api/comments/:id/reactions', authenticateToken, reactionsLimiter, async (req, res) => {
    const commentId = parseInt(req.params.id, 10);
    if (isNaN(commentId)) return res.status(400).json({ message: 'Некорректный id.' });
    const { emoji } = req.body || {};
    if (!ALLOWED_REACTIONS.has(emoji)) {
        return res.status(400).json({ message: 'Недопустимый emoji.' });
    }
    try {
        // Проверяем что комментарий существует и не удалён, и заодно достаём request_id
        // для последующего broadcast'а.
        const c = await new sql.Request()
            .input('id', sql.Int, commentId)
            .query('SELECT request_id, deleted_at FROM Comments WHERE id = @id');
        if (c.recordset.length === 0) return res.status(404).json({ message: 'Сообщение не найдено.' });
        const requestId = c.recordset[0].request_id;

        // IDOR-guard: реагировать на коммент можно только если юзер видит саму
        // заявку. Раньше Сотрудник, угадав id чужого коммента, мог ставить
        // реакции на чужой заявке — искажение метрик + leak факта существования.
        const access = await requireAccessToRequest(requestId, req.user);
        if (!access) return res.status(404).json({ message: 'Сообщение не найдено.' });

        // Терминальные статусы — реакции замораживаются (как и комментарии).
        // Архивная заявка не должна получать новых уведомлений.
        const TERMINAL_R = [STATUSES.APPROVED, STATUSES.REJECTED, STATUSES.WITHDRAWN];
        if (TERMINAL_R.includes(access.status_id) && req.user.role !== ROLE_NAMES[ROLES.ADMIN]) {
            return res.status(409).json({ message: 'Реакции в архивной заявке отключены.' });
        }

        if (c.recordset[0].deleted_at) {
            return res.status(409).json({ message: 'Нельзя реагировать на удалённое сообщение.' });
        }

        // Toggle: если уже есть — убираем, иначе добавляем.
        // UQ_CommentReactions_Triple (mig 20, table-level UNIQUE) делает race-condition безопасным:
        // если между нашим SELECT и INSERT кто-то параллельно вставил ту же
        // запись — мы поймаем 2627 (Violation of UNIQUE) и трактуем как «уже
        // стоит» → DELETE (toggle off). Без UNIQUE могли бы образоваться
        // дубли в БД.
        // атомарный toggle одним SQL-блоком. Раньше SELECT-then-INSERT/DELETE
        // в трёх отдельных запросах создавал нечёткое состояние при retry'е:
        // SELECT exists=0 → T1: INSERT pending → клиент retry'ит → T2:
        // SELECT exists=1 (видит наш INSERT) → DELETE → реакция исчезла, хотя
        // юзер кликнул один раз. Теперь весь toggle + cap-проверка в одном
        // batch'е под XACT_ABORT — операция целиком проваливается или целиком
        // применяется. OUTPUT-таблица возвращает финальный action клиенту.
        const reqDb = new sql.Request()
            .input('cid', sql.Int, commentId)
            .input('uid', sql.Int, req.user.id)
            .input('e',   sql.NVarChar, emoji);
        // WITH (UPDLOCK, HOLDLOCK) на IF EXISTS-проверке
        // сериализует параллельные toggle'ы на ту же тройку (cid, uid, emoji).
        // Раньше под READ COMMITTED две параллельные сессии могли пройти
        // IF EXISTS=0, обе пытаются INSERT, второй падает с UNIQUE-violation
        // (UQ_CommentReactions_Triple) → catch отдаёт generic 500. Теперь
        // первая сессия удерживает range-lock до COMMIT'а, вторая ждёт.
        const toggleResult = await reqDb.query(`
            SET XACT_ABORT ON;
            DECLARE @action NVARCHAR(8) = 'noop';
            BEGIN TRANSACTION;
            IF EXISTS (SELECT 1 FROM CommentReactions WITH (UPDLOCK, HOLDLOCK)
                       WHERE comment_id = @cid AND user_id = @uid AND emoji = @e)
            BEGIN
                DELETE FROM CommentReactions
                WHERE comment_id = @cid AND user_id = @uid AND emoji = @e;
                SET @action = 'removed';
            END
            ELSE
            BEGIN
                -- M8: cap ≤3 разных эмодзи на (user, comment).
                IF (SELECT COUNT(*) FROM CommentReactions
                    WHERE comment_id = @cid AND user_id = @uid) >= 3
                BEGIN
                    SET @action = 'limit';
                END
                ELSE
                BEGIN
                    INSERT INTO CommentReactions (comment_id, user_id, emoji)
                    VALUES (@cid, @uid, @e);
                    SET @action = 'added';
                END
            END
            COMMIT TRANSACTION;
            SELECT @action AS action;
        `);
        const action = toggleResult.recordset[0]?.action;
        if (action === 'limit') {
            return res.status(409).json({
                message: 'Можно поставить не больше 3 разных реакций на одно сообщение.'
            });
        }
        broadcastToRequest(String(requestId), { type: 'detail_update' });
        res.json({ ok: true, action });
    } catch (err) {
        console.error('Ошибка реакции:', err);
        res.status(500).json({ message: 'Не удалось обновить реакцию' });
    }
});

/**
 * Typing-indicator: фронт шлёт WS-сообщение `{type:'typing', requestId}`,
 * а уже broadcast по подписчикам канала request-N в WS.on('message') —
 * там обработчик ниже. Здесь HTTP-эндпоинта нет.
 */


/**
 * @openapi
 * /api/requests/{id}/comments:
 *   post:
 *     tags: [Comments]
 *     summary: Отправить сообщение в чат заявки (опционально как ответ на другое)
 *     parameters:
 *       - { in: path, name: id, required: true, schema: { type: integer } }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [comment_text]
 *             properties:
 *               comment_text: { type: string, minLength: 1 }
 *               reply_to_id:  { type: integer, nullable: true, description: 'id сообщения в этой же заявке, на которое отвечаем' }
 *     responses:
 *       201: { description: Создано }
 */
app.post('/api/requests/:id/comments', authenticateToken, commentCreationLimiter, async (req, res) => {
    const { id: requestId } = req.params;
    const { id: userId, fullName } = req.user;
    const { comment_text, reply_to_id } = req.body;

    // idempotency. Те же гарантии что и у POST /api/requests — двойной
    // submit при флаки сети не плодит дубликат комментария.
    const idempKey = await checkIdempotency(req, res);
    if (idempKey === 'sent') return;

    if (!comment_text || typeof comment_text !== 'string' || !comment_text.trim()) {
        return res.status(400).json({ message: 'Пустое сообщение.' });
    }
    if (comment_text.length > 5000) {
        return res.status(400).json({ message: 'Сообщение слишком длинное (максимум 5000 символов).' });
    }

    const access = await requireAccessToRequest(requestId, req.user);
    if (!access) return res.status(404).json({ message: 'Заявка не найдена' });

    // Терминальные статусы (Утверждена/Отклонена/Отозвана) — заявка закрыта
    // для новых сообщений. Раньше можно было спамить уведомлениями автору
    // после полного завершения процесса. Для админа исключение — он может
    // оставить служебную пометку даже в архивной заявке.
    const TERMINAL_STATUSES = [STATUSES.APPROVED, STATUSES.REJECTED, STATUSES.WITHDRAWN];
    if (TERMINAL_STATUSES.includes(access.status_id) && req.user.role !== ROLE_NAMES[ROLES.ADMIN]) {
        return res.status(409).json({
            message: `Заявка закрыта для комментариев (статус: ${access.status}).`
        });
    }

    let replyToId = null;
    if (reply_to_id !== undefined && reply_to_id !== null && reply_to_id !== '') {
        replyToId = parseInt(reply_to_id, 10);
        if (!Number.isInteger(replyToId) || replyToId <= 0) {
            return res.status(400).json({ message: 'Некорректный reply_to_id.' });
        }
        // reply должен ссылаться на сообщение из этой же заявки (защита от cross-request reply).
        const parent = await new sql.Request()
            .input('parentId',  sql.Int, replyToId)
            .input('requestId', sql.Int, parseInt(requestId, 10))
            .query('SELECT 1 AS x FROM Comments WHERE id = @parentId AND request_id = @requestId');
        if (parent.recordset.length === 0) {
            return res.status(400).json({ message: 'Родительское сообщение не найдено в этой заявке.' });
        }
    }

    // атомарность comment-create. Раньше UPDATE Requests.updated_at
    // выполнялся ДО INSERT Comments — если INSERT падал по trigger из mig 30
    // (cross-request reply check) или CHECK comment_text non-empty — updated_at
    // оставался обновлённым без сообщения. Теперь UPDATE + INSERT + History +
    // Notifications в одной tx. Post-commit broadcasts.
    const transaction = new sql.Transaction();
    let txStarted = false;
    const pendingBroadcasts = [];
    let newCommentId = null;
    try {
        await transaction.begin();
        txStarted = true;

        await new sql.Request(transaction)
            .input('rid', sql.Int, parseInt(requestId, 10))
            .query('UPDATE Requests SET updated_at = GETUTCDATE() WHERE id = @rid');

        const commentQuery = `
            DECLARE @OutputTbl TABLE (ID INT);
            INSERT INTO Comments (request_id, user_id, comment_text, reply_to_id)
            OUTPUT INSERTED.id INTO @OutputTbl(ID)
            VALUES (@requestId, @userId, @comment_text, @reply_to_id);
            SELECT ID FROM @OutputTbl;`;

        const result = await new sql.Request(transaction)
            .input('requestId', sql.Int, parseInt(requestId, 10))
            .input('userId', sql.Int, userId)
            .input('comment_text', sql.NVarChar, comment_text)
            .input('reply_to_id', sql.Int, replyToId)
            .query(commentQuery);

        newCommentId = result.recordset[0].ID;

        const logBroadcast = await logAdminEventInTx(transaction, 'Новый комментарий', comment_text.substring(0, 200), userId, fullName, requestId);
        pendingBroadcasts.push(logBroadcast);

        const recipients = await getNotificationRecipients(requestId, userId, transaction);

        const preview = comment_text.length > 80 ? comment_text.slice(0, 80).trim() + '…' : comment_text;
        const notifBroadcast = await createNotificationsInTx(transaction, {
            recipientIds: recipients,
            requestId, actorId: userId,
            type: NOTIFICATION_TYPES.NEW_COMMENT,
            message: `${fullName} в чате заявки №${requestId}: «${preview}»`
        });
        pendingBroadcasts.push(notifBroadcast);

        await transaction.commit();
        txStarted = false;
    } catch (txErr) {
        if (txStarted) await transaction.rollback().catch(() => {});
        console.error('Транзакция comment-create упала:', txErr);
        // D2/H-4: на 1205 deadlock — 503 + Retry-After. Иначе 500.
        if (txErr && (txErr.number === 1205 || txErr.number === 40001)) {
            res.set('Retry-After', '1');
            return res.status(503).json({ message: 'Временный конфликт транзакции, повторите запрос.' });
        }
        return res.status(500).send();
    }

    // === POST-COMMIT broadcasts ===
    broadcastToRequest(String(requestId), { type: 'detail_update', newCommentId });
    await broadcastListUpdate(String(requestId));
    for (const fn of pendingBroadcasts) {
        try { fn(); } catch (e) { console.error('post-commit broadcast failed:', e.message); }
    }

    const successBody = { newCommentId };
    await saveIdempotency(req, idempKey, 201, successBody);
    res.status(201).json(successBody);
});

/**
 * @openapi
 * /api/comments/{id}:
 *   patch:
 *     tags: [Comments]
 *     summary: Редактирование своего сообщения
 *     description: |
 *       Редактирование разрешено только автору и только пока не прошло 24 часа
 *       с момента отправки. Удалённые сообщения редактировать нельзя.
 *       После успеха выставляется `edited_at`.
 *     parameters:
 *       - { in: path, name: id, required: true, schema: { type: integer } }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [comment_text]
 *             properties:
 *               comment_text: { type: string, maxLength: 5000 }
 *     responses:
 *       200: { description: Обновлено }
 *       403: { description: 'Не автор / окно редактирования закрыто' }
 *   delete:
 *     tags: [Comments]
 *     summary: Удаление своего сообщения (или любого — для админа)
 *     description: 'Soft-delete: проставляется `deleted_at`, текст обнуляется.'
 *     parameters:
 *       - { in: path, name: id, required: true, schema: { type: integer } }
 *     responses:
 *       200: { description: Удалено }
 *       403: { description: 'Только автор или админ' }
 */
app.patch('/api/comments/:id', authenticateToken, async (req, res) => {
    const commentId = parseInt(req.params.id, 10);
    if (isNaN(commentId)) return res.status(400).json({ message: 'Некорректный id.' });

    const { comment_text } = req.body || {};
    if (!comment_text || typeof comment_text !== 'string' || !comment_text.trim()) {
        return res.status(400).json({ message: 'Пустое сообщение.' });
    }
    if (comment_text.length > 5000) {
        return res.status(400).json({ message: 'Сообщение слишком длинное.' });
    }

    try {
        const c = await new sql.Request()
            .input('id', sql.Int, commentId)
            .query('SELECT id, user_id, request_id, created_at, deleted_at FROM Comments WHERE id = @id');
        if (c.recordset.length === 0) return res.status(404).json({ message: 'Сообщение не найдено.' });
        const row = c.recordset[0];

        if (row.user_id !== req.user.id) {
            return res.status(403).json({ message: 'Можно редактировать только свои сообщения.' });
        }
        if (row.deleted_at) {
            return res.status(403).json({ message: 'Удалённое сообщение нельзя редактировать.' });
        }
        // Окно редактирования — 24 часа от создания. Защита от «исторической ревизии».
        const ageHours = (Date.now() - new Date(row.created_at).getTime()) / (1000 * 60 * 60);
        if (ageHours > 24) {
            return res.status(403).json({ message: 'Окно редактирования (24 часа) закрыто. Удалите и напишите заново, если необходимо.' });
        }

        // терминальная заявка immutable. Block E добавил guard
        // только на POST — но edit чужого сообщения через 24-часовое окно
        // тоже переписывает историю архивной заявки.
        // F1/H-2: тот же fix что и DELETE — accessR=null обязан
        // дать 404, иначе guard пропускается на заявках вне role-visibility.
        const accessR = await requireAccessToRequest(row.request_id, req.user);
        if (!accessR) {
            return res.status(404).json({ message: 'Заявка не найдена.' });
        }
        const TERMINAL_E = [STATUSES.APPROVED, STATUSES.REJECTED, STATUSES.WITHDRAWN];
        if (TERMINAL_E.includes(accessR.status_id) && req.user.role !== ROLE_NAMES[ROLES.ADMIN]) {
            return res.status(409).json({ message: 'Заявка закрыта для редактирования сообщений.' });
        }

        await new sql.Request()
            .input('id',   sql.Int, commentId)
            .input('text', sql.NVarChar, comment_text)
            .query('UPDATE Comments SET comment_text = @text, edited_at = SYSUTCDATETIME() WHERE id = @id');

        broadcastToRequest(String(row.request_id), { type: 'detail_update' });
        res.json({ message: 'Обновлено', editedAt: new Date().toISOString() });
    } catch (err) {
        console.error('Ошибка редактирования:', err);
        res.status(500).json({ message: 'Не удалось обновить' });
    }
});

/**
 * @openapi
 * /api/comments/{id}:
 *   delete:
 *     tags: [Comments]
 *     summary: Soft-delete комментария
 *     description: |
 *       Удалить можно только своё сообщение, либо любое — администратору.
 *       На терминальных статусах заявки (Одобрена/Отклонена/Отозвана) даже автор
 *       не может удалить — заявка immutable. Soft-delete: `deleted_at` ставится,
 *       текст обнуляется, реакции чистятся.
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer }
 *     responses:
 *       200: { description: 'Удалено' }
 *       400: { description: 'Некорректный id' }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 *       403: { description: 'Не своё сообщение и не админ' }
 *       404: { $ref: '#/components/responses/NotFound' }
 *       409: { description: 'Уже удалено ИЛИ заявка в терминальном статусе' }
 */
app.delete('/api/comments/:id', authenticateToken, async (req, res) => {
    const commentId = parseInt(req.params.id, 10);
    if (isNaN(commentId)) return res.status(400).json({ message: 'Некорректный id.' });

    try {
        const c = await new sql.Request()
            .input('id', sql.Int, commentId)
            .query('SELECT id, user_id, request_id, deleted_at FROM Comments WHERE id = @id');
        if (c.recordset.length === 0) return res.status(404).json({ message: 'Сообщение не найдено.' });
        const row = c.recordset[0];

        const isOwner = row.user_id === req.user.id;
        const isAdminUser = req.user.role === ROLE_NAMES[ROLES.ADMIN];
        if (!isOwner && !isAdminUser) {
            return res.status(403).json({ message: 'Удалить можно только свои сообщения (админ — любые).' });
        }
        if (row.deleted_at) {
            return res.status(409).json({ message: 'Сообщение уже удалено.' });
        }

        // терминальная заявка immutable. Не-админу нельзя удалять
        // даже свои сообщения в архивной заявке. Админ может — для compliance.
        const accessD = await requireAccessToRequest(row.request_id, req.user);
        // F1/H-2: если у юзера НЕТ доступа к заявке — 404.
        // Раньше `if (accessD && terminal...)` пропускался при `accessD === null`,
        // и не-админ мог удалить свой коммент в WITHDRAWN-заявке (статус не
        // в approverVisibleStatusIds). Plus broadcast уходил на канал заявки,
        // до которой у юзера нет доступа. Админ всегда видит → accessD не null.
        if (!accessD) {
            return res.status(404).json({ message: 'Заявка не найдена.' });
        }
        const TERMINAL_D = [STATUSES.APPROVED, STATUSES.REJECTED, STATUSES.WITHDRAWN];
        if (TERMINAL_D.includes(accessD.status_id) && !isAdminUser) {
            return res.status(409).json({ message: 'Заявка закрыта для удаления сообщений.' });
        }

        // Soft-delete: проставляем deleted_at, текст обнуляем
        // (фронту его всё равно не отдадим — см. SELECT в /comments).
        // чистим реакции на удалённое сообщение. Реакции на placeholder
        // «сообщение удалено» бесполезны (UI их не рендерит для deleted), но
        // SELECT с reactions_raw продолжает их тащить — bandwidth waste.
        // атомарность UPDATE + DELETE через BEGIN TRANSACTION.
        // Раньше два statement'а в одном round-trip'е, но БЕЗ транзакции —
        // SQL Server applied их auto-commit раздельно: UPDATE прошёл, DELETE
        // упал → soft-deleted сообщение с висящими реакциями (UI не рендерит,
        // но bandwidth+disk waste, плюс orphan'ы для cleanup-job'ов).
        await new sql.Request()
            .input('id', sql.Int, commentId)
            .query(`
                SET XACT_ABORT ON;
                BEGIN TRANSACTION;
                UPDATE Comments SET deleted_at = SYSUTCDATETIME(), comment_text = N'' WHERE id = @id;
                DELETE FROM CommentReactions WHERE comment_id = @id;
                COMMIT TRANSACTION;
            `);

        if (isAdminUser && !isOwner) {
            await logAdminEvent(
                'Удаление сообщения',
                `Администратор ${req.user.fullName} удалил сообщение #${commentId}.`,
                req.user.id, req.user.fullName, row.request_id
            );
        }
        broadcastToRequest(String(row.request_id), { type: 'detail_update' });
        res.json({ message: 'Удалено' });
    } catch (err) {
        console.error('Ошибка удаления комментария:', err);
        res.status(500).json({ message: 'Не удалось удалить' });
    }
});

/* =============================================================================
   API уведомлений пользователя.
   - GET    /api/notifications              — пагинированный список
   - GET    /api/notifications/unread-count — только число для bell-badge
   - POST   /api/notifications/mark-read    — отметить набор id как прочитанные
   - POST   /api/notifications/mark-all-read — сбросить все непрочитанные
   ============================================================================= */

/**
 * @openapi
 * /api/notifications:
 *   get:
 *     tags: [Notifications]
 *     summary: Список уведомлений текущего пользователя
 *     parameters:
 *       - { in: query, name: page,       schema: { type: integer, default: 1 } }
 *       - { in: query, name: pageSize,   schema: { type: integer, default: 20, maximum: 50 } }
 *       - { in: query, name: unreadOnly, schema: { type: boolean, default: false } }
 *     responses:
 *       200:
 *         description: Пагинированный список
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 items: { type: array, items: { $ref: '#/components/schemas/Notification' } }
 *                 totalItems: { type: integer }
 *                 page: { type: integer }
 *                 pageSize: { type: integer }
 */
app.get('/api/notifications', authenticateToken, async (req, res) => {
    const page     = Math.max(1, parseInt(req.query.page, 10) || 1);
    const pageSize = Math.min(50, Math.max(1, parseInt(req.query.pageSize, 10) || 20));
    const offset   = (page - 1) * pageSize;
    const unreadOnly = req.query.unreadOnly === 'true';

    try {
        const reqDb = new sql.Request()
            .input('userId',   sql.Int, req.user.id)
            .input('offset',   sql.Int, offset)
            .input('pageSize', sql.Int, pageSize);

        const where = unreadOnly ? 'AND n.is_read = 0' : '';

        const totalRes = await reqDb.query(`
            SELECT COUNT(*) AS total
            FROM Notifications n
            WHERE n.user_id = @userId ${where}`);

        const dataRes = await reqDb.query(`
            SELECT n.id, n.request_id, n.actor_id, n.type, n.message,
                   n.is_read, n.created_at,
                   actor.full_name AS actor_name
            FROM Notifications n
            LEFT JOIN Users actor ON actor.id = n.actor_id
            WHERE n.user_id = @userId ${where}
            ORDER BY n.created_at DESC
            OFFSET @offset ROWS FETCH NEXT @pageSize ROWS ONLY`);

        res.json({
            items: dataRes.recordset,
            totalItems: totalRes.recordset[0].total,
            page, pageSize
        });
    } catch (err) {
        console.error('Ошибка получения уведомлений:', err);
        res.status(500).json({ message: 'Не удалось загрузить уведомления' });
    }
});

/**
 * @openapi
 * /api/notifications/unread-count:
 *   get:
 *     tags: [Notifications]
 *     summary: Количество непрочитанных уведомлений
 *     description: 'Используется для badge на Bell-иконке. Кэшируется на 30с'
 *     responses:
 *       200:
 *         description: Счётчик
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 count: { type: integer, example: 7 }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 */
app.get('/api/notifications/unread-count', authenticateToken, async (req, res) => {
    try {
        const r = await new sql.Request()
            .input('userId', sql.Int, req.user.id)
            .query('SELECT COUNT(*) AS unread FROM Notifications WHERE user_id = @userId AND is_read = 0');
        res.json({ unread: r.recordset[0].unread });
    } catch (err) {
        res.status(500).json({ message: 'Не удалось получить счётчик' });
    }
});

/**
 * @openapi
 * /api/notifications/mark-read:
 *   post:
 *     tags: [Notifications]
 *     summary: Пометить конкретные уведомления как прочитанные
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [ids]
 *             properties:
 *               ids: { type: array, items: { type: integer } }
 *     responses:
 *       200: { description: 'Помечены прочитанными' }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 */
app.post('/api/notifications/mark-read', authenticateToken, async (req, res) => {
    const { ids } = req.body;
    if (!Array.isArray(ids) || ids.length === 0) {
        return res.status(400).json({ message: 'Список id обязателен' });
    }
    // Защита от мусора: ограничиваем размер пакета и фильтруем не-числа.
    const cleanIds = ids.slice(0, 200).map(x => parseInt(x, 10)).filter(n => Number.isInteger(n) && n > 0);
    if (cleanIds.length === 0) return res.json({ ok: true });

    try {
        const reqDb = new sql.Request().input('userId', sql.Int, req.user.id);
        const params = cleanIds.map((id, i) => {
            reqDb.input(`n${i}`, sql.Int, id);
            return `@n${i}`;
        }).join(',');
        await reqDb.query(`
            UPDATE Notifications SET is_read = 1
            WHERE user_id = @userId AND id IN (${params}) AND is_read = 0`);
        // НЕ возвращаем `updated` count — это oracle для существования
        // чужих Notifications.id (sequential int). При передаче 1 чужого id →
        // updated:0; своего непрочитанного → updated:1. Различимое поведение
        // = enumeration leak. Теперь всегда `{ok:true}`. Фронту счётчик
        // непрочитанных он и так получает через GET /unread-count.
        res.json({ ok: true });
    } catch (err) {
        console.error('Ошибка mark-read уведомлений:', err);
        res.status(500).json({ message: 'Не удалось обновить' });
    }
});

/**
 * @openapi
 * /api/notifications/mark-all-read:
 *   post:
 *     tags: [Notifications]
 *     summary: Пометить ВСЕ уведомления текущего юзера как прочитанные
 *     responses:
 *       200: { description: 'Все помечены прочитанными' }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 */
app.post('/api/notifications/mark-all-read', authenticateToken, async (req, res) => {
    try {
        const r = await new sql.Request()
            .input('userId', sql.Int, req.user.id)
            .query('UPDATE Notifications SET is_read = 1 WHERE user_id = @userId AND is_read = 0');
        res.json({ updated: r.rowsAffected[0] || 0 });
    } catch (err) {
        res.status(500).json({ message: 'Не удалось обновить' });
    }
});

/* =============================================================================
   API профиля пользователя.
   - GET  /api/profile/me                — данные текущего юзера + последние входы
   - POST /api/profile/me/password       — смена пароля
   ============================================================================= */

/**
 * @openapi
 * /api/profile/me:
 *   get:
 *     tags: [Profile]
 *     summary: Профиль текущего пользователя + последние 10 входов
 *     responses:
 *       200:
 *         description: Профиль с историей входов
 *         content: { application/json: { schema: { $ref: '#/components/schemas/ProfileMe' } } }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 *       404: { $ref: '#/components/responses/NotFound' }
 */
app.get('/api/profile/me', authenticateToken, async (req, res) => {
    try {
        const u = await new sql.Request()
            .input('userId', sql.Int, req.user.id)
            .query(`
                SELECT u.id, u.full_name, u.email, u.login,
                       u.is_active, u.locked_until,
                       r.name AS role_name, b.name AS branch_name, b.id AS branch_id,
                       (SELECT MIN(login_time) FROM LoginHistory WHERE user_id = u.id) AS first_login_at
                FROM Users u
                JOIN Roles r       ON u.role_id   = r.id
                LEFT JOIN Branches b ON u.branch_id = b.id
                WHERE u.id = @userId`);

        if (u.recordset.length === 0) return res.status(404).json({ message: 'Пользователь не найден' });

        const recent = await new sql.Request()
            .input('userId', sql.Int, req.user.id)
            .query(`
                SELECT TOP 10 login_time, ip_address
                FROM LoginHistory
                WHERE user_id = @userId
                ORDER BY login_time DESC`);

        res.json({
            user: u.recordset[0],
            recentLogins: recent.recordset
        });
    } catch (err) {
        console.error('Ошибка /api/profile/me:', err);
        res.status(500).json({ message: 'Не удалось загрузить профиль' });
    }
});

/**
 * @openapi
 * /api/profile/me/password:
 *   post:
 *     tags: [Profile]
 *     summary: Смена собственного пароля
 *     description: |
 *       Требует подтверждения старого пароля. После смены — bumpTokenVersion
 *       (все живые access-токены этого юзера инвалидируются, кроме текущего —
 *       refresh_token_hash сразу обновляется на новый).
 *     requestBody:
 *       required: true
 *       content: { application/json: { schema: { $ref: '#/components/schemas/ChangePasswordRequest' } } }
 *     responses:
 *       200: { description: 'Пароль успешно изменён' }
 *       400: { description: 'Невалидный новый пароль (длина, состав)' }
 *       401: { description: 'Неверный старый пароль', content: { application/json: { schema: { $ref: '#/components/schemas/Error' } } } }
 */
app.post('/api/profile/me/password', authenticateToken, async (req, res) => {
    const { oldPassword, newPassword } = req.body || {};
    if (!oldPassword || !newPassword) {
        return res.status(400).json({ message: 'Старый и новый пароль обязательны.' });
    }
    // Та же regex-политика что и при создании юзера.
    // upper bound 72. bcrypt усекает пароль на 72 байтах
    // молчаливо — юзер с 100-символьной passphrase реально проверяет первые
    // 72, последние 28 не учитываются. Для русских символов (UTF-8 ~2 байта)
    // лимит 72 байта = ~36 русских chars. Граница 72 chars в regex —
    // консервативно: ASCII-only password ≤72 chars гарантированно <=72 байт.
    // Mixed-charset (русский + латиница) тоже укладывается в большинстве
    // случаев. Если юзер хочет длиннее — explicit error лучше silent truncation.
    const passwordRegex = /^(?=.*[A-Za-zА-Яа-я])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-zА-Яа-я\d@$!%*#?&]{10,72}$/;
    if (!passwordRegex.test(newPassword)) {
        return res.status(400).json({
            message: 'Новый пароль: 10–72 символа, минимум буква, цифра и спецсимвол (@$!%*#?&). Длиннее 72 — bcrypt усекает.'
        });
    }
    if (oldPassword === newPassword) {
        return res.status(400).json({ message: 'Новый пароль не должен совпадать со старым.' });
    }

    try {
        const r = await new sql.Request()
            .input('userId', sql.Int, req.user.id)
            .query('SELECT password_hash FROM Users WHERE id = @userId');
        if (r.recordset.length === 0) return res.status(404).json({ message: 'Пользователь не найден' });

        const ok = await bcrypt.compare(oldPassword, r.recordset[0].password_hash);
        if (!ok) return res.status(403).json({ message: 'Старый пароль введён неверно.' });

        const newHash = await bcrypt.hash(newPassword, BCRYPT_COST);
        // Self-password-change: НЕ вызываем bumpTokenVersion — иначе сервер
        // отправит `auth_revoked` через WS, и наш же фронт сделает logout
        // прямо в момент успешной смены. Стандартный UX (Google/Okta):
        // - текущая сессия остаётся (refresh_token_hash перепишем на новый)
        // - другие сессии: их refresh-токен не пройдёт (hash не совпадёт),
        // access-токены доживут естественные max 15 мин и выкинутся при
        // следующем refresh.
        // Это компромисс между instant-revoke (хорошо для compromise-сценария)
        // и UX (плохо когда юзер сам меняет пароль из настроек).
        const tv = req.user.tv ?? 1;
        const newAccessToken  = signAccess({
            id: req.user.id,
            fullName: req.user.fullName,
            role: req.user.role,
            tv
        });
        const newRefreshToken = signRefresh({ id: req.user.id, tv });
        const newRefreshHash  = crypto.createHash('sha256').update(newRefreshToken).digest('hex');

        await new sql.Request()
            .input('userId', sql.Int, req.user.id)
            .input('hash',   sql.NVarChar, newHash)
            .input('rhash',  sql.NVarChar, newRefreshHash)
            .query(`UPDATE Users
                    SET password_hash = @hash,
                        refresh_token_hash = @rhash
                    WHERE id = @userId`);

        res.cookie('refreshToken', newRefreshToken, REFRESH_COOKIE_OPTS);

        await logAdminEvent('Смена пароля', `Пользователь ${req.user.fullName} сменил собственный пароль.`, req.user.id, req.user.fullName);
        res.json({
            message: 'Пароль обновлён. На других устройствах нужно войти заново.',
            accessToken: newAccessToken
        });
    } catch (err) {
        console.error('Ошибка смены пароля:', err);
        res.status(500).json({ message: 'Не удалось сменить пароль' });
    }
});

// Глобальный error handler. Ловит ошибки multer fileFilter (он вызывает next(err)
// до того как handler роута начнёт работать) и направляет их в нашу security-логику.
app.use(async (err, req, res, next) => {
    if (err instanceof InvalidFileTypeError && req.user) {
        try {
            return await handleInvalidFileError(err, req, res);
        } catch (e) {
            console.error('Ошибка при обработке нарушения загрузки:', e);
            return res.status(500).json({ message: 'Внутренняя ошибка сервера' });
        }
    }
    if (err && err.message === 'File too large') {
        return res.status(413).json({ message: 'Файл превышает максимально допустимый размер 15 МБ.' });
    }
    // body-parser PayloadTooLargeError (express.json limit '256kb') — возвращаем
    // 413 (как клиент ожидает на превышение размера), не 500.
    if (err && (err.type === 'entity.too.large' || err.status === 413)) {
        return res.status(413).json({ message: 'Запрос превышает максимально допустимый размер.' });
    }
    if (err) {
        console.error('Необработанная ошибка middleware:', err);
        return res.status(500).json({ message: 'Внутренняя ошибка сервера' });
    }
    next();
});

/* =============================================================================
   Swagger UI на /api-docs.
   Доступ — только администратору. Браузер не передаёт `Authorization: Bearer`
   на обычный навигационный GET, поэтому используется cookie-авторизация:
     1. Админ через UI запрашивает POST /api/admin/api-docs-session — сервер
        выдаёт короткоживущую (10 мин) httpOnly cookie `docs_session`.
     2. Все запросы на /api-docs/* проверяют эту cookie (а не Bearer).
     3. Если cookie нет — 401 с подсказкой «откройте /api-docs из админ-центра».
   Это пускает Swagger UI работать прямо в браузере, не открывая API
   для случайных юзеров.

   Сырая JSON-спецификация остаётся под Bearer (Postman/Insomnia удобно).
   ============================================================================= */

const DOCS_COOKIE_NAME = 'docs_session';
const DOCS_TOKEN_TTL_MS = 10 * 60 * 1000;

function docsCookieGuard(req, res, next) {
    const token = req.cookies?.[DOCS_COOKIE_NAME];
    if (!token) {
        return res.status(401).type('html').send(`
            <!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8">
            <title>Требуется доступ</title>
            <style>body{font-family:sans-serif;background:#0f172a;color:#f1f5f9;display:grid;place-items:center;min-height:100vh;margin:0}
            .b{max-width:480px;text-align:center;padding:32px;border:1px solid #334155;border-radius:12px;background:#1e293b}
            a{color:#38bdf8}</style></head><body>
            <div class="b"><h1>Документация API</h1>
            <p>Откройте Swagger UI через <a href="/#/admin">админ-центр</a> →
               вкладка «Сводка» → кнопка «API-документация».</p></div></body></html>`);
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET, {
            algorithms: [JWT_ALG],
            issuer: JWT_ISSUER,
            audience: JWT_AUD_DOCS
        });
        if (decoded.purpose !== 'api-docs' || decoded.role !== 'Администратор') {
            return res.status(403).end();
        }
        req.user = decoded;
        next();
    } catch (e) {
        return res.status(401).end();
    }
}

// Эндпоинт: админ получает доступ. Проверяется обычным authenticateToken+isAdmin.
// Cookie выдаётся с `Path=/api-docs/` (со слешом). По RFC 6265 §5.1.4
// cookie-path должен быть префиксом запроса, и если он НЕ оканчивается на `/`,
// то символ после prefix должен быть `/`. Запрос `/api-docs.json` имеет после
// prefix символ `.`, и cookie с `Path=/api-docs` НЕ матчит. Поэтому:
// - cookie Path=/api-docs/ (со слешом)
// - spec моунтится на /api-docs/swagger.json (тоже под /api-docs/)
// - публичный /api-docs.json остаётся под Bearer-only для Postman.
/**
 * @openapi
 * /api/admin/api-docs-session:
 *   post:
 *     tags: [Auth]
 *     summary: Выдача short-lived cookie для доступа к /api-docs UI
 *     description: |
 *       Swagger UI грузится в браузере без Bearer-токена в каждом запросе.
 *       Этот эндпоинт выдаёт короткоживущую (10 мин) httpOnly cookie
 *       `docs_session`, по которой `docsCookieGuard` авторизует запросы
 *       к `/api-docs.json` и статике UI.
 *     responses:
 *       200:
 *         description: Cookie выдана
 *         content: { application/json: { schema: { type: 'object', properties: { message: { type: 'string' } } } } }
 *       401: { $ref: '#/components/responses/Unauthorized' }
 *       403: { $ref: '#/components/responses/Forbidden' }
 */
app.post('/api/admin/api-docs-session', authenticateToken, isAdmin, (req, res) => {
    const token = jwt.sign(
        { id: req.user.id, role: req.user.role, purpose: 'api-docs' },
        process.env.JWT_SECRET,
        {
            expiresIn: '10m',
            algorithm: JWT_ALG,
            issuer: JWT_ISSUER,
            audience: JWT_AUD_DOCS
        }
    );
    res.cookie(DOCS_COOKIE_NAME, token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: DOCS_TOKEN_TTL_MS,
        path: '/api-docs/'
    });
    res.json({ message: 'Сессия Swagger открыта.', expiresIn: DOCS_TOKEN_TTL_MS });
});

// /api-docs.json — публичный endpoint для Postman/Insomnia, только Bearer.
app.get('/api-docs.json', authenticateToken, isAdmin, (req, res) => {
    res.json(swaggerSpec);
});

// /api-docs/swagger.json — путь под cookie-сессию (для самого Swagger UI).
app.get('/api-docs/swagger.json', docsCookieGuard, (req, res) => {
    res.json(swaggerSpec);
});

app.use(
    '/api-docs',
    docsCookieGuard,
    swaggerUi.serve,
    swaggerUi.setup(swaggerSpec, {
        customSiteTitle: 'VitEnergo API',
        customCss: '.topbar { display: none }',
        // Подсовываем UI URL spec'а под тем же путём, что покрывает cookie.
        swaggerUrl: '/api-docs/swagger.json',
        swaggerOptions: { docExpansion: 'none', persistAuthorization: true }
    })
);

/**
 * @openapi
 * /api/public/events:
 *   get:
 *     tags: [Reference]
 *     summary: Публичный список одобренных мероприятий (текущих и архивных)
 *     description: |
 *       Доступен без аутентификации — отображается на публичной витрине /events.
 *       Возвращает только заявки в статусе «Одобрена». Чувствительные поля
 *       (создатель, описание, ответственный) скрыты — только название, дата,
 *       место, категория, филиал.
 *
 *       По умолчанию — будущие мероприятия (с сегодняшнего дня вперёд).
 *       `?archive=true` — прошедшие за последние 12 месяцев, по убыванию даты.
 *     security: []
 *     parameters:
 *       - in: query
 *         name: archive
 *         schema: { type: boolean, default: false }
 *         description: 'true = вернуть архив (прошедшие за последние 12 месяцев)'
 *     responses:
 *       200:
 *         description: Массив одобренных мероприятий
 */
app.get('/api/public/events', async (req, res) => {
    try {
        // ?archive=true → вернуть прошедшие мероприятия (последние
        // 12 месяцев, по убыванию даты). По умолчанию — только будущие.
        // Кэш отдельный по режиму, чтобы archive не «отравил» upcoming.
        const archive = req.query.archive === 'true';
        const cacheKey = archive ? 'public-events-archive' : 'public-events';
        const data = await cached(cacheKey, 5 * 60 * 1000, async () => {
            // created_at нужен фронту для «Новое» badge (Раунд 11): события,
            // одобренные недавно, помечаются — обращает внимание посетителя.
            const r = archive
                ? await sql.query`
                    SELECT TOP 100
                           r.id, r.title, r.planned_date, r.location, r.expected_attendees,
                           r.created_at,
                           ec.name      AS category_name,
                           ec.color_hex AS category_color,
                           b.name       AS branch_name
                    FROM Requests r
                    LEFT JOIN EventCategories ec ON ec.id = r.category_id
                    JOIN Users u ON u.id = r.creator_id
                    LEFT JOIN Branches b ON b.id = u.branch_id
                    WHERE r.status_id = ${STATUSES.APPROVED}
                      AND r.planned_date < SYSUTCDATETIME()
                      AND r.planned_date >= DATEADD(MONTH, -12, SYSUTCDATETIME())
                    ORDER BY r.planned_date DESC`
                : await sql.query`
                    SELECT TOP 50
                           r.id, r.title, r.planned_date, r.location, r.expected_attendees,
                           r.created_at,
                           ec.name      AS category_name,
                           ec.color_hex AS category_color,
                           b.name       AS branch_name
                    FROM Requests r
                    LEFT JOIN EventCategories ec ON ec.id = r.category_id
                    JOIN Users u ON u.id = r.creator_id
                    LEFT JOIN Branches b ON b.id = u.branch_id
                    WHERE r.status_id = ${STATUSES.APPROVED}
                      AND r.planned_date >= SYSUTCDATETIME()
                    ORDER BY r.planned_date ASC`;
            return r.recordset;
        });
        res.set('Cache-Control', 'public, max-age=300');
        res.json(data);
    } catch (err) {
        console.error('Ошибка /api/public/events:', err);
        res.status(500).json({ message: 'Не удалось загрузить мероприятия' });
    }
});

/**
 * @openapi
 * /api/health:
 *   get:
 *     tags: [Health]
 *     summary: Проверка работоспособности сервера, БД, пула, WebSocket
 *     security: []
 *     responses:
 *       200:
 *         description: Все компоненты работают
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:    { type: string, example: ok }
 *                 uptime:    { type: number, description: 'секунд с момента старта процесса' }
 *                 db:        { type: string, example: ok }
 *                 pool:      { type: object, description: 'статистика SQL-пула (size/available/borrowed/pending)' }
 *                 wss:       { type: object, description: 'статистика WebSocket: количество активных клиентов' }
 *                 memory:    { type: object, description: 'rss/heapUsed/heapTotal в МБ' }
 *                 timestamp: { type: string, format: date-time }
 *       503:
 *         description: Один из компонентов недоступен
 */
app.get('/api/health', async (req, res) => {
    // M-2: расширенный health для мониторинга прода. Smoke-эндпоинт
    // должен показывать не только «БД отвечает», но и реальные метрики:
    // утечка пула (borrowed растёт без освобождения) и WS-фантомы (clients.size
    // растёт после disconnect'ов) — частые причины деградации, которые точечно
    // ловятся только через такие счётчики. Память — для раннего обнаружения
    // утечек heap.
    let dbOk = false;
    try {
        await new sql.Request().query('SELECT 1 AS x');
        dbOk = true;
    } catch (e) { /* БД недоступна */ }

    // Pool stats: mssql экспонирует tarn-пул через sql.pool / globalPool.
    // Защищаемся try-блоком: API мог измениться в будущих major-версиях.
    let pool = null;
    try {
        if (dbPool) {
            pool = {
                size:      typeof dbPool.size === 'number' ? dbPool.size : null,
                available: typeof dbPool.available === 'number' ? dbPool.available : null,
                borrowed:  typeof dbPool.borrowed === 'number' ? dbPool.borrowed : null,
                pending:   typeof dbPool.pending === 'number' ? dbPool.pending : null
            };
        }
    } catch (_) { /* ignore */ }

    // WSS clients: wss.clients — Set активных соединений.
    let wssStats = null;
    try {
        wssStats = { clients: wss?.clients?.size ?? null };
    } catch (_) { /* ignore */ }

    // Memory: значения в МБ для читабельности dashboard'ов.
    const mem = process.memoryUsage();
    const memoryMb = {
        rss:       Math.round(mem.rss / 1024 / 1024),
        heapUsed:  Math.round(mem.heapUsed / 1024 / 1024),
        heapTotal: Math.round(mem.heapTotal / 1024 / 1024)
    };

    res.status(dbOk ? 200 : 503).json({
        status:    dbOk ? 'ok' : 'degraded',
        uptime:    Math.round(process.uptime()),
        db:        dbOk ? 'ok' : 'down',
        pool,
        wss:       wssStats,
        memory:    memoryMb,
        timestamp: new Date().toISOString()
    });
});

app.use((req, res, next) => {
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({
            message: 'Эндпоинт не найден'
        });
    }
    if (req.method === 'GET') {
        // Запросы на статические файлы по расширению, которые не нашлись (например, .js.map от DevTools),
        // — отдаём 404 без подмены на HTML, иначе будет stack trace в логах.
        if (/\.(map|ico|png|jpe?g|gif|svg|webp|woff2?|ttf|otf|eot|css|js|mjs|json|txt|xml|pdf)$/i.test(req.path)) {
            return res.status(404).end();
        }
        // Корень — отдаём SPA shell. Любой другой путь — кастомная 404 страница.
        // root-форма sendFile — см. комментарий у /login: обходит dotfile-guard
        // в send 1.x для путей с `.claude` в __dirname.
        if (req.path === '/' || req.path === '') {
            return res.sendFile('index.html', { root: PUBLIC_ROOT }, (err) => {
                if (err && !res.headersSent) res.status(404).end();
            });
        }
        return res.status(404).sendFile('404.html', { root: PUBLIC_ROOT });
    }
    next();
});

/* =============================================================================
   WebSocket-аутентификация.
   Токен НЕ передаётся через query string — он попал бы в access-логи прокси
   (nginx/IIS). Вместо этого:
     1. Клиент открывает соединение БЕЗ токена.
     2. Первым WS-сообщением шлёт `{ type: 'auth', token: '<JWT>' }`.
     3. Сервер либо принимает (ставит ws.user, шлёт `{type:'auth_ok'}`),
        либо закрывает с кодом 1008 'Authentication failed'.
     4. До успешного auth — все остальные сообщения игнорируются.
     5. На auth даётся 5 секунд от момента подключения. Иначе close 1008.
   ============================================================================= */

const WS_AUTH_GRACE_MS = 5000;

// ограничение одновременных НЕаутентифицированных WS-подключений с одного IP.
// Бот без валидного JWT не может больше зарезервировать N сокетов и держать
// их 5-секундный grace, ел RAM и file descriptor'ы. Авторизованные коннекшны
// этим лимитом не считаются — они уже идентифицированы по token_version.
const MAX_UNAUTH_WS_PER_IP = 5;
const _unauthWsByIp = new Map(); // ip → live count

// per-user post-auth cap. До закрытия H10 один авторизованный юзер мог
// открыть unlimited WS (после auth счётчик _unauthWsByIp его не считает).
// Скомпрометированный аккаунт → 10к WS = FD exhaustion. 5 параллельных WS
// на юзера хватает: основной таб + ещё пару разных вкладок/устройств.
const MAX_AUTH_WS_PER_USER = 5;
const _authWsByUser = new Map(); // userId → live count

// per-connection token bucket на любые WS-сообщения. Защита от flood'а
// 64 КБ × N msg/sec — handler работа + JSON.parse + возможные DB-запросы
// (например в messages_read). 30 msgs/sec в ширину 1 сек скользящее окно —
// больше чем нормальный клиент когда-либо посылает (обычно <1/сек).
const WS_MSG_BUDGET_PER_SEC = 30;

// per-connection cooldown на typing. Клиентский debounce 3 сек злоумышленник
// игнорирует. Серверный 1.5 сек — ниже клиентского, но любая попытка флудить
// 1000/сек typing'ом дропается на сервере без broadcast'а.
const WS_TYPING_COOLDOWN_MS = 1500;
// per-connection cooldown на messages_read. 200 ids в одном сообщении →
// до 200 INSERT statement'ов; 100 запросов/сек = 20k INSERTs/сек = DoS на БД.
const WS_MSG_READ_COOLDOWN_MS = 200;

wss.on('connection', (ws, req) => {
    const ip = req.socket?.remoteAddress || 'unknown';
    ws._ip = ip;

    // квота на анонимные коннекшны с этого IP.
    const unauthCount = (_unauthWsByIp.get(ip) || 0) + 1;
    if (unauthCount > MAX_UNAUTH_WS_PER_IP) {
        try { ws.close(1008, 'Too many unauthenticated connections'); } catch (e) {}
        return;
    }
    _unauthWsByIp.set(ip, unauthCount);

    ws.isAlive = true;
    ws.on('pong', () => { ws.isAlive = true; });
    ws.on('error', console.error);
    ws.subscriptions = new Set();
    ws.user = null;

    // H1/H2 счётчики бюджетов сообщений и cooldown'ов.
    ws._msgBudget = WS_MSG_BUDGET_PER_SEC;
    ws._msgBudgetResetAt = Date.now() + 1000;
    ws._lastTypingAt = 0;
    ws._lastMessagesReadAt = 0;

    // Грейс-таймер: если за 5 секунд не пришло сообщение auth — закрываем.
    const authTimeout = setTimeout(() => {
        if (!ws.user && ws.readyState === WebSocket.OPEN) {
            try { ws.close(1008, 'Authentication timeout'); } catch (e) {}
        }
    }, WS_AUTH_GRACE_MS);

    ws.on('close', () => {
        clearTimeout(authTimeout);
        // Уменьшаем счётчик анонимных коннекшнов с этого IP. Если ws успел
        // авторизоваться — он уже не считается как unauth, и даже если был,
        // мы декрементим в одном месте (на close).
        if (!ws.user) {
            const c = (_unauthWsByIp.get(ip) || 1) - 1;
            if (c <= 0) _unauthWsByIp.delete(ip);
            else _unauthWsByIp.set(ip, c);
        } else {
            // освобождаем per-user слот при закрытии аутентифицированного WS.
            const u = (_authWsByUser.get(ws.user.id) || 1) - 1;
            if (u <= 0) _authWsByUser.delete(ws.user.id);
            else _authWsByUser.set(ws.user.id, u);
        }
    });

    ws.on('message', (message) => {
        // rate-limit любых сообщений. Превышение — terminate, без graceful close.
        const nowTs = Date.now();
        if (nowTs > ws._msgBudgetResetAt) {
            ws._msgBudget = WS_MSG_BUDGET_PER_SEC;
            ws._msgBudgetResetAt = nowTs + 1000;
        }
        if (--ws._msgBudget < 0) {
            try { ws.send(JSON.stringify({ type: 'flood_detected', message: 'Слишком частые сообщения.' })); } catch (e) {}
            try { ws.terminate(); } catch (e) {}
            return;
        }

        let data;
        try { data = JSON.parse(message); }
        catch (e) {
            console.error('WS: невалидный JSON', e);
            return;
        }

        // Auth-сообщение принимается только один раз, до него никаких других не обрабатываем.
        if (data.type === 'auth') {
            if (ws.user) return; // уже авторизован — игнор
            const token = data.token;
            if (!token || typeof token !== 'string') {
                try { ws.send(JSON.stringify({ type: 'auth_error', message: 'token required' })); } catch (e) {}
                try { ws.close(1008, 'Token not provided'); } catch (e) {}
                return;
            }
            verifyAccess(token, async (err, user) => {
                if (err || !user) {
                    try { ws.send(JSON.stringify({ type: 'auth_error', message: 'invalid token' })); } catch (e) {}
                    try { ws.close(1008, 'Invalid token'); } catch (e) {}
                    return;
                }
                // Token version check: если админ отозвал юзера через
                // bumpTokenVersion (delete-user / reset-password), старый JWT
                // ещё валиден по подписи, но `tv` в payload отстал. Это та же
                // проверка, что в softDecodeToken для HTTP — для WS она была
                // забыта, поэтому отозванный юзер мог держать live-канал
                // открытым до 15-минутного истечения access-токена.
                // WS auth — токен без tv-claim тоже отказ.
                if (typeof user.tv !== 'number') {
                    try { ws.send(JSON.stringify({ type: 'auth_error', message: 'token revoked' })); } catch (e) {}
                    try { ws.close(1008, 'Token revoked'); } catch (e) {}
                    return;
                }
                try {
                    const expected = await getTokenVersion(user.id);
                    if (user.tv < expected) {
                        try { ws.send(JSON.stringify({ type: 'auth_error', message: 'token revoked' })); } catch (e) {}
                        try { ws.close(1008, 'Token revoked'); } catch (e) {}
                        return;
                    }
                } catch (tvErr) {
                    // При ошибке БД лучше отказать чем пустить отозванного.
                    console.error('WS auth getTokenVersion failed:', tvErr.message);
                    try { ws.close(1011, 'Auth check failed'); } catch (e) {}
                    return;
                }
                // atomic increment-then-check + relative decrement.
                // Раньше между `set(tentative)` и `set(tentative - 1)` (rollback при
                // overflow) close-handler параллельного ws того же юзера мог сделать
                // свой decrement → counter был 6, close сделал 5, rollback set(6-1)=5.
                // Финальный counter=5, но ws live=4 — lost decrement, slow leak.
                // Решение: при overflow читаем актуальное значение перед decrement'ом.
                const tentative = (_authWsByUser.get(user.id) || 0) + 1;
                _authWsByUser.set(user.id, tentative);
                if (tentative > MAX_AUTH_WS_PER_USER) {
                    // Relative: текущее значение могло измениться (close-handler
                    // другого ws). Берём актуальное и декрементим.
                    const current = _authWsByUser.get(user.id) || 1;
                    const after = current - 1;
                    if (after <= 0) _authWsByUser.delete(user.id);
                    else _authWsByUser.set(user.id, after);
                    try { ws.send(JSON.stringify({ type: 'auth_error', message: 'too many active sessions' })); } catch (e) {}
                    try { ws.close(1008, 'Too many sessions'); } catch (e) {}
                    return;
                }

                ws.user = user;
                clearTimeout(authTimeout);
                // освобождаем слот в IP-квоте — аутентифицированные коннекшны
                // идентифицированы по token_version и под общую анти-DoS политику
                // не попадают.
                const c = (_unauthWsByIp.get(ip) || 1) - 1;
                if (c <= 0) _unauthWsByIp.delete(ip);
                else _unauthWsByIp.set(ip, c);
                try { ws.send(JSON.stringify({ type: 'auth_ok' })); } catch (e) {}
            });
            return;
        }

        // До auth — всё остальное молча отбрасываем.
        if (!ws.user) return;

        if (data.type === 'subscribe' && data.channel) {
            // cap на количество подписок одного коннекшна. Без cap'а
            // авторизованный юзер может subscribe'нуть тысячи каналов и сожрать
            // память (Set растёт неограниченно). 50 — больше чем UI когда-либо
            // использует (обычно 1-2: список + текущая открытая заявка).
            if (ws.subscriptions.size >= 50) {
                try { ws.send(JSON.stringify({ type: 'subscribe_denied', channel: data.channel, reason: 'too_many_subscriptions' })); } catch (e) {}
                return;
            }
            // IDOR-guard на real-time: подписка на request-N разрешается
            // только если юзер видит саму заявку. Раньше broadcastToRequest
            // фильтровал только по `subscriptions.has(channel)` — Сотрудник
            // мог подписаться на чужой канал и получать `detail_update`.
            const m = String(data.channel).match(/^request-(\d+)$/);
            if (m) {
                const reqId = parseInt(m[1], 10);
                requireAccessToRequest(reqId, ws.user).then(access => {
                    if (access) {
                        ws.subscriptions.add(data.channel);
                    } else {
                        try { ws.send(JSON.stringify({ type: 'subscribe_denied', channel: data.channel })); } catch (e) {}
                    }
                }).catch(() => { /* при ошибке — не подписываем */ });
            } else {
                // Не-request-каналы (admin-logs и т.п.) — пропускаем как было.
                ws.subscriptions.add(data.channel);
            }
        } else if (data.type === 'unsubscribe' && data.channel) {
            ws.subscriptions.delete(data.channel);
        } else if (data.type === 'typing') {
            // серверный cooldown 1.5 сек. Клиентский debounce может быть
            // обойдён (атакующий патчит JS), но broadcast на N подписчиков
            // дорогой — N×N амплификация на горячем канале. На сервере жёсткий
            // throttle.
            if (nowTs - ws._lastTypingAt < WS_TYPING_COOLDOWN_MS) return;
            ws._lastTypingAt = nowTs;

            // Typing-indicator: транслируем «N печатает...» всем подписчикам канала
            // КРОМЕ самого отправителя. Это HTTP-free — никакой записи в БД,
            // только эфир.
            const ch = Array.from(ws.subscriptions).find(s => s.startsWith('request-'));
            if (ch) {
                const reqId = ch.split('-')[1];
                broadcastToRequest(reqId, {
                    type: 'typing',
                    requestId: reqId,        // Раунд 11: явно requestId — клиент-side filter
                    userId: ws.user.id,
                    fullName: ws.user.fullName
                }, ws);
            }
        } else if (data.type === 'messages_read' && data.messageIds?.length > 0) {
            // cooldown 200ms между messages_read запросами. До 200 INSERT'ов
            // в одном запросе — допустимо; сотня запросов/сек = 20k INSERT/сек = DoS на БД.
            if (nowTs - ws._lastMessagesReadAt < WS_MSG_READ_COOLDOWN_MS) return;
            ws._lastMessagesReadAt = nowTs;

            const currentRequestChannel = Array.from(ws.subscriptions).find(s => s.startsWith('request-'));
            if (!currentRequestChannel) return;
            const requestId = currentRequestChannel.split('-')[1];

            // Параметризируем bulk-insert: до этого был interpolation в строку.
            const reqDb = new sql.Request().input('userId', sql.Int, ws.user.id);
            reqDb.input('reqId', sql.Int, parseInt(requestId, 10));
            const cleanIds = data.messageIds
                .map(id => parseInt(id, 10))
                .filter(n => Number.isInteger(n) && n > 0)
                .slice(0, 200);
            if (cleanIds.length === 0) return;
            // ownership-validation. Раньше юзер мог подписаться на request-X
            // (где доступен) и послать messages_read с message_id из чужой
            // заявки → грязный INSERT в CommentReadStatus. Теперь WHERE c.id
            // IN (...) AND c.request_id = @reqId фильтрует чужие на уровне SQL.
            const stmts = cleanIds.map((id, i) => {
                reqDb.input(`m${i}`, sql.Int, id);
                return `IF EXISTS (SELECT 1 FROM Comments WHERE id=@m${i} AND request_id=@reqId)
                            AND NOT EXISTS (SELECT 1 FROM CommentReadStatus WHERE comment_id=@m${i} AND user_id=@userId)
                        BEGIN INSERT INTO CommentReadStatus(comment_id, user_id) VALUES(@m${i}, @userId) END;`;
            }).join('\n');
            reqDb.query(stmts).catch(err => console.error('WS messages_read:', err));

            broadcastToRequest(requestId, {
                type: 'receipts_updated',
                readerId: ws.user.id
            }, ws);
        }
    });
});

const interval = setInterval(() => {
    wss.clients.forEach(ws => {
        if (ws.isAlive === false) return ws.terminate();
        ws.isAlive = false;
        ws.ping();
    });
}, 30000);

wss.on('close', () => clearInterval(interval));

// server-level WS-error handler. Без него ошибки уровня wss
// (EMFILE, EADDRINUSE, парсер-ошибки на handshake до того как сокет
// прикреплён к connection-handler) уходят в `process.on('uncaughtException')`,
// которого до Block V не было — процесс падал без forensic trail.
// Per-socket ошибки уже ловятся через `ws.on('error', console.error)` в
// connection-handler'е (server.js:6080+).
wss.on('error', (err) => {
    console.error('[wss] server-level error:', err && err.stack || err);
    // Не падаем — пытаемся продолжить. Но фиксируем в security-логе для аудита.
    try {
        writeFileLog('security', {
            event: 'wss_server_error',
            err: err && err.message || String(err),
            timestamp: new Date().toISOString()
        });
    } catch (_) { /* лог не должен ронять handler */ }
});

/* =============================================================================
   Background scheduler: эскалация «зависших» заявок.

   Раз в 30 минут проверяет заявки, которые «зависли» в активном статусе:
   updated_at > 3 дней назад. Для каждой такой:
     - Однократно (per-day) шлём уведомление автору и админу
     - В History пишется запись «escalation_stuck»

   Защита от дублей: проверяем, что в History сегодня уже не было записи
   «Заявка зависла» по этой заявке. Иначе при каждом прогоне получим спам.

   Интервал — 30 минут (компромисс между «свежим алертом» и нагрузкой).
   В production-уровне это нужно вынести в cron или отдельный worker —
   у нас нет такой инфраструктуры, поэтому in-process.
   ============================================================================= */
const STUCK_THRESHOLD_DAYS = 3;
const STUCK_CHECK_INTERVAL_MS = 30 * 60 * 1000;

// in-flight mutex — защита от overlap когда предыдущий прогон ещё идёт
// (медленная БД, большая партия данных). Обёртка вокруг async-задачи.
function withInflightFlag(name, fn) {
    let running = false;
    return async function wrapped(...args) {
        if (running) {
            console.warn(`[${name}] skip: previous run still in progress`);
            return;
        }
        running = true;
        try { return await fn(...args); }
        finally { running = false; }
    };
}

async function _checkStuckRequestsImpl() {
    try {
        const r = await new sql.Request().query(`
            SELECT r.id, r.title, r.creator_id, r.status_id, rs.name AS status_name,
                   DATEDIFF(DAY, r.updated_at, SYSUTCDATETIME()) AS stuck_days
            FROM Requests r
            JOIN RequestStatuses rs ON rs.id = r.status_id
            WHERE r.status_id IN (${activeStatusList()})
              AND DATEDIFF(DAY, r.updated_at, SYSUTCDATETIME()) >= ${STUCK_THRESHOLD_DAYS}
              AND NOT EXISTS (
                  SELECT 1 FROM History h
                  WHERE h.request_id = r.id
                    AND h.action = 'Эскалация: заявка зависла'
                    AND h.timestamp >= CAST(GETUTCDATE() AS DATE)
              )`);

        const adminRow = await new sql.Request().query(
            `SELECT id FROM Users WHERE role_id = ${ROLES.ADMIN} AND deleted_at IS NULL AND is_active = 1`
        );
        const adminIds = adminRow.recordset.map(x => x.id);

        for (const row of r.recordset) {
            const detail = `Заявка №${row.id} «${row.title}» находится в статусе «${row.status_name}» уже ${row.stuck_days} дней. Требуется внимание.`;
            // 1. История заявки
            await new sql.Request()
                .input('rid',     sql.Int, row.id)
                .input('details', sql.NVarChar, detail)
                .query(`INSERT INTO History (request_id, user_id, action, details)
                        VALUES (@rid, NULL, N'Эскалация: заявка зависла', @details)`);

            // 2. Уведомления автору + всем админам
            const recipients = [row.creator_id, ...adminIds].filter((v, i, arr) => v && arr.indexOf(v) === i);
            await createNotifications({
                recipientIds: recipients,
                requestId: row.id,
                actorId: null,
                type: NOTIFICATION_TYPES.STATUS_CHANGED,
                message: `⚠ Заявка №${row.id} «${row.title}» зависла в статусе «${row.status_name}» уже ${row.stuck_days} дней`
            });
        }

        if (r.recordset.length > 0) {
            console.log(`[stuck-check] эскалировано заявок: ${r.recordset.length}`);
        }
    } catch (err) {
        console.error('[stuck-check] error:', err.message);
    }
}
const checkStuckRequests = withInflightFlag('stuck-check', _checkStuckRequestsImpl);

/**
 * Регулярная чистка старых записей AccessAudit. Закон РБ №99-З требует хранить
 * аудит ПДн «не больше срока обработки данных». Установлен retention = 1 год.
 * Запускается раз в сутки.
 */
const AUDIT_RETENTION_DAYS = 365;
async function _cleanupOldAuditRecordsImpl() {
    try {
        const r = await new sql.Request()
            .input('days', sql.Int, AUDIT_RETENTION_DAYS)
            .query(`DELETE FROM AccessAudit
                    WHERE accessed_at < DATEADD(DAY, -@days, SYSUTCDATETIME())`);
        const deleted = r.rowsAffected[0] || 0;
        if (deleted > 0) {
            console.log(`[audit-cleanup] удалено старых записей: ${deleted}`);
        }
    } catch (err) {
        console.error('[audit-cleanup] error:', err.message);
    }
}
const cleanupOldAuditRecords = withInflightFlag('audit-cleanup', _cleanupOldAuditRecordsImpl);

/**
 * Чистка остальных журнальных таблиц с разными retention'ами:
 *   - History (бизнес-события)        — 365 дней (нужно для PII compliance тоже)
 *   - LoginHistory                    —  90 дней (для security-аналитики достаточно)
 *   - FileUploadAttempts              —  90 дней
 *   - Notifications                   —  90 дней (read или нет — после трёх месяцев теряют смысл)
 *
 * Без этого через год эксплуатации `History` накопит десятки миллионов строк
 * и тормознёт `/api/admin/logs`. Все таблицы имеют индекс по timestamp/created_at,
 * так что DELETE с фильтром по дате быстрый.
 *
 * RequestViewHistory намеренно НЕ чистим — он мелкий (по строке на пару
 * user×request), и используется для индикатора «новая для меня».
 */
const JOURNAL_RETENTION = {
    History:            { col: 'timestamp',    days: 365 },
    LoginHistory:       { col: 'login_time',   days: 90  },
    FileUploadAttempts: { col: 'attempted_at', days: 90  },
    Notifications:      { col: 'created_at',   days: 90  },
    // Idempotency-keys живут 24 часа (1 день), но ставим 7 для надёжного
    // покрытия поздних retry'ев и реалистичных сетевых задержек.
    IdempotencyKeys:    { col: 'created_at',   days: 7   }
};

async function _cleanupJournalsImpl() {
    for (const [table, { col, days }] of Object.entries(JOURNAL_RETENTION)) {
        try {
            const r = await new sql.Request()
                .input('days', sql.Int, days)
                .query(`DELETE FROM ${table}
                        WHERE ${col} < DATEADD(DAY, -@days, SYSUTCDATETIME())`);
            const deleted = r.rowsAffected[0] || 0;
            if (deleted > 0) {
                console.log(`[journal-cleanup] ${table}: удалено ${deleted} записей старше ${days} дн.`);
            }
        } catch (err) {
            console.error(`[journal-cleanup] ${table} error:`, err.message);
        }
    }
}
const cleanupJournals = withInflightFlag('journal-cleanup', _cleanupJournalsImpl);

/**
 * Ротация log-файлов из папки logs/. Файлы создаются по дням
 * (access-YYYY-MM-DD.log, security-..., admin-...). Удаляем старше 30 дней.
 * Текущий день пропускаем (active-write).
 */
const LOG_RETENTION_DAYS = 30;
async function _cleanupOldLogFilesImpl() {
    const logsDir = path.join(__dirname, 'logs');
    try {
        const files = await fs.promises.readdir(logsDir);
        const cutoff = Date.now() - LOG_RETENTION_DAYS * 24 * 60 * 60 * 1000;
        let removed = 0;
        for (const fname of files) {
            if (!fname.endsWith('.log')) continue;
            const fullPath = path.join(logsDir, fname);
            try {
                const st = await fs.promises.stat(fullPath);
                if (st.mtimeMs < cutoff) {
                    await fs.promises.unlink(fullPath);
                    removed++;
                }
            } catch (_) { /* файл исчез — ок */ }
        }
        if (removed > 0) {
            console.log(`[log-rotate] удалено ${removed} лог-файлов старше ${LOG_RETENTION_DAYS} дн.`);
        }
    } catch (err) {
        if (err.code !== 'ENOENT') {
            console.error('[log-rotate] error:', err.message);
        }
    }
}
const cleanupOldLogFiles = withInflightFlag('log-rotate', _cleanupOldLogFilesImpl);

/**
 * еженедельный сборщик orphan-файлов в `uploads/`.
 *
 * Источники orphan'ов:
 *   - failure-paths POST /api/requests / /documents (catch'ы стараются чистить,
 *     но при OOM / kill -9 файл может остаться)
 *   - hash-collision race до C2 (одинаковые hash в разных file_path)
 *   - .tmp-файлы которые не были переименованы (rename упал после commit'а БД)
 *
 * Алгоритм:
 *   1. Берём snapshot всех `Documents.file_path` (relative).
 *   2. Читаем `uploads/` через readdir.
 *   3. Файл orphan если: не в snapshot И mtime старше ORPHAN_AGE_DAYS.
 *      Возрастной критерий нужен чтобы НЕ удалить файл, который только что
 *      записан мульттером, но Documents-запись ещё не закоммичена (race с
 *      handler'ом).
 *
 * Запускается раз в 7 дней.
 */
const ORPHAN_AGE_DAYS = 7;
const ORPHAN_CLEANUP_INTERVAL_MS = 7 * 24 * 60 * 60 * 1000;
async function _cleanupOrphanUploadsImpl() {
    try {
        const docs = await new sql.Request().query('SELECT file_path FROM Documents');
        const knownPaths = new Set(docs.recordset.map(r => r.file_path).filter(Boolean));
        const files = await fs.promises.readdir(UPLOADS_DIR);
        const cutoff = Date.now() - ORPHAN_AGE_DAYS * 24 * 60 * 60 * 1000;
        let removed = 0;
        let scanned = 0;
        for (const fname of files) {
            scanned++;
            // .tmp-файлы старше ORPHAN_AGE_DAYS — чистим всегда (кто-то не завершил
            // upload).
            const isTmp = fname.endsWith('.tmp');
            const baseName = isTmp ? fname.slice(0, -4) : fname;
            if (!isTmp && knownPaths.has(baseName)) continue; // регулярный, ссылается из БД
            const fullPath = path.join(UPLOADS_DIR, fname);
            try {
                const st = await fs.promises.stat(fullPath);
                if (st.mtimeMs < cutoff) {
                    await fs.promises.unlink(fullPath);
                    removed++;
                }
            } catch (_) { /* gone or denied */ }
        }
        if (removed > 0) {
            console.log(`[orphan-janitor] просканировано ${scanned}, удалено ${removed} orphan-файлов старше ${ORPHAN_AGE_DAYS} дн.`);
            // Логируем как admin event — это compliance-relevant действие.
            await logAdminEvent(
                'Очистка osiротевших файлов'.replace('osi', 'оси'),
                `Удалено ${removed} файлов из uploads/ старше ${ORPHAN_AGE_DAYS} дней`,
                null, 'Система'
            ).catch(e => console.error('[orphan-janitor] logAdminEvent failed:', e.message));
        }
    } catch (err) {
        console.error('[orphan-janitor] error:', err.message);
    }
}
const cleanupOrphanUploads = withInflightFlag('orphan-janitor', _cleanupOrphanUploadsImpl);

// Таймеры инициализируются в startServer() ПОСЛЕ sql.connect — иначе на медленной
// БД первый прогон гарантированно упадёт с «No connection pool».
// держим ссылки на ВСЕ background-таймеры — gracefulShutdown
// должен clearInterval всех, иначе Node не выходит и форс-exit через 10с.
let stuckCheckInterval = null;
let auditCleanupInterval = null;
let journalCleanupInterval = null;
let logRotateInterval = null;
let orphanCleanupInterval = null;

const startServer = async () => {
    try {
        if (!process.env.JWT_SECRET || !process.env.REFRESH_TOKEN_SECRET) {
            console.error('ОШИБКА: Секретные ключи JWT не найдены!');
            process.exit(1);
        }

        // boot-time guards. Раньше валидация ограничивалась
        // «оба секрета не пустые». Реальные риски, которые проверка должна ловить:
        // 1) JWT_SECRET === REFRESH_TOKEN_SECRET — admin скопировал один
        // секрет в оба поля .env. Audience-claim ('vitenergo-access' vs
        // 'vitenergo-refresh') защищает, но это **defence-in-depth**:
        // одна опечатка в audience = полный обход. Раздельные секреты
        // делают обход двухступенчатым.
        // 2) Длина < 32 байт — один-символьный секрет проходит. HMAC-SHA256
        // с слабым ключом перебирается. NIST SP800-117: ≥256 бит.
        // 3) Newline-injection: dotenv 16+ корректно обрабатывает quoted,
        // но raw newlines в unquoted значениях иногда попадают через
        // copy-paste. jwt-lib примет, но это симптом мисскорма.
        // 4) Production-leak rate-limit: dev-`.env` с AUTH_LIMITER_MAX=200
        // случайно скопирован в прод → бруфорс открыт в 20 раз шире.
        // Hard-fail если NODE_ENV=production И значение > 30.
        const JWT_SECRET = process.env.JWT_SECRET;
        const REFRESH_SECRET = process.env.REFRESH_TOKEN_SECRET;
        if (JWT_SECRET === REFRESH_SECRET) {
            console.error('ОШИБКА: JWT_SECRET и REFRESH_TOKEN_SECRET должны различаться (defence-in-depth).');
            process.exit(1);
        }
        if (JWT_SECRET.length < 32 || REFRESH_SECRET.length < 32) {
            console.error('ОШИБКА: JWT_SECRET / REFRESH_TOKEN_SECRET должны быть длиной ≥32 символов.');
            process.exit(1);
        }
        if (/[\r\n]/.test(JWT_SECRET) || /[\r\n]/.test(REFRESH_SECRET)) {
            console.error('ОШИБКА: JWT-секреты не должны содержать переводов строк (newline-injection через .env).');
            process.exit(1);
        }
        if (process.env.NODE_ENV === 'production') {
            const authMax = parseInt(process.env.AUTH_LIMITER_MAX, 10) || 10;
            const uploadMax = parseInt(process.env.UPLOAD_LIMITER_MAX, 10) || 3;
            const reqCreateMax = parseInt(process.env.REQUEST_CREATE_MAX, 10) || 30;
            const cmtCreateMax = parseInt(process.env.COMMENT_CREATE_MAX, 10) || 120;
            if (authMax > 30) {
                console.error(`ОШИБКА: AUTH_LIMITER_MAX=${authMax} в production (max 30). Похоже dev-.env попал в прод.`);
                process.exit(1);
            }
            if (uploadMax > 10) {
                console.error(`ОШИБКА: UPLOAD_LIMITER_MAX=${uploadMax} в production (max 10).`);
                process.exit(1);
            }
            if (reqCreateMax > 100) {
                console.error(`ОШИБКА: REQUEST_CREATE_MAX=${reqCreateMax} в production (max 100).`);
                process.exit(1);
            }
            if (cmtCreateMax > 300) {
                console.error(`ОШИБКА: COMMENT_CREATE_MAX=${cmtCreateMax} в production (max 300).`);
                process.exit(1);
            }
        }

        dbPool = await sql.connect(dbConfig);
        console.log('Подключение к БД успешно.');

        // Загружаем доменные константы (Roles, Statuses) из БД ДО старта сервера.
        // Если что-то отсутствует — падаем явно, чтобы не работать с битыми данными.
        await loadConstants();
        console.log(`Константы загружены: ${Object.keys(ROLES).length} ролей, ${Object.keys(STATUSES).length} статусов.`);

        // Background-задачи — стартуем только после успешного подключения к БД.
        // Stuck-escalation: первая проверка через 60 сек, далее раз в 30 мин.
        // Audit cleanup: раз в сутки, удаляем записи старше 1 года.
        // Journal/log cleanup: раз в сутки, разные retention'ы (см. константы).
        stuckCheckInterval = setInterval(checkStuckRequests, STUCK_CHECK_INTERVAL_MS);
        setTimeout(checkStuckRequests, 60 * 1000);

        const DAY_MS = 24 * 60 * 60 * 1000;
        auditCleanupInterval = setInterval(cleanupOldAuditRecords, DAY_MS);
        setTimeout(cleanupOldAuditRecords, 5 * 60 * 1000);
        journalCleanupInterval = setInterval(cleanupJournals, DAY_MS);
        setTimeout(cleanupJournals, 7 * 60 * 1000);   // через 7 мин после старта
        logRotateInterval = setInterval(cleanupOldLogFiles, DAY_MS);
        setTimeout(cleanupOldLogFiles, 9 * 60 * 1000); // через 9 мин (разнос по времени)

        // orphan-janitor для uploads/. Запускается раз в неделю.
        // Первый прогон через 11 мин — НЕ синхронно с другими, чтобы не
        // нагружать FS одновременно с log/journal cleanup.
        orphanCleanupInterval = setInterval(cleanupOrphanUploads, ORPHAN_CLEANUP_INTERVAL_MS);
        setTimeout(cleanupOrphanUploads, 11 * 60 * 1000);

        server.listen(PORT, () => console.log(`Сервер запущен на порту ${PORT}`));
    } catch (err) {
        console.error('ОШИБКА ПОДКЛЮЧЕНИЯ К БД:', err);
        process.exit(1);
    }
};

/* =============================================================================
   Graceful shutdown.
   При получении SIGTERM (Docker stop, systemd) или SIGINT (Ctrl+C):
     1. Прекращаем приём новых HTTP-соединений.
     2. Закрываем все открытые WS-соединения с кодом 1001 «Going away».
     3. Останавливаем keepalive-ping таймер.
     4. Закрываем пул mssql, дописываем что висит в очереди.
     5. Выходим с кодом 0.
   Force-exit через 10 секунд, если что-то зависнет.
   ============================================================================= */
let shuttingDown = false;
async function gracefulShutdown(signal) {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`[shutdown] Получен ${signal}. Закрытие сервера…`);
    const forceExit = setTimeout(() => {
        console.error('[shutdown] Превышено время ожидания, force-exit.');
        process.exit(1);
    }, 10000).unref();

    try {
        // clearInterval ВСЕХ background-таймеров, иначе Node не
        // выйдет до force-exit (10 сек) — таймеры держат event-loop. До фикса
        // только interval (WS keepalive) и stuckCheckInterval чистились.
        clearInterval(interval);
        clearInterval(stuckCheckInterval);
        clearInterval(auditCleanupInterval);
        clearInterval(journalCleanupInterval);
        clearInterval(logRotateInterval);
        clearInterval(orphanCleanupInterval);

        // закрываем idle keep-alive HTTP-сокеты немедленно —
        // иначе server.close() ждёт пока все не станут idle (может висеть до
        // дефолтного keepAliveTimeout в 5 сек × N коннекшнов). Активные
        // соединения остаются работать до завершения текущего request'а.
        if (typeof server.closeIdleConnections === 'function') {
            server.closeIdleConnections();
        }

        // Закрываем WS-соединения. ws.close(1001) — graceful, но если клиент
        // не ответит на close-handshake, сокет висит. Ставим страховочный
        // ws.terminate() через 2 сек.
        wss.clients.forEach(ws => {
            try { ws.close(1001, 'server shutting down'); } catch (e) {}
            setTimeout(() => {
                try { if (ws.readyState !== ws.CLOSED) ws.terminate(); } catch (_) {}
            }, 2000).unref();
        });

        // Дополнительная страховка: если активные HTTP-соединения зависли
        // (slow upload, broken peer), через 8 сек принудительно дропаем все.
        setTimeout(() => {
            if (typeof server.closeAllConnections === 'function') {
                console.log('[shutdown] Принудительно закрываем зависшие HTTP-соединения.');
                server.closeAllConnections();
            }
        }, 8000).unref();

        await new Promise(resolve => server.close(resolve));
        console.log('[shutdown] HTTP-сервер закрыт.');
        await sql.close();
        console.log('[shutdown] Пул БД закрыт. До свидания.');
        clearTimeout(forceExit);
        process.exit(0);
    } catch (e) {
        console.error('[shutdown] Ошибка при остановке:', e);
        process.exit(1);
    }
}
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT',  () => gracefulShutdown('SIGINT'));

// защита от silent-crash при невпойманной Promise-ошибке.
// До Block V Node 20 default'но прибивал процесс на unhandledRejection без
// логов. Теперь:
// 1) Логируем в security-журнал (для post-mortem).
// 2) Делаем graceful shutdown — БД pool / WS-клиенты закрываются корректно,
// далее process.exit(1). Docker/PM2/systemd рестартует процесс.
// Не делаем fail-open (process.on('uncaughtException') без exit) — состояние
// процесса после необработанного исключения непредсказуемо, продолжать опасно.
let _shutdownInProgress = false;
async function bailOut(label, err) {
    console.error(`[${label}]`, err && err.stack || err);
    try {
        writeFileLog('security', {
            event: label,
            err: err && err.message || String(err),
            stack: err && err.stack,
            timestamp: new Date().toISOString()
        });
    } catch (_) { /* лог не должен мешать выходу */ }
    if (_shutdownInProgress) return;
    _shutdownInProgress = true;
    try {
        await gracefulShutdown(label);
    } catch (_) { /* в критическом пути любая ошибка → принудительный exit */ }
    process.exit(1);
}
process.on('uncaughtException',  (err) => { bailOut('uncaughtException',  err); });
process.on('unhandledRejection', (reason) => { bailOut('unhandledRejection', reason instanceof Error ? reason : new Error(String(reason))); });

// E2/H-6: Node-warnings handler. Без него native warnings типа
// `MaxListenersExceededWarning`, `[DEP0157]`, `ExperimentalWarning` уходят
// в stderr и теряются в Docker journal'ах. Для observability в production
// — пишем в writeFileLog('security'), без rate-limit (security категория
// исключена из bucket'ирования). Не падаем процессом — warnings не fatal.
process.on('warning', (w) => {
    try {
        writeFileLog('security', {
            event: 'node_warning',
            name: w && w.name,
            message: w && w.message,
            stack: w && w.stack,
            timestamp: new Date().toISOString()
        });
    } catch (_) { /* лог не должен мешать */ }
});

startServer();