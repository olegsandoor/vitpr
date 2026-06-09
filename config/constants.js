/**
 * config/constants.js
 *
 * Доменные константы (роли пользователей и статусы заявок) загружаются
 * один раз при старте сервера из таблиц Roles и RequestStatuses.
 * Это устраняет «магические числа» (status_id = 4, role_id IN (3, 4) и т.п.)
 * по всему коду — вместо этого используются осмысленные имена:
 *
 *   ROLES.ADMIN, ROLES.EMPLOYEE, ROLES.MODERATOR, ROLES.APPROVER
 *   STATUSES.NEW, STATUSES.MODERATION, STATUSES.APPROVAL,
 *   STATUSES.APPROVED, STATUSES.REJECTED, STATUSES.REWORK
 *
 * Если в БД будет добавлен новый статус или роль — достаточно перезапустить
 * сервер и обновить мапинги ниже (если name → key пишется по другому
 * правилу).
 */

const sql = require('mssql');

// ===== Маппинги «человеческое имя из БД → программный ключ» =====
const ROLE_NAME_TO_KEY = {
    'Администратор': 'ADMIN',
    'Сотрудник':     'EMPLOYEE',
    'Модератор':     'MODERATOR',
    'Согласующий':   'APPROVER'
};

const STATUS_NAME_TO_KEY = {
    'Новая':              'NEW',
    'На модерации':       'MODERATION',
    'На согласовании':    'APPROVAL',
    'Одобрена':           'APPROVED',
    'Отклонена':          'REJECTED',
    'Требует доработки':  'REWORK',
    'Отозвана':           'WITHDRAWN'
};

// ===== Заполняются при вызове loadConstants() =====
const ROLES         = {};   // { ADMIN: 1, EMPLOYEE: 2, ... }
const ROLE_NAMES    = {};   // { 1: 'Администратор', 2: 'Сотрудник', ... }
const STATUSES      = {};   // { NEW: 1, MODERATION: 2, ... }
const STATUS_NAMES  = {};   // { 1: 'Новая', ... }

// Map<roleId, Map<fromStatusId, Set<toStatusId>>> — матрица переходов из БД.
const TRANSITIONS   = new Map();

/**
 * Загружает справочники из БД и заполняет константы. Вызывается из startServer().
 * Возвращает promise, который должен резолвиться до начала обработки запросов.
 */
async function loadConstants() {
    const rolesRes = await sql.query`SELECT id, name FROM Roles`;
    rolesRes.recordset.forEach(row => {
        const key = ROLE_NAME_TO_KEY[row.name] || row.name.toUpperCase();
        ROLES[key] = row.id;
        ROLE_NAMES[row.id] = row.name;
    });

    const statusesRes = await sql.query`SELECT id, name FROM RequestStatuses`;
    statusesRes.recordset.forEach(row => {
        const key = STATUS_NAME_TO_KEY[row.name] || row.name.toUpperCase();
        STATUSES[key] = row.id;
        STATUS_NAMES[row.id] = row.name;
    });

    // Sanity-check: все ожидаемые ключи должны быть заполнены
    const requiredRoles    = ['ADMIN', 'EMPLOYEE', 'MODERATOR', 'APPROVER'];
    const requiredStatuses = ['NEW', 'MODERATION', 'APPROVAL', 'APPROVED', 'REJECTED', 'REWORK', 'WITHDRAWN'];
    const missingRoles    = requiredRoles.filter(k => !(k in ROLES));
    const missingStatuses = requiredStatuses.filter(k => !(k in STATUSES));
    if (missingRoles.length || missingStatuses.length) {
        throw new Error(
            `Не загружены доменные константы. ` +
            `Missing roles: ${missingRoles.join(',')}. ` +
            `Missing statuses: ${missingStatuses.join(',')}.`
        );
    }

    // Загружаем матрицу переходов статусов (миграция 14).
    TRANSITIONS.clear();
    const transRes = await sql.query`SELECT role_id, from_status_id, to_status_id FROM StatusTransitions`;
    transRes.recordset.forEach(row => {
        if (!TRANSITIONS.has(row.role_id)) TRANSITIONS.set(row.role_id, new Map());
        const byFrom = TRANSITIONS.get(row.role_id);
        if (!byFrom.has(row.from_status_id)) byFrom.set(row.from_status_id, new Set());
        byFrom.get(row.from_status_id).add(row.to_status_id);
    });
    if (TRANSITIONS.size === 0) {
        throw new Error('Таблица StatusTransitions пуста — миграция 14 не применена?');
    }
}

/**
 * Проверка разрешённости перехода: «может ли роль R перевести заявку из X в Y?».
 * Чисто per-role/per-status проверка по таблице StatusTransitions. Дополнительные
 * условия (типа «сотрудник может только свои») остаются в коде роутов.
 */
function isTransitionAllowed(roleId, fromStatusId, toStatusId) {
    const byFrom = TRANSITIONS.get(roleId);
    if (!byFrom) return false;
    const toSet = byFrom.get(fromStatusId);
    return !!(toSet && toSet.has(toStatusId));
}

/** Получает roleId по имени роли (для перевода req.user.role → числовой id). */
function getRoleIdByName(name) {
    for (const [id, n] of Object.entries(ROLE_NAMES)) {
        if (n === name) return parseInt(id, 10);
    }
    return null;
}

/**
 * Возвращает массив целевых статусов, в которые роль может перевести заявку
 * из указанного текущего статуса. Удобно для построения select на UI и
 * для batch-валидации.
 */
function getAllowedTargetStatuses(roleId, fromStatusId) {
    const byFrom = TRANSITIONS.get(roleId);
    if (!byFrom) return [];
    const toSet = byFrom.get(fromStatusId);
    return toSet ? Array.from(toSet) : [];
}

/** Все целевые статусы для роли (объединение по всем from). Для UI batch-bar. */
function getAllowedTargetsForRole(roleId) {
    const byFrom = TRANSITIONS.get(roleId);
    if (!byFrom) return [];
    const all = new Set();
    for (const toSet of byFrom.values()) {
        for (const id of toSet) all.add(id);
    }
    return Array.from(all);
}

/**
 * Хелпер: безопасно собирает CSV-список status_id для SQL-фрагментов вида
 *   `r.status_id IN (${statusList(['NEW', 'MODERATION'])})`.
 *
 * До этого по коду были разбросаны ${STATUSES.NEW}, ${STATUSES.MODERATION}
 * как чистые интерполяции — даже зная что значения числовые, это «пахнет»
 * SQL-injection при беглом чтении. Хелпер:
 *   1. явно парсит числа (parseInt + isFinite),
 *   2. бросает ошибку если ключ не загружен (опечатка / БД не синхронизирована),
 *   3. отдаёт чистую CSV-строку гарантированно числовых значений.
 *
 * Это всё ещё интерполяция, но — централизованная, валидированная и
 * однострочная. Если нужно добавить параметризацию — меняем в одном месте.
 */
function statusList(keys) {
    return keys.map(k => {
        const v = STATUSES[k];
        if (!Number.isFinite(v)) {
            throw new Error(`statusList: неизвестный статус "${k}". Загружены: ${Object.keys(STATUSES).join(',')}`);
        }
        return v;
    }).join(',');
}

/** Список «активных» статусов (заявка ещё в работе). */
const ACTIVE_STATUS_KEYS = ['NEW', 'MODERATION', 'APPROVAL', 'REWORK'];
function activeStatusList() {
    return statusList(ACTIVE_STATUS_KEYS);
}

/* =============================================================================
   Матрица доступа к PDF-протоколу. Раунд 11 UX (доменная логика).

   Протокол — юридический артефакт, фиксирующий РЕШЕНИЕ. Поэтому он имеет
   смысл только на стадиях, где решение принимается или уже принято:
     • APPROVAL  → «бланк к подписи»     (draft, согласующий распечатывает,
                   подписывает физически, сканит → грузит как signed_protocol)
     • APPROVED  → «итоговый протокол согласования» (final, делопроизводство)
     • REJECTED  → «протокол отказа»        (final, ответ заявителю + архив)

   REWORK / NEW / MODERATION / WITHDRAWN — концептуально не имеют PDF:
     • REWORK     = «вернули с замечаниями» — это не решение, а просьба
                    исправить. Замечания уже в чате. Заявка пойдёт по
                    второму кругу и получит полноценный протокол на
                    APPROVED/REJECTED.
     • NEW / MOD  = ещё никто не рассматривал.
     • WITHDRAWN  = автор отозвал, рассмотрения не было.

   Кто может скачать — зависит от роли И стадии:
     • APPROVAL: Сотрудник (даже автор) НЕ может — решение ещё не принято,
                 черновик его не касается до публикации финального вердикта.
     • APPROVED / REJECTED: все стейкхолдеры (через requireAccessToRequest),
                 включая автора — нужен для записи и формального ответа.

   Источник истины — здесь. Server.js и dashboard.js используют один справочник,
   чтобы фронт-скрытие кнопки и backend-403 не разъехались.
   ============================================================================= */
const PDF_PROTOCOL_CONFIG = {
    APPROVAL: {
        label: 'Бланк к подписи',
        hint: 'Готовый к подписи бланк с pre-заполненным ФИО и сегодняшней датой. Распечатайте, подпишите и приложите как «Подписанный протокол».',
        // isDraft=false: на APPROVAL это полноценный рабочий бланк, не черновик.
        // Watermark отключён, в PDF секции «Решение» уже стоит «ОДОБРЕНА»,
        // в таблице подписей pre-заполнен открывший бланк юзер.
        isDraft: false,
        deniedRoleKeys: ['EMPLOYEE']  // автор не видит бланк до принятия решения
    },
    APPROVED: {
        label: 'Протокол согласования',
        hint: 'Утверждённый протокол для делопроизводства.',
        isDraft: false,
        deniedRoleKeys: []
    },
    REJECTED: {
        label: 'Протокол отказа',
        hint: 'Итоговый документ с обоснованием отказа.',
        isDraft: false,
        deniedRoleKeys: []
    }
};

/**
 * Проверка доступа к PDF-протоколу по статусу и роли.
 * Возвращает {allowed, isDraft, label, hint, reason}.
 * `reason` присутствует только когда `allowed=false` — для логирования.
 *
 * Caller обязан ОТДЕЛЬНО проверить доступ к самой заявке через
 * `requireAccessToRequest` (см. server.js) — этот хелпер только про
 * стадию workflow, не про visibility заявки.
 */
function getPdfProtocolAccess(statusId, roleId) {
    // Найдём ключ статуса по ID
    const statusKey = Object.keys(STATUSES).find(k => STATUSES[k] === statusId);
    const cfg = statusKey ? PDF_PROTOCOL_CONFIG[statusKey] : null;
    if (!cfg) {
        return { allowed: false, reason: 'invalid_status' };
    }
    // Найдём ключ роли по ID
    const roleKey = Object.keys(ROLES).find(k => ROLES[k] === roleId);
    if (cfg.deniedRoleKeys.includes(roleKey)) {
        return { allowed: false, reason: 'role_denied_for_status' };
    }
    return {
        allowed: true,
        isDraft: cfg.isDraft,
        label: cfg.label,
        hint: cfg.hint
    };
}

module.exports = {
    ROLES, ROLE_NAMES,
    STATUSES, STATUS_NAMES,
    loadConstants,
    statusList,
    activeStatusList,
    ACTIVE_STATUS_KEYS,
    isTransitionAllowed,
    getRoleIdByName,
    getAllowedTargetStatuses,
    getAllowedTargetsForRole,
    PDF_PROTOCOL_CONFIG,
    getPdfProtocolAccess
};
