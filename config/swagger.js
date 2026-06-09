/**
 * config/swagger.js
 *
 * Конфигурация OpenAPI 3.0 для встроенной документации API. Документация
 * собирается через swagger-jsdoc из JSDoc-аннотаций в server.js, плюс
 * предопределённые схемы основных моделей.
 *
 * Доступ к UI — только админу (см. server.js, монтирование /api-docs).
 *
 * схемы синхронизированы с реальной БД-моделью. Убраны устаревшие
 * поля `priority` / `deadline_date` / `is_overdue` (концептуально удалены
 * в миграции 15, см. CLAUDE.md #17). Заполнены все теги (Profile, Stats и др.).
 */

const swaggerJsdoc = require('swagger-jsdoc');

const swaggerSpec = swaggerJsdoc({
    definition: {
        openapi: '3.0.3',
        info: {
            title: 'VitEnergo API',
            version: '1.0.0',
            description: [
                'REST API системы автоматизации согласования заявок на проведение',
                'мероприятий РУП «Витебскэнерго».',
                '',
                '## Аутентификация',
                'JWT bearer-токен (access 15 минут) + refresh-cookie 7 дней с ротацией',
                'на каждое обращение. При утечке access-токена — `bumpTokenVersion`',
                'мгновенно инвалидирует все живые сессии юзера.',
                '',
                '## Защиты',
                '- CSRF-guard через Origin/Referer + Sec-Fetch-Site',
                '- BREACH-mitigation: compression отключена на auth-эндпоинтах',
                '- Rate-limit per-user + per-IP (см. 429 ответы)',
                '- IDOR-guard `requireAccessToRequest` в каждом `/api/requests/:id*`',
                '- PII access audit в соответствии с законом РБ №99-З'
            ].join('\n')
        },
        servers: [
            { url: 'http://localhost:3000', description: 'Локальный сервер разработки' }
        ],
        tags: [
            { name: 'Auth',          description: 'Вход, выход, обновление токена' },
            { name: 'Profile',       description: 'Профиль текущего пользователя' },
            { name: 'Requests',      description: 'Заявки на мероприятия — основная сущность системы' },
            { name: 'Comments',      description: 'Комментарии и реакции в чате заявки' },
            { name: 'Documents',     description: 'Файлы, прикреплённые к заявкам (включая подписанные протоколы)' },
            { name: 'Notifications', description: 'Уведомления пользователя (Bell)' },
            { name: 'Stats',         description: 'Аналитика и календарь мероприятий' },
            { name: 'Reference',     description: 'Справочники (филиалы, категории, статусы, шаблоны)' },
            { name: 'Admin',         description: 'Управление пользователями, категориями, журналы (роль «Администратор»)' },
            { name: 'Health',        description: 'Сервисные эндпоинты для мониторинга' }
        ],
        components: {
            securitySchemes: {
                bearerAuth: {
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT',
                    description: 'Access-токен, полученный при `POST /api/login`. В заголовке: `Authorization: Bearer <token>`. Истекает через 15 минут — обновляется через `POST /api/refresh-token` (refresh-cookie ставится при login).'
                }
            },
            schemas: {
                /* ===========  Общие  =========== */
                Error: {
                    type: 'object',
                    required: ['message'],
                    properties: {
                        message: { type: 'string', example: 'Описание ошибки на русском' }
                    }
                },
                PaginatedMeta: {
                    type: 'object',
                    properties: {
                        totalItems: { type: 'integer', example: 137 },
                        page:       { type: 'integer', example: 1 },
                        pageSize:   { type: 'integer', example: 50 }
                    }
                },

                /* ===========  Auth  =========== */
                LoginRequest: {
                    type: 'object',
                    required: ['login', 'password'],
                    properties: {
                        login:    { type: 'string', example: 'admin@vitebskenergo.by', description: 'Email или логин пользователя' },
                        password: { type: 'string', example: 'X12345678!', description: 'Пароль (10–72 символа, минимум буква+цифра+спецсимвол @$!%*#?&)' }
                    }
                },
                LoginResponse: {
                    type: 'object',
                    properties: {
                        message:     { type: 'string', example: 'Вход успешен' },
                        accessToken: { type: 'string', description: 'JWT access-токен (живёт 15 минут). Refresh-токен ставится в httpOnly cookie.' }
                    }
                },
                RefreshResponse: {
                    type: 'object',
                    properties: {
                        accessToken: { type: 'string', description: 'Новый access-токен. Старый refresh-токен инвалидирован, новый — в cookie.' }
                    }
                },

                /* ===========  User / Profile  =========== */
                ProfileMe: {
                    type: 'object',
                    properties: {
                        user: {
                            type: 'object',
                            properties: {
                                id:              { type: 'integer', example: 1 },
                                full_name:       { type: 'string', example: 'Иванов Иван Иванович' },
                                email:           { type: 'string', example: 'i.ivanov@vitebskenergo.by' },
                                login:           { type: 'string', example: 'i.ivanov@vitebskenergo.by' },
                                is_active:       { type: 'boolean' },
                                locked_until:    { type: 'string', format: 'date-time', nullable: true },
                                role_name:       { type: 'string', example: 'Сотрудник' },
                                branch_id:       { type: 'integer', nullable: true },
                                branch_name:     { type: 'string', nullable: true, example: 'Витебская ТЭЦ' },
                                first_login_at:  { type: 'string', format: 'date-time', nullable: true }
                            }
                        },
                        recentLogins: {
                            type: 'array',
                            items: {
                                type: 'object',
                                properties: {
                                    login_time: { type: 'string', format: 'date-time' },
                                    ip_address: { type: 'string', example: '192.168.1.10' }
                                }
                            }
                        }
                    }
                },
                ChangePasswordRequest: {
                    type: 'object',
                    required: ['oldPassword', 'newPassword'],
                    properties: {
                        oldPassword: { type: 'string', example: 'OldPass123!' },
                        newPassword: { type: 'string', example: 'NewPass456@', description: '10–72 символа, минимум буква+цифра+спецсимвол' }
                    }
                },
                AdminUserListItem: {
                    type: 'object',
                    properties: {
                        id:                    { type: 'integer' },
                        full_name:             { type: 'string' },
                        email:                 { type: 'string' },
                        login:                 { type: 'string' },
                        is_active:             { type: 'boolean' },
                        role_id:               { type: 'integer' },
                        role_name:             { type: 'string' },
                        branch_id:             { type: 'integer', nullable: true },
                        branch_name:           { type: 'string', nullable: true },
                        failed_uploads_count:  { type: 'integer' },
                        locked_until:          { type: 'string', format: 'date-time', nullable: true },
                        deleted_at:            { type: 'string', format: 'date-time', nullable: true },
                        violations_24h:        { type: 'integer', description: 'Кол-во нарушений загрузки файлов за последние 24ч' }
                    }
                },
                AdminUserCreate: {
                    type: 'object',
                    required: ['fio', 'email', 'password'],
                    properties: {
                        fio:       { type: 'string', minLength: 5, maxLength: 200, example: 'Петров Пётр Петрович' },
                        email:     { type: 'string', format: 'email', example: 'p.petrov@vitebskenergo.by' },
                        login:     { type: 'string', nullable: true, description: 'По умолчанию = email' },
                        branch_id: { type: 'integer', nullable: true },
                        role_id:   { type: 'integer', example: 2, description: '2=Сотрудник, 3=Модератор, 4=Согласующий. Админа через UI не создать.' },
                        password:  { type: 'string', example: 'StartPass1!', description: '10–72 символа, буква+цифра+спецсимвол' }
                    }
                },
                AdminUserUpdate: {
                    type: 'object',
                    properties: {
                        full_name: { type: 'string' },
                        email:     { type: 'string' },
                        branch_id: { type: 'integer', nullable: true },
                        role_id:   { type: 'integer' },
                        is_active: { type: 'boolean' }
                    }
                },

                /* ===========  Requests  =========== */
                Request: {
                    type: 'object',
                    properties: {
                        id:                  { type: 'integer', example: 42 },
                        title:               { type: 'string', example: 'Заседание комиссии по противодействию коррупции' },
                        status:              { type: 'string', example: 'На модерации', description: 'Имя статуса (см. RequestStatuses).' },
                        creator_name:        { type: 'string' },
                        creator_id:          { type: 'integer' },
                        category_name:       { type: 'string' },
                        category_color:      { type: 'string', example: '#38bdf8' },
                        planned_date:        { type: 'string', format: 'date-time' },
                        docs_count:          { type: 'integer' },
                        comments_count:      { type: 'integer' },
                        has_unread_activity: { type: 'integer', enum: [0, 1] },
                        has_unread_comments: { type: 'integer', enum: [0, 1] },
                        created_at:          { type: 'string', format: 'date-time' },
                        updated_at:          { type: 'string', format: 'date-time' }
                    }
                },
                RequestDetail: {
                    type: 'object',
                    properties: {
                        id:                 { type: 'integer' },
                        title:              { type: 'string' },
                        description:        { type: 'string', nullable: true },
                        status_id:          { type: 'integer' },
                        status_name:        { type: 'string' },
                        creator_id:         { type: 'integer' },
                        creator_name:       { type: 'string' },
                        branch_name:        { type: 'string', nullable: true },
                        category_id:        { type: 'integer', nullable: true },
                        category_name:      { type: 'string', nullable: true },
                        category_color:     { type: 'string', nullable: true },
                        planned_date:       { type: 'string', format: 'date-time' },
                        location:           { type: 'string', nullable: true },
                        expected_attendees: { type: 'integer', nullable: true },
                        responsible_person: { type: 'string', nullable: true },
                        created_at:         { type: 'string', format: 'date-time' },
                        updated_at:         { type: 'string', format: 'date-time' }
                    }
                },
                CreateRequest: {
                    type: 'object',
                    required: ['title', 'planned_date', 'category_id'],
                    properties: {
                        title:              { type: 'string', maxLength: 255, example: 'Совещание по плану ремонта' },
                        description:        { type: 'string', nullable: true },
                        planned_date:       { type: 'string', format: 'date-time', example: '2026-05-20T14:00:00Z' },
                        category_id:        { type: 'integer', example: 3 },
                        location:           { type: 'string', nullable: true, maxLength: 255 },
                        expected_attendees: { type: 'integer', nullable: true, minimum: 1, maximum: 100000 },
                        responsible_person: { type: 'string', nullable: true, maxLength: 255 },
                        documentFiles:      { type: 'array', items: { type: 'string', format: 'binary' }, description: 'multipart-поле: до 10 файлов, каждый ≤ 15МБ' }
                    }
                },
                StatusChangeRequest: {
                    type: 'object',
                    required: ['newStatusId'],
                    properties: {
                        newStatusId: { type: 'integer', example: 3, description: '1=Новая, 2=На модерации, 3=На согласовании, 4=Одобрена, 5=Отклонена, 6=Требует доработки, 7=Отозвана' },
                        details:     { type: 'string', nullable: true, description: 'При REWORK обязательна непустая причина (≥3 символа)' }
                    }
                },
                BatchStatusRequest: {
                    type: 'object',
                    required: ['ids', 'newStatusId'],
                    properties: {
                        ids:         { type: 'array', items: { type: 'integer' }, maxItems: 50, example: [12, 13, 14] },
                        newStatusId: { type: 'integer', example: 3 },
                        details:     { type: 'string', nullable: true, description: 'При REWORK обязательна причина' }
                    }
                },
                BatchStatusResponse: {
                    type: 'object',
                    properties: {
                        results: {
                            type: 'array',
                            items: {
                                type: 'object',
                                properties: {
                                    id:     { type: 'integer' },
                                    ok:     { type: 'boolean' },
                                    reason: { type: 'string', nullable: true, description: 'no_signed_protocol / status_changed / transition_forbidden' }
                                }
                            }
                        }
                    }
                },
                CalendarEvent: {
                    type: 'object',
                    properties: {
                        id:             { type: 'integer' },
                        title:          { type: 'string' },
                        start:          { type: 'string', format: 'date-time' },
                        category_name:  { type: 'string' },
                        category_color: { type: 'string' },
                        status:         { type: 'string' },
                        creator_name:   { type: 'string' }
                    }
                },

                /* ===========  Comments  =========== */
                Comment: {
                    type: 'object',
                    properties: {
                        id:                  { type: 'integer' },
                        user_id:             { type: 'integer' },
                        full_name:           { type: 'string' },
                        comment_text:        { type: 'string', nullable: true, description: 'null для удалённых сообщений' },
                        created_at:          { type: 'string', format: 'date-time' },
                        edited_at:           { type: 'string', format: 'date-time', nullable: true },
                        deleted_at:          { type: 'string', format: 'date-time', nullable: true },
                        reply_to_id:         { type: 'integer', nullable: true },
                        reply_to_user_id:    { type: 'integer', nullable: true },
                        reply_to_user_name:  { type: 'string', nullable: true },
                        reply_to_text:       { type: 'string', nullable: true },
                        reply_to_deleted_at: { type: 'string', format: 'date-time', nullable: true },
                        readers:             { type: 'string', nullable: true, description: 'CSV id юзеров, прочитавших сообщение' },
                        reactions_raw:       { type: 'string', nullable: true, description: '`emoji:user_id;emoji:user_id` — парсится фронтом' }
                    }
                },
                CommentCreate: {
                    type: 'object',
                    required: ['comment_text'],
                    properties: {
                        comment_text: { type: 'string', minLength: 1, maxLength: 5000 },
                        reply_to_id:  { type: 'integer', nullable: true, description: 'ID родительского комментария при ответе' }
                    }
                },
                CommentEdit: {
                    type: 'object',
                    required: ['comment_text'],
                    properties: {
                        comment_text: { type: 'string', minLength: 1, maxLength: 5000 }
                    }
                },
                ReactionToggle: {
                    type: 'object',
                    required: ['emoji'],
                    properties: {
                        emoji: { type: 'string', example: '👍', description: 'Из whitelist: 👍 ❤️ 😂 😢 🔥 👏' }
                    }
                },

                /* ===========  Documents  =========== */
                Document: {
                    type: 'object',
                    properties: {
                        id:                 { type: 'integer' },
                        file_name:          { type: 'string' },
                        uploaded_at:        { type: 'string', format: 'date-time' },
                        uploaded_by_id:     { type: 'integer' },
                        uploaded_by_name:   { type: 'string' },
                        is_signed_protocol: { type: 'boolean', description: 'true = подписанный протокол согласования (прикладывается согласующим при одобрении)' }
                    }
                },

                /* ===========  History  =========== */
                HistoryItem: {
                    type: 'object',
                    properties: {
                        id:         { type: 'integer' },
                        timestamp:  { type: 'string', format: 'date-time' },
                        user_id:    { type: 'integer', nullable: true, description: 'null = системное событие' },
                        full_name:  { type: 'string' },
                        action:     { type: 'string', example: 'Смена статуса' },
                        details:    { type: 'string', nullable: true },
                        is_read:    { type: 'boolean' }
                    }
                },
                AdminLogItem: {
                    type: 'object',
                    properties: {
                        id:         { type: 'integer' },
                        event_time: { type: 'string', format: 'date-time' },
                        user_name:  { type: 'string' },
                        user_id:    { type: 'integer', nullable: true },
                        event_type: { type: 'string', example: 'Вход в систему' },
                        details:    { type: 'string', nullable: true },
                        request_id: { type: 'integer', nullable: true }
                    }
                },

                /* ===========  Notifications  =========== */
                Notification: {
                    type: 'object',
                    properties: {
                        id:           { type: 'integer' },
                        request_id:   { type: 'integer', nullable: true },
                        actor_id:     { type: 'integer', nullable: true },
                        actor_name:   { type: 'string', nullable: true },
                        type:         { type: 'string', enum: ['status_changed', 'new_comment', 'new_document', 'returned_for_rework'] },
                        message:      { type: 'string' },
                        is_read:      { type: 'integer', enum: [0, 1] },
                        created_at:   { type: 'string', format: 'date-time' }
                    }
                },

                /* ===========  Reference  =========== */
                Branch: {
                    type: 'object',
                    properties: {
                        id:   { type: 'integer' },
                        name: { type: 'string', example: 'Витебская ТЭЦ' }
                    }
                },
                Category: {
                    type: 'object',
                    properties: {
                        id:        { type: 'integer' },
                        name:      { type: 'string', example: 'Профилактическое (ОТ, ТБ, ПБ)' },
                        color_hex: { type: 'string', example: '#ef4444' },
                        is_active: { type: 'integer', enum: [0, 1] }
                    }
                },
                CategoryUpsert: {
                    type: 'object',
                    required: ['name', 'color_hex'],
                    properties: {
                        name:      { type: 'string', minLength: 2, maxLength: 100 },
                        color_hex: { type: 'string', pattern: '^#[0-9A-Fa-f]{6}$', example: '#38bdf8' },
                        is_active: { type: 'boolean' }
                    }
                },
                SystemConstants: {
                    type: 'object',
                    description: 'Доменные константы — раздаются фронту один раз при загрузке для синхронизации id ↔ name.',
                    properties: {
                        roles:       { type: 'object', additionalProperties: { type: 'integer' }, example: { ADMIN: 1, EMPLOYEE: 2, MODERATOR: 3, APPROVER: 4 } },
                        roleNames:   { type: 'object', additionalProperties: { type: 'string' } },
                        statuses:    { type: 'object', additionalProperties: { type: 'integer' } },
                        statusNames: { type: 'object', additionalProperties: { type: 'string' } },
                        pdfProtocol: { type: 'object', description: 'Матрица доступа к PDF-протоколу по ключу статуса (APPROVAL/APPROVED/REJECTED)' }
                    }
                },

                /* ===========  Stats  =========== */
                StatsResponse: {
                    type: 'object',
                    properties: {
                        scope: { type: 'string', enum: ['personal', 'approval', 'enterprise'] },
                        kpi: {
                            type: 'object',
                            properties: {
                                total:               { type: 'integer' },
                                approved:            { type: 'integer' },
                                rejected:            { type: 'integer' },
                                in_progress:         { type: 'integer' },
                                avg_approval_hours:  { type: 'number', nullable: true, description: 'Среднее время от создания до одобрения (часы)' }
                            }
                        },
                        byCategory: { type: 'array', items: { type: 'object' } },
                        byBranch:   { type: 'array', items: { type: 'object' } },
                        byMonth:    { type: 'array', items: { type: 'object' } }
                    }
                },

                /* ===========  Health  =========== */
                HealthResponse: {
                    type: 'object',
                    properties: {
                        status:    { type: 'string', enum: ['ok', 'degraded'] },
                        db:        { type: 'string', enum: ['ok', 'fail'] },
                        uploads:   { type: 'string', enum: ['ok', 'fail'] },
                        timestamp: { type: 'string', format: 'date-time' }
                    }
                }
            },
            responses: {
                Unauthorized: {
                    description: 'Токен отсутствует, истёк или невалиден',
                    content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } }
                },
                Forbidden: {
                    description: 'Недостаточно прав для операции',
                    content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } }
                },
                NotFound: {
                    description: 'Сущность не найдена ИЛИ пользователь не имеет к ней доступа (намеренно одинаковый код — anti-enumeration)',
                    content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } }
                },
                TooManyRequests: {
                    description: 'Превышен rate-limit',
                    content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } }
                },
                Conflict: {
                    description: 'Состояние ресурса не позволяет операцию (optimistic concurrency, transition mismatch)',
                    content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } }
                }
            }
        },
        security: [{ bearerAuth: [] }]
    },
    apis: [require('path').join(__dirname, '..', 'server.js')]
});

module.exports = { swaggerSpec };
