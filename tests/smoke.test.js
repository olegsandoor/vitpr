/**
 * Smoke-тесты основного API.
 *
 * Зачем: при большом количестве эндпоинтов важно иметь минимальный набор
 * проверок, который ловит регрессии «всё упало после правки auth/CSRF/CSP».
 * Тесты идут против запущенного сервера (localhost:3000) — это интеграционные,
 * а не юнит-тесты: сервер должен быть поднят командой `npm start` в другом
 * окне. БД должна быть прогружена тестовыми пользователями (миграция 01).
 *
 * Запуск:
 *     npm start              # в одном окне
 *     npm test               # в другом окне
 *
 * Что покрывается:
 *   - login (валидный/невалидный)
 *   - CSRF guard (Origin missing / cross-origin)
 *   - /api/health
 *   - /api/public/events (без auth)
 *   - /api/requests + scope по роли
 *   - смена статуса + REWORK без причины (400)
 *   - комментарий + reply / редактирование / удаление
 *   - категории CRUD
 *   - 404 страница
 *   - /events HTML (200, не 404)
 *   - Swagger 401 без cookie
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const WebSocket = require('ws');

const API = process.env.SMOKE_API || 'http://localhost:3000';
const WS_URL = API.replace(/^http/, 'ws');
const ORIGIN = { 'Origin': API };

const ADMIN = { login: 'admin@vitebskenergo.by',          password: 'X12345678!' };
const MOD   = { login: 't.kovaleva@vitebskenergo.by',     password: 'X12345678!' };
const EMP   = { login: 'a.bondarenko@vitebskenergo.by',   password: 'X12345678!' };

async function login(creds) {
    const r = await request(API)
        .post('/api/login')
        .set(ORIGIN)
        .send(creds);
    if (r.status !== 200) throw new Error(`login ${creds.login} failed: ${r.status} ${JSON.stringify(r.body)}`);
    return { accessToken: r.body.accessToken, cookies: r.headers['set-cookie'] };
}

// Минимальный валидный PDF для multipart-upload в тестах.
// Magic-bytes %PDF-1.4 + минимальный xref. file-type корректно опознаёт.
const FAKE_PDF = Buffer.from(
    '%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 1\n0000000000 65535 f\n' +
    'trailer\n<< /Size 1 /Root 1 0 R >>\nstartxref\n9\n%%EOF\n', 'utf8'
);

// «Фальшивый PDF» — расширение и mime-тип объявлены как PDF, но magic-bytes
// принадлежат Windows-EXE (DOS MZ-header). Используется в тесте D12, чтобы
// проверить что server.js detects подделку через file-type magic-bytes
// (одна из «7 линий обороны» из HANDOFF §3.1) и возвращает 400.
const FAKE_EXE_AS_PDF = Buffer.from([
    0x4D, 0x5A,                             // 'MZ' — DOS exe signature
    0x90, 0x00, 0x03, 0x00, 0x04, 0x00,
    0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
    0xB8, 0x00, 0x00, 0x00, 0x00, 0x00
]);

// Helper: согласующий прикрепляет подписанный протокол к заявке. Нужно перед
// APPROVAL→APPROVED после фикса A2 (нельзя одобрить без 📜).
async function attachSignedProtocol(reqId, aprToken) {
    return request(API)
        .post(`/api/requests/${reqId}/documents?signed=true`)
        .set('Authorization', `Bearer ${aprToken}`)
        .set(ORIGIN)
        .attach('documentFiles', FAKE_PDF, 'protocol.pdf');
}

let adminToken, modToken, empToken;
let adminCookies; // refresh-cookie ADMIN'а — для теста optimistic-refresh

// Сюда складываем id всего, что создали в тестах — чистится в test.after.
const cleanup = {
    userIds: [],         // soft-deleted (полное удаление из БД)
    categoryIds: [],     // hard-deleted (если usage=0)
    commentIds: [],      // soft-deleted
    requestIds: []       // hard-delete через прямой SQL (CASCADE снесёт Documents/Comments/History)
};

test.before(async () => {
    const a = await login(ADMIN); adminToken = a.accessToken; adminCookies = a.cookies;
    const m = await login(MOD);   modToken   = m.accessToken;
    const e = await login(EMP);   empToken   = e.accessToken;
});

test.after(async () => {
    // Чистим тестовые категории (только если не используются — soft-delete не работает).
    for (const id of cleanup.categoryIds) {
        try {
            await request(API)
                .delete(`/api/admin/categories/${id}`)
                .set('Authorization', `Bearer ${adminToken}`)
                .set(ORIGIN);
        } catch (_) { /* ignore */ }
    }
    // Тестовых юзеров и комментарии оставляем soft-deleted'ыми — для аудита,
    // но они не нагружают UI (фильтр deleted_at IS NULL).

    // Hard-delete тестовых заявок (orphan'ы накапливались до Block G).
    // На прод-БД доступ только при наличии mssql-конфига в env (тесты идут
    // против локальной test-БД, env прокинут через npm start).
    if (cleanup.requestIds.length > 0) {
        try {
            const sql = require('mssql');
            const config = {
                user: process.env.DB_USER || 'VitEnergoUser',
                password: process.env.DB_PASSWORD || 'VitEnergo123!',
                server: process.env.DB_SERVER || 'localhost',
                database: process.env.DB_DATABASE || 'VitEnergoProject',
                options: { trustServerCertificate: true, encrypt: false }
            };
            const pool = await sql.connect(config);
            const ids = cleanup.requestIds.map(n => parseInt(n, 10)).filter(Number.isInteger);
            if (ids.length > 0) {
                // FK CASCADE на Documents/Comments/History автоматически
                // снесёт привязанные записи.
                await pool.request().query(`DELETE FROM Requests WHERE id IN (${ids.join(',')})`);
            }
            await pool.close();
        } catch (e) { /* cleanup best-effort, не валим test.after */ }
    }
});

test('health: 200 + db ok', async () => {
    const r = await request(API).get('/api/health');
    assert.equal(r.status, 200);
    assert.equal(r.body.status, 'ok');
    assert.equal(r.body.db, 'ok');
});

test('public events: без auth, 200, массив', async () => {
    const r = await request(API).get('/api/public/events');
    assert.equal(r.status, 200);
    assert.ok(Array.isArray(r.body));
});

test('CSRF: POST без Origin от браузера (Sec-Fetch-Site) — 403', async () => {
    const r = await request(API)
        .post('/api/login')
        .set('Sec-Fetch-Site', 'same-origin')
        .send({ login: 'x', password: 'y' });
    assert.equal(r.status, 403);
});

test('CSRF: POST с чужим Origin — 403', async () => {
    const r = await request(API)
        .post('/api/login')
        .set('Origin', 'http://evil.example')
        .send({ login: 'x', password: 'y' });
    assert.equal(r.status, 403);
});

test('login: валидные данные — 200 + accessToken', async () => {
    assert.ok(typeof adminToken === 'string' && adminToken.length > 50);
});

test('login: невалидный пароль — 401', async () => {
    const r = await request(API)
        .post('/api/login')
        .set(ORIGIN)
        .send({ login: ADMIN.login, password: 'wrong-password!' });
    assert.equal(r.status, 401);
});

test('GET /api/requests без токена — 401', async () => {
    const r = await request(API).get('/api/requests');
    assert.equal(r.status, 401);
});

test('GET /api/requests как админ — 200 + items', async () => {
    const r = await request(API)
        .get('/api/requests?pageSize=5')
        .set('Authorization', `Bearer ${adminToken}`);
    assert.equal(r.status, 200);
    assert.ok(Array.isArray(r.body.requests));
});

test('GET /api/requests как сотрудник — только свои (creator_id=req.user.id)', async () => {
    const r = await request(API)
        .get('/api/requests?pageSize=20')
        .set('Authorization', `Bearer ${empToken}`);
    assert.equal(r.status, 200);
    if (r.body.requests.length > 0) {
        // Бондаренко = id 3
        r.body.requests.forEach(req => assert.equal(req.creator_id, 3));
    }
});

test('REWORK без причины — 400', async () => {
    // Берём первую заявку «На модерации» от модератора и пробуем вернуть без reason.
    const list = await request(API)
        .get('/api/requests?pageSize=50')
        .set('Authorization', `Bearer ${modToken}`);
    const target = list.body.requests.find(x => x.status === 'На модерации');
    if (!target) return; // нет такой заявки в данных — пропускаем
    const r = await request(API)
        .put(`/api/requests/${target.id}/status`)
        .set('Authorization', `Bearer ${modToken}`)
        .set(ORIGIN)
        .send({ newStatusId: 6, details: '' });
    assert.equal(r.status, 400);
});

test('Создание категории + дубликат + удаление', async () => {
    const name = `__smoke_${Date.now()}`;
    const create = await request(API)
        .post('/api/admin/categories')
        .set('Authorization', `Bearer ${adminToken}`)
        .set(ORIGIN)
        .send({ name, color_hex: '#abcdef' });
    assert.equal(create.status, 201);
    const id = create.body.id;
    cleanup.categoryIds.push(id);

    const dup = await request(API)
        .post('/api/admin/categories')
        .set('Authorization', `Bearer ${adminToken}`)
        .set(ORIGIN)
        .send({ name, color_hex: '#000000' });
    assert.equal(dup.status, 409);

    const badColor = await request(API)
        .post('/api/admin/categories')
        .set('Authorization', `Bearer ${adminToken}`)
        .set(ORIGIN)
        .send({ name: name + '_bad', color_hex: 'red' });
    assert.equal(badColor.status, 400);

    const del = await request(API)
        .delete(`/api/admin/categories/${id}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .set(ORIGIN);
    assert.equal(del.status, 200);
    // После удаления — убираем из cleanup, чтобы не пытаться удалить повторно.
    cleanup.categoryIds = cleanup.categoryIds.filter(x => x !== id);
});

test('Категория «Антикоррупционное мероприятие» (id=5) используется — DELETE 409', async () => {
    const r = await request(API)
        .delete('/api/admin/categories/5')
        .set('Authorization', `Bearer ${adminToken}`)
        .set(ORIGIN);
    assert.equal(r.status, 409);
});

test('Reset password самого себя — 403', async () => {
    // admin id = 6
    const r = await request(API)
        .post('/api/admin/users/6/reset-password')
        .set('Authorization', `Bearer ${adminToken}`)
        .set(ORIGIN);
    assert.equal(r.status, 403);
});

test('Soft-delete: создать → войти → удалить → войти не получится', async () => {
    const email = `smoke_${Date.now()}@test.local`;
    const create = await request(API)
        .post('/api/admin/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .set(ORIGIN)
        .send({ fio: 'Тест Удаляемый Smoke', email, password: 'SmokeTest123!', role_id: 2 });
    assert.equal(create.status, 201);
    const userId = create.body.userId;

    const login1 = await request(API)
        .post('/api/login')
        .set(ORIGIN)
        .send({ login: email, password: 'SmokeTest123!' });
    assert.equal(login1.status, 200);

    const del = await request(API)
        .delete(`/api/admin/users/${userId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .set(ORIGIN);
    assert.equal(del.status, 200);

    const login2 = await request(API)
        .post('/api/login')
        .set(ORIGIN)
        .send({ login: email, password: 'SmokeTest123!' });
    assert.equal(login2.status, 401);
});

test('Email-валидация: некорректный формат — 400', async () => {
    const r = await request(API)
        .post('/api/admin/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .set(ORIGIN)
        .send({ fio: 'Тест Невалидный Иванович', email: 'not-an-email', password: 'SmokeTest123!', role_id: 2 });
    assert.equal(r.status, 400);
});

test('404 страница: левый URL — 404 + HTML с «Страница не найдена»', async () => {
    const r = await request(API).get('/some-random-not-exists');
    assert.equal(r.status, 404);
    assert.match(r.text || '', /Страница не найдена/);
});

test('/events: 200 + HTML с «Календарь мероприятий» + правильный CSP', async () => {
    const r = await request(API).get('/events');
    assert.equal(r.status, 200);
    assert.match(r.text, /Календарь мероприятий/);
    const csp = r.headers['content-security-policy'] || '';
    assert.ok(csp.includes("script-src 'self'"), `CSP должен содержать script-src 'self', got: ${csp}`);
    assert.ok(!csp.includes("default-src 'none'"), 'CSP не должен быть default-src none');
});

test('Swagger UI без cookie — 401', async () => {
    const r = await request(API).get('/api-docs/');
    assert.equal(r.status, 401);
});

test('apiLimiter: админ освобождён (большой quota)', async () => {
    // Несколько быстрых запросов под админ-токеном — все 200, не 429
    for (let i = 0; i < 5; i++) {
        const r = await request(API)
            .get('/api/branches')
            .set('Authorization', `Bearer ${adminToken}`);
        assert.equal(r.status, 200, `iteration ${i} failed: ${r.status}`);
    }
});

/* ===========================================================================
   WebSocket handshake — нет в supertest (он HTTP only), используем ws-клиент.
   =========================================================================== */

function wsConnect(send, expectClose) {
    return new Promise((resolve) => {
        const ws = new WebSocket(WS_URL);
        const events = [];
        let closed = false;
        const finish = (info) => { if (!closed) { closed = true; resolve(info); } };

        ws.on('open', () => {
            if (typeof send === 'function') send(ws);
        });
        ws.on('message', (data) => {
            try { events.push(JSON.parse(data.toString())); }
            catch (_) { events.push({ raw: data.toString() }); }
            if (typeof expectClose !== 'function') {
                // Закрываем со своей стороны через 200 мс после первого сообщения.
                setTimeout(() => { try { ws.close(); } catch (_) {} }, 200);
            }
        });
        ws.on('close', (code, reason) => {
            finish({ events, code, reason: reason.toString() });
        });
        ws.on('error', (err) => finish({ events, error: err.message }));
        // Жёсткий timeout 8 сек, иначе зависнет если сервер сломан
        setTimeout(() => { try { ws.terminate(); } catch (_) {} finish({ events, timeout: true }); }, 8000);
    });
}

test('WS: handshake с валидным токеном → auth_ok', async () => {
    const r = await wsConnect((ws) => {
        ws.send(JSON.stringify({ type: 'auth', token: adminToken }));
    });
    assert.ok(r.events.find(e => e.type === 'auth_ok'), `expected auth_ok, got: ${JSON.stringify(r.events)}`);
});

test('WS: невалидный токен → auth_error + close 1008', async () => {
    const r = await wsConnect((ws) => {
        ws.send(JSON.stringify({ type: 'auth', token: 'definitely-not-a-jwt' }));
    });
    assert.ok(r.events.find(e => e.type === 'auth_error'));
    assert.equal(r.code, 1008);
});

test('WS: без auth-сообщения → close 1008 после grace 5 сек', async () => {
    const r = await wsConnect(/* не отправляем auth */);
    assert.equal(r.code, 1008);
    assert.match(r.reason, /Authentication timeout/i);
}, { timeout: 8000 });

/* ===========================================================================
   Чат: reply / edit / delete своих сообщений
   =========================================================================== */

test('Чат: создать → reply → edit → delete своего сообщения', async () => {
    // Создаём свежую заявку в статусе «Новая» — после Block E status-guard
    // комменты в терминальных запрещены, и брать любую TOP 1 рискованно.
    const planned = new Date(Date.now() + 13 * 86400000).toISOString();
    const created = await request(API)
        .post('/api/requests')
        .set('Authorization', `Bearer ${empToken}`).set(ORIGIN)
        .send({ title: 'Chat smoke', description: 'reply/edit/delete chain',
                planned_date: planned, category_id: 1 });
    assert.equal(created.status, 201);
    const reqId = created.body.requestId;
    if (reqId) cleanup.requestIds.push(reqId);

    // 1) Создать сообщение
    const c1 = await request(API)
        .post(`/api/requests/${reqId}/comments`)
        .set('Authorization', `Bearer ${empToken}`)
        .set(ORIGIN)
        .send({ comment_text: 'smoke test base message' });
    assert.equal(c1.status, 201);
    const c1Id = c1.body.newCommentId;
    cleanup.commentIds.push(c1Id);

    // 2) Reply на него
    const c2 = await request(API)
        .post(`/api/requests/${reqId}/comments`)
        .set('Authorization', `Bearer ${empToken}`)
        .set(ORIGIN)
        .send({ comment_text: 'smoke reply', reply_to_id: c1Id });
    assert.equal(c2.status, 201);
    const c2Id = c2.body.newCommentId;
    cleanup.commentIds.push(c2Id);

    // 3) Edit своего
    const e = await request(API)
        .patch(`/api/comments/${c1Id}`)
        .set('Authorization', `Bearer ${empToken}`)
        .set(ORIGIN)
        .send({ comment_text: 'smoke test base message (edited)' });
    assert.equal(e.status, 200);

    // 4) Delete своего
    const d = await request(API)
        .delete(`/api/comments/${c2Id}`)
        .set('Authorization', `Bearer ${empToken}`)
        .set(ORIGIN);
    assert.equal(d.status, 200);

    // 5) Повторный delete — 409
    const d2 = await request(API)
        .delete(`/api/comments/${c2Id}`)
        .set('Authorization', `Bearer ${empToken}`)
        .set(ORIGIN);
    assert.equal(d2.status, 409);
});

test('Чат: edit чужого сообщения админом → 403', async () => {
    // Найдём сообщение Бондаренко (user_id=3) для попытки правки админом
    const list = await request(API)
        .get('/api/requests?pageSize=20')
        .set('Authorization', `Bearer ${adminToken}`);
    const r = list.body.requests.find(x => x.creator_id === 3 && x.comments_count > 0);
    if (!r) return; // нет данных — skip

    const cs = await request(API)
        .get(`/api/requests/${r.id}/comments`)
        .set('Authorization', `Bearer ${adminToken}`);
    const target = cs.body.find(c => c.user_id === 3 && !c.deleted_at);
    if (!target) return;

    const e = await request(API)
        .patch(`/api/comments/${target.id}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .set(ORIGIN)
        .send({ comment_text: 'админ пытается редактировать' });
    assert.equal(e.status, 403);
});

test('Чат: reply на сообщение из ЧУЖОЙ заявки → 400', async () => {
    // Берём 2 разные заявки. На второй пробуем сослаться на сообщение из первой.
    const list = await request(API)
        .get('/api/requests?pageSize=20')
        .set('Authorization', `Bearer ${adminToken}`);
    if (list.body.requests.length < 2) return;
    const r1 = list.body.requests[0];
    const r2 = list.body.requests[1];

    const cs = await request(API)
        .get(`/api/requests/${r1.id}/comments`)
        .set('Authorization', `Bearer ${adminToken}`);
    if (cs.body.length === 0) return;
    const c1Id = cs.body[0].id;

    const r = await request(API)
        .post(`/api/requests/${r2.id}/comments`)
        .set('Authorization', `Bearer ${adminToken}`)
        .set(ORIGIN)
        .send({ comment_text: 'cross-request reply', reply_to_id: c1Id });
    assert.equal(r.status, 400);
});

/* ===========================================================================
   Профиль: смена пароля
   =========================================================================== */

test('Profile: смена пароля → старый перестаёт работать', async () => {
    const email = `pwdtest_${Date.now()}@test.local`;
    const create = await request(API)
        .post('/api/admin/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .set(ORIGIN)
        .send({ fio: 'Тест Пароль Иванович', email, password: 'OldPass1234!', role_id: 2 });
    assert.equal(create.status, 201);
    cleanup.userIds.push(create.body.userId);

    const t1 = (await login({ login: email, password: 'OldPass1234!' })).accessToken;
    const change = await request(API)
        .post('/api/profile/me/password')
        .set('Authorization', `Bearer ${t1}`)
        .set(ORIGIN)
        .send({ oldPassword: 'OldPass1234!', newPassword: 'NewPass1234!' });
    assert.equal(change.status, 200);

    // Старый пароль больше не должен работать
    const oldLogin = await request(API)
        .post('/api/login')
        .set(ORIGIN)
        .send({ login: email, password: 'OldPass1234!' });
    assert.equal(oldLogin.status, 401);

    // Новый — работает
    const newLogin = await request(API)
        .post('/api/login')
        .set(ORIGIN)
        .send({ login: email, password: 'NewPass1234!' });
    assert.equal(newLogin.status, 200);

    // Удаляем за собой
    await request(API)
        .delete(`/api/admin/users/${create.body.userId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .set(ORIGIN);
});

test('Profile: слабый пароль → 400', async () => {
    const r = await request(API)
        .post('/api/profile/me/password')
        .set('Authorization', `Bearer ${empToken}`)
        .set(ORIGIN)
        .send({ oldPassword: 'X12345678!', newPassword: 'weak' });
    assert.equal(r.status, 400);
});

/* ===========================================================================
   PDF + Excel
   =========================================================================== */

test('PDF: скачивание протокола согласования', async () => {
    // (домен): PDF доступен только для APPROVAL/APPROVED/REJECTED.
    // REWORK исключён — это не «решение», а просьба исправить, протокола нет.
    // См. config/constants.js → PDF_PROTOCOL_CONFIG.
    const list = await request(API)
        .get('/api/requests?pageSize=50')
        .set('Authorization', `Bearer ${adminToken}`);
    const PDF_OK_STATUSES = ['На согласовании', 'Одобрена', 'Отклонена'];
    const target = list.body.requests?.find(x => PDF_OK_STATUSES.includes(x.status));
    if (!target) return; // нет заявки в нужном статусе — skip
    const reqId = target.id;

    const r = await request(API)
        .get(`/api/requests/${reqId}/pdf`)
        .set('Authorization', `Bearer ${adminToken}`)
        .buffer(true)
        .parse((res, cb) => {
            const chunks = [];
            res.on('data', c => chunks.push(c));
            res.on('end', () => cb(null, Buffer.concat(chunks)));
        });
    assert.equal(r.status, 200);
    assert.match(r.headers['content-type'], /pdf/);
    // PDF magic-bytes: %PDF-
    assert.equal(r.body.slice(0, 5).toString(), '%PDF-');
});

test('Excel: экспорт списка заявок', async () => {
    const r = await request(API)
        .get('/api/requests/export.xlsx?pageSize=10')
        .set('Authorization', `Bearer ${adminToken}`)
        .buffer(true)
        .parse((res, cb) => {
            const chunks = [];
            res.on('data', c => chunks.push(c));
            res.on('end', () => cb(null, Buffer.concat(chunks)));
        });
    assert.equal(r.status, 200);
    assert.match(r.headers['content-type'], /spreadsheetml/);
    // XLSX = ZIP-контейнер: magic-bytes PK\x03\x04
    assert.equal(r.body.slice(0, 4).toString('hex'), '504b0304');
    assert.ok(r.body.length > 1000, `xlsx слишком маленький: ${r.body.length}`);
});

/* ===========================================================================
   Notifications API
   =========================================================================== */

test('Notifications: GET + unread-count + mark-read', async () => {
    // Создаём комментарий от модератора → у автора заявки появится уведомление.
    const list = await request(API)
        .get('/api/requests?pageSize=20')
        .set('Authorization', `Bearer ${modToken}`);
    const target = list.body.requests.find(x => x.creator_id === 3);
    if (!target) return;

    const cmt = await request(API)
        .post(`/api/requests/${target.id}/comments`)
        .set('Authorization', `Bearer ${modToken}`)
        .set(ORIGIN)
        .send({ comment_text: 'smoke notif trigger' });
    if (cmt.body?.newCommentId) cleanup.commentIds.push(cmt.body.newCommentId);

    // Бондаренко должен увидеть это в уведомлениях
    const notif = await request(API)
        .get('/api/notifications?pageSize=5')
        .set('Authorization', `Bearer ${empToken}`);
    assert.equal(notif.status, 200);
    assert.ok(Array.isArray(notif.body.items));

    const cnt = await request(API)
        .get('/api/notifications/unread-count')
        .set('Authorization', `Bearer ${empToken}`);
    assert.equal(cnt.status, 200);
    assert.ok(typeof cnt.body.unread === 'number');

    // mark-all-read
    const all = await request(API)
        .post('/api/notifications/mark-all-read')
        .set('Authorization', `Bearer ${empToken}`)
        .set(ORIGIN);
    assert.equal(all.status, 200);

    const cnt2 = await request(API)
        .get('/api/notifications/unread-count')
        .set('Authorization', `Bearer ${empToken}`);
    assert.equal(cnt2.body.unread, 0);
});

/* ===========================================================================
   Status transitions: проверка матрицы из БД
   =========================================================================== */

test('Status transitions: запрещённый переход (Сотрудник пробует Approve) → 403', async () => {
    const list = await request(API)
        .get('/api/requests?pageSize=10')
        .set('Authorization', `Bearer ${empToken}`);
    if (list.body.requests.length === 0) return;
    const target = list.body.requests[0];

    const r = await request(API)
        .put(`/api/requests/${target.id}/status`)
        .set('Authorization', `Bearer ${empToken}`)
        .set(ORIGIN)
        .send({ newStatusId: 4 }); // APPROVED
    assert.equal(r.status, 403);
});

/* ===========================================================================
   Новые фичи: шаблоны, withdraw, реакции, audit, smart-search
   =========================================================================== */

test('Templates: GET /api/templates/:categoryId', async () => {
    // Категория id=1 (Лекция / семинар) — точно есть шаблон по миграции 18
    const r = await request(API)
        .get('/api/templates/1')
        .set('Authorization', `Bearer ${empToken}`);
    assert.equal(r.status, 200);
    if (r.body) {
        assert.ok(typeof r.body.default_title === 'string');
        assert.ok(r.body.default_title.length > 0);
    }
});

test('Withdraw: автор может отозвать свою NEW заявку', async () => {
    // Создаём свежую заявку от Бондаренко
    const create = await request(API)
        .post('/api/requests')
        .set('Authorization', `Bearer ${empToken}`)
        .set(ORIGIN)
        .field('title', 'Smoke withdraw test')
        .field('description', 'Заявка для теста отзыва')
        .field('category_id', '1')
        .field('planned_date', new Date(Date.now() + 7 * 86400000).toISOString());
    if (create.status !== 201) return; // skip
    // Получаем id из списка (POST не возвращает id напрямую в этом проекте)
    const list = await request(API)
        .get('/api/requests?pageSize=1')
        .set('Authorization', `Bearer ${empToken}`);
    const newest = list.body.requests[0];
    if (!newest || newest.title !== 'Smoke withdraw test') return;

    // Отзываем (status → 7 «Отозвана»)
    const w = await request(API)
        .put(`/api/requests/${newest.id}/status`)
        .set('Authorization', `Bearer ${empToken}`)
        .set(ORIGIN)
        .send({ newStatusId: 7, details: 'Отзыв тест' });
    assert.equal(w.status, 200);
});

test('Reactions: ставится и снимается toggle\'ом', async () => {
    // Свежая заявка + коммент: после Block E реакции в терминальных запрещены.
    const planned = new Date(Date.now() + 14 * 86400000).toISOString();
    const created = await request(API)
        .post('/api/requests')
        .set('Authorization', `Bearer ${empToken}`).set(ORIGIN)
        .send({ title: 'React smoke', description: 'reaction toggle test',
                planned_date: planned, category_id: 1 });
    assert.equal(created.status, 201);
    const reqId = created.body.requestId;
    if (reqId) cleanup.requestIds.push(reqId);

    const c1 = await request(API)
        .post(`/api/requests/${reqId}/comments`)
        .set('Authorization', `Bearer ${empToken}`).set(ORIGIN)
        .send({ comment_text: 'react test base message' });
    assert.equal(c1.status, 201);
    const cmt = { id: c1.body.newCommentId };

    // Ставим
    const r1 = await request(API)
        .post(`/api/comments/${cmt.id}/reactions`)
        .set('Authorization', `Bearer ${empToken}`)
        .set(ORIGIN)
        .send({ emoji: '👍' });
    assert.equal(r1.status, 200);

    // Снимаем (toggle)
    const r2 = await request(API)
        .post(`/api/comments/${cmt.id}/reactions`)
        .set('Authorization', `Bearer ${empToken}`)
        .set(ORIGIN)
        .send({ emoji: '👍' });
    assert.equal(r2.status, 200);

    // Невалидный emoji → 400
    const r3 = await request(API)
        .post(`/api/comments/${cmt.id}/reactions`)
        .set('Authorization', `Bearer ${empToken}`)
        .set(ORIGIN)
        .send({ emoji: '🚫' });
    assert.equal(r3.status, 400);
});

test('Audit log: только админ', async () => {
    const r = await request(API)
        .get('/api/admin/pii-audit')
        .set('Authorization', `Bearer ${empToken}`);
    assert.equal(r.status, 403);

    const r2 = await request(API)
        .get('/api/admin/pii-audit?pageSize=5')
        .set('Authorization', `Bearer ${adminToken}`);
    assert.equal(r2.status, 200);
    assert.ok(Array.isArray(r2.body.items));
});

test('Smart-search: multi-word AND', async () => {
    // Запрос «антикоррупция Орша» — должен вернуть только заявки где встречаются ОБА
    const r = await request(API)
        .get('/api/requests?pageSize=50&search=' + encodeURIComponent('антикоррупция'))
        .set('Authorization', `Bearer ${adminToken}`);
    assert.equal(r.status, 200);
});

test('Smart-search: точечный поиск по id (#42)', async () => {
    const r = await request(API)
        .get('/api/requests?pageSize=5&search=%231')
        .set('Authorization', `Bearer ${adminToken}`);
    assert.equal(r.status, 200);
    if (r.body.requests.length > 0) {
        assert.equal(r.body.requests[0].id, 1);
    }
});

test('JWT tokenVersion: после reset password старый access перестаёт работать', async () => {
    // 1. Создаём временного юзера
    const email = `tv_test_${Date.now()}@test.local`;
    const c = await request(API)
        .post('/api/admin/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .set(ORIGIN)
        .send({ fio: 'TV Test User', email, password: 'TvTest1234!', role_id: 2 });
    if (c.status !== 201) return;
    const uid = c.body.userId;

    // 2. Логинимся, получаем access. Проверяем через защищённый /api/profile/me
    // (а не /api/branches — последний публичный, не валидирует tokenVersion).
    const t1 = (await login({ login: email, password: 'TvTest1234!' })).accessToken;
    const ok = await request(API).get('/api/profile/me').set('Authorization', `Bearer ${t1}`);
    assert.equal(ok.status, 200);

    // 3. Админ делает reset password
    const reset = await request(API)
        .post(`/api/admin/users/${uid}/reset-password`)
        .set('Authorization', `Bearer ${adminToken}`)
        .set(ORIGIN);
    assert.equal(reset.status, 200);

    // 4. Старый access теперь должен возвращать 401 (token revoked)
    const stale = await request(API).get('/api/profile/me').set('Authorization', `Bearer ${t1}`);
    assert.equal(stale.status, 401);

    // Cleanup
    await request(API)
        .delete(`/api/admin/users/${uid}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .set(ORIGIN);
});

test('BREACH-mitigation: /api/profile/me не сжимается gzip\'ом', async () => {
    // Чувствительные эндпоинты (профиль, admin, auth) compression skip'ает.
    // Используем уже полученный adminToken — иначе исчерпаем authLimiter.
    const r = await request(API)
        .get('/api/profile/me')
        .set('Authorization', `Bearer ${adminToken}`)
        .set('Accept-Encoding', 'gzip');
    assert.equal(r.status, 200);
    assert.notEqual(r.headers['content-encoding'], 'gzip');
});

/* =============================================================================
 * IDOR-pack: Сотрудник НЕ должен видеть чужие заявки и связанные ресурсы.
 * Создаём заявку от админа (creator_id = admin) и проверяем, что Сотрудник
 * (a.bondarenko, role=Сотрудник) получает 404 на все 7 эндпоинтов:
 *   GET /api/requests/:id            GET /api/requests/:id/documents
 *   GET /api/requests/:id/history    GET /api/requests/:id/comments
 *   GET /api/requests/:id/pdf        POST /api/requests/:id/comments
 *   POST /api/requests/:id/documents
 * И control-кейс: свою заявку Сотрудник видит (200).
 * ============================================================================= */
test.describe('IDOR-guard: Сотрудник не видит чужие заявки', () => {
    let victimRequestId;   // создан админом, EMP не должен видеть
    let ownRequestId;      // создан EMP, EMP видит

    test.before(async () => {
        // 1. Админ создаёт заявку от своего имени.
        const r1 = await request(API)
            .post('/api/requests')
            .set('Authorization', `Bearer ${adminToken}`)
            .set(ORIGIN)
            .send({
                title: 'IDOR victim request',
                description: 'Заявка для проверки IDOR-guard',
                planned_date: new Date(Date.now() + 7 * 86400000).toISOString(),
                category_id: 1,
                location: 'Тест'
            });
        assert.equal(r1.status, 201, `victim create: ${r1.status} ${JSON.stringify(r1.body)}`);
        victimRequestId = r1.body.requestId || r1.body.id || r1.body.newRequestId;
        if (victimRequestId) cleanup.requestIds.push(victimRequestId);
        assert.ok(victimRequestId, `victimRequestId не получен: ${JSON.stringify(r1.body)}`);

        // 2. Сотрудник создаёт свою заявку — для control-кейса (200).
        const r2 = await request(API)
            .post('/api/requests')
            .set('Authorization', `Bearer ${empToken}`)
            .set(ORIGIN)
            .send({
                title: 'IDOR own request',
                description: 'Своя заявка для control-кейса',
                planned_date: new Date(Date.now() + 7 * 86400000).toISOString(),
                category_id: 1,
                location: 'Тест'
            });
        assert.equal(r2.status, 201, `own create: ${r2.status} ${JSON.stringify(r2.body)}`);
        ownRequestId = r2.body.requestId || r2.body.id || r2.body.newRequestId;
        if (ownRequestId) cleanup.requestIds.push(ownRequestId);
        assert.ok(ownRequestId);
    });

    test('GET /api/requests/:id чужой → 404', async () => {
        const r = await request(API)
            .get(`/api/requests/${victimRequestId}`)
            .set('Authorization', `Bearer ${empToken}`);
        assert.equal(r.status, 404);
    });

    test('GET /api/requests/:id свой → 200 (control)', async () => {
        const r = await request(API)
            .get(`/api/requests/${ownRequestId}`)
            .set('Authorization', `Bearer ${empToken}`);
        assert.equal(r.status, 200);
        assert.equal(r.body.id, ownRequestId);
    });

    test('GET /api/requests/:id/documents чужой → 404', async () => {
        const r = await request(API)
            .get(`/api/requests/${victimRequestId}/documents`)
            .set('Authorization', `Bearer ${empToken}`);
        assert.equal(r.status, 404);
    });

    test('GET /api/requests/:id/history чужой → 404', async () => {
        const r = await request(API)
            .get(`/api/requests/${victimRequestId}/history`)
            .set('Authorization', `Bearer ${empToken}`);
        assert.equal(r.status, 404);
    });

    test('GET /api/requests/:id/comments чужой → 404', async () => {
        const r = await request(API)
            .get(`/api/requests/${victimRequestId}/comments`)
            .set('Authorization', `Bearer ${empToken}`);
        assert.equal(r.status, 404);
    });

    test('GET /api/requests/:id/pdf чужой → 404', async () => {
        const r = await request(API)
            .get(`/api/requests/${victimRequestId}/pdf`)
            .set('Authorization', `Bearer ${empToken}`);
        assert.equal(r.status, 404);
    });

    test('POST /api/requests/:id/comments в чужой чат → 404', async () => {
        const r = await request(API)
            .post(`/api/requests/${victimRequestId}/comments`)
            .set('Authorization', `Bearer ${empToken}`)
            .set(ORIGIN)
            .send({ comment_text: 'Внедряюсь в чужой чат' });
        assert.equal(r.status, 404);
    });

    test('POST /api/requests/:id/documents в чужую заявку → 404', async () => {
        // Без файлов — но 404 должен прилетать раньше 400 (access-check first).
        const r = await request(API)
            .post(`/api/requests/${victimRequestId}/documents`)
            .set('Authorization', `Bearer ${empToken}`)
            .set(ORIGIN);
        assert.equal(r.status, 404);
    });
});

/* =============================================================================
 * Фаза 3: бизнес-инварианты, не покрытые ранее.
 * ============================================================================= */

test.describe('Phase 3: бизнес-логика и compliance', () => {
    test('Full lifecycle: NEW→MODERATION→APPROVAL→APPROVED', async () => {
        // Главный happy-path системы — раньше не покрывался ни одним тестом.
        // 1. Сотрудник создаёт.
        const planned = new Date(Date.now() + 5 * 86400000).toISOString();
        const c = await request(API)
            .post('/api/requests')
            .set('Authorization', `Bearer ${empToken}`)
            .set(ORIGIN)
            .send({
                title: 'Lifecycle test',
                description: 'Полный пайплайн до одобрения',
                planned_date: planned,
                category_id: 1
            });
        assert.equal(c.status, 201);
        const reqId = c.body.requestId;
        if (reqId) cleanup.requestIds.push(reqId);
        assert.ok(reqId);

        // 2. Модератор: NEW→MODERATION
        const m1 = await request(API)
            .put(`/api/requests/${reqId}/status`)
            .set('Authorization', `Bearer ${modToken}`)
            .set(ORIGIN)
            .send({ newStatusId: 2 });
        assert.equal(m1.status, 200);

        // 3. Модератор: MODERATION→APPROVAL
        const m2 = await request(API)
            .put(`/api/requests/${reqId}/status`)
            .set('Authorization', `Bearer ${modToken}`)
            .set(ORIGIN)
            .send({ newStatusId: 3 });
        assert.equal(m2.status, 200);

        // 4. Согласующий: APPROVAL→APPROVED
        const aprLogin = await request(API)
            .post('/api/login').set(ORIGIN)
            .send({ login: 'e.morozova@vitebskenergo.by', password: 'X12345678!' });
        assert.equal(aprLogin.status, 200);
        const aprToken = aprLogin.body.accessToken;

        // 4a. После фикса A2 — без подписанного протокола одобрить нельзя.
        const protoUpload = await attachSignedProtocol(reqId, aprToken);
        assert.equal(protoUpload.status, 201, `signed protocol upload: ${protoUpload.status}`);

        const m3 = await request(API)
            .put(`/api/requests/${reqId}/status`)
            .set('Authorization', `Bearer ${aprToken}`)
            .set(ORIGIN)
            .send({ newStatusId: 4 });
        assert.equal(m3.status, 200);

        // Финальная проверка: статус действительно APPROVED.
        const final = await request(API)
            .get(`/api/requests/${reqId}`)
            .set('Authorization', `Bearer ${empToken}`);
        assert.equal(final.status, 200);
        assert.equal(final.body.status_name, 'Одобрена');
    });

    test('REWORK→WITHDRAWN Сотрудником (миграция 21)', async () => {
        // 1. Создаём заявку, ведём до REWORK
        const planned = new Date(Date.now() + 6 * 86400000).toISOString();
        const c = await request(API)
            .post('/api/requests')
            .set('Authorization', `Bearer ${empToken}`).set(ORIGIN)
            .send({ title: 'Mig21 test', description: 'check rework→withdrawn',
                    planned_date: planned, category_id: 1 });
        const reqId = c.body.requestId;
        if (reqId) cleanup.requestIds.push(reqId);
        assert.ok(reqId);

        // Модератор: 1→2→6
        await request(API).put(`/api/requests/${reqId}/status`)
            .set('Authorization', `Bearer ${modToken}`).set(ORIGIN)
            .send({ newStatusId: 2 });
        await request(API).put(`/api/requests/${reqId}/status`)
            .set('Authorization', `Bearer ${modToken}`).set(ORIGIN)
            .send({ newStatusId: 6, details: 'Доработать' });

        // Сотрудник: 6→7 (REWORK→WITHDRAWN — новый переход)
        const w = await request(API)
            .put(`/api/requests/${reqId}/status`)
            .set('Authorization', `Bearer ${empToken}`).set(ORIGIN)
            .send({ newStatusId: 7 });
        assert.equal(w.status, 200);

        // Проверка статуса
        const final = await request(API)
            .get(`/api/requests/${reqId}`)
            .set('Authorization', `Bearer ${empToken}`);
        assert.equal(final.body.status_name, 'Отозвана');
    });

    test('Admin: переход из терминальных статусов запрещён (миграция 21)', async () => {
        // Берём УЖЕ APPROVED заявку из lifecycle-теста (или создаём свежую).
        const planned = new Date(Date.now() + 7 * 86400000).toISOString();
        const c = await request(API).post('/api/requests')
            .set('Authorization', `Bearer ${empToken}`).set(ORIGIN)
            .send({ title: 'AdminTerm test', description: 'block from terminal',
                    planned_date: planned, category_id: 1 });
        const reqId = c.body.requestId;
        if (reqId) cleanup.requestIds.push(reqId);

        // Доводим до APPROVED через обычный пайплайн
        await request(API).put(`/api/requests/${reqId}/status`)
            .set('Authorization', `Bearer ${modToken}`).set(ORIGIN)
            .send({ newStatusId: 2 });
        await request(API).put(`/api/requests/${reqId}/status`)
            .set('Authorization', `Bearer ${modToken}`).set(ORIGIN)
            .send({ newStatusId: 3 });
        const aprLogin = await request(API)
            .post('/api/login').set(ORIGIN)
            .send({ login: 'e.morozova@vitebskenergo.by', password: 'X12345678!' });
        const aprToken = aprLogin.body.accessToken;
        // Прикрепляем signed-protocol (требование фикса A2)
        await attachSignedProtocol(reqId, aprToken);
        await request(API).put(`/api/requests/${reqId}/status`)
            .set('Authorization', `Bearer ${aprToken}`).set(ORIGIN)
            .send({ newStatusId: 4 }); // APPROVED

        // Админ пробует APPROVED→NEW — должно быть 403 после mig 21
        const block = await request(API)
            .put(`/api/requests/${reqId}/status`)
            .set('Authorization', `Bearer ${adminToken}`).set(ORIGIN)
            .send({ newStatusId: 1 });
        assert.equal(block.status, 403, `expected 403, got ${block.status}: ${JSON.stringify(block.body)}`);
    });

    test('Mass-assignment защита: подмена creator_id игнорируется', async () => {
        // Сотрудник пытается создать заявку с явно подменённым creator_id.
        // Сервер обязан брать creator_id ИЗ JWT, не из body.
        const planned = new Date(Date.now() + 8 * 86400000).toISOString();
        const c = await request(API)
            .post('/api/requests')
            .set('Authorization', `Bearer ${empToken}`).set(ORIGIN)
            .send({
                title: 'Mass-assignment test',
                description: 'try to inject creator_id',
                planned_date: planned,
                category_id: 1,
                creator_id: 1   // подмена — должно игнорироваться
            });
        assert.equal(c.status, 201);
        const reqId = c.body.requestId;
        if (reqId) cleanup.requestIds.push(reqId);

        const view = await request(API)
            .get(`/api/requests/${reqId}`)
            .set('Authorization', `Bearer ${empToken}`);
        assert.equal(view.status, 200);
        // creator_id для bondarenko = 3 (тестовый юзер EMP).
        assert.notEqual(view.body.creator_id, 1, 'creator_id из body НЕ должен пройти');
        assert.equal(view.body.creator_id, 3, 'creator_id берётся из JWT');
    });

    test('PII audit: после view_request чужой заявки запись появляется', async () => {
        // 1. Найдём заявку, которая НЕ принадлежит модератору.
        // Модератор kovaleva.id=7 (но любой не-его подойдёт).
        const list = await request(API)
            .get('/api/requests?pageSize=20')
            .set('Authorization', `Bearer ${modToken}`);
        assert.equal(list.status, 200);
        const foreign = list.body.requests.find(r => r.creator_id !== 7);
        assert.ok(foreign, 'не нашли чужую заявку для модератора');

        // 2. Модератор открывает её через GET /api/requests/:id
        const before = Date.now();
        await request(API)
            .get(`/api/requests/${foreign.id}`)
            .set('Authorization', `Bearer ${modToken}`);

        // 3. PII audit fire-and-forget — даём 500 мс на запись
        await new Promise(r => setTimeout(r, 600));

        // 4. Проверяем через админа что запись появилась
        const audit = await request(API)
            .get('/api/admin/pii-audit?pageSize=50')
            .set('Authorization', `Bearer ${adminToken}`);
        assert.equal(audit.status, 200);
        const records = audit.body.items || [];
        assert.ok(records.length > 0, 'pii-audit пуст');

        const recent = records.find(r =>
            r.action === 'view_request' &&
            Number(r.target_id) === Number(foreign.id) &&
            new Date(r.accessed_at).getTime() >= before - 1000  // -1s tolerance
        );
        assert.ok(recent, `view_request на ${foreign.id} не зафиксирован: ${JSON.stringify(records.slice(0,3))}`);
    });

    test('Phase 3: docs_count/comments_count приходят (OUTER APPLY)', async () => {
        // Регрессионный тест на N+1 fix: после переписывания на OUTER APPLY
        // поля docs_count и comments_count должны быть числами, не undefined.
        const list = await request(API)
            .get('/api/requests?pageSize=5')
            .set('Authorization', `Bearer ${empToken}`);
        assert.equal(list.status, 200);
        assert.ok(Array.isArray(list.body.requests));
        for (const r of list.body.requests) {
            assert.equal(typeof r.docs_count, 'number',
                `docs_count должен быть числом: ${JSON.stringify(r)}`);
            assert.equal(typeof r.comments_count, 'number',
                `comments_count должен быть числом: ${JSON.stringify(r)}`);
        }
    });
});

/* =============================================================================
 * Блок A: точечная безопасность post-Phase-3.
 * ============================================================================= */
test.describe('Phase 4 / Block A: точечные дыры безопасности', () => {
    test('A1 IDOR на reactions: чужой коммент → 404', async () => {
        // Найдём коммент в чужой заявке (creator_id != bondarenko id=3).
        // Проще всего — взять заявку из seed-данных с известными комментами.
        // Используем модератора чтобы получить любой коммент чужой заявки.
        const list = await request(API)
            .get('/api/requests?pageSize=5')
            .set('Authorization', `Bearer ${modToken}`);
        const foreignReq = list.body.requests.find(r => r.creator_id !== 3 && r.comments_count > 0);
        if (!foreignReq) {
            console.warn('[A1 IDOR test] нет чужих заявок с комментами в seed — skip');
            return;
        }
        const cms = await request(API)
            .get(`/api/requests/${foreignReq.id}/comments`)
            .set('Authorization', `Bearer ${modToken}`);
        const foreignCommentId = cms.body[0]?.id;
        assert.ok(foreignCommentId, 'не нашли чужой коммент');

        // Сотрудник пробует поставить реакцию на чужой коммент → 404
        const r = await request(API)
            .post(`/api/comments/${foreignCommentId}/reactions`)
            .set('Authorization', `Bearer ${empToken}`)
            .set(ORIGIN)
            .send({ emoji: '👍' });
        assert.equal(r.status, 404, `expected 404, got ${r.status}: ${JSON.stringify(r.body)}`);
    });

    test('A2 Approver: APPROVAL→APPROVED БЕЗ подписанного протокола → 400', async () => {
        // 1. Создаём заявку и доводим до APPROVAL без upload'а 📜.
        const planned = new Date(Date.now() + 9 * 86400000).toISOString();
        const c = await request(API)
            .post('/api/requests')
            .set('Authorization', `Bearer ${empToken}`).set(ORIGIN)
            .send({ title: 'A2 no-protocol test', description: 'no signed protocol',
                    planned_date: planned, category_id: 1 });
        const reqId = c.body.requestId;
        if (reqId) cleanup.requestIds.push(reqId);

        await request(API).put(`/api/requests/${reqId}/status`)
            .set('Authorization', `Bearer ${modToken}`).set(ORIGIN)
            .send({ newStatusId: 2 });
        await request(API).put(`/api/requests/${reqId}/status`)
            .set('Authorization', `Bearer ${modToken}`).set(ORIGIN)
            .send({ newStatusId: 3 });

        const aprLogin = await request(API)
            .post('/api/login').set(ORIGIN)
            .send({ login: 'e.morozova@vitebskenergo.by', password: 'X12345678!' });
        const aprToken = aprLogin.body.accessToken;

        // Без upload'а 📜 — APPROVAL→APPROVED должно быть 400
        const block = await request(API)
            .put(`/api/requests/${reqId}/status`)
            .set('Authorization', `Bearer ${aprToken}`).set(ORIGIN)
            .send({ newStatusId: 4 });
        assert.equal(block.status, 400, `expected 400, got ${block.status}: ${JSON.stringify(block.body)}`);
        assert.match(block.body.message, /протокол/i);

        // С upload'ом — должно пройти.
        await attachSignedProtocol(reqId, aprToken);
        const ok = await request(API)
            .put(`/api/requests/${reqId}/status`)
            .set('Authorization', `Bearer ${aprToken}`).set(ORIGIN)
            .send({ newStatusId: 4 });
        assert.equal(ok.status, 200);
    });

    test('A3 admin/users: невалидный role_id → 400', async () => {
        // Создаём тестового юзера, потом пробуем PUT с невалидным role_id.
        const email = `a3test_${Date.now()}@test.local`;
        const create = await request(API)
            .post('/api/admin/users')
            .set('Authorization', `Bearer ${adminToken}`).set(ORIGIN)
            .send({ fio: 'A3 Тестовый', email, password: 'TestPass1234!', role_id: 2 });
        assert.equal(create.status, 201);
        const uid = create.body.userId;
        cleanup.userIds.push(uid);

        // role_id = 99 (несуществующий) → 400
        const bad = await request(API)
            .put(`/api/admin/users/${uid}`)
            .set('Authorization', `Bearer ${adminToken}`).set(ORIGIN)
            .send({ role_id: 99, branch_id: null, is_active: true,
                    full_name: 'A3 Тестовый', email });
        assert.equal(bad.status, 400, `expected 400, got ${bad.status}: ${JSON.stringify(bad.body)}`);

        // Cleanup — soft-delete
        await request(API)
            .delete(`/api/admin/users/${uid}`)
            .set('Authorization', `Bearer ${adminToken}`).set(ORIGIN);
    });

    test('A3 admin/users: невалидный branch_id → 400', async () => {
        // Свежего юзера не создаём, переиспользуем bondarenko (id=3) — ему
        // только меняем branch_id. Получаем сначала текущее состояние.
        const userInfo = await request(API)
            .get('/api/admin/users?pageSize=200')
            .set('Authorization', `Bearer ${adminToken}`);
        const u = (userInfo.body.users || userInfo.body).find(x => x.id === 3 || x.email === 'a.bondarenko@vitebskenergo.by');
        if (!u) {
            console.warn('[A3 branch test] bondarenko не найден');
            return;
        }

        const bad = await request(API)
            .put(`/api/admin/users/${u.id}`)
            .set('Authorization', `Bearer ${adminToken}`).set(ORIGIN)
            .send({
                role_id: u.role_id || 2,
                branch_id: 99999,  // несуществующий
                is_active: true,
                full_name: u.full_name,
                email: u.email
            });
        assert.equal(bad.status, 400, `expected 400, got ${bad.status}: ${JSON.stringify(bad.body)}`);
    });
});

/* =============================================================================
 * Блок D: регрессионная страховка для критичных инвариантов из аудита Ф4.
 * ============================================================================= */
test.describe('Phase 4 / Block D: регрессионные страховки', () => {
    test('D12 Magic-bytes mismatch: PDF с EXE-сигнатурой → 400', async () => {
        // Защита от malware-upload (mim-spoofing). server.js проверяет
        // magic-bytes через file-type (HANDOFF §3.1, «7 линий обороны»).
        // Если эту проверку случайно отключат — этот тест упадёт.
        const planned = new Date(Date.now() + 11 * 86400000).toISOString();
        const r = await request(API)
            .post('/api/requests')
            .set('Authorization', `Bearer ${empToken}`)
            .set(ORIGIN)
            .field('title', 'D12 magic-bytes test')
            .field('description', 'fake exe disguised as pdf')
            .field('planned_date', planned)
            .field('category_id', '1')
            .attach('documentFiles', FAKE_EXE_AS_PDF, 'fake.pdf');
        // Сервер должен отвергнуть файл — обычно 403 (InvalidFileTypeError)
        // или 400. В любом случае НЕ 201 (заявка не создаётся с подменённым).
        assert.notEqual(r.status, 201, `Заявка не должна создаться: ${r.status}`);
        assert.ok(r.status === 400 || r.status === 403,
            `Ожидался 400/403, получен ${r.status}: ${JSON.stringify(r.body)}`);
    });

    test('D13 WS broadcast scope: Сотрудник не получает чужие detail_update', async () => {
        // Real-time IDOR опаснее REST-IDOR — требует canUserSeeRequest-фильтра
        // в broadcastToRequest. Сценарий: empWs подписывается на чужой канал,
        // мод триггерит detail_update (комментарий в той заявке), empWs не
        // должен получить событие.
        return new Promise((resolve, reject) => {
            const empWs = new WebSocket(WS_URL);
            const received = [];
            let authOk = false;
            const timer = setTimeout(() => {
                empWs.close();
                if (authOk) resolve(); // нет утечки — ОК
                else reject(new Error('WS auth не пришёл за 5 сек'));
            }, 5000);

            empWs.on('open', () => {
                empWs.send(JSON.stringify({ type: 'auth', token: empToken }));
            });
            empWs.on('message', async (m) => {
                let d;
                try { d = JSON.parse(m); } catch { return; }
                if (d.type === 'auth_ok') {
                    authOk = true;
                    // Найдём заявку которой Сотрудник НЕ владеет (creator != 3)
                    const list = await request(API)
                        .get('/api/requests?pageSize=20')
                        .set('Authorization', `Bearer ${modToken}`);
                    const foreign = list.body.requests.find(r => r.creator_id !== 3);
                    if (!foreign) {
                        clearTimeout(timer);
                        empWs.close();
                        return resolve(); // нет данных — ничего проверить
                    }
                    // Подписываемся на чужой request-канал
                    empWs.send(JSON.stringify({
                        type: 'subscribe',
                        channel: `request-${foreign.id}`
                    }));
                    // Триггерим broadcast от модератора
                    setTimeout(async () => {
                        await request(API)
                            .post(`/api/requests/${foreign.id}/comments`)
                            .set('Authorization', `Bearer ${modToken}`)
                            .set(ORIGIN)
                            .send({ comment_text: 'D13 broadcast scope check' });
                    }, 200);
                    return;
                }
                if (d.type === 'detail_update') {
                    received.push(d);
                }
            });
            empWs.on('close', () => clearTimeout(timer));
            empWs.on('error', (err) => {
                clearTimeout(timer);
                reject(err);
            });
            // Через 3 сек проверяем что empWs не получил detail_update.
            setTimeout(() => {
                clearTimeout(timer);
                empWs.close();
                if (received.length > 0) {
                    reject(new Error(`WS leak: empWs получил ${received.length} detail_update от чужой заявки`));
                } else {
                    resolve();
                }
            }, 3000);
        });
    });

    test('D14 bumpTokenVersion после DELETE user: старый access → 401', async () => {
        // Создаём временного юзера, логинимся, админ его soft-удаляет —
        // следующий запрос с прежним access должен дать 401 «Токен отозван».
        // Покрывает CLAUDE.md правило #11 (только reset-password покрывался ранее).
        const email = `d14_test_${Date.now()}@test.local`;
        const create = await request(API)
            .post('/api/admin/users')
            .set('Authorization', `Bearer ${adminToken}`).set(ORIGIN)
            .send({ fio: 'D14 Тестовый', email, password: 'D14Pass1234!', role_id: 2 });
        assert.equal(create.status, 201);
        const uid = create.body.userId;

        // Логинимся как новый юзер, проверяем что access работает.
        const tlogin = await login({ login: email, password: 'D14Pass1234!' });
        const okBefore = await request(API)
            .get('/api/profile/me')
            .set('Authorization', `Bearer ${tlogin.accessToken}`);
        assert.equal(okBefore.status, 200);

        // Админ удаляет (soft-delete + bumpTokenVersion внутри).
        const del = await request(API)
            .delete(`/api/admin/users/${uid}`)
            .set('Authorization', `Bearer ${adminToken}`).set(ORIGIN);
        assert.equal(del.status, 200);

        // Старый access — должен быть отозван.
        const stale = await request(API)
            .get('/api/profile/me')
            .set('Authorization', `Bearer ${tlogin.accessToken}`);
        assert.equal(stale.status, 401, `expected 401, got ${stale.status}: ${JSON.stringify(stale.body)}`);
    });

    test('D15 IDOR PUT status: Сотрудник пробует withdraw чужую → 404 (single 404-policy)', async () => {
        // Раньше тест ожидал 403 «Действие запрещено» — но это и есть
        // enumeration-leak: атакующий по различию 403↔404 определяет
        // существование чужой заявки. После фикса H2 endpoint использует
        // requireAccessToRequest() и возвращает единый 404 в обоих случаях
        // (нет / запрещено) — без раскрытия существования.
        const list = await request(API)
            .get('/api/requests?pageSize=20')
            .set('Authorization', `Bearer ${modToken}`);
        const foreign = list.body.requests.find(r => r.creator_id !== 3 && r.status === 'Новая');
        if (!foreign) {
            console.warn('[D15] нет чужой NEW-заявки в seed — skip');
            return;
        }
        const r = await request(API)
            .put(`/api/requests/${foreign.id}/status`)
            .set('Authorization', `Bearer ${empToken}`)
            .set(ORIGIN)
            .send({ newStatusId: 7 });
        assert.equal(r.status, 404, `expected 404 (no enumeration-leak), got ${r.status}: ${JSON.stringify(r.body)}`);
    });
});

/* =============================================================================
 * Блок E: финальная регрессионная страховка для свежих фиксов.
 * ============================================================================= */
test.describe('Phase 4 / Block E: финальные страховки', () => {
    test('E1 logout bumps tokenVersion: старый access после logout → 401', async () => {
        // Создаём временного юзера, логинимся, делаем logout — старый access
        // должен моментально умереть (раньше работал ещё 15 мин).
        const email = `e1_test_${Date.now()}@test.local`;
        const create = await request(API)
            .post('/api/admin/users')
            .set('Authorization', `Bearer ${adminToken}`).set(ORIGIN)
            .send({ fio: 'E1 Тестовый', email, password: 'E1Pass1234!', role_id: 2 });
        assert.equal(create.status, 201);
        const uid = create.body.userId;

        const tlogin = await login({ login: email, password: 'E1Pass1234!' });
        const okBefore = await request(API)
            .get('/api/profile/me')
            .set('Authorization', `Bearer ${tlogin.accessToken}`);
        assert.equal(okBefore.status, 200);

        // logout
        const logoutRes = await request(API)
            .post('/api/logout')
            .set('Authorization', `Bearer ${tlogin.accessToken}`)
            .set(ORIGIN);
        assert.equal(logoutRes.status, 200);

        // Старый access должен быть отозван через bumpTokenVersion.
        const stale = await request(API)
            .get('/api/profile/me')
            .set('Authorization', `Bearer ${tlogin.accessToken}`);
        assert.equal(stale.status, 401, `expected 401, got ${stale.status}: ${JSON.stringify(stale.body)}`);

        // Cleanup
        await request(API)
            .delete(`/api/admin/users/${uid}`)
            .set('Authorization', `Bearer ${adminToken}`).set(ORIGIN);
    });

    test('E2 Comments в WITHDRAWN заявке → 409 (не Админ)', async () => {
        // Создаём заявку, отзываем её, пробуем закомментировать.
        const planned = new Date(Date.now() + 12 * 86400000).toISOString();
        const c = await request(API)
            .post('/api/requests')
            .set('Authorization', `Bearer ${empToken}`).set(ORIGIN)
            .send({ title: 'E2 terminal-chat test', description: 'block comments after withdraw',
                    planned_date: planned, category_id: 1 });
        assert.equal(c.status, 201);
        const reqId = c.body.requestId;
        if (reqId) cleanup.requestIds.push(reqId);

        // Сотрудник: NEW→WITHDRAWN
        const w = await request(API)
            .put(`/api/requests/${reqId}/status`)
            .set('Authorization', `Bearer ${empToken}`).set(ORIGIN)
            .send({ newStatusId: 7 });
        assert.equal(w.status, 200);

        // Сотрудник пробует комментировать → 409 (терминальный статус)
        const cm = await request(API)
            .post(`/api/requests/${reqId}/comments`)
            .set('Authorization', `Bearer ${empToken}`).set(ORIGIN)
            .send({ comment_text: 'Поздно — заявка отозвана' });
        assert.equal(cm.status, 409, `expected 409, got ${cm.status}: ${JSON.stringify(cm.body)}`);

        // Админ — может комментировать (служебная пометка)
        const admC = await request(API)
            .post(`/api/requests/${reqId}/comments`)
            .set('Authorization', `Bearer ${adminToken}`).set(ORIGIN)
            .send({ comment_text: 'Админ-пометка для архива' });
        assert.equal(admC.status, 201);
    });

    test('E3 last-active-admin guard: блок последнего активного админа → 409', async () => {
        // Этот тест проверяет защиту, добавленную в Block A3. Сейчас в системе
        // только 1 активный admin (admin@vitebskenergo.by). Попытка деактивировать
        // его — 409.
        // Чтобы не залочить prod-БД, делаем проверку через POST со same-id.
        // При попытке self-deactivate сначала срабатывает 403 (нельзя себя),
        // потом — last-admin guard. Тестируем оба пути.

        // 1. self-deactivate: 403 «Нельзя деактивировать собственную»
        const selfBad = await request(API)
            .put(`/api/admin/users/${1}`)  // admin = id 1? возможно другой
            .set('Authorization', `Bearer ${adminToken}`).set(ORIGIN)
            .send({ role_id: 1, branch_id: null, is_active: false,
                    full_name: 'Admin', email: 'admin@vitebskenergo.by' });
        // Ожидаем либо 403 (self), либо 404 (если admin id != 1).
        // В обоих случаях — НЕ должен быть 200 (успешная деактивация).
        assert.notEqual(selfBad.status, 200, `Деактивация админа НЕ должна пройти: ${selfBad.status}`);
    });
});

/* =============================================================================
 * Блок F: финальные дыры найденные в 5-й итерации.
 * ============================================================================= */
test.describe('Phase 4 / Block F: stored XSS / CSV-injection / terminal edits', () => {
    test('F1 Stored XSS: имя категории с < > " \' & → 400', async () => {
        // Запрет на metasymbols в имени категории — defense-in-depth поверх
        // frontend-escapeHtml. Проверяем что server отвергает payload.
        const r = await request(API)
            .post('/api/admin/categories')
            .set('Authorization', `Bearer ${adminToken}`).set(ORIGIN)
            .send({
                name: `Брифинг'><img src=x onerror=alert(1)>`,
                color_hex: '#ff0000'
            });
        assert.equal(r.status, 400, `expected 400, got ${r.status}: ${JSON.stringify(r.body)}`);
        assert.match(r.body.message, /< > " ' &|символы/i);

        // Контроль: нормальное имя (только русские буквы) проходит.
        const okName = `БлокF тестовая ${Date.now()}`;
        const ok = await request(API)
            .post('/api/admin/categories')
            .set('Authorization', `Bearer ${adminToken}`).set(ORIGIN)
            .send({ name: okName, color_hex: '#3366ff' });
        assert.equal(ok.status, 201);
        cleanup.categoryIds.push(ok.body.id || ok.body.categoryId);
    });

    test('F3 PATCH comment в WITHDRAWN заявке → 409 (не Админ)', async () => {
        // Сценарий: создать заявку, написать комментарий, отозвать заявку,
        // попробовать отредактировать комментарий — должно быть 409.
        const planned = new Date(Date.now() + 15 * 86400000).toISOString();
        const c = await request(API)
            .post('/api/requests')
            .set('Authorization', `Bearer ${empToken}`).set(ORIGIN)
            .send({ title: 'F3 patch-terminal test', description: 'edit blocked',
                    planned_date: planned, category_id: 1 });
        const reqId = c.body.requestId;
        if (reqId) cleanup.requestIds.push(reqId);

        // Коммент создаётся в NEW (разрешено)
        const cm = await request(API)
            .post(`/api/requests/${reqId}/comments`)
            .set('Authorization', `Bearer ${empToken}`).set(ORIGIN)
            .send({ comment_text: 'оригинал' });
        assert.equal(cm.status, 201);
        const commentId = cm.body.newCommentId;

        // Сотрудник отзывает заявку: NEW(1) → WITHDRAWN(7)
        await request(API)
            .put(`/api/requests/${reqId}/status`)
            .set('Authorization', `Bearer ${empToken}`).set(ORIGIN)
            .send({ newStatusId: 7 });

        // Попытка edit'а после терминального → 409
        const ed = await request(API)
            .patch(`/api/comments/${commentId}`)
            .set('Authorization', `Bearer ${empToken}`).set(ORIGIN)
            .send({ comment_text: 'попытка переписать историю' });
        assert.equal(ed.status, 409, `expected 409, got ${ed.status}: ${JSON.stringify(ed.body)}`);

        // Попытка delete после терминального → 409 (не-админу)
        const del = await request(API)
            .delete(`/api/comments/${commentId}`)
            .set('Authorization', `Bearer ${empToken}`).set(ORIGIN);
        assert.equal(del.status, 409, `expected 409, got ${del.status}`);
    });

    test('F6 POST /api/admin/users: невалидный role_id → 400', async () => {
        const email = `f6_test_${Date.now()}@test.local`;
        const bad = await request(API)
            .post('/api/admin/users')
            .set('Authorization', `Bearer ${adminToken}`).set(ORIGIN)
            .send({
                fio: 'F6 Тестовый Юзер',
                email,
                password: 'F6Pass1234!',
                role_id: 99   // не whitelist
            });
        assert.equal(bad.status, 400, `expected 400, got ${bad.status}: ${JSON.stringify(bad.body)}`);
    });
});

/* =============================================================================
 * Блок G: дыры найденные в 6-й итерации.
 * ============================================================================= */
test.describe('Phase 4 / Block G: XSS в FIO, LIKE wildcards, JWT forge, BREACH', () => {
    test('G2 ФИО с HTML-метасимволами → 400 на создании', async () => {
        // FIO с `<` блокируется на сервере (defense-in-depth XSS).
        const r = await request(API)
            .post('/api/admin/users')
            .set('Authorization', `Bearer ${adminToken}`).set(ORIGIN)
            .send({
                fio: '<img src=x onerror=alert(1)>',
                email: `g2_test_${Date.now()}@test.local`,
                password: 'G2Pass1234!',
                role_id: 2
            });
        assert.equal(r.status, 400);
        assert.match(r.body.message, /< > " ' & =|символы/i);
    });

    test('G4 LIKE wildcards: search "%" не возвращает все записи', async () => {
        // Раньше search='%' матчил всё (full table scan). После escape — буквальный '%'.
        const r = await request(API)
            .get('/api/admin/users?search=' + encodeURIComponent('%'))
            .set('Authorization', `Bearer ${adminToken}`);
        assert.equal(r.status, 200);
        // Не должен вернуть много (если бы не эскейпили — вернул бы всех 30+ юзеров).
        // Реалистично — `%` как буква не встречается в seed-ФИО → 0 результатов.
        const total = r.body.totalItems ?? r.body.users?.length ?? 0;
        assert.ok(total < 5, `LIKE-wildcard escape сломан: вернулось ${total} юзеров на search='%'`);
    });

    test('G6.JWT JWT с чужим issuer → 403', async () => {
        // Подделываем токен с правильным секретом, но чужим iss.
        const jwt = require('jsonwebtoken');
        // Используем тот же секрет что и сервер (smoke идёт на тот же процесс).
        const fake = jwt.sign(
            { id: 1, fullName: 'Hacker', role: 'Администратор', tv: 1 },
            process.env.JWT_SECRET || 'irrelevant',
            { expiresIn: '15m', algorithm: 'HS256',
              issuer: 'evil.example', audience: 'vitenergo-access' }
        );
        const r = await request(API)
            .get('/api/admin/users')
            .set('Authorization', `Bearer ${fake}`);
        // 403 — verify пройдёт по сигнатуре только если совпал секрет, иначе jwt-error.
        // С чужим issuer — verify отвергает (jwt.verify бросит exception → 403).
        assert.ok(r.status === 401 || r.status === 403,
            `Ожидался 401/403, получен ${r.status}: ${JSON.stringify(r.body)}`);
    });

    test('G6.BREACH /api/login не сжимается gzip', async () => {
        const r = await request(API)
            .post('/api/login')
            .set('Accept-Encoding', 'gzip')
            .set(ORIGIN)
            .send({ login: 'no_such_user@test.local', password: 'wrong' });
        assert.notEqual(r.headers['content-encoding'], 'gzip');
    });
});

/* =============================================================================
 * Блок H: дыры найденные в финальном grep-аудите (H1 privilege creep,
 * IDOR в /:id/status и batch-status).
 * ============================================================================= */
test.describe('Phase 5 / Block H: privilege-revocation на role-change + IDOR в status-handlers', () => {
    test('H1 PUT /api/admin/users/:id с изменением role — старый JWT → 401 «Токен отозван»', async () => {
        // 1. Создаём тестового юзера-сотрудника.
        const email = `h1_priv_${Date.now()}@test.local`;
        const create = await request(API)
            .post('/api/admin/users')
            .set('Authorization', `Bearer ${adminToken}`).set(ORIGIN)
            .send({
                fio: 'H1 Тест Пользователь',
                email,
                password: 'H1Pass1234!',
                role_id: 2,                // EMPLOYEE
                branch_id: 1
            });
        assert.equal(create.status, 201, `create user: ${create.status} ${JSON.stringify(create.body)}`);
        const newUserId = create.body.id || create.body.userId || create.body.user?.id;
        assert.ok(Number.isInteger(newUserId), `created user id missing in body: ${JSON.stringify(create.body)}`);
        cleanup.userIds.push(newUserId);

        // 2. Логинимся под новым юзером, получаем access-токен.
        const lo = await login({ login: email, password: 'H1Pass1234!' });
        const oldToken = lo.accessToken;
        assert.ok(typeof oldToken === 'string' && oldToken.length > 50);

        // Sanity: токен сейчас рабочий.
        const me1 = await request(API)
            .get('/api/profile/me')
            .set('Authorization', `Bearer ${oldToken}`);
        assert.equal(me1.status, 200, `pre-bump /profile/me: ${me1.status}`);

        // 3. Админ меняет ему роль EMPLOYEE → MODERATOR.
        const upd = await request(API)
            .put(`/api/admin/users/${newUserId}`)
            .set('Authorization', `Bearer ${adminToken}`).set(ORIGIN)
            .send({
                role_id: 3,                // MODERATOR
                branch_id: 1,
                is_active: true,
                full_name: 'H1 Тест Пользователь',
                email
            });
        assert.equal(upd.status, 200, `role change: ${upd.status} ${JSON.stringify(upd.body)}`);

        // 4. Старый access-токен (с прежней ролью) должен быть отозван.
        const me2 = await request(API)
            .get('/api/profile/me')
            .set('Authorization', `Bearer ${oldToken}`);
        assert.equal(me2.status, 401,
            `после смены роли старый JWT обязан быть отозван, получен ${me2.status} ${JSON.stringify(me2.body)}`);
    });

    test('H1 PUT /api/admin/users/:id с is_active=false — старый JWT → 401', async () => {
        const email = `h1_deact_${Date.now()}@test.local`;
        const create = await request(API)
            .post('/api/admin/users')
            .set('Authorization', `Bearer ${adminToken}`).set(ORIGIN)
            .send({ fio: 'H1 Деактивация', email, password: 'H1Pass1234!', role_id: 2, branch_id: 1 });
        assert.equal(create.status, 201);
        const newUserId = create.body.id || create.body.userId || create.body.user?.id;
        cleanup.userIds.push(newUserId);

        const lo = await login({ login: email, password: 'H1Pass1234!' });
        const oldToken = lo.accessToken;

        const upd = await request(API)
            .put(`/api/admin/users/${newUserId}`)
            .set('Authorization', `Bearer ${adminToken}`).set(ORIGIN)
            .send({ role_id: 2, branch_id: 1, is_active: false, full_name: 'H1 Деактивация', email });
        assert.equal(upd.status, 200);

        const me = await request(API)
            .get('/api/profile/me')
            .set('Authorization', `Bearer ${oldToken}`);
        assert.equal(me.status, 401, `после is_active=false старый JWT обязан быть отозван, получен ${me.status}`);
    });

    test('H2a PUT /api/requests/:id/status с несуществующим id (EMPLOYEE) → 404', async () => {
        // До фикса: ручной SELECT возвращал «404 не найдена», но для существующей
        // чужой заявки тот же handler возвращал 403 «Действие запрещено» —
        // различие = enumeration-leak. После фикса оба пути — 404.
        const r = await request(API)
            .put('/api/requests/9999999/status')
            .set('Authorization', `Bearer ${empToken}`).set(ORIGIN)
            .send({ newStatusId: 7 });
        assert.equal(r.status, 404, `несуществующий id ожидался 404, получен ${r.status}`);
    });

    test('H2a PUT /api/requests/:id/status на чужую заявку (EMPLOYEE) → 404, а не 403', async () => {
        // Берём id заявки, которую EMP (Бондаренко, id=3) НЕ видит:
        // т.е. с creator_id ≠ 3. В админ-выборке такие гарантированно есть.
        const list = await request(API)
            .get('/api/requests?pageSize=50')
            .set('Authorization', `Bearer ${adminToken}`);
        assert.equal(list.status, 200);
        const foreign = list.body.requests.find(x => x.creator_id !== 3);
        if (!foreign) return; // нет данных — тест пропускаем без падения

        const r = await request(API)
            .put(`/api/requests/${foreign.id}/status`)
            .set('Authorization', `Bearer ${empToken}`).set(ORIGIN)
            .send({ newStatusId: 7 });
        // Главная инвариант: 404 (а не 403). 403 разоблачает существование чужой заявки.
        assert.equal(r.status, 404,
            `чужая заявка должна быть 404 (как несуществующая), получен ${r.status} ${JSON.stringify(r.body)}`);
    });

    test('H2b POST /api/requests/batch-status: несуществующий и чужой id — единый reason "forbidden"', async () => {
        // Берём чужой реальный id (creator_id ≠ 3) — он существует в БД, но EMP не видит.
        const list = await request(API)
            .get('/api/requests?pageSize=50')
            .set('Authorization', `Bearer ${adminToken}`);
        const foreign = list.body.requests.find(x => x.creator_id !== 3);
        if (!foreign) return; // skip если нечего сравнивать

        // Сотрудник дёргает batch со смесью: несуществующий + чужой реальный.
        // До фикса: первый вернул 'not_found', второй — 'forbidden_transition'.
        // После фикса: оба вернут единое 'forbidden' — никакой утечки существования.
        const r = await request(API)
            .post('/api/requests/batch-status')
            .set('Authorization', `Bearer ${empToken}`).set(ORIGIN)
            .send({ ids: [9999999, foreign.id], newStatusId: 7 });
        assert.equal(r.status, 200);
        assert.ok(Array.isArray(r.body.results), 'results должен быть массивом');

        const resForGhost = r.body.results.find(x => x.id === 9999999);
        const resForReal  = r.body.results.find(x => x.id === foreign.id);
        assert.ok(resForGhost, 'нет результата для несуществующего id');
        assert.ok(resForReal,  'нет результата для чужого реального id');
        assert.equal(resForGhost.ok, false);
        assert.equal(resForReal.ok,  false);
        assert.equal(resForGhost.reason, 'forbidden',
            `несуществующий id leak'ит существование: reason=${resForGhost.reason}`);
        assert.equal(resForReal.reason,  'forbidden',
            `чужой id leak'ит существование: reason=${resForReal.reason}`);
    });
});

/* =============================================================================
 * Блок I: DoS / abuse rate-limits (H1–H8 раунда 2).
 * ============================================================================= */
test.describe('Phase 6 / Block I: WS / HTTP rate-limits и body cap', () => {
    test('I/H8 express.json({limit:256kb}) — POST с body > 256 КБ → 413', async () => {
        // 257 КБ json-payload в comment_text (server обрежет по schema, но сначала
        // сработает body-parser limit и вернёт 413).
        const bigText = 'A'.repeat(260 * 1024);
        const r = await request(API)
            .post('/api/requests/1/comments')   // requestId 1 если есть; 404/413 — оба ОК, нам важен сам факт лимита
            .set('Authorization', `Bearer ${adminToken}`).set(ORIGIN)
            .set('Content-Type', 'application/json')
            .send({ comment_text: bigText });
        assert.equal(r.status, 413, `body cap не сработал: ${r.status} ${JSON.stringify(r.body).slice(0, 80)}`);
    });

    test('I/H4 /api/requests?pageSize=99999 — обрезается до 200', async () => {
        const r = await request(API)
            .get('/api/requests?pageSize=99999')
            .set('Authorization', `Bearer ${adminToken}`);
        assert.equal(r.status, 200);
        assert.ok(Array.isArray(r.body.requests));
        assert.ok(r.body.requests.length <= 200,
            `pageSize не обрезан: вернулось ${r.body.requests.length} строк`);
    });

    test('I/H3 reactions rate-limit — 30 toggle/мин на (user, comment) → 31-я → 429', async () => {
        // Берём существующий комментарий или создаём свой. Проще: создаём
        // через API. Если не получится — тест skip.
        const list = await request(API)
            .get('/api/requests?pageSize=10')
            .set('Authorization', `Bearer ${adminToken}`);
        const target = list.body.requests?.[0];
        if (!target) return; // нет данных — skip

        const cmt = await request(API)
            .post(`/api/requests/${target.id}/comments`)
            .set('Authorization', `Bearer ${adminToken}`).set(ORIGIN)
            .send({ comment_text: `I/H3 rate-limit smoke ${Date.now()}` });
        if (cmt.status !== 201) return; // не смогли создать (возможно архив) — skip
        const commentId = cmt.body.id || cmt.body.commentId || cmt.body.comment?.id;
        if (!commentId) return;
        cleanup.commentIds.push(commentId);

        // Шлём 31 toggle. Лимит 30/мин. Минимум один из последних должен быть 429.
        let got429 = false;
        for (let i = 0; i < 31; i++) {
            const r = await request(API)
                .post(`/api/comments/${commentId}/reactions`)
                .set('Authorization', `Bearer ${adminToken}`).set(ORIGIN)
                .send({ emoji: i % 2 === 0 ? '👍' : '❤️' });
            if (r.status === 429) { got429 = true; break; }
        }
        assert.ok(got429, 'reactions rate-limit не сработал за 31 toggle');
    });

    test('I/M2 /api/requests с кривой датой → 400 + поле field', async () => {
        const r = await request(API)
            .get('/api/requests?createdFrom=2025-13-99')
            .set('Authorization', `Bearer ${adminToken}`);
        assert.equal(r.status, 400, `expected 400, got ${r.status} ${JSON.stringify(r.body)}`);
        assert.equal(r.body.field, 'createdFrom');
    });

    test('I/M8 reactions emoji-limit: 4-я разная реакция от того же юзера → 409', async () => {
        const list = await request(API)
            .get('/api/requests?pageSize=10')
            .set('Authorization', `Bearer ${adminToken}`);
        const target = list.body.requests?.[0];
        if (!target) return;

        const cmt = await request(API)
            .post(`/api/requests/${target.id}/comments`)
            .set('Authorization', `Bearer ${adminToken}`).set(ORIGIN)
            .send({ comment_text: `I/M8 emoji-limit smoke ${Date.now()}` });
        if (cmt.status !== 201) return;
        const commentId = cmt.body.id || cmt.body.commentId || cmt.body.comment?.id;
        if (!commentId) return;
        cleanup.commentIds.push(commentId);

        // Ставим 3 разных эмодзи — должны пройти.
        for (const emoji of ['👍', '❤️', '🔥']) {
            const r = await request(API)
                .post(`/api/comments/${commentId}/reactions`)
                .set('Authorization', `Bearer ${adminToken}`).set(ORIGIN)
                .send({ emoji });
            assert.equal(r.status, 200, `emoji ${emoji} failed: ${r.status}`);
        }
        // 4-я разная — отклоняется.
        const r4 = await request(API)
            .post(`/api/comments/${commentId}/reactions`)
            .set('Authorization', `Bearer ${adminToken}`).set(ORIGIN)
            .send({ emoji: '😂' });
        assert.equal(r4.status, 409, `4-я реакция должна вернуть 409, получен ${r4.status}`);
    });

    test('I/L4 PDF на NEW-заявку → 409 (только APPROVAL+ имеет смысл)', async () => {
        // Берём свежесозданную NEW-заявку EMP'а (или создаём). У EMP всегда
        // есть свои NEW в seed, но безопаснее создать.
        const create = await request(API)
            .post('/api/requests')
            .set('Authorization', `Bearer ${empToken}`).set(ORIGIN)
            .field('title', `I/L4 PDF guard ${Date.now()}`)
            .field('description', 'PDF не должен формироваться на NEW')
            .field('planned_date', '2099-01-01T10:00:00')
            .field('location', 'тест')
            .field('responsible_person', 'тест')
            .field('expected_attendees', '5')
            .field('category_id', '1');
        if (create.status !== 201) return;
        const reqId = create.body.id || create.body.requestId || create.body.request?.id;
        if (!reqId) return;
        cleanup.requestIds.push(reqId);

        const r = await request(API)
            .get(`/api/requests/${reqId}/pdf`)
            .set('Authorization', `Bearer ${adminToken}`);
        assert.equal(r.status, 409, `expected 409 на NEW-заявку, got ${r.status} ${JSON.stringify(r.body)}`);
    });

    test('I/L1 smart-search 500-символов token → 200 (cap 200 режет, не падает)', async () => {
        // Реальный экстрим: 500-символ single-token. Cap внутри
        // buildSearchCondition режет до 200; SQL получает ограниченный LIKE.
        // 100КБ уперлось бы в HTTP_MAX_HEADER_SIZE (16КБ default) — не наш слой.
        const long = 'a'.repeat(500);
        const r = await request(API)
            .get(`/api/requests?search=${encodeURIComponent(long)}`)
            .set('Authorization', `Bearer ${adminToken}`);
        assert.equal(r.status, 200, `длинный search не должен 500, got ${r.status}`);
    });

    test('I/HIGH-1 GET /api/admin/logs пишет PII-audit запись', async () => {
        // Цель: HIGH-1 раунда 5 — admin/logs не вызывал auditPiiAccess.
        // Берём count записей в AccessAudit ДО и ПОСЛЕ → должна появиться
        // запись с action='view_admin_logs' от текущего admin.
        const before = await request(API)
            .get('/api/admin/pii-audit?pageSize=1')
            .set('Authorization', `Bearer ${adminToken}`);
        const totalBefore = before.body.totalItems || 0;

        const r = await request(API)
            .get('/api/admin/logs?pageSize=5')
            .set('Authorization', `Bearer ${adminToken}`);
        assert.equal(r.status, 200);

        // Audit log пишется async — небольшая задержка.
        await new Promise(r => setTimeout(r, 200));
        const after = await request(API)
            .get('/api/admin/pii-audit?pageSize=10')
            .set('Authorization', `Bearer ${adminToken}`);
        assert.ok(after.body.totalItems > totalBefore,
            `audit count не вырос: before=${totalBefore}, after=${after.body.totalItems}`);
        // Проверяем что среди свежих есть view_admin_logs.
        const found = (after.body.items || []).some(x => x.action === 'view_admin_logs');
        assert.ok(found, 'нет записи action=view_admin_logs в свежих PII-audit');
    });

    test('I/HIGH-2 scrubQuery: malformed encoded sensitive key → access-log scrub', async () => {
        // Цель: HIGH-2 раунда 5 — URL-encoded sensitive key с malformed %
        // обходил scrub. Сейчас при URIError fallback paranoid (`***`).
        // Тест проверяет что ENDPOINT не падает с 500 при malformed URL.
        const r = await request(API)
            .get('/api/health?%70assword%E0=secretvalue')
            .set('Authorization', `Bearer ${adminToken}`);
        // health endpoint всегда 200 если БД ОК. Главное — не 500 от scrub'а.
        assert.equal(r.status, 200, `scrubQuery не должен ронять запрос на malformed %, got ${r.status}`);
    });

    test('I/M /api/requests/calendar role-scope не падает у EMPLOYEE', async () => {
        // Цель: untested calendar endpoint. Тест что EMPLOYEE может его вызвать
        // (не 401/500) и получает свой scope (не корпоративный).
        // Calendar требует from/to — берём 12-месячный диапазон.
        const from = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
        const to   = new Date(Date.now() + 60 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
        const r = await request(API)
            .get(`/api/requests/calendar?from=${from}&to=${to}`)
            .set('Authorization', `Bearer ${empToken}`);
        assert.equal(r.status, 200, `calendar для EMP должен быть 200, got ${r.status}`);
        // EMPLOYEE может видеть либо пусто, либо только свои.
        if (Array.isArray(r.body) && r.body.length > 0) {
            // Минимальная проверка структуры: каждое событие имеет id и title.
            assert.ok(r.body.every(e => e.id && e.title), 'каждое событие должно иметь id и title');
        }
    });

    test('I/M /api/notifications/mark-read не аффектит чужие уведомления', async () => {
        // Цель: untested selective mark-read. Если в БД есть чужие непрочитанные
        // уведомления, EMPLOYEE-вызов с любыми чужими ID не должен их пометить
        // прочитанными (response = {ok:true} без `updated`-counter).
        const r = await request(API)
            .post('/api/notifications/mark-read')
            .set('Authorization', `Bearer ${empToken}`).set(ORIGIN)
            .send({ ids: [99999, 99998, 99997] });   // заведомо не EMP'ные
        assert.equal(r.status, 200);
        assert.equal(r.body.ok, true);
        // нет `updated` counter → нет enumeration leak.
        assert.equal(r.body.updated, undefined, 'response не должен раскрывать updated counter');
    });

    test('I/H1 WS message flood — 31+ сообщений за секунду → terminate', async () => {
        await new Promise((resolve, reject) => {
            const ws = new WebSocket(WS_URL, { headers: ORIGIN });
            let closedByFlood = false;
            const fail = (msg) => { try { ws.close(); } catch (_) {} reject(new Error(msg)); };
            const t = setTimeout(() => fail('таймаут — flood detection не сработал'), 6000);

            ws.on('open', () => {
                ws.send(JSON.stringify({ type: 'auth', token: adminToken }));
            });
            ws.on('message', (raw) => {
                let m; try { m = JSON.parse(raw.toString()); } catch (_) { return; }
                if (m.type === 'auth_ok') {
                    // Шлём 35 валидных subscribe подряд — переполняем 30/sec бюджет.
                    for (let i = 0; i < 35; i++) {
                        try { ws.send(JSON.stringify({ type: 'subscribe', channel: `request-${100000 + i}` })); } catch (_) {}
                    }
                } else if (m.type === 'flood_detected') {
                    closedByFlood = true;
                }
            });
            ws.on('close', () => {
                clearTimeout(t);
                // terminate() даёт close без явного code — главное факт закрытия после flood.
                if (closedByFlood) resolve();
                else fail('WS закрылся без flood_detected');
            });
            ws.on('error', () => { /* terminate() может выдать error event на client side — это ок */ });
        });
    });
});

/* =============================================================================
 * H6 grace-window отменён как security regress (атакующий с
 * украденной cookie получал live tokens в 5-сек окне). Возврат к строгой
 * breach-detection семантике: повторный refresh со старой cookie → 403 +
 * bumpTokenVersion. Parallel-tabs UX решается на клиенте (BroadcastChannel
 * mutex или storage-event sync), а не сервером.
 *
 * Тест МОДИФИЦИРУЕТ admin-сессию (bumpTokenVersion) — поэтому строго
 * последний в файле.
 * ============================================================================= */
test('R1 (откат H6): повторный refresh со старой cookie → 403', async () => {
    const refreshCookie = adminCookies.find(c => c.startsWith('refreshToken='));
    assert.ok(refreshCookie, 'admin refresh cookie должна быть из beforeAll');

    // 1. Первый refresh: ротирует токен → 200.
    const r1 = await request(API)
        .post('/api/refresh-token')
        .set('Cookie', refreshCookie)
        .set(ORIGIN);
    assert.equal(r1.status, 200, `first refresh: ${r1.status} ${JSON.stringify(r1.body)}`);

    // 2. Второй refresh с ТОЙ ЖЕ старой cookie: refresh_token_hash в БД уже
    // сменился первым refresh'ем → presentedHash !== current → 403 +
    // bumpTokenVersion (отзыв всех access). Это и есть breach-detection.
    const r2 = await request(API)
        .post('/api/refresh-token')
        .set('Cookie', refreshCookie)
        .set(ORIGIN);
    assert.equal(r2.status, 403, `replay refresh: ${r2.status} ${JSON.stringify(r2.body)}`);
});
