require('dotenv').config();

const express = require('express');
const path = require('path');
const http = require('http');
const WebSocket = require('ws');
const url = require('url');
const fs = require('fs').promises;
const crypto = require('crypto');

const sql = require('mssql');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const archiver = require('archiver');
const cookieParser = require('cookie-parser');

const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

class InvalidFileTypeError extends Error {
    constructor(fileName) {
        super(`Файл "${fileName}" имеет недопустимый или неподтвержденный тип.`);
        this.name = "InvalidFileTypeError";
        this.fileName = fileName;
    }
}

const app = express();
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;
const dbConfig = {
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    server: process.env.DB_SERVER,
    database: process.env.DB_DATABASE,
    options: {
        encrypt: true,
        trustServerCertificate: process.env.NODE_ENV !== 'production'
    }
};

app.use(helmet());

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        message: 'Слишком много попыток. Пожалуйста, попробуйте снова через 15 минут.'
    }
});

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20000,
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
        const token = req.headers['authorization']?.split(' ')[1];
        if (!token) return false;
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            return decoded && decoded.role === 'Администратор';
        } catch (err) {
            return false;
        }
    }
});

app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.json());
app.use(cookieParser());

const ALLOWED_MIME_TYPES = [
    'application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'image/jpeg', 'image/png', 'application/zip', 'application/x-rar-compressed', 'text/plain'
];

const upload = multer({
    storage: multer.memoryStorage(),
    fileFilter: (req, file, cb) => {
        ALLOWED_MIME_TYPES.includes(file.mimetype) ? cb(null, true) : cb(new Error('Недопустимый MIME-тип файла'), false);
    },
    limits: {
        fileSize: 15 * 1024 * 1024
    }
});

async function validateAndSaveFiles(files) {
    if (!files || files.length === 0) return [];

    const {
        fileTypeFromBuffer
    } = await import('file-type');
    const filesToProcess = [];

    for (const file of files) {
        let isValid = false;
        const originalname = Buffer.from(file.originalname, 'latin1').toString('utf8');

        if (!ALLOWED_MIME_TYPES.includes(file.mimetype)) {
            throw new InvalidFileTypeError(originalname);
        }

        if (file.mimetype === 'text/plain') {
            isValid = true;
        } else {
            const typeInfo = await fileTypeFromBuffer(file.buffer);
            if (typeInfo && ALLOWED_MIME_TYPES.includes(typeInfo.mime)) {
                isValid = true;
            }
        }

        if (!isValid) {
            throw new InvalidFileTypeError(originalname);
        }

        const fileHash = crypto.createHash('sha256').update(file.buffer).digest('hex');
        const result = await new sql.Request()
            .input('hash', sql.NVarChar, fileHash)
            .query `SELECT TOP 1 file_path FROM Documents WHERE file_hash = @hash`;

        let filePath;
        let isDuplicate = false;
        if (result.recordset.length > 0) {
            filePath = result.recordset[0].file_path;
            isDuplicate = true;
        } else {
            const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
            const filename = uniqueSuffix + '-' + originalname;
            filePath = path.join(__dirname, 'uploads', filename);
        }

        filesToProcess.push({ ...file,
            originalname,
            path: filePath,
            hash: fileHash,
            isDuplicate
        });
    }

    await Promise.all(
        filesToProcess
        .filter(file => !file.isDuplicate)
        .map(file => fs.writeFile(file.path, file.buffer))
    );

    return filesToProcess;
}

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.sendStatus(403);
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

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (!err) {
            req.user = user;
        }
        next();
    });
}

const server = http.createServer(app);
const wss = new WebSocket.Server({
    server
});

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
    } catch (e) {
        console.error("Критическая ошибка при логировании события:", e);
    }
}

async function blockUserAndLog(userId, userName, reason) {
    try {
        await new sql.Request()
            .input('userId', sql.Int, userId)
            .query('UPDATE Users SET is_active = 0 WHERE id = @userId');
        await logAdminEvent('Блокировка пользователя', reason, userId, userName);
    } catch (error) {
        console.error(`Критическая ошибка при блокировке пользователя ${userId}:`, error);
    }
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
    wss.clients.forEach((client) => {
        if (client !== excludeClient && client.readyState === WebSocket.OPEN && client.subscriptions.has(channel)) {
            client.send(JSON.stringify(data));
        }
    });
}

async function broadcastListUpdate(requestId) {
    try {
        const data = await new sql.Request()
            .input('requestId', sql.Int, requestId)
            .query `SELECT r.id, r.title, rs.name as status, r.created_at, u.full_name as creator_name, r.creator_id, r.updated_at FROM Requests r JOIN RequestStatuses rs ON r.status_id = rs.id JOIN Users u ON r.creator_id = u.id WHERE r.id = @requestId`;

        if (!data.recordset[0]) return;

        wss.clients.forEach((client) => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify({
                    type: 'list_item_update',
                    request: data.recordset[0]
                }));
            }
        });
    } catch (error) {
        console.error("Ошибка при вещании обновления списка:", error);
    }
}

app.post('/api/login', authLimiter, async (req, res) => {
    const {
        login,
        password
    } = req.body;
    try {
        const result = await sql.query `SELECT u.*, r.name as role_name FROM Users u JOIN Roles r ON u.role_id = r.id WHERE u.email = ${login} OR u.login = ${login}`;

        if (result.recordset.length === 0) {
            await logAdminEvent('Неудачный вход', `Попытка входа для несуществующего пользователя: ${login}`, null, 'Система');
            return res.status(401).json({
                message: 'Неверные учетные данные'
            });
        }

        const user = result.recordset[0];
        if (!user.is_active) {
            return res.status(403).json({
                message: 'Аккаунт неактивен.'
            });
        }

        const isPasswordCorrect = await bcrypt.compare(password, user.password_hash);
        if (!isPasswordCorrect) {
            await logAdminEvent('Неудачный вход', `Неверный пароль для пользователя: ${login}`, user.id, user.full_name);
            return res.status(401).json({
                message: 'Неверные учетные данные'
            });
        }

        const ip_address = req.ip || req.socket.remoteAddress;
        await logAdminEvent('Вход в систему', `IP: ${ip_address}`, user.id, user.full_name);

        try {
            await sql.query `INSERT INTO LoginHistory (user_id, ip_address) VALUES (${user.id}, ${ip_address})`;
        } catch (e) {}

        const payload = {
            id: user.id,
            fullName: user.full_name,
            role: user.role_name
        };
        const accessToken = jwt.sign(payload, process.env.JWT_SECRET, {
            expiresIn: '15m'
        });
        const refreshToken = jwt.sign({
            id: user.id
        }, process.env.REFRESH_TOKEN_SECRET, {
            expiresIn: '7d'
        });

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });
        res.json({
            message: 'Вход успешен',
            accessToken
        });

    } catch (err) {
        console.error('Ошибка входа:', err);
        res.status(500).json({
            message: 'Внутренняя ошибка сервера'
        });
    }
});

app.post('/api/refresh-token', authLimiter, async (req, res) => {
    const {
        refreshToken
    } = req.cookies;
    if (!refreshToken) {
        return res.status(401).json({
            message: 'Refresh токен не предоставлен'
        });
    }

    try {
        const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
        const result = await sql.query `SELECT u.*, r.name as role_name FROM Users u JOIN Roles r ON u.role_id = r.id WHERE u.id = ${decoded.id} AND u.is_active = 1`;

        if (result.recordset.length === 0) {
            return res.status(403).json({
                message: 'Пользователь не найден или неактивен'
            });
        }

        const user = result.recordset[0];
        const payload = {
            id: user.id,
            fullName: user.full_name,
            role: user.role_name
        };
        const newAccessToken = jwt.sign(payload, process.env.JWT_SECRET, {
            expiresIn: '15m'
        });
        res.json({
            accessToken: newAccessToken
        });
    } catch (err) {
        res.clearCookie('refreshToken');
        return res.status(403).json({
            message: 'Невалидный refresh токен'
        });
    }
});

app.use('/api/', apiLimiter);

app.post('/api/logout', optionalAuthenticateToken, async (req, res) => {
    if (req.user) {
        await logAdminEvent('Выход из системы', `Пользователь вышел из системы.`, req.user.id, req.user.fullName);
    }
    res.clearCookie('refreshToken');
    res.status(200).json({
        message: 'Выход выполнен успешно'
    });
});

app.post('/api/register', async (req, res) => {
    const {
        fio,
        email,
        branch_id,
        password,
        password_confirm
    } = req.body;

    if (!fio || !email || !branch_id || !password || !password_confirm) {
        return res.status(400).json({
            message: "Все поля обязательны"
        });
    }

    if (password !== password_confirm) {
        return res.status(400).json({
            message: "Пароли не совпадают"
        });
    }

    const passwordRegex = /^(?=.*[A-Za-zА-Яа-я])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-zА-Яа-я\d@$!%*#?&]{10,}$/;
    if (!passwordRegex.test(password)) {
        return res.status(400).json({
            message: "Пароль не соответствует требованиям безопасности"
        });
    }

    try {
        const existingUser = await sql.query `SELECT id FROM Users WHERE email = ${email}`;
        if (existingUser.recordset.length > 0) {
            return res.status(409).json({
                message: "Пользователь с таким email уже существует"
            });
        }

        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);
        const result = await sql.query `
            INSERT INTO Users (full_name, login, password_hash, email, role_id, branch_id, is_active)
            OUTPUT INSERTED.id
            VALUES (${fio}, ${email}, ${passwordHash}, ${email}, 2, ${branch_id}, 1)`;

        const newUserId = result.recordset[0].id;
        await logAdminEvent('Регистрация пользователя', `Зарегистрирован новый пользователь: ${fio} (ID: ${newUserId})`, newUserId, fio);
        res.status(201).json({
            message: "Регистрация успешна!"
        });
    } catch (err) {
        console.error('Ошибка регистрации:', err);
        res.status(500).json({
            message: 'Ошибка на сервере'
        });
    }
});

app.get('/api/branches', async (req, res) => {
    try {
        const result = await sql.query `SELECT id, name FROM Branches ORDER BY name`;
        res.json(result.recordset);
    } catch (err) {
        res.status(500).json({
            message: 'Не удалось загрузить список филиалов'
        });
    }
});

app.get('/api/roles', authenticateToken, isAdmin, async (req, res) => {
    try {
        const result = await sql.query `SELECT id, name FROM Roles ORDER BY name`;
        res.json(result.recordset);
    } catch (err) {
        res.status(500).json({
            message: 'Не удалось загрузить список ролей'
        });
    }
});

app.get('/api/admin/users', authenticateToken, isAdmin, async (req, res) => {
    try {
        const result = await sql.query `
            SELECT u.id, u.full_name, u.email, u.login, u.is_active, u.role_id,
                   r.name as role_name, u.branch_id, b.name as branch_name
            FROM Users u
            JOIN Roles r ON u.role_id = r.id
            LEFT JOIN Branches b ON u.branch_id = b.id
            ORDER BY u.id`;
        res.json(result.recordset);
    } catch (err) {
        console.error("Ошибка получения пользователей:", err);
        res.status(500).json({
            message: 'Ошибка сервера'
        });
    }
});

app.get('/api/admin/logs', authenticateToken, isAdmin, async (req, res) => {
    const page = parseInt(req.query.page, 10) || 1;
    const pageSize = parseInt(req.query.pageSize, 10) || 50;
    const offset = (page - 1) * pageSize;

    try {
        const countResult = await new sql.Request().query('SELECT COUNT(*) as total FROM History');
        const totalItems = countResult.recordset[0].total;

        const dataResult = await new sql.Request().query(`
            SELECT h.timestamp as event_time, ISNULL(u.full_name, 'Система') as user_name,
                   h.action as event_type, h.details, h.request_id
            FROM History h
            LEFT JOIN Users u ON h.user_id = u.id
            ORDER BY h.timestamp DESC
            OFFSET ${offset} ROWS FETCH NEXT ${pageSize} ROWS ONLY`);

        res.json({
            logs: dataResult.recordset,
            totalItems: totalItems
        });
    } catch (err) {
        console.error("Ошибка получения логов:", err);
        res.status(500).json({
            message: "Ошибка сервера"
        });
    }
});

app.put('/api/admin/users/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const {
            id: userIdToChange
        } = req.params;
        const {
            role_id,
            branch_id,
            is_active
        } = req.body;

        const adminRoleResult = await sql.query `SELECT id FROM Roles WHERE name = 'Администратор'`;
        const adminRoleId = adminRoleResult.recordset[0]?.id || -1;

        const userToChangeResult = await sql.query `SELECT role_id FROM Users WHERE id = ${userIdToChange}`;
        if (userToChangeResult.recordset.length === 0) {
            return res.status(404).json({
                message: 'Пользователь не найден.'
            });
        }
        const currentRoleId = userToChangeResult.recordset[0].role_id;

        const newRoleId = parseInt(role_id, 10);
        if ((currentRoleId === adminRoleId && newRoleId !== adminRoleId) || (newRoleId === adminRoleId && currentRoleId !== adminRoleId)) {
            return res.status(403).json({
                message: 'Запрещено изменять роль "Администратор".'
            });
        }

        await new sql.Request()
            .input('id', sql.Int, userIdToChange)
            .input('role_id', sql.Int, role_id)
            .input('branch_id', sql.Int, branch_id)
            .input('is_active', sql.Bit, is_active)
            .query `UPDATE Users SET role_id = @role_id, branch_id = @branch_id, is_active = @is_active WHERE id = @id`;

        await logAdminEvent('Изменение пользователя', `Пользователем ${req.user.fullName} обновлены данные для ID: ${userIdToChange}.`, req.user.id, req.user.fullName);
        res.json({
            message: 'Данные пользователя обновлены.'
        });
    } catch (err) {
        console.error("Ошибка обновления пользователя:", err);
        res.status(500).json({
            message: 'Ошибка сервера'
        });
    }
});


app.get('/api/requests', authenticateToken, async (req, res) => {
    const page = parseInt(req.query.page, 10) || 1;
    const pageSize = parseInt(req.query.pageSize, 10) || 20;
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

    try {
        const {
            role,
            id: userId
        } = req.user;
        const requestPool = new sql.Request();
        const baseQuery = ` FROM Requests r JOIN RequestStatuses rs ON r.status_id = rs.id JOIN Users u ON r.creator_id = u.id `;
        const whereConditions = [];
        requestPool.input('userId', sql.Int, userId);

        switch (role) {
            case 'Согласующий':
                whereConditions.push(`r.status_id IN (3, 4, 5, 6)`);
                break;
            case 'Сотрудник':
                whereConditions.push(`r.creator_id = @userId`);
                break;
            case 'Администратор':
            case 'Модератор':
                break;
            default:
                whereConditions.push(`r.creator_id = @userId`);
                break;
        }

        if (search) {
            whereConditions.push(`(r.title LIKE @searchQuery OR CAST(r.id AS NVARCHAR(10)) LIKE @searchQuery)`);
            requestPool.input('searchQuery', sql.NVarChar, `%${search}%`);
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

        const dataQuery = `
            SELECT r.id, r.title, rs.name as status, r.created_at, u.full_name as creator_name, r.creator_id, r.updated_at,
                   ${unreadActivitySubquery} AS has_unread_activity,
                   ${unreadCommentsSubquery} AS has_unread_comments
            ${baseQuery} ${whereClause}
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


app.post('/api/requests', authenticateToken, upload.array('documentFiles', 10), async (req, res) => {
    let processedFiles = [];
    const transaction = new sql.Transaction();
    try {
        const {
            title,
            description,
            planned_date
        } = req.body;
        if (!title || !planned_date || (!description?.trim() && (!req.files || req.files.length === 0))) {
            return res.status(400).json({
                message: "Название, дата и описание (или файл) обязательны."
            });
        }
        processedFiles = await validateAndSaveFiles(req.files);
        await transaction.begin();

        const requestQuery = `
            DECLARE @OutputTbl TABLE (ID INT);
            INSERT INTO Requests (title, description, planned_date, creator_id, status_id)
            OUTPUT inserted.id INTO @OutputTbl(ID)
            VALUES (@title, @description, @planned_date, @creator_id, 1);
            SELECT ID FROM @OutputTbl;`;

        const requestResult = await new sql.Request(transaction)
            .input('title', sql.NVarChar, title)
            .input('description', sql.NVarChar, description || '')
            .input('planned_date', sql.DateTime2, new Date(planned_date))
            .input('creator_id', sql.Int, req.user.id)
            .query(requestQuery);

        const newRequestId = requestResult.recordset[0].ID;

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

        await logAdminEvent('Заявка создана', `Название: "${title}"`, req.user.id, req.user.fullName, newRequestId);
        await broadcastListUpdate(String(newRequestId));
        res.status(201).json({
            message: "Заявка успешно создана!",
            requestId: newRequestId
        });
    } catch (err) {
        await transaction.rollback();
        processedFiles.filter(f => !f.isDuplicate).forEach(f => {
            try {
                fs.unlink(f.path)
            } catch (e) {}
        });
        if (err instanceof InvalidFileTypeError) {
            const reason = `Попытка загрузки недопустимого файла: ${err.fileName}`;
            await blockUserAndLog(req.user.id, req.user.fullName, reason);
            res.clearCookie('refreshToken');
            return res.status(403).json({
                message: 'Обнаружена подозрительная активность. Ваш аккаунт заблокирован. Обратитесь к администратору.'
            });
        }
        console.error("Ошибка создания заявки:", err);
        res.status(500).json({
            message: err.message || 'Ошибка на сервере'
        });
    }
});


app.get('/api/requests/:id', authenticateToken, async (req, res) => {
    const requestId = parseInt(req.params.id, 10);
    const {
        id: userId,
        role,
        fullName
    } = req.user;

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
                SELECT r.*, rs.name as status_name, u.full_name as creator_name, b.name as branch_name
                FROM Requests r
                JOIN RequestStatuses rs ON r.status_id = rs.id
                JOIN Users u ON r.creator_id = u.id
                LEFT JOIN Branches b ON u.branch_id = b.id
                WHERE r.id = @id`;
        if (result.recordset.length === 0) {
            return res.status(404).json({
                message: "Заявка не найдена"
            });
        }
        res.json(result.recordset[0]);
    } catch (err) {
        res.status(500).json({
            message: 'Внутренняя ошибка'
        });
    }
});


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
        const request = new sql.Request();
        const result = await request.input('requestId', sql.Int, requestId)
            .query `SELECT status_id, creator_id FROM Requests WHERE id = @requestId`;

        if (result.recordset.length === 0) {
            return res.status(404).json({
                message: "Заявка не найдена"
            });
        }
        const {
            status_id: currentStatusId,
            creator_id
        } = result.recordset[0];

        const transitions = {
            'Сотрудник': {
                from: [6],
                to: [2]
            },
            'Модератор': {
                from: [1, 2],
                to: [2, 3, 5, 6]
            },
            'Согласующий': {
                from: [3],
                to: [4, 5, 6]
            },
            'Администратор': {
                from: [1, 2, 3, 4, 5, 6],
                to: [1, 2, 3, 4, 5, 6]
            }
        };

        const transition = transitions[role];
        const isTransitionAllowed = transition &&
            transition.from.includes(currentStatusId) &&
            transition.to.includes(parsedStatusId) &&
            !(role === 'Сотрудник' && userId !== creator_id);

        if (!isTransitionAllowed) {
            return res.status(403).json({
                message: "Действие запрещено."
            });
        }

        await request.input('newStatusId', sql.Int, parsedStatusId)
            .query `UPDATE Requests SET status_id = @newStatusId, updated_at = GETUTCDATE() WHERE id = @requestId`;

        const statusResult = await new sql.Request()
            .input('newStatusId', sql.Int, parsedStatusId)
            .query `SELECT name FROM RequestStatuses WHERE id = @newStatusId`;

        const actionType = 'Смена статуса';
        const logDetails = details || `Статус изменен на "${statusResult.recordset[0].name}"`;

        await logAdminEvent(actionType, logDetails, userId, fullName, requestId);
        broadcastToRequest(String(requestId), {
            type: 'detail_update'
        });
        await broadcastListUpdate(String(requestId));
        res.json({
            message: 'Статус обновлен'
        });
    } catch (err) {
        res.status(500).json({
            message: 'Внутренняя ошибка сервера'
        });
    }
});


app.get('/api/requests/:id/documents', authenticateToken, async (req, res) => {
    try {
        const result = await sql.query `
            SELECT d.id, d.file_name, d.uploaded_at, u.full_name as uploaded_by_name, d.uploaded_by as uploaded_by_id
            FROM Documents d JOIN Users u ON d.uploaded_by = u.id
            WHERE d.request_id = ${req.params.id}
            ORDER BY d.uploaded_at DESC`;
        res.json(result.recordset);
    } catch (err) {
        res.status(500).json({
            message: "Не удалось загрузить документы"
        });
    }
});


app.post('/api/requests/:id/documents', authenticateToken, upload.array('documentFiles', 10), async (req, res) => {
    if (!req.files || req.files.length === 0) {
        return res.status(400).json({
            message: 'Файлы не были загружены'
        });
    }
    let processedFiles = [];
    try {
        processedFiles = await validateAndSaveFiles(req.files);
        const {
            id: requestId
        } = req.params;
        const {
            id: userId,
            fullName
        } = req.user;

        const fileNames = processedFiles.map(f => f.originalname).join(', ');
        const actionType = 'Загрузка файла';
        const logDetails = `Добавлены файлы: ${fileNames}`;

        for (const file of processedFiles) {
            await new sql.Request()
                .input('request_id', sql.Int, requestId)
                .input('file_name', sql.NVarChar, file.originalname)
                .input('file_path', sql.NVarChar, file.path)
                .input('uploaded_by', sql.Int, userId)
                .input('file_hash', sql.NVarChar, file.hash)
                .query(`INSERT INTO Documents (request_id, file_name, file_path, uploaded_by, file_hash) VALUES (@request_id, @file_name, @file_path, @uploaded_by, @file_hash)`);
        }
        await new sql.Request()
            .input('id', sql.Int, requestId)
            .query('UPDATE Requests SET updated_at = GETUTCDATE() WHERE id = @id');

        await logAdminEvent(actionType, logDetails, userId, fullName, requestId);
        broadcastToRequest(String(requestId), {
            type: 'detail_update'
        });
        await broadcastListUpdate(String(requestId));
        res.status(201).json({
            message: 'Файлы успешно загружены'
        });
    } catch (err) {
        processedFiles.filter(f => !f.isDuplicate).forEach(f => {
            try {
                fs.unlink(f.path)
            } catch (e) {}
        });
        if (err instanceof InvalidFileTypeError) {
            const reason = `Попытка загрузки недопустимого файла: ${err.fileName}`;
            await blockUserAndLog(req.user.id, req.user.fullName, reason);
            res.clearCookie('refreshToken');
            return res.status(403).json({
                message: 'Обнаружена подозрительная активность. Ваш аккаунт заблокирован. Обратитесь к администратору.'
            });
        }
        console.error("Ошибка загрузки документов:", err);
        res.status(500).json({
            message: err.message || 'Ошибка на сервере'
        });
    }
});


app.get('/api/documents/:id/download', authenticateToken, async (req, res) => {
    try {
        const result = await sql.query `SELECT d.file_name, d.file_path, d.request_id FROM Documents d WHERE d.id = ${req.params.id}`;
        if (result.recordset.length === 0) {
            return res.status(404).send();
        }

        const doc = result.recordset[0];
        await logAdminEvent('Скачивание файла', `Пользователь ${req.user.fullName} скачал файл: "${doc.file_name}"`, req.user.id, req.user.fullName, doc.request_id);

        res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(doc.file_name)}"`);
        res.download(doc.file_path, doc.file_name, (err) => {
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
    try {
        const request = new sql.Request();
        const idParameters = documentIds.map((id, i) => `@id${i}`);
        documentIds.forEach((id, i) => request.input(`id${i}`, sql.Int, id));
        const result = await request.query(`SELECT file_name, file_path, request_id FROM Documents WHERE id IN (${idParameters.join(',')})`);

        if (result.recordset.length === 0) {
            return res.status(404).send();
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
            archive.file(doc.file_path, {
                name: doc.file_name
            });
        }
        await archive.finalize();

        await logAdminEvent('Скачивание файла', `Скачан архив из ${result.recordset.length} файлов`, req.user.id, req.user.fullName, result.recordset[0].request_id);
    } catch (err) {
        if (!res.headersSent) {
            res.status(500).send();
        }
    }
});


app.get('/api/requests/:id/history', authenticateToken, async (req, res) => {
    try {
        const result = await new sql.Request()
            .input('request_id', sql.Int, req.params.id)
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


app.post('/api/requests/:id/history/mark-read', authenticateToken, async (req, res) => {
    const {
        historyIds
    } = req.body;
    if (!Array.isArray(historyIds) || historyIds.length === 0) {
        return res.status(400).send();
    }
    try {
        const queries = historyIds.map(id => `
            IF NOT EXISTS (SELECT 1 FROM HistoryReadStatus WHERE history_id = ${parseInt(id, 10)} AND user_id = ${req.user.id})
            BEGIN
                INSERT INTO HistoryReadStatus (history_id, user_id) VALUES (${parseInt(id, 10)}, ${req.user.id})
            END;`);
        await new sql.Request().query(queries.join(' '));
        res.status(200).send();
    } catch (err) {
        res.status(500).send();
    }
});


app.get('/api/requests/:id/comments', authenticateToken, async (req, res) => {
    try {
        const result = await sql.query `
            SELECT c.id, c.comment_text, c.created_at, c.user_id, u.full_name,
                   (SELECT STRING_AGG(crs.user_id, ',') FROM CommentReadStatus crs WHERE crs.comment_id = c.id) as readers
            FROM Comments c JOIN Users u ON c.user_id = u.id
            WHERE c.request_id = ${req.params.id}
            ORDER BY c.created_at ASC`;
        res.json(result.recordset);
    } catch (err) {
        res.status(500).send();
    }
});


app.post('/api/requests/:id/comments', authenticateToken, async (req, res) => {
    const {
        id: requestId
    } = req.params;
    const {
        id: userId,
        fullName
    } = req.user;
    const {
        comment_text
    } = req.body;
    try {
        await sql.query `UPDATE Requests SET updated_at = GETUTCDATE() WHERE id = ${requestId}`;
        const commentQuery = `
            DECLARE @OutputTbl TABLE (ID INT);
            INSERT INTO Comments (request_id, user_id, comment_text)
            OUTPUT INSERTED.id INTO @OutputTbl(ID)
            VALUES (@requestId, @userId, @comment_text);
            SELECT ID FROM @OutputTbl;`;

        const result = await new sql.Request()
            .input('requestId', sql.Int, requestId)
            .input('userId', sql.Int, userId)
            .input('comment_text', sql.NVarChar, comment_text)
            .query(commentQuery);

        const newCommentId = result.recordset[0].ID;

        await logAdminEvent('Новый комментарий', comment_text.substring(0, 200), userId, fullName, requestId);
        broadcastToRequest(String(requestId), {
            type: 'detail_update',
            newCommentId
        });
        await broadcastListUpdate(String(requestId));
        res.status(201).json({
            newCommentId
        });
    } catch (err) {
        console.error("Ошибка добавления комментария:", err);
        res.status(500).send();
    }
});

app.use((req, res, next) => {
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({
            message: 'Эндпоинт не найден'
        });
    }
    if (req.method === 'GET') {
        if (req.path.toLowerCase() === '/login') {
            return res.sendFile(path.join(__dirname, 'public', 'login.html'));
        }
        return res.sendFile(path.join(__dirname, 'public', 'index.html'));
    }
    next();
});

wss.on('connection', (ws, req) => {
    ws.isAlive = true;
    ws.on('pong', () => {
        ws.isAlive = true;
    });
    ws.on('error', console.error);
    ws.subscriptions = new Set();

    const params = new URLSearchParams(url.parse(req.url).search);
    const token = params.get('token');
    if (!token) return ws.close(1008, 'Token not provided');

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return ws.close(1008, 'Invalid token');
        ws.user = user;
    });

    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message);
            if (data.type === 'subscribe' && data.channel) {
                ws.subscriptions.add(data.channel);
            } else if (data.type === 'unsubscribe' && data.channel) {
                ws.subscriptions.delete(data.channel);
            } else if (data.type === 'messages_read' && data.messageIds?.length > 0 && ws.user) {
                const currentRequestChannel = Array.from(ws.subscriptions).find(s => s.startsWith('request-'));
                if (!currentRequestChannel) return;
                const requestId = currentRequestChannel.split('-')[1];

                const queries = data.messageIds.map(id =>
                    `IF NOT EXISTS (SELECT 1 FROM CommentReadStatus WHERE comment_id=${parseInt(id,10)} AND user_id=${ws.user.id})
                     BEGIN
                         INSERT INTO CommentReadStatus(comment_id,user_id) VALUES(${parseInt(id,10)},${ws.user.id})
                     END;`
                ).join('');
                sql.query(queries);

                broadcastToRequest(requestId, {
                    type: 'receipts_updated',
                    readerId: ws.user.id
                }, ws);
            }
        } catch (e) {
            console.error('WS message error:', e);
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

const startServer = async () => {
    try {
        if (!process.env.JWT_SECRET || !process.env.REFRESH_TOKEN_SECRET) {
            console.error('ОШИБКА: Секретные ключи JWT не найдены!');
            process.exit(1);
        }
        await sql.connect(dbConfig);
        console.log('Подключение к БД успешно.');
        server.listen(PORT, () => console.log(`Сервер запущен на порту ${PORT}`));
    } catch (err) {
        console.error('ОШИБКА ПОДКЛЮЧЕНИЯ К БД:', err);
        process.exit(1);
    }
};

startServer();