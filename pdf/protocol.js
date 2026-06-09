/**
 * pdf/protocol.js — генерация официального PDF-протокола согласования заявки.
 *
 * Стилистика — деловой документ по СТБ 6.38-2017 «Унифицированная система
 * организационно-распорядительной документации Республики Беларусь».
 *
 * Основной принцип вёрстки: вместо того чтобы полагаться на внутренний
 * курсор pdfkit (`doc.y`), который ведёт себя по-разному при разных
 * выравниваниях и переносах, мы:
 *   1) считаем высоту каждого блока заранее через doc.heightOfString
 *   2) сами явно контролируем переменную y и переходы на новую страницу
 * Это гарантирует компактную вёрстку без сюрпризов с автоматическими
 * pagebreak'ами.
 */

const PDFDocument = require('pdfkit');
const path = require('path');
const fs = require('fs');

// pre-load шрифты в Buffer один раз при require'е модуля. pdfkit при
// `registerFont(path)` под капотом делает sync `fs.readFileSync` КАЖДЫЙ раз —
// при 100 параллельных PDF event loop сериализуется на 100×600KB sync-чтениях.
// Buffer-вариант избавляет от этого: pdfkit принимает Buffer без дисковых
// операций. Если шрифт битый/отсутствует — модуль не загрузится, что лучше
// чем падать на середине генерации с уже отправленными HTTP-заголовками.
const FONT_REGULAR_BUFFER = fs.readFileSync(path.join(__dirname, '..', 'assets', 'fonts', 'Arial.ttf'));
const FONT_BOLD_BUFFER    = fs.readFileSync(path.join(__dirname, '..', 'assets', 'fonts', 'Arial-Bold.ttf'));

const MONTHS_RU = ['января', 'февраля', 'марта', 'апреля', 'мая', 'июня',
                   'июля', 'августа', 'сентября', 'октября', 'ноября', 'декабря'];

function pad2(n) { return String(n).padStart(2, '0'); }

function fmtDateLong(d) {
    if (!d) return '—';
    const dt = new Date(d);
    return `«${pad2(dt.getDate())}» ${MONTHS_RU[dt.getMonth()]} ${dt.getFullYear()} г.`;
}

function fmtDateShort(d) {
    if (!d) return '—';
    const dt = new Date(d);
    return `${pad2(dt.getDate())}.${pad2(dt.getMonth() + 1)}.${dt.getFullYear()}`;
}

function fmtDateTime(d) {
    if (!d) return '—';
    const dt = new Date(d);
    const t = dt.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
    return `${fmtDateShort(d)} ${t}`;
}

const C = {
    text:  '#000000',
    muted: '#555555',
    line:  '#000000'
};

/**
 * Генерация PDF-протокола согласования.
 *
 * @param {Object} req      — данные заявки (status_id, status_name, title, ...)
 * @param {Array}  history  — записи смены статуса для секции подписей
 * @param {Object} opts
 *   @param {boolean} opts.isDraft — «черновой» режим. Накладывает диагональный
 *     watermark «ПРОЕКТ — НЕ ПОДПИСАН» на каждой странице.
 *   @param {Object} [opts.presumptiveSigner] — «потенциальный» подписант
 *     (ФИО + дата). Используется для бланка к подписи на статусе APPROVAL:
 *     согласующий открывает бланк — система pre-заполняет его ФИО и сегодняшнюю
 *     дату в строке «Утверждено (согласующий)» и в секции «Решение».
 *     Не перетирает данные из history — если запись о реальном одобрении уже
 *     есть, используется она.
 */
function generateProtocolPDF(req, history, opts = {}) {
    const isDraft = opts.isDraft === true;
    const presumptiveSigner = opts.presumptiveSigner || null;

    const doc = new PDFDocument({
        size: 'A4',
        margin: 50,
        bufferPages: true,
        info: {
            Title:    isDraft
                ? `Протокол согласования заявки № ${req.id} (черновик)`
                : `Протокол согласования заявки № ${req.id}`,
            Author:   'РУП «Витебскэнерго»',
            Subject:  'Протокол согласования заявки на проведение мероприятия',
            Producer: 'VitEnergo System'
        }
    });

    doc.registerFont('regular', FONT_REGULAR_BUFFER);
    doc.registerFont('bold',    FONT_BOLD_BUFFER);

    // Отключаем автоматический pagebreak от pdfkit. Иначе он добавляет страницу
    // когда внутренний doc.y приближается к margins.bottom, не считаясь с тем
    // что мы передаём явные координаты. Все переносы страниц теперь — только
    // там, где мы явно вызываем doc.addPage(). Применяется к КАЖДОЙ странице
    // через хук 'pageAdded' (стартовая страница уже создана к этому моменту,
    // её нужно настроить отдельно).
    doc.on('pageAdded', () => { doc.page.margins.bottom = 0; });
    doc.page.margins.bottom = 0;

    const pageW  = doc.page.width;     // 595
    const pageH  = doc.page.height;    // 842
    const ml     = doc.page.margins.left;
    const mr     = doc.page.margins.right;
    const innerW = pageW - ml - mr;    // 495
    const SAFE_BOTTOM = pageH - 50;    // визуальная нижняя граница (842 - 50)

    // Локальный курсор. doc.y НЕ используем — только для измерения высоты.
    let y;

    /* ===========  helper'ы  =========== */

    /** Сечение «label : value» в одну строку с фиксированной шириной label-колонки. */
    const drawKV = (label, value, opts = {}) => {
        if (value === null || value === undefined || value === '') return;
        const labelW = opts.labelW || 175;
        const valueW = innerW - labelW;
        const text = String(value);

        doc.font('regular').fontSize(10).fillColor(C.text);
        const hLabel = doc.heightOfString(label, { width: labelW });
        doc.font('bold').fontSize(10);
        const hValue = doc.heightOfString(text, { width: valueW });
        const blockH = Math.max(hLabel, hValue);

        // Перенос на новую страницу если не влезаем
        if (y + blockH > SAFE_BOTTOM) { doc.addPage(); y = ml; }

        doc.font('regular').fontSize(10).fillColor(C.text)
            .text(label, ml, y, { width: labelW });
        doc.font('bold').fontSize(10)
            .text(text, ml + labelW, y, { width: valueW });

        y += blockH + 4;
    };

    /** Заголовок секции вида «1. Предмет заявки» с тонкой линией под ним. */
    const drawSectionTitle = (title) => {
        if (y + 24 > SAFE_BOTTOM) { doc.addPage(); y = ml; }
        y += 6;
        doc.font('bold').fontSize(10).fillColor(C.text)
            .text(title, ml, y, { width: innerW });
        y += 14;
        doc.strokeColor(C.line).lineWidth(0.5);
        doc.moveTo(ml, y - 2).lineTo(pageW - mr, y - 2).stroke();
        y += 6;
    };

    /* ===========  ШАПКА БЛАНКА  ===========
       Все позиции рассчитываются динамически от высоты предыдущего блока,
       чтобы длинное название организации (которое может занять 1 или 2 строки)
       не наезжало на следующие элементы. */
    doc.fillColor(C.text);

    // === Левая колонка ===
    const orgLine = 'Государственное производственное объединение «Белэнерго»';
    const leftW = innerW * 0.62;
    let yL = 50;

    doc.font('bold').fontSize(9);
    const orgLineH = doc.heightOfString(orgLine, { width: leftW });
    doc.text(orgLine, ml, yL, { width: leftW });
    yL += orgLineH + 2;

    doc.font('bold').fontSize(12);
    doc.text('РУП «ВИТЕБСКЭНЕРГО»', ml, yL, { width: leftW });
    yL += doc.heightOfString('РУП «ВИТЕБСКЭНЕРГО»', { width: leftW }) + 4;

    doc.font('regular').fontSize(8.5).fillColor(C.muted);
    doc.text('210029, г. Витебск, ул. Правды, 30', ml, yL);
    yL += 11;
    doc.text('Тел./факс: (0212) 67-22-22 · e-mail: priem@vitebsk.energo.by', ml, yL);
    yL += 11;

    // === Правая колонка — реквизиты документа ===
    const rightX = ml + innerW * 0.65;
    const rightW = innerW * 0.35;
    let yR = 50;
    doc.font('regular').fontSize(10).fillColor(C.text)
        .text(`№ ${req.id}`, rightX, yR, { width: rightW, align: 'right' });
    yR += 14;
    doc.text(`от ${fmtDateLong(new Date())}`, rightX, yR, { width: rightW, align: 'right' });
    yR += 14;
    doc.font('regular').fontSize(7.5).fillColor(C.muted)
        .text('(внутренний регистрационный номер)', rightX, yR, { width: rightW, align: 'right' });
    yR += 10;

    // === Разделитель шапки — после максимума из двух колонок ===
    const headerEnd = Math.max(yL, yR) + 5;
    doc.strokeColor(C.line).lineWidth(0.7);
    doc.moveTo(ml, headerEnd).lineTo(pageW - mr, headerEnd).stroke();

    /* ===========  ЗАГОЛОВОК ДОКУМЕНТА  =========== */
    let yT = headerEnd + 18;
    doc.fillColor(C.text).font('bold').fontSize(14)
        .text(`П Р О Т О К О Л   №   ${req.id}`, ml, yT, { align: 'center', width: innerW });
    yT += 22;
    doc.font('regular').fontSize(10.5)
        .text('согласования заявки на проведение мероприятия', ml, yT, { align: 'center', width: innerW });
    yT += 24;

    // Город — дата (по принципу делового бланка)
    doc.font('regular').fontSize(10).fillColor(C.text)
        .text('г. Витебск', ml, yT, { width: innerW * 0.5 })
        .text(fmtDateLong(new Date()), ml + innerW * 0.5, yT, { width: innerW * 0.5, align: 'right' });
    yT += 22;

    y = yT;

    /* ===========  1. ПРЕДМЕТ ЗАЯВКИ  =========== */
    drawSectionTitle('1. Предмет заявки');
    drawKV('1.1. Категория мероприятия:',  req.category_name);
    drawKV('1.2. Наименование:',           req.title);
    drawKV('1.3. Дата и время проведения:', fmtDateTime(req.planned_date));
    drawKV('1.4. Место проведения:',       req.location);
    if (req.expected_attendees)
        drawKV('1.5. Кол-во участников:',  `${req.expected_attendees} чел.`);
    drawKV('1.6. Ответственный за проведение:', req.responsible_person);

    /* ===========  2. ЗАЯВИТЕЛЬ  =========== */
    drawSectionTitle('2. Заявитель');
    drawKV('2.1. Ф.И.О.:',                 req.creator_name);
    drawKV('2.2. Структурное подразделение:', req.branch_name);
    drawKV('2.3. Дата подачи заявки:',     fmtDateTime(req.created_at));

    /* ===========  3. СОДЕРЖАНИЕ МЕРОПРИЯТИЯ  =========== */
    if (req.description && req.description.trim()) {
        drawSectionTitle('3. Содержание мероприятия');
        const opts = { width: innerW, indent: 25, lineGap: 2 };
        const h = doc.heightOfString(req.description, opts);
        if (y + h > SAFE_BOTTOM) {
            // если описание длинное и не помещается на текущей странице,
            // временно включаем автоматический pagebreak pdfkit'а для этого
            // блока — иначе текст обрежется снизу. Раньше bottomMargin=0
            // выключал pagebreak для всего документа: длинное описание
            // (>1 страницы) теряло хвост за пределами листа. Теперь pdfkit
            // сам разорвёт текст. После блока возвращаем margin=0 и
            // используем `doc.y` как актуальный курсор после flow.
            doc.addPage();
            y = ml;
        }
        // Локально разрешаем pagebreak — даже короткое описание под нижней
        // границей теперь не пропадёт.
        const SAFE_BOTTOM_MARGIN = 50;
        doc.page.margins.bottom = SAFE_BOTTOM_MARGIN;
        doc.font('regular').fontSize(10).fillColor(C.text).text(req.description, ml, y, opts);
        // pdfkit мог уйти на следующую страницу через автоматический pagebreak.
        // Берём актуальный y из doc, прибавляем отступ и снова отключаем
        // pagebreak для строгой ручной вёрстки оставшихся секций.
        y = doc.y + 8;
        doc.page.margins.bottom = 0;
    }

    /* ===========  4. РЕШЕНИЕ  =========== */
    drawSectionTitle('4. Решение по заявке');

    // Решение в виде осмысленной фразы. Для бланка к подписи (APPROVAL +
    // presumptiveSigner) показываем формулировку ОДОБРЕНА с сегодняшней
    // датой — документ готов к физической подписи согласующего.
    const status = (req.status_name || '').toLowerCase();
    let decisionLine;
    if (status === 'одобрена') {
        decisionLine = `Заявка ОДОБРЕНА. Дата принятия решения: ${fmtDateLong(req.updated_at)}.`;
    } else if (status === 'отклонена') {
        decisionLine = `Заявка ОТКЛОНЕНА. Дата принятия решения: ${fmtDateLong(req.updated_at)}.`;
    } else if (status === 'требует доработки') {
        decisionLine = `Заявка ВОЗВРАЩЕНА НА ДОРАБОТКУ. Дата: ${fmtDateLong(req.updated_at)}.`;
    } else if (status === 'на согласовании' && presumptiveSigner) {
        decisionLine = `Заявка ОДОБРЕНА. Дата принятия решения: ${fmtDateLong(presumptiveSigner.date)}.`;
    } else {
        decisionLine = `На дату формирования протокола заявка находится в статусе «${req.status_name}».`;
    }
    const decH = doc.font('regular').fontSize(10).heightOfString(decisionLine, { width: innerW });
    if (y + decH > SAFE_BOTTOM) { doc.addPage(); y = ml; }
    doc.fillColor(C.text).text(decisionLine, ml, y, { width: innerW });
    y += decH + 12;

    /* ===========  5. ПОДПИСИ  ===========
       findActor ищет в history запись о переходе на конкретный статус.
       Используем короткие корни ('согласован', 'одобр', 'отклон') чтобы
       матчить все возможные формы: «На согласовании» / «согласование» /
       «Одобрена» / «Одобрить» (старые записи до Раунда 11) / «Отклонена».
       findLast — берём ПОСЛЕДНЮЮ запись с этим корнем: если заявка
       прошла rework-петлю и согласовывалась дважды, актуальная подпись
       принадлежит последнему согласованию. */
    const findActor = (roots) => {
        const rootsLower = Array.isArray(roots) ? roots : [roots];
        let found = null;
        for (const h of history) {
            if (h.action !== 'Смена статуса' || !h.details) continue;
            const dl = h.details.toLowerCase();
            if (rootsLower.some(r => dl.includes(r))) {
                found = h;  // продолжаем перебор — берём последнее совпадение
            }
        }
        return found ? { name: found.full_name, when: found.timestamp } : null;
    };

    // moderator → кто перевёл в «На согласовании»
    // approver → кто принял финальное решение (Одобрена ИЛИ Отклонена).
    // Для отказа всё равно нужна строка «Утверждено» с подписантом.
    const moderator = findActor(['согласован']);
    let approver    = findActor(['одобр', 'отклон']);

    // Fallback: для бланка к подписи (APPROVAL) реального approver'а ещё нет
    // в history. Подставляем «потенциального» подписанта — текущего юзера,
    // открывшего бланк. Согласующий распечатывает уже готовый к подписи
    // документ со своим ФИО и сегодняшней датой.
    if (!approver && presumptiveSigner) {
        approver = { name: presumptiveSigner.name, when: presumptiveSigner.date };
    }

    // Заголовок последней строки зависит от исхода: «Утверждено» при одобрении,
    // «Решение принято» — нейтральная формулировка для отклонения.
    const reqStatusLower = (req.status_name || '').toLowerCase();
    const approverRoleLabel = reqStatusLower === 'отклонена'
        ? 'Решение об отказе (согласующий)'
        : 'Утверждено (согласующий)';

    const signatories = [
        { role: 'Заявитель',                    name: req.creator_name, date: req.created_at },
        { role: 'Согласовано (модератор)',      name: (moderator || {}).name, date: (moderator || {}).when },
        { role: approverRoleLabel,               name: (approver  || {}).name, date: (approver  || {}).when }
    ];

    // Высота таблицы заранее = шапка + 3 строки
    const colW = [180, 130, innerW - 180 - 130]; // должность | подпись | расшифровка
    const headerH = 18;
    const rowH    = 38;
    const tableH  = headerH + rowH * signatories.length;

    if (y + tableH + 60 > SAFE_BOTTOM) { doc.addPage(); y = ml; }

    drawSectionTitle('5. Согласование и подписи');

    // Шапка таблицы
    doc.strokeColor(C.line).lineWidth(0.5);
    let cx = ml;
    [colW[0], colW[1], colW[2]].forEach((w) => {
        doc.rect(cx, y, w, headerH).stroke();
        cx += w;
    });
    doc.font('bold').fontSize(9).fillColor(C.text);
    doc.text('Должность',       ml + 6,              y + 5, { width: colW[0] - 12 });
    doc.text('Подпись',          ml + colW[0] + 6,    y + 5, { width: colW[1] - 12, align: 'center' });
    doc.text('Расшифровка / дата', ml + colW[0] + colW[1] + 6, y + 5, { width: colW[2] - 12 });
    y += headerH;

    // Строки таблицы
    signatories.forEach(s => {
        cx = ml;
        [colW[0], colW[1], colW[2]].forEach(w => {
            doc.rect(cx, y, w, rowH).stroke();
            cx += w;
        });

        doc.font('regular').fontSize(10).fillColor(C.text)
            .text(s.role, ml + 6, y + 6, { width: colW[0] - 12 });

        // Колонка «Подпись» — пустая, пометка под линией
        doc.font('regular').fontSize(7.5).fillColor(C.muted)
            .text('(личная подпись)', ml + colW[0] + 6, y + rowH - 11, { width: colW[1] - 12, align: 'center' });

        // Колонка «Расшифровка / дата»
        const nameTxt = s.name || '________________________';
        doc.font('regular').fontSize(10).fillColor(C.text)
            .text(nameTxt, ml + colW[0] + colW[1] + 6, y + 6, { width: colW[2] - 12 });
        if (s.date) {
            doc.font('regular').fontSize(8.5).fillColor(C.muted)
                .text(fmtDateLong(s.date), ml + colW[0] + colW[1] + 6, y + 22, { width: colW[2] - 12 });
        }
        y += rowH;
    });

    /* ===========  МЕСТО ПЕЧАТИ  =========== */
    y += 14;
    if (y + 30 > SAFE_BOTTOM) { doc.addPage(); y = ml; }
    doc.font('regular').fontSize(9).fillColor(C.text)
        .text('М.П.', ml, y);

    /* ===========  ФУТЕР + WATERMARK (на каждой странице, через bufferPages)  =========== */
    const range = doc.bufferedPageRange();
    for (let i = 0; i < range.count; i++) {
        doc.switchToPage(range.start + i);

        // === Watermark «ПРОЕКТ — НЕ ПОДПИСАН» для черновых статусов ===
        // Рисуется ДО футера, по диагонали, бледно-красным с прозрачностью —
        // чтобы основной текст оставался читаемым, но было невозможно
        // выдать распечатку за подписанный документ.
        if (isDraft) {
            doc.save();
            doc.translate(pageW / 2, pageH / 2);
            doc.rotate(-30);
            doc.fillColor('#c62828').opacity(0.12);
            doc.font('bold').fontSize(96)
                .text('ПРОЕКТ', -pageW / 2, -60, { width: pageW, align: 'center' });
            doc.fontSize(22).opacity(0.18)
                .text('НЕ ПОДПИСАН — ЧЕРНОВИК', -pageW / 2, 50, { width: pageW, align: 'center' });
            doc.restore();
            doc.opacity(1);
        }

        const fY = pageH - 38;
        doc.strokeColor(C.line).lineWidth(0.3);
        doc.moveTo(ml, fY - 4).lineTo(pageW - mr, fY - 4).stroke();
        doc.font('regular').fontSize(7).fillColor(C.muted)
            .text(
                `Документ сформирован автоматически информационной системой РУП «Витебскэнерго». ` +
                `ID: REQ-${req.id}-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}${isDraft ? '-DRAFT' : ''}. ` +
                `Стр. ${i + 1} из ${range.count}.`,
                ml, fY, { align: 'center', width: innerW }
            );
        doc.text(
            isDraft
                ? 'Предварительный документ. Не имеет юридической силы до утверждения решения по заявке.'
                : 'Электронная версия. Для бумажного оборота требуется печать организации и собственноручные подписи.',
            ml, fY + 11, { align: 'center', width: innerW }
        );
    }

    return doc;
}

module.exports = { generateProtocolPDF };
