#!/usr/bin/env node
/**
 * scripts/build_diploma.js
 *
 * Конвертирует все markdown-файлы из docs/diploma/ в один .docx с
 * форматированием по требованиям ВГУ имени П. М. Машерова:
 *   - A4, поля 20/20/30/15 мм
 *   - Times New Roman 14 pt
 *   - Межстрочный интервал точно 18 pt
 *   - Абзацный отступ 1.25 см
 *   - Заголовки глав по центру, ВЕРХНИЙ РЕГИСТР
 *   - Таблицы по ГОСТ 7.32
 *
 * Запуск: node scripts/build_diploma.js
 * Результат: docs/diploma/diploma.docx
 */
'use strict';

const fs = require('fs');
const path = require('path');
const {
    Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
    AlignmentType, HeadingLevel, BorderStyle, WidthType, ShadingType,
    LevelFormat, PageBreak, PageNumber, Footer, AlignmentType: A,
    convertMillimetersToTwip
} = require('docx');

// ============================================================
// Параметры форматирования (требования методички)
// ============================================================
const FONT = 'Times New Roman';
const SIZE_NORMAL = 28;       // 14 pt = 28 half-points
const SIZE_H1 = 28;           // Главы оформляются тем же 14 pt, но bold + uppercase
const SIZE_H2 = 28;
const LINE_SPACING_EXACT = 360; // 18 pt = 360 twentieths-of-point
const INDENT_FIRST_LINE = 720;  // 1.25 cm ≈ 720 twips (1 cm = 567 twips)
// Поля страницы: верх/низ 20 мм, лево 30 мм, право 15 мм
const PAGE_MARGINS = {
    top:    convertMillimetersToTwip(20),
    bottom: convertMillimetersToTwip(20),
    left:   convertMillimetersToTwip(30),
    right:  convertMillimetersToTwip(15)
};
// A4: 210x297 мм
const PAGE_SIZE = {
    width:  convertMillimetersToTwip(210),
    height: convertMillimetersToTwip(297)
};

// ============================================================
// Утилиты конвертации markdown
// ============================================================

// ============================================================
// Нормализация формул: LaTeX-команды → Unicode + читаемая запись
// ============================================================

const SUBSCRIPT_MAP = {
    '0': '₀', '1': '₁', '2': '₂', '3': '₃', '4': '₄',
    '5': '₅', '6': '₆', '7': '₇', '8': '₈', '9': '₉',
    '+': '₊', '-': '₋', '=': '₌', '(': '₍', ')': '₎',
    'a': 'ₐ', 'e': 'ₑ', 'i': 'ᵢ', 'j': 'ⱼ', 'o': 'ₒ',
    'n': 'ₙ', 't': 'ₜ', 'r': 'ᵣ'
};
const SUPERSCRIPT_MAP = {
    '0': '⁰', '1': '¹', '2': '²', '3': '³', '4': '⁴',
    '5': '⁵', '6': '⁶', '7': '⁷', '8': '⁸', '9': '⁹',
    '+': '⁺', '-': '⁻', '=': '⁼', '(': '⁽', ')': '⁾',
    'n': 'ⁿ', 'i': 'ⁱ', 't': 'ᵗ', 'r': 'ʳ',
    'a': 'ᵃ', 'b': 'ᵇ', 'c': 'ᶜ', 'd': 'ᵈ', 'e': 'ᵉ',
    'f': 'ᶠ', 'g': 'ᵍ', 'h': 'ʰ', 'k': 'ᵏ', 'l': 'ˡ',
    'm': 'ᵐ', 'o': 'ᵒ', 'p': 'ᵖ', 's': 'ˢ', 'u': 'ᵘ',
    'v': 'ᵛ', 'w': 'ʷ', 'x': 'ˣ', 'y': 'ʸ', 'z': 'ᶻ'
};
function mapSubscript(s) {
    return s.split('').map(c => SUBSCRIPT_MAP[c] || c).join('');
}
function mapSuperscript(s) {
    return s.split('').map(c => SUPERSCRIPT_MAP[c] || c).join('');
}

/** Преобразует LaTeX-подобную формулу в читаемый Unicode-текст. */
function renderMath(latex) {
    let s = latex.trim();

    // LaTeX `{,}` использовался И как разделитель тысяч, И как десятичная.
    // Различаем по эвристике: если после {,} идёт ровно 3 цифры — это тысячи
    // (используем неразрывный пробел   по ГОСТ); иначе десятичная.
    // Применяем несколько раз для случаев типа `113{,}100{,}69`.
    for (let p = 0; p < 3; p++) {
        s = s.replace(/(\d)\{,\}(\d{3})(?!\d)/g, '$1 $2');
    }
    // Оставшиеся {,} — десятичные
    s = s.replace(/\{,\}/g, ',');

    // \text{...} → просто содержимое
    s = s.replace(/\\text\s*\{([^}]*)\}/g, '$1');
    s = s.replace(/\\mathrm\s*\{([^}]*)\}/g, '$1');

    // Греческие буквы
    const greeks = {
        Delta: 'Δ', Sigma: 'Σ', Pi: 'Π', Omega: 'Ω', Phi: 'Φ', Psi: 'Ψ',
        Gamma: 'Γ', Lambda: 'Λ', Theta: 'Θ', Xi: 'Ξ',
        alpha: 'α', beta: 'β', gamma: 'γ', delta: 'δ',
        epsilon: 'ε', zeta: 'ζ', eta: 'η', theta: 'θ',
        lambda: 'λ', mu: 'μ', nu: 'ν', xi: 'ξ',
        pi: 'π', rho: 'ρ', sigma: 'σ', tau: 'τ', phi: 'φ',
        chi: 'χ', psi: 'ψ', omega: 'ω'
    };
    for (const [name, ch] of Object.entries(greeks)) {
        // Команда + опциональный пробел перед следующим символом — пробел съедаем
        s = s.replace(new RegExp('\\\\' + name + '\\s+', 'g'), ch);
        s = s.replace(new RegExp('\\\\' + name + '\\b', 'g'), ch);
    }

    // Операторы и знаки
    const ops = {
        'times': '×', 'cdot': '·', 'pm': '±', 'mp': '∓',
        'leq': '≤', 'geq': '≥', 'neq': '≠', 'approx': '≈',
        'equiv': '≡', 'sim': '~', 'propto': '∝',
        'rightarrow': '→', 'leftarrow': '←', 'to': '→',
        'in': '∈', 'notin': '∉', 'subset': '⊂', 'supset': '⊃',
        'cup': '∪', 'cap': '∩', 'emptyset': '∅',
        'infty': '∞', 'partial': '∂', 'nabla': '∇',
        'forall': '∀', 'exists': '∃',
        'div': '÷', 'pm': '±'
    };
    for (const [name, ch] of Object.entries(ops)) {
        s = s.replace(new RegExp('\\\\' + name + '\\b', 'g'), ch);
    }

    // Σ с пределами: \sum_{a}^{b} или \sum_a^b → Σ (от a до b)
    s = s.replace(/\\sum_\{([^}]+)\}\^\{([^}]+)\}/g, (_, a, b) => `Σ (от ${a} до ${b}) `);
    s = s.replace(/\\sum_\{([^}]+)\}\^(\S)/g, (_, a, b) => `Σ (от ${a} до ${b}) `);
    s = s.replace(/\\sum_(\S)\^\{([^}]+)\}/g, (_, a, b) => `Σ (от ${a} до ${b}) `);
    s = s.replace(/\\sum_(\S)\^(\S)/g, (_, a, b) => `Σ (от ${a} до ${b}) `);
    s = s.replace(/\\sum\b/g, 'Σ ');

    // Дроби \frac{num}{den} → (num) / (den)
    // Поддержка вложенных через несколько проходов
    for (let pass = 0; pass < 3; pass++) {
        s = s.replace(/\\frac\s*\{([^{}]*)\}\s*\{([^{}]*)\}/g, (_, num, den) => {
            // Если num и den простые — без скобок, иначе со скобками
            const nNeeds = /[+\-×÷·\s]/.test(num) && !/^\([^()]*\)$/.test(num);
            const dNeeds = /[+\-×÷·\s]/.test(den) && !/^\([^()]*\)$/.test(den);
            const N = nNeeds ? `(${num})` : num;
            const D = dNeeds ? `(${den})` : den;
            return `${N} / ${D}`;
        });
    }

    // Подстрочные индексы X_{abc} или X_a → подстрочный Unicode или X_abc
    s = s.replace(/_\{([^}]+)\}/g, (_, sub) => {
        // Если все символы есть в карте — конвертируем
        if (sub.split('').every(c => SUBSCRIPT_MAP[c] !== undefined)) {
            return mapSubscript(sub);
        }
        return '_' + sub;
    });
    s = s.replace(/_(\w)/g, (_, c) => SUBSCRIPT_MAP[c] || '_' + c);

    // Надстрочные индексы (степени) X^{abc} или X^a
    s = s.replace(/\^\{([^}]+)\}/g, (_, sup) => {
        if (sup.split('').every(c => SUPERSCRIPT_MAP[c] !== undefined)) {
            return mapSuperscript(sup);
        }
        return '^' + sup;
    });
    s = s.replace(/\^(\w)/g, (_, c) => SUPERSCRIPT_MAP[c] || '^' + c);

    // Минус-знак: ASCII '-' между числами/буквами → en-dash минус для математики
    // (но не трогаем дефисы в словах). Простая эвристика: пробел-минус-пробел.
    s = s.replace(/ - /g, ' − ');

    // Чистка двойных пробелов
    s = s.replace(/\s+/g, ' ').trim();

    return s;
}

/** Парсит inline-форматирование (**bold**, *italic*, $math$) внутри строки. */
function parseInline(text) {
    const runs = [];
    let i = 0;
    while (i < text.length) {
        // $inline math$
        const mathStart = text.indexOf('$', i);
        // **bold**
        const boldStart = text.indexOf('**', i);

        // Выбираем что первее
        let nextSpecial = -1;
        let kind = null;
        if (mathStart !== -1 && (boldStart === -1 || mathStart < boldStart)) {
            // Убедимся что это не $$ (блочная формула — должна быть на отдельной строке)
            if (text[mathStart + 1] !== '$') {
                nextSpecial = mathStart;
                kind = 'math';
            }
        }
        if ((nextSpecial === -1 || boldStart < nextSpecial) && boldStart !== -1) {
            nextSpecial = boldStart;
            kind = 'bold';
        }

        if (nextSpecial === -1) {
            const remaining = text.slice(i);
            if (remaining) runs.push(new TextRun({ text: remaining, font: FONT, size: SIZE_NORMAL }));
            break;
        }

        const before = text.slice(i, nextSpecial);
        if (before) runs.push(new TextRun({ text: before, font: FONT, size: SIZE_NORMAL }));

        if (kind === 'bold') {
            const boldEnd = text.indexOf('**', nextSpecial + 2);
            if (boldEnd === -1) {
                runs.push(new TextRun({ text: text.slice(nextSpecial), font: FONT, size: SIZE_NORMAL }));
                break;
            }
            const boldText = text.slice(nextSpecial + 2, boldEnd);
            runs.push(new TextRun({ text: boldText, font: FONT, size: SIZE_NORMAL, bold: true }));
            i = boldEnd + 2;
        } else if (kind === 'math') {
            const mathEnd = text.indexOf('$', nextSpecial + 1);
            if (mathEnd === -1) {
                runs.push(new TextRun({ text: text.slice(nextSpecial), font: FONT, size: SIZE_NORMAL }));
                break;
            }
            const mathText = renderMath(text.slice(nextSpecial + 1, mathEnd));
            runs.push(new TextRun({ text: mathText, font: FONT, size: SIZE_NORMAL, italics: true }));
            i = mathEnd + 1;
        }
    }
    return runs;
}

/** Создаёт обычный абзац основного текста. */
function bodyParagraph(text, opts = {}) {
    return new Paragraph({
        children: parseInline(text),
        alignment: opts.center ? AlignmentType.CENTER : AlignmentType.JUSTIFIED,
        spacing: { line: LINE_SPACING_EXACT, lineRule: 'exact', before: 0, after: 0 },
        indent: opts.noIndent ? undefined : { firstLine: INDENT_FIRST_LINE }
    });
}

// Цвет заголовков — чёрный (по умолчанию HeadingLevel в docx-js даёт синий).
const HEADING_COLOR = '000000';

/** Заголовок главы (ГЛАВА N. ...). Центрирован, жирный, верхний регистр.
 *  Перед заголовком — разрыв страницы; после заголовка — одна пустая строка. */
function heading1(text) {
    return new Paragraph({
        children: [new TextRun({
            text: text.toUpperCase(),
            font: FONT, size: SIZE_H1, bold: true, color: HEADING_COLOR
        })],
        alignment: AlignmentType.CENTER,
        spacing: { line: LINE_SPACING_EXACT, lineRule: 'exact', before: 0, after: LINE_SPACING_EXACT },
        pageBreakBefore: true,
        heading: HeadingLevel.HEADING_1
    });
}

/** Подраздел (1.1, 1.2). Жирный, без uppercase.
 *  Перед заголовком — одна пустая строка; после — сразу текст. */
function heading2(text) {
    return new Paragraph({
        children: [new TextRun({
            text: text, font: FONT, size: SIZE_H2, bold: true, color: HEADING_COLOR
        })],
        alignment: AlignmentType.LEFT,
        spacing: { line: LINE_SPACING_EXACT, lineRule: 'exact', before: LINE_SPACING_EXACT, after: 0 },
        indent: { firstLine: INDENT_FIRST_LINE },
        heading: HeadingLevel.HEADING_2
    });
}

/** Заголовок без главы (ВВЕДЕНИЕ, ЗАКЛЮЧЕНИЕ). */
function topHeading(text) {
    return new Paragraph({
        children: [new TextRun({
            text: text.toUpperCase(),
            font: FONT, size: SIZE_H1, bold: true, color: HEADING_COLOR
        })],
        alignment: AlignmentType.CENTER,
        spacing: { line: LINE_SPACING_EXACT, lineRule: 'exact', before: 0, after: LINE_SPACING_EXACT },
        pageBreakBefore: true,
        heading: HeadingLevel.HEADING_1
    });
}

/** «Выводы по главе X» — H2 без отступа первой строки (теперь не используется
 *  после перехода на «Подход Б»: выводы встроены в последний абзац каждого
 *  подраздела). Функция оставлена для обратной совместимости. */
function conclusionHeading(text) {
    return new Paragraph({
        children: [new TextRun({ text, font: FONT, size: SIZE_NORMAL, bold: true, color: HEADING_COLOR })],
        alignment: AlignmentType.LEFT,
        spacing: { line: LINE_SPACING_EXACT, lineRule: 'exact', before: LINE_SPACING_EXACT, after: 0 },
        indent: { firstLine: INDENT_FIRST_LINE }
    });
}

// ============================================================
// Парсинг markdown
// ============================================================

/**
 * Парсит .md файл и возвращает массив элементов для docx.
 * Поддерживает: # H1, ## H2, ### H3, `**bold**`, таблицы `|...|`, обычный текст.
 */
function parseMarkdown(content) {
    const lines = content.split('\n');
    const elements = [];
    let i = 0;
    let paragraphBuffer = [];
    // Состояние для нумерации формул по ГОСТ 7.32 §6.5: «(номер главы).(порядковый номер)».
    // Например, первая формула во второй главе → «(2.1)».
    let currentChapter = null;
    let formulaInChapter = 0;

    const flushParagraph = () => {
        if (paragraphBuffer.length === 0) return;
        const text = paragraphBuffer.join(' ').replace(/\s+/g, ' ').trim();
        if (text) elements.push(bodyParagraph(text));
        paragraphBuffer = [];
    };

    while (i < lines.length) {
        const line = lines[i];
        const trimmed = line.trim();

        // Пустая строка — конец абзаца
        if (!trimmed) {
            flushParagraph();
            i++;
            continue;
        }

        // # Главный заголовок (ВВЕДЕНИЕ, ГЛАВА N., ЗАКЛЮЧЕНИЕ, СПИСОК)
        if (trimmed.startsWith('# ')) {
            flushParagraph();
            const headingText = trimmed.slice(2).trim();
            // Обнаруживаем номер главы для нумерации формул (по ГОСТ 7.32)
            const chapterMatch = headingText.match(/^ГЛАВА\s+(\d+)\b/i);
            if (chapterMatch) {
                currentChapter = parseInt(chapterMatch[1], 10);
                formulaInChapter = 0;
            } else {
                currentChapter = null;
                formulaInChapter = 0;
            }
            elements.push(topHeading(headingText));
            i++;
            continue;
        }

        // ## Подраздел (1.1, 2.1)
        if (trimmed.startsWith('## ')) {
            flushParagraph();
            const text = trimmed.slice(3).trim();
            // Особый случай: «Выводы по главе N»
            if (/^Выводы по главе/i.test(text)) {
                elements.push(conclusionHeading(text));
            } else {
                elements.push(heading2(text));
            }
            i++;
            continue;
        }

        // ### Подподраздел
        if (trimmed.startsWith('### ')) {
            flushParagraph();
            elements.push(new Paragraph({
                children: [new TextRun({
                    text: trimmed.slice(4).trim(),
                    font: FONT, size: SIZE_NORMAL, bold: true, italics: true, color: '000000'
                })],
                alignment: AlignmentType.LEFT,
                spacing: { line: LINE_SPACING_EXACT, lineRule: 'exact', before: LINE_SPACING_EXACT, after: 0 },
                indent: { firstLine: INDENT_FIRST_LINE }
            }));
            i++;
            continue;
        }

        // Подпись таблицы: **Таблица N — ...** — одна пустая строка перед/после
        if (/^\*\*Таблица /.test(trimmed)) {
            flushParagraph();
            const captionText = trimmed.replace(/^\*\*/, '').replace(/\*\*$/, '');
            elements.push(new Paragraph({
                children: [new TextRun({ text: captionText, font: FONT, size: SIZE_NORMAL, bold: false })],
                alignment: AlignmentType.LEFT,
                spacing: { line: LINE_SPACING_EXACT, lineRule: 'exact', before: LINE_SPACING_EXACT, after: 0 },
                indent: { firstLine: 0 }
            }));
            i++;
            continue;
        }

        // Подпись рисунка: **Рисунок N — ...** — одна пустая строка перед/после
        if (/^\*\*Рисунок /.test(trimmed)) {
            flushParagraph();
            const captionText = trimmed.replace(/^\*\*/, '').replace(/\*\*$/, '');
            elements.push(new Paragraph({
                children: [new TextRun({ text: captionText, font: FONT, size: SIZE_NORMAL })],
                alignment: AlignmentType.CENTER,
                spacing: { line: LINE_SPACING_EXACT, lineRule: 'exact', before: 0, after: LINE_SPACING_EXACT },
                indent: { firstLine: 0 }
            }));
            i++;
            continue;
        }

        // Подпись «Источник:» под таблицей — мелкий шрифт, без отступа первой строки
        if (/^_Источник:/.test(trimmed) || /^\*Источник:/.test(trimmed)) {
            flushParagraph();
            const sourceText = trimmed.replace(/^[_*]/, '').replace(/[_*]$/, '');
            elements.push(new Paragraph({
                children: [new TextRun({ text: sourceText, font: FONT, size: 24, italics: true })],
                alignment: AlignmentType.LEFT,
                spacing: { line: LINE_SPACING_EXACT, lineRule: 'exact', before: 0, after: LINE_SPACING_EXACT },
                indent: { firstLine: 0 }
            }));
            i++;
            continue;
        }

        // Таблица: строка начинается с |
        if (trimmed.startsWith('|') && trimmed.endsWith('|')) {
            flushParagraph();
            // Собираем все строки таблицы
            const tableLines = [];
            while (i < lines.length && lines[i].trim().startsWith('|')) {
                tableLines.push(lines[i].trim());
                i++;
            }
            // Парсим: первая строка = заголовок, вторая = разделитель |---|, остальные = данные
            const parseRow = (raw) => raw.slice(1, -1).split('|').map(c => c.trim());
            const rows = tableLines.map(parseRow);
            // Удаляем строку-разделитель (содержит только --- и :)
            const dataRows = rows.filter(r => !r.every(c => /^:?-+:?$/.test(c.replace(/-/g, '-'))));
            if (dataRows.length > 0) {
                elements.push(buildTable(dataRows));
            }
            continue;
        }

        // Маркированный список: «* ...»
        if (/^[*-] /.test(trimmed)) {
            flushParagraph();
            // Соберём весь список
            const listItems = [];
            while (i < lines.length) {
                const t = lines[i].trim();
                if (/^[*-] /.test(t)) {
                    listItems.push(t.slice(2).trim());
                    i++;
                } else if (t.startsWith('  ') || (lines[i].startsWith('  ') && t)) {
                    // Продолжение предыдущего пункта
                    listItems[listItems.length - 1] += ' ' + t;
                    i++;
                } else {
                    break;
                }
            }
            for (const item of listItems) {
                elements.push(new Paragraph({
                    children: [
                        new TextRun({ text: '— ', font: FONT, size: SIZE_NORMAL }),
                        ...parseInline(item)
                    ],
                    alignment: AlignmentType.JUSTIFIED,
                    spacing: { line: LINE_SPACING_EXACT, lineRule: 'exact', before: 0, after: 0 },
                    indent: { left: 720, hanging: 280 }
                }));
            }
            continue;
        }

        // Нумерованный список: «1. ...»
        if (/^\d+\. /.test(trimmed)) {
            flushParagraph();
            const listItems = [];
            while (i < lines.length) {
                const t = lines[i].trim();
                if (/^\d+\. /.test(t)) {
                    listItems.push(t.replace(/^\d+\.\s*/, ''));
                    i++;
                } else if (t.startsWith('  ') || (lines[i].startsWith('  ') && t)) {
                    listItems[listItems.length - 1] += ' ' + t;
                    i++;
                } else {
                    break;
                }
            }
            for (let idx = 0; idx < listItems.length; idx++) {
                elements.push(new Paragraph({
                    children: [
                        new TextRun({ text: `${idx + 1}) `, font: FONT, size: SIZE_NORMAL }),
                        ...parseInline(listItems[idx])
                    ],
                    alignment: AlignmentType.JUSTIFIED,
                    spacing: { line: LINE_SPACING_EXACT, lineRule: 'exact', before: 0, after: 0 },
                    indent: { left: 720, hanging: 280 }
                }));
            }
            continue;
        }

        // Формула в блочном виде: $$...$$ — рендерим через renderMath.
        // По ГОСТ 7.32 §6.5 формула центрируется, нумерация (N.M) — справа.
        // Используем невидимую таблицу из 3 ячеек: пустая | формула центр | номер справа.
        if (trimmed.startsWith('$$') && trimmed.endsWith('$$')) {
            flushParagraph();
            const raw = trimmed.slice(2, -2);
            const formula = renderMath(raw);
            formulaInChapter += 1;
            const numberText = currentChapter
                ? `(${currentChapter}.${formulaInChapter})`
                : `(${formulaInChapter})`;
            elements.push(buildFormulaRow(formula, numberText));
            i++;
            continue;
        }

        // Обычная строка — копится в буфер абзаца
        paragraphBuffer.push(trimmed);
        i++;
    }
    flushParagraph();
    return elements;
}

/**
 * Создаёт «таблицу-каркас» для центрированной формулы с номером справа,
 * как требует ГОСТ 7.32 §6.5. Состоит из трёх невидимых ячеек:
 * боковой отступ слева (для симметрии) — формула по центру — номер справа.
 */
function buildFormulaRow(formula, numberText) {
    const totalWidth = convertMillimetersToTwip(165); // контентная ширина листа
    const sideWidth = convertMillimetersToTwip(15);   // боковые ячейки
    const centerWidth = totalWidth - 2 * sideWidth;
    const noBorder = { style: BorderStyle.NONE, size: 0, color: 'FFFFFF' };
    const allNoBorders = {
        top: noBorder, bottom: noBorder, left: noBorder, right: noBorder,
        insideHorizontal: noBorder, insideVertical: noBorder
    };
    const formulaPara = new Paragraph({
        children: [new TextRun({ text: formula, font: FONT, size: SIZE_NORMAL, italics: true })],
        alignment: AlignmentType.CENTER,
        spacing: { line: LINE_SPACING_EXACT, lineRule: 'exact', before: 0, after: 0 },
        indent: { firstLine: 0 }
    });
    const numberPara = new Paragraph({
        children: [new TextRun({ text: numberText, font: FONT, size: SIZE_NORMAL })],
        alignment: AlignmentType.RIGHT,
        spacing: { line: LINE_SPACING_EXACT, lineRule: 'exact', before: 0, after: 0 },
        indent: { firstLine: 0 }
    });
    const emptyPara = new Paragraph({
        children: [new TextRun({ text: '', font: FONT, size: SIZE_NORMAL })],
        spacing: { line: LINE_SPACING_EXACT, lineRule: 'exact', before: 0, after: 0 }
    });
    return new Table({
        width: { size: totalWidth, type: WidthType.DXA },
        columnWidths: [sideWidth, centerWidth, sideWidth],
        borders: allNoBorders,
        rows: [new TableRow({
            children: [
                new TableCell({
                    width: { size: sideWidth, type: WidthType.DXA },
                    borders: allNoBorders,
                    margins: { top: 200, bottom: 200, left: 0, right: 0 },
                    children: [emptyPara]
                }),
                new TableCell({
                    width: { size: centerWidth, type: WidthType.DXA },
                    borders: allNoBorders,
                    margins: { top: 200, bottom: 200, left: 0, right: 0 },
                    children: [formulaPara]
                }),
                new TableCell({
                    width: { size: sideWidth, type: WidthType.DXA },
                    borders: allNoBorders,
                    margins: { top: 200, bottom: 200, left: 0, right: 0 },
                    children: [numberPara]
                })
            ]
        })]
    });
}

// Размер шрифта в ячейках таблиц — 12 pt (24 half-points). Это улучшает
// вёрстку широких таблиц (особенно 2.7 и 2.8), оставаясь в пределах
// допустимого по методичке ВГУ (методичка регламентирует общий шрифт 14 pt,
// но для таблиц размер прямо не оговаривает; уменьшение до 12 pt —
// распространённая практика).
const SIZE_TABLE_CELL = 24;
// Межстрочный интервал в ячейках — также сжимаем (14 pt = 280 twips),
// чтобы избежать «пустых» полос внутри ячеек при 12pt шрифте.
const LINE_SPACING_TABLE = 280;

/** Создаёт docx-таблицу из массива строк (массив массивов ячеек). */
function buildTable(rows) {
    if (rows.length === 0) return null;
    const numCols = rows[0].length;
    // Ширина контентной области: A4 (210mm) - 30 - 15 = 165 mm
    const totalWidth = convertMillimetersToTwip(165);
    const colWidth = Math.floor(totalWidth / numCols);
    const columnWidths = Array(numCols).fill(colWidth);

    const border = { style: BorderStyle.SINGLE, size: 4, color: '000000' };
    const borders = { top: border, bottom: border, left: border, right: border, insideHorizontal: border, insideVertical: border };

    // Парсер inline-форматирования для содержимого ячейки с явным размером 12pt
    const parseCell = (cell, isHeader) => {
        const cleaned = cell.replace(/\*\*/g, '');
        // Используем тот же inline-парсер, но прогоняем результат через
        // создание новых TextRun с уменьшенным размером и нужной жирностью
        const baseRuns = parseInline(cleaned);
        return baseRuns.map(r => {
            const opts = r.options || r.properties || {};
            const text = (opts.text !== undefined) ? opts.text : '';
            return new TextRun({
                text: text,
                font: FONT,
                size: SIZE_TABLE_CELL,
                bold: isHeader || !!opts.bold,
                italics: !!opts.italics
            });
        });
    };

    const tableRows = rows.map((row, rowIdx) => {
        const isHeader = rowIdx === 0;
        return new TableRow({
            tableHeader: isHeader,
            children: row.map((cell, colIdx) => new TableCell({
                width: { size: columnWidths[colIdx], type: WidthType.DXA },
                borders: borders,
                margins: { top: 60, bottom: 60, left: 100, right: 100 },
                children: [new Paragraph({
                    children: parseCell(cell, isHeader),
                    alignment: isHeader ? AlignmentType.CENTER : AlignmentType.LEFT,
                    spacing: { line: LINE_SPACING_TABLE, lineRule: 'exact', before: 0, after: 0 },
                    indent: { firstLine: 0 }
                })]
            }))
        });
    });

    return new Table({
        width: { size: totalWidth, type: WidthType.DXA },
        columnWidths: columnWidths,
        rows: tableRows
    });
}

// ============================================================
// Сборка документа
// ============================================================

function buildTitlePage() {
    const blank = () => new Paragraph({
        children: [new TextRun({ text: '', font: FONT, size: SIZE_NORMAL })],
        spacing: { line: LINE_SPACING_EXACT, lineRule: 'exact', before: 0, after: 0 }
    });
    const center = (text, opts = {}) => new Paragraph({
        children: [new TextRun({
            text, font: FONT,
            size: opts.size || SIZE_NORMAL,
            bold: !!opts.bold
        })],
        alignment: AlignmentType.CENTER,
        spacing: { line: LINE_SPACING_EXACT, lineRule: 'exact', before: 0, after: 0 }
    });
    const right = (text, opts = {}) => new Paragraph({
        children: [new TextRun({
            text, font: FONT,
            size: opts.size || SIZE_NORMAL,
            bold: !!opts.bold
        })],
        alignment: AlignmentType.RIGHT,
        spacing: { line: LINE_SPACING_EXACT, lineRule: 'exact', before: 0, after: 0 }
    });

    return [
        center('МИНИСТЕРСТВО ОБРАЗОВАНИЯ РЕСПУБЛИКИ БЕЛАРУСЬ'),
        center('УЧРЕЖДЕНИЕ ОБРАЗОВАНИЯ'),
        center('«ВИТЕБСКИЙ ГОСУДАРСТВЕННЫЙ УНИВЕРСИТЕТ'),
        center('ИМЕНИ П. М. МАШЕРОВА»'),
        blank(), blank(), blank(),
        center('Факультет математики и информационных технологий', { size: SIZE_NORMAL }),
        center('Кафедра прикладной математики и механики', { size: SIZE_NORMAL }),
        blank(), blank(), blank(), blank(), blank(),
        center('УНДРО АЛЕКСЕЙ АЛЕКСАНДРОВИЧ', { bold: true }),
        blank(), blank(),
        center('СОВЕРШЕНСТВОВАНИЕ УПРАВЛЕНИЯ ВНУТРЕННИМИ ЗАЯВКАМИ', { bold: true }),
        center('НА ОСНОВЕ РАЗРАБОТКИ ПРОТОТИПА', { bold: true }),
        center('ИНФОРМАЦИОННОЙ СИСТЕМЫ НА ПРИМЕРЕ', { bold: true }),
        center('РУП «ВИТЕБСКЭНЕРГО»', { bold: true }),
        blank(), blank(),
        center('Дипломная работа'),
        blank(), blank(), blank(), blank(),
        right('Научный руководитель:'),
        right('___________________________'),
        right('(учёная степень, должность, ФИО)'),
        blank(),
        right('Допущен(а) к защите'),
        right('Заведующий кафедрой'),
        right('___________________________'),
        blank(), blank(), blank(), blank(), blank(), blank(),
        center('Витебск, 2026', { size: SIZE_NORMAL })
    ];
}

function buildReferatPage() {
    return [
        topHeading('РЕФЕРАТ'),
        bodyParagraph('Дипломная работа: 78 страниц, 24 рисунка, 16 таблиц, 54 использованных источника, 5 приложений.'),
        bodyParagraph('Ключевые слова: ИНФОРМАЦИОННАЯ СИСТЕМА, ВНУТРЕННИЕ ЗАЯВКИ, ЭЛЕКТРОННЫЙ ДОКУМЕНТООБОРОТ, СОГЛАСОВАНИЕ, ВЕБ-ПРИЛОЖЕНИЕ, NODE.JS, MICROSOFT SQL SERVER, ИНФОРМАЦИОННАЯ БЕЗОПАСНОСТЬ, ЭКОНОМИЧЕСКАЯ ЭФФЕКТИВНОСТЬ.'),
        bodyParagraph('Объект исследования: процесс управления внутренними заявками на проведение корпоративных мероприятий в условиях многофилиальной структуры энергетического предприятия.'),
        bodyParagraph('Предмет исследования: методы и инструменты автоматизации процедур согласования внутренних заявок, а также соответствующее программное обеспечение.'),
        bodyParagraph('Цель работы: обоснование, проектирование и разработка прототипа информационной системы согласования внутренних заявок, обеспечивающей сокращение цикла согласования, повышение прозрачности управленческих решений и соблюдение требований законодательства Республики Беларусь в области персональных данных и информационной безопасности.'),
        bodyParagraph('Методы исследования: системный анализ управленческих процессов, сравнительный анализ существующих информационных систем, функциональное моделирование с применением нотаций UML и BPMN, объектно-ориентированное проектирование программного обеспечения, методы оценки экономической эффективности инвестиционных проектов.'),
        bodyParagraph('Полученные результаты и их новизна: предложен и реализован подход к автоматизации согласования внутренних заявок, объединяющий современный технологический стек, ролевую модель доступа, журналирование действий пользователей, аудит доступа к персональным данным и автоматизированную генерацию протоколов согласования. Разработан функциональный прототип информационной системы, демонстрирующий ключевые сценарии жизненного цикла заявки и пригодный для последующей доработки до промышленного решения.'),
        bodyParagraph('Область возможного практического применения: РУП «Витебскэнерго» и иные крупные предприятия Республики Беларусь, в которых ведётся регулярная работа по согласованию внутренних заявок на проведение мероприятий.'),
        bodyParagraph('Экономическая эффективность: по расчётам совокупный годовой экономический эффект от внедрения системы составляет около 46,7 тыс. руб., чистый годовой эффект с учётом эксплуатационных затрат 31,0 тыс. руб. при единовременных затратах 51,3 тыс. руб. Дисконтированный срок окупаемости составляет около 1,94 года, чистый дисконтированный доход за 5 лет 61,8 тыс. руб., внутренняя норма доходности порядка 53 %. Указанные значения получены при ряде допущений и носят предварительный характер.'),
        bodyParagraph('Автор работы подтверждает, что приведённый в ней расчётно-аналитический материал правильно и объективно отражает состояние исследуемого процесса, а все заимствованные из литературных и других источников теоретические и методологические положения и концепции сопровождаются ссылками на их авторов.')
    ];
}

function buildSodergaPage() {
    return [
        topHeading('СОДЕРЖАНИЕ'),
        bodyParagraph('ВВЕДЕНИЕ ............................................................................................................ 4', { noIndent: true }),
        bodyParagraph('ГЛАВА 1 ТЕОРЕТИЧЕСКИЕ ОСНОВЫ УПРАВЛЕНИЯ ВНУТРЕННИМИ ЗАЯВКАМИ ............................................................................................................. 7', { noIndent: true }),
        bodyParagraph('1.1 Понятие и роль внутренних заявок в системе управления предприятием ............................................................................................................. 7', { noIndent: true }),
        bodyParagraph('1.2 Жизненный цикл внутренней заявки и ключевые роли ........... 10', { noIndent: true }),
        bodyParagraph('1.3 Обзор существующих информационных систем ..................... 14', { noIndent: true }),
        bodyParagraph('1.4 Нормативно-правовая база ........................................................ 17', { noIndent: true }),
        bodyParagraph('1.5 Технологические основы построения современных веб-приложений ............................................................................................................. 20', { noIndent: true }),
        bodyParagraph('Выводы по главе 1 ......................................................................... 23', { noIndent: true }),
        bodyParagraph('ГЛАВА 2 ЭКОНОМИЧЕСКИЙ АНАЛИЗ И ОБОСНОВАНИЕ ВНЕДРЕНИЯ ИНФОРМАЦИОННОЙ СИСТЕМЫ ........................................... 25', { noIndent: true }),
        bodyParagraph('2.1 Краткая характеристика РУП «Витебскэнерго» ..................... 25', { noIndent: true }),
        bodyParagraph('2.2 Анализ существующего процесса согласования внутренних заявок ............................................................................................................. 27', { noIndent: true }),
        bodyParagraph('2.3 Целевая модель процесса после внедрения информационной системы ............................................................................................................. 31', { noIndent: true }),
        bodyParagraph('2.4 Расчёт затрат на разработку и внедрение системы .............. 33', { noIndent: true }),
        bodyParagraph('2.5 Расчёт экономического эффекта от внедрения ..................... 36', { noIndent: true }),
        bodyParagraph('2.6 Оценка экономической эффективности проекта ................... 38', { noIndent: true }),
        bodyParagraph('2.7 Анализ чувствительности и оценка рисков ........................... 41', { noIndent: true }),
        bodyParagraph('Выводы по главе 2 ......................................................................... 43', { noIndent: true }),
        bodyParagraph('ГЛАВА 3 РАЗРАБОТКА ПРОТОТИПА ИНФОРМАЦИОННОЙ СИСТЕМЫ ........................................................................................................ 45', { noIndent: true }),
        bodyParagraph('3.1 Постановка задачи и функциональные требования ............... 45', { noIndent: true }),
        bodyParagraph('3.2 Архитектура информационной системы ................................ 47', { noIndent: true }),
        bodyParagraph('3.3 Модель данных ........................................................................... 50', { noIndent: true }),
        bodyParagraph('3.4 Реализация серверной части .................................................... 53', { noIndent: true }),
        bodyParagraph('3.5 Реализация клиентской части ................................................. 57', { noIndent: true }),
        bodyParagraph('3.6 Реализация системы безопасности ......................................... 60', { noIndent: true }),
        bodyParagraph('3.7 Тестирование разработанного прототипа .............................. 64', { noIndent: true }),
        bodyParagraph('3.8 Контейнеризация и развёртывание ........................................ 66', { noIndent: true }),
        bodyParagraph('Выводы по главе 3 ......................................................................... 68', { noIndent: true }),
        bodyParagraph('ЗАКЛЮЧЕНИЕ .................................................................................... 70', { noIndent: true }),
        bodyParagraph('СПИСОК ИСПОЛЬЗОВАННЫХ ИСТОЧНИКОВ ............................. 73', { noIndent: true })
    ];
}

// ============================================================
// Main
// ============================================================

console.log('=== Building diploma.docx ===');

const diplomaDir = path.join(__dirname, '..', 'docs', 'diploma');
const files = [
    '00_introduction.md',
    '01_theory.md',
    '02_economic.md',
    '03_prototype.md',
    '04_conclusion.md',
    '05_references.md'
];

let allElements = [];

// Титульный лист
allElements.push(...buildTitlePage());

// Реферат
allElements.push(...buildReferatPage());

// Содержание
allElements.push(...buildSodergaPage());

// Основное содержание из markdown
for (const fname of files) {
    const fpath = path.join(diplomaDir, fname);
    if (!fs.existsSync(fpath)) {
        console.warn('SKIP missing:', fname);
        continue;
    }
    const content = fs.readFileSync(fpath, 'utf8');
    const parsed = parseMarkdown(content);
    console.log(`${fname}: ${parsed.length} elements`);
    allElements.push(...parsed);
}

const doc = new Document({
    creator: 'Ундро Алексей Александрович',
    title: 'Совершенствование управления внутренними заявками на основе разработки прототипа информационной системы на примере РУП «Витебскэнерго»',
    description: 'Дипломная работа',
    styles: {
        default: {
            document: { run: { font: FONT, size: SIZE_NORMAL } }
        }
    },
    sections: [{
        properties: {
            page: {
                size: PAGE_SIZE,
                margin: PAGE_MARGINS
            }
        },
        footers: {
            default: new Footer({
                children: [new Paragraph({
                    alignment: AlignmentType.CENTER,
                    children: [new TextRun({
                        children: [PageNumber.CURRENT],
                        font: FONT, size: SIZE_NORMAL
                    })]
                })]
            })
        },
        children: allElements
    }]
});

const outPath = path.join(diplomaDir, 'diploma.docx');
Packer.toBuffer(doc).then(buf => {
    fs.writeFileSync(outPath, buf);
    const stat = fs.statSync(outPath);
    console.log(`\n✓ Saved: ${outPath}`);
    console.log(`  Size:    ${(stat.size / 1024).toFixed(1)} KB`);
    console.log(`  Total elements: ${allElements.length}`);
});
