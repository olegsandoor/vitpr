/**
 * events.js — клиент публичной страницы /events.
 *
 * Подход: золотая середина между futurism и минимализмом.
 * Спокойный navy + один яркий accent для upcoming, secondary purple для archive.
 * Лёгкие анимации (fade-in групп, dot-loader), без countdown'ов и pulsing-dot'ов.
 *
 * Что делает:
 *   • Загружает /api/public/events (upcoming) или ?archive=true (past)
 *   • Tab-switcher: Предстоящие / Архив с count-badges
 *   • Statistics: контекстные для режима
 *   • Featured-карточка для ближайшего события (только в upcoming)
 *   • Фильтры (период + категории)
 *   • Группировка по корзинам дат (в archive — обратно)
 *   • Empty / loading / error states
 *   • Авто-обновление каждые 5 минут + при возврате на вкладку
 *
 * CSP-safe: только addEventListener, без inline-handlers.
 */
(function () {
    'use strict';

    const REFRESH_INTERVAL_MS = 5 * 60 * 1000;
    const MONTHS_GENITIVE = ['января', 'февраля', 'марта', 'апреля', 'мая', 'июня',
                             'июля', 'августа', 'сентября', 'октября', 'ноября', 'декабря'];
    const MONTHS_SHORT = ['янв', 'фев', 'мар', 'апр', 'мая', 'июн',
                          'июл', 'авг', 'сен', 'окт', 'ноя', 'дек'];
    const WEEKDAYS_SHORT = ['вс', 'пн', 'вт', 'ср', 'чт', 'пт', 'сб'];

    const state = {
        mode: 'upcoming',        // upcoming | archive
        upcoming: null,          // массив событий (или null до первой загрузки)
        archive: null,
        filterTime: 'all',
        filterCategory: null
    };

    // Окно «свежести» — события, одобренные за последние N дней,
    // помечаются «Новое» badge. 7 дней — баланс между «успел заметить»
    // и «не превратилось в постоянный шум».
    const FRESHNESS_DAYS = 7;
    const ICS_PRODID = '-//RUP Vitebskenergo//Calendar//RU';

    // ============================================================
    // Утилиты
    // ============================================================

    function escapeHtml(s) {
        const d = document.createElement('div');
        d.textContent = String(s == null ? '' : s);
        return d.innerHTML;
    }

    function safeColor(c) {
        return /^#[0-9A-Fa-f]{6}$/.test(c) ? c : '#7dd3fc';
    }

    function hexAlpha(hex, alpha) {
        const safe = safeColor(hex);
        const r = parseInt(safe.slice(1, 3), 16);
        const g = parseInt(safe.slice(3, 5), 16);
        const b = parseInt(safe.slice(5, 7), 16);
        return `rgba(${r},${g},${b},${alpha})`;
    }

    function startOfDay(d) {
        const x = new Date(d);
        x.setHours(0, 0, 0, 0);
        return x;
    }

    function diffDays(future, base) {
        base = base || new Date();
        const ms = startOfDay(future) - startOfDay(base);
        return Math.round(ms / 86400000);
    }

    function plural(n, forms) {
        const m10 = n % 10;
        const m100 = n % 100;
        if (m10 === 1 && m100 !== 11) return forms[0];
        if (m10 >= 2 && m10 <= 4 && (m100 < 10 || m100 >= 20)) return forms[1];
        return forms[2];
    }

    function humanLabel(date) {
        const ms = new Date(date) - new Date();
        if (ms <= 0) return 'сейчас';
        const days = Math.floor(ms / 86400000);
        const hours = Math.floor((ms % 86400000) / 3600000);
        const mins = Math.floor((ms % 3600000) / 60000);
        if (days >= 1) return `${days} ${plural(days, ['день', 'дня', 'дней'])}`;
        if (hours >= 1) return `${hours} ${plural(hours, ['час', 'часа', 'часов'])}`;
        return `${mins} ${plural(mins, ['минута', 'минуты', 'минут'])}`;
    }

    /**
     * Событие «свежее», если оно ОДОБРЕНО (created_at в API = момент создания
     * заявки, но для approved-только списка это близко к моменту одобрения)
     * не более FRESHNESS_DAYS назад И ещё не наступило.
     */
    function isFreshEvent(ev) {
        if (!ev.created_at) return false;
        const created = new Date(ev.created_at);
        if (isNaN(created.getTime())) return false;
        const daysSinceCreated = (new Date() - created) / 86400000;
        if (daysSinceCreated > FRESHNESS_DAYS) return false;
        // Не показываем «Новое» на уже прошедших событиях — это archive.
        return new Date(ev.planned_date) > new Date();
    }

    // ============================================================
    // iCal (.ics) генератор — клиент-сайд
    // ============================================================

    function icsEscape(s) {
        return String(s == null ? '' : s)
            .replace(/\\/g, '\\\\')
            .replace(/;/g, '\\;')
            .replace(/,/g, '\\,')
            .replace(/\r?\n/g, '\\n');
    }

    /** Дата в формате iCalendar UTC: YYYYMMDDTHHMMSSZ */
    function toICSDate(d) {
        const dt = new Date(d);
        const p = n => String(n).padStart(2, '0');
        return dt.getUTCFullYear() +
               p(dt.getUTCMonth() + 1) +
               p(dt.getUTCDate()) + 'T' +
               p(dt.getUTCHours()) +
               p(dt.getUTCMinutes()) +
               p(dt.getUTCSeconds()) + 'Z';
    }

    /** Длина события неизвестна — берём дефолт 1 час. */
    function buildVEvent(ev) {
        const start = new Date(ev.planned_date);
        const end = new Date(start.getTime() + 60 * 60 * 1000);
        const descParts = [];
        if (ev.category_name) descParts.push('Категория: ' + ev.category_name);
        if (ev.branch_name)   descParts.push('Филиал: ' + ev.branch_name);
        if (ev.expected_attendees) descParts.push('Участников: ' + ev.expected_attendees);
        descParts.push('Источник: РУП «Витебскэнерго»');

        return [
            'BEGIN:VEVENT',
            `UID:event-${ev.id}@vitebskenergo.by`,
            `DTSTAMP:${toICSDate(new Date())}`,
            `DTSTART:${toICSDate(start)}`,
            `DTEND:${toICSDate(end)}`,
            `SUMMARY:${icsEscape(ev.title)}`,
            ev.location ? `LOCATION:${icsEscape(ev.location)}` : null,
            `DESCRIPTION:${icsEscape(descParts.join('\\n'))}`,
            'END:VEVENT'
        ].filter(Boolean).join('\r\n');
    }

    function buildICS(events, calendarName) {
        const lines = [
            'BEGIN:VCALENDAR',
            'VERSION:2.0',
            `PRODID:${ICS_PRODID}`,
            'CALSCALE:GREGORIAN',
            'METHOD:PUBLISH',
            `X-WR-CALNAME:${icsEscape(calendarName || 'Мероприятия РУП «Витебскэнерго»')}`,
            'X-WR-TIMEZONE:Europe/Minsk',
            ...events.map(buildVEvent),
            'END:VCALENDAR'
        ];
        return lines.join('\r\n');
    }

    /** Download blob через временную <a> ссылку. UTF-8 + BOM для Outlook. */
    function downloadICS(content, filename) {
        const blob = new Blob(['﻿', content], { type: 'text/calendar;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        setTimeout(() => {
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }, 100);
    }

    function downloadEventICS(ev) {
        const safeTitle = String(ev.title || 'event').replace(/[^\wа-яА-Я0-9\- ]+/g, '_').slice(0, 60).trim();
        downloadICS(buildICS([ev], ev.title), `event-${ev.id}-${safeTitle}.ics`);
    }

    function downloadAllICS() {
        const events = currentEvents();
        if (events.length === 0) return;
        const calName = state.mode === 'archive'
            ? 'Архив мероприятий — РУП «Витебскэнерго»'
            : 'Мероприятия РУП «Витебскэнерго»';
        const suffix = state.mode === 'archive' ? '-archive' : '';
        downloadICS(buildICS(events, calName), `vitebskenergo-events${suffix}.ics`);
    }

    function humanPastLabel(date) {
        const ms = new Date() - new Date(date);
        if (ms <= 0) return 'сейчас';
        const days = Math.floor(ms / 86400000);
        if (days < 1) return 'сегодня';
        if (days === 1) return 'вчера';
        if (days < 30) return `${days} ${plural(days, ['день', 'дня', 'дней'])} назад`;
        const months = Math.floor(days / 30);
        if (months < 12) return `${months} ${plural(months, ['месяц', 'месяца', 'месяцев'])} назад`;
        return 'более года назад';
    }

    // ============================================================
    // Группировка
    // ============================================================

    function groupKeyUpcoming(date) {
        const days = diffDays(date);
        if (days === 0) return 'today';
        if (days === 1) return 'tomorrow';
        if (days <= 7) return 'week';
        if (days <= 31) return 'month';
        return 'later';
    }

    function groupKeyArchive(date) {
        const days = -diffDays(date);
        if (days <= 1) return 'recent';
        if (days <= 7) return 'pastWeek';
        if (days <= 31) return 'pastMonth';
        if (days <= 93) return 'past3Months';
        return 'older';
    }

    const GROUP_TITLES_UPCOMING = {
        today:    'Сегодня',
        tomorrow: 'Завтра',
        week:     'На этой неделе',
        month:    'В ближайший месяц',
        later:    'Позже'
    };
    const GROUP_ORDER_UPCOMING = ['today', 'tomorrow', 'week', 'month', 'later'];

    const GROUP_TITLES_ARCHIVE = {
        recent:       'Недавно',
        pastWeek:     'На прошлой неделе',
        pastMonth:    'В прошлом месяце',
        past3Months:  'Последние 3 месяца',
        older:        'Ранее'
    };
    const GROUP_ORDER_ARCHIVE = ['recent', 'pastWeek', 'pastMonth', 'past3Months', 'older'];

    function groupEvents(events) {
        const isArchive = state.mode === 'archive';
        const keyFn = isArchive ? groupKeyArchive : groupKeyUpcoming;
        const titles = isArchive ? GROUP_TITLES_ARCHIVE : GROUP_TITLES_UPCOMING;
        const order = isArchive ? GROUP_ORDER_ARCHIVE : GROUP_ORDER_UPCOMING;

        const groups = {};
        events.forEach(ev => {
            const k = keyFn(ev.planned_date);
            (groups[k] = groups[k] || []).push(ev);
        });
        return order
            .filter(k => groups[k] && groups[k].length)
            .map(k => ({ key: k, title: titles[k], items: groups[k] }));
    }

    // ============================================================
    // Фильтры
    // ============================================================

    function applyFilters(events) {
        return events.filter(ev => {
            if (state.filterTime !== 'all') {
                const days = state.mode === 'archive'
                    ? -diffDays(ev.planned_date)
                    : diffDays(ev.planned_date);
                if (state.filterTime === 'today' && days !== 0) return false;
                if (state.filterTime === 'week'  && (days > 7 || days < 0)) return false;
                if (state.filterTime === 'month' && (days > 31 || days < 0)) return false;
            }
            if (state.filterCategory && ev.category_name !== state.filterCategory) return false;
            return true;
        });
    }

    function currentEvents() {
        return (state.mode === 'archive' ? state.archive : state.upcoming) || [];
    }

    // ============================================================
    // Stats — контекстные для режима
    // ============================================================

    function renderStats() {
        const events = currentEvents();
        const total = events.length;
        const cats = new Set(events.filter(e => e.category_name).map(e => e.category_name)).size;

        let html;
        if (state.mode === 'upcoming') {
            const next = events[0];
            const nextLabel = next ? humanLabel(next.planned_date) : '—';
            const weekStart = startOfDay(new Date());
            const weekEnd = new Date(weekStart); weekEnd.setDate(weekEnd.getDate() + 7);
            const weekCount = events.filter(ev => {
                const d = new Date(ev.planned_date);
                return d >= weekStart && d < weekEnd;
            }).length;

            html = `
                <div class="stats-cell" data-accent="primary">
                    <div class="stats-value">${total}</div>
                    <div class="stats-label">${plural(total, ['Мероприятие предстоит', 'Мероприятия предстоят', 'Мероприятий предстоит'])}</div>
                </div>
                <div class="stats-cell" data-accent="today">
                    <div class="stats-value">${escapeHtml(nextLabel)}</div>
                    <div class="stats-label">До ближайшего</div>
                </div>
                <div class="stats-cell">
                    <div class="stats-value">${weekCount}</div>
                    <div class="stats-label">На этой неделе</div>
                </div>
                <div class="stats-cell">
                    <div class="stats-value">${cats}</div>
                    <div class="stats-label">${plural(cats, ['Категория', 'Категории', 'Категорий'])}</div>
                </div>`;
        } else {
            // Archive mode
            const last = events[0]; // последнее (по DESC) = самое свежее прошедшее
            const lastLabel = last ? humanPastLabel(last.planned_date) : '—';
            const now = new Date();
            const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
            const thisMonth = events.filter(ev => {
                const d = new Date(ev.planned_date);
                return d >= monthStart;
            }).length;
            const yearStart = new Date(now.getFullYear(), 0, 1);
            const thisYear = events.filter(ev => {
                const d = new Date(ev.planned_date);
                return d >= yearStart;
            }).length;

            html = `
                <div class="stats-cell" data-accent="archive">
                    <div class="stats-value">${total}</div>
                    <div class="stats-label">${plural(total, ['В архиве', 'В архиве', 'В архиве'])}</div>
                </div>
                <div class="stats-cell" data-accent="archive">
                    <div class="stats-value">${escapeHtml(lastLabel)}</div>
                    <div class="stats-label">Последнее событие</div>
                </div>
                <div class="stats-cell">
                    <div class="stats-value">${thisMonth}</div>
                    <div class="stats-label">В этом месяце</div>
                </div>
                <div class="stats-cell">
                    <div class="stats-value">${thisYear}</div>
                    <div class="stats-label">В этом году</div>
                </div>`;
        }
        document.getElementById('evStats').innerHTML = html;
    }

    // ============================================================
    // Featured — только для upcoming
    // ============================================================

    function renderFeatured() {
        const el = document.getElementById('evFeatured');
        if (state.mode === 'archive') { el.hidden = true; el.innerHTML = ''; return; }

        const events = state.upcoming || [];
        const next = events[0];
        if (!next) { el.hidden = true; el.innerHTML = ''; return; }

        const dt = new Date(next.planned_date);
        const isToday = diffDays(dt) === 0;
        const day = dt.getDate();
        const month = MONTHS_SHORT[dt.getMonth()];
        const weekday = WEEKDAYS_SHORT[dt.getDay()];

        const dateStr = `${day} ${MONTHS_GENITIVE[dt.getMonth()]} ${dt.getFullYear()} г.`;
        const time = dt.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });

        const ICON_CLK = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>';
        const ICON_PIN = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>';
        const ICON_BLD = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 21h18"/><path d="M5 21V7l7-4 7 4v14"/><path d="M9 9h6"/><path d="M9 13h6"/><path d="M9 17h6"/></svg>';

        const ICON_DL = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>';

        el.hidden = false;
        el.className = isToday ? 'featured is-today' : 'featured';
        el.innerHTML = `
            <div class="featured-date">
                <div class="featured-day">${day}</div>
                <div class="featured-month">${month}</div>
                <div class="featured-weekday">${weekday}</div>
            </div>
            <div class="featured-body">
                <div class="featured-tag">${isToday ? 'Сегодня' : 'Ближайшее'} · через ${escapeHtml(humanLabel(next.planned_date))}</div>
                <h2>${escapeHtml(next.title)}</h2>
                <div class="featured-meta">
                    <span class="featured-meta-item">${ICON_CLK}${dateStr} · ${time}</span>
                    ${next.location ? `<span class="featured-meta-item">${ICON_PIN}${escapeHtml(next.location)}</span>` : ''}
                    ${next.branch_name ? `<span class="featured-meta-item">${ICON_BLD}${escapeHtml(next.branch_name)}</span>` : ''}
                </div>
                <div class="featured-actions">
                    <button type="button" class="featured-action-btn" data-act="ics" data-event-id="${next.id}">
                        ${ICON_DL}<span>Добавить в календарь</span>
                    </button>
                </div>
            </div>`;
    }

    // ============================================================
    // Filters
    // ============================================================

    function renderFilters() {
        const el = document.getElementById('evFilters');
        const events = currentEvents();
        if (events.length === 0) { el.hidden = true; el.innerHTML = ''; return; }

        const cats = new Map();
        events.forEach(ev => {
            if (ev.category_name && !cats.has(ev.category_name)) {
                cats.set(ev.category_name, safeColor(ev.category_color));
            }
        });

        const isArchive = state.mode === 'archive';
        const timeChips = isArchive
            ? [
                { v: 'all',   t: 'Все' },
                { v: 'today', t: 'Сегодня' },
                { v: 'week',  t: 'Прошлая неделя' },
                { v: 'month', t: 'Прошлый месяц' }
              ]
            : [
                { v: 'all',   t: 'Все' },
                { v: 'today', t: 'Сегодня' },
                { v: 'week',  t: 'Эта неделя' },
                { v: 'month', t: 'Этот месяц' }
              ];

        let html = `
            <div class="filter-group">
                <div class="filter-label">Период</div>
                <div class="filter-chips" role="group">
                    ${timeChips.map(c => `
                        <button type="button" class="filter-btn" data-filter-time="${c.v}"
                                aria-pressed="${state.filterTime === c.v}">${escapeHtml(c.t)}</button>
                    `).join('')}
                </div>
            </div>`;

        if (cats.size > 0) {
            html += `
            <div class="filter-group">
                <div class="filter-label">Категория</div>
                <div class="filter-chips" role="group">
                    <button type="button" class="filter-btn" data-filter-cat=""
                            aria-pressed="${state.filterCategory === null}">Все</button>
                    ${Array.from(cats.entries()).map(([name, color]) => `
                        <button type="button" class="filter-btn filter-btn-cat"
                                style="--chip-color:${color};"
                                data-filter-cat="${escapeHtml(name)}"
                                aria-pressed="${state.filterCategory === name}">${escapeHtml(name)}</button>
                    `).join('')}
                </div>
            </div>`;
        }

        el.hidden = false;
        el.innerHTML = html;

        el.querySelectorAll('[data-filter-time]').forEach(btn => {
            btn.addEventListener('click', () => {
                state.filterTime = btn.dataset.filterTime;
                renderEvents();
                syncFilterStates();
            });
        });
        el.querySelectorAll('[data-filter-cat]').forEach(btn => {
            btn.addEventListener('click', () => {
                const v = btn.dataset.filterCat;
                state.filterCategory = v === '' ? null : v;
                renderEvents();
                syncFilterStates();
            });
        });
    }

    function syncFilterStates() {
        document.querySelectorAll('[data-filter-time]').forEach(btn => {
            btn.setAttribute('aria-pressed', String(btn.dataset.filterTime === state.filterTime));
        });
        document.querySelectorAll('[data-filter-cat]').forEach(btn => {
            const v = btn.dataset.filterCat;
            const active = (v === '' && state.filterCategory === null) || v === state.filterCategory;
            btn.setAttribute('aria-pressed', String(active));
        });
    }

    // ============================================================
    // Card
    // ============================================================

    function renderEventCard(ev) {
        const dt = new Date(ev.planned_date);
        const isToday = diffDays(dt) === 0;
        const isArchive = state.mode === 'archive';
        const cat = safeColor(ev.category_color);
        const day = dt.getDate();
        const month = MONTHS_SHORT[dt.getMonth()];
        const weekday = WEEKDAYS_SHORT[dt.getDay()];
        const time = dt.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });

        const ICON_CLK = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>';
        const ICON_PIN = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>';
        const ICON_BLD = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 21h18"/><path d="M5 21V7l7-4 7 4v14"/><path d="M9 9h6"/><path d="M9 13h6"/><path d="M9 17h6"/></svg>';
        const ICON_USR = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/></svg>';

        const catBlock = ev.category_name
            ? `<span class="card-cat" style="--cat-text:${cat};--cat-bg:${hexAlpha(cat, 0.1)};--cat-border:${hexAlpha(cat, 0.3)};" title="${escapeHtml(ev.category_name)}">${escapeHtml(ev.category_name)}</span>`
            : '<span></span>';

        // «Новое» badge для upcoming имеет приоритет над пустым местом
        // справа сверху. Для archive остаётся «Состоялось».
        let cornerTag = '';
        if (isArchive) {
            cornerTag = '<span class="card-archived-tag">Состоялось</span>';
        } else if (isFreshEvent(ev)) {
            cornerTag = '<span class="card-new-tag">Новое</span>';
        }

        const ICON_DL = '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>';

        const actionsBlock = !isArchive
            ? `<div class="card-actions">
                   <button type="button" class="card-action-btn" data-act="ics" data-event-id="${ev.id}" title="Добавить в календарь">${ICON_DL}<span>В календарь</span></button>
               </div>`
            : '';

        return `
            <article class="card${isToday ? ' is-today' : ''}">
                ${cornerTag}
                <div class="card-top">
                    <div class="card-date">
                        <div class="card-day">${day}</div>
                        <div class="card-month-weekday">${month} · ${weekday}</div>
                    </div>
                    ${!isArchive ? catBlock : ''}
                </div>
                <h3 class="card-title">${escapeHtml(ev.title)}</h3>
                <div class="card-meta">
                    <div class="card-meta-row">${ICON_CLK}<strong>${time}</strong>${isArchive && ev.category_name ? ` · ${escapeHtml(ev.category_name)}` : ''}</div>
                    ${ev.location ? `<div class="card-meta-row">${ICON_PIN}${escapeHtml(ev.location)}</div>` : ''}
                    ${ev.branch_name ? `<div class="card-meta-row">${ICON_BLD}${escapeHtml(ev.branch_name)}</div>` : ''}
                    ${ev.expected_attendees ? `<div class="card-meta-row">${ICON_USR}${ev.expected_attendees} ${plural(ev.expected_attendees, ['участник', 'участника', 'участников'])}</div>` : ''}
                </div>
                ${actionsBlock}
            </article>`;
    }

    function renderEvents() {
        const el = document.getElementById('evContent');
        el.setAttribute('aria-busy', 'false');

        const events = currentEvents();
        const filtered = applyFilters(events);

        if (filtered.length === 0) {
            const isFiltered = events.length > 0;
            el.innerHTML = isFiltered ? renderFilteredEmpty() : renderEmpty();
            return;
        }

        const groups = groupEvents(filtered);
        el.innerHTML = `<div class="timeline">${groups.map(g => `
            <section class="group" data-key="${g.key}">
                <header class="group-header">
                    <h2 class="group-title">${escapeHtml(g.title)}</h2>
                    <span class="group-count">${g.items.length} ${plural(g.items.length, ['событие', 'события', 'событий'])}</span>
                </header>
                <div class="grid">
                    ${g.items.map(renderEventCard).join('')}
                </div>
            </section>
        `).join('')}</div>`;
    }

    // ============================================================
    // Empty / error
    // ============================================================

    function renderEmpty() {
        const isArchive = state.mode === 'archive';
        const icon = isArchive
            ? '<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/><line x1="10" y1="12" x2="14" y2="12"/></svg>'
            : '<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>';
        const title = isArchive ? 'В архиве пусто' : 'Расписание свободно';
        const text = isArchive
            ? 'За последние 12 месяцев одобренных мероприятий не зафиксировано.'
            : 'На ближайшее время утверждённых мероприятий нет. Заявки публикуются по мере прохождения согласования.';
        const hint = isArchive
            ? ''
            : '<span class="state-hint"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>Обновляется каждые 5 минут</span>';

        return `
            <div class="state">
                <div class="state-icon">${icon}</div>
                <div class="state-title">${title}</div>
                <p class="state-text">${text}</p>
                ${hint}
            </div>`;
    }

    function renderFilteredEmpty() {
        return `
            <div class="state">
                <div class="state-icon">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.5" y2="16.5"/></svg>
                </div>
                <div class="state-title">По выбранным фильтрам ничего не найдено</div>
                <p class="state-text">Попробуйте другой период или сбросьте фильтр категорий.</p>
            </div>`;
    }

    function renderError() {
        const el = document.getElementById('evContent');
        el.setAttribute('aria-busy', 'false');
        el.innerHTML = `
            <div class="error">
                <strong>Не удалось загрузить расписание</strong>
                Повторите попытку через минуту или обновите страницу.
            </div>`;
        document.getElementById('evFeatured').hidden = true;
        document.getElementById('evFilters').hidden = true;
        document.getElementById('evStats').innerHTML = '';
    }

    // ============================================================
    // Tabs
    // ============================================================

    async function switchMode(mode, opts) {
        opts = opts || {};
        if (mode !== 'upcoming' && mode !== 'archive') mode = 'upcoming';
        if (mode === state.mode && !opts.force) return;
        state.mode = mode;
        state.filterTime = 'all';
        state.filterCategory = null;
        document.body.classList.toggle('is-archive', mode === 'archive');
        document.body.classList.add('is-switching');
        syncTabStates();

        // URL hash sync — `#archive` остаётся при reload, делится ссылкой.
        if (opts.updateHash !== false) {
            const newHash = mode === 'archive' ? '#archive' : '';
            if (window.location.hash !== newHash) {
                history.replaceState(null, '', window.location.pathname + newHash);
            }
        }

        try {
            await ensureLoaded(mode);
            fullRender();
        } finally {
            // Маленькая задержка для fade-out → fade-in эффекта
            requestAnimationFrame(() => {
                document.body.classList.remove('is-switching');
            });
        }
    }

    function bindTabs() {
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => switchMode(tab.dataset.tab));
        });

        // Hash-changed (например, юзер вручную поменял URL) — реагируем
        window.addEventListener('hashchange', () => {
            const mode = window.location.hash === '#archive' ? 'archive' : 'upcoming';
            if (mode !== state.mode) switchMode(mode, { updateHash: false });
        });
    }

    function syncTabStates() {
        document.querySelectorAll('.tab').forEach(t => {
            t.setAttribute('aria-pressed', String(t.dataset.tab === state.mode));
        });
    }

    function updateCounts() {
        const upCount = document.getElementById('evCountUpcoming');
        const arCount = document.getElementById('evCountArchive');
        if (upCount) upCount.textContent = state.upcoming ? state.upcoming.length : '—';
        if (arCount) arCount.textContent = state.archive  ? state.archive.length  : '—';
    }

    // ============================================================
    // Load
    // ============================================================

    async function fetchEvents(archive) {
        const url = archive ? '/api/public/events?archive=true' : '/api/public/events';
        const r = await fetch(url, { cache: 'no-store' });
        if (!r.ok) throw new Error('HTTP ' + r.status);
        const arr = await r.json();
        return Array.isArray(arr) ? arr : [];
    }

    async function ensureLoaded(mode) {
        try {
            if (mode === 'archive' && state.archive === null) {
                state.archive = await fetchEvents(true);
            } else if (mode === 'upcoming' && state.upcoming === null) {
                state.upcoming = await fetchEvents(false);
            }
            updateCounts();
        } catch (err) {
            console.error('events: load failed', err);
            renderError();
            throw err;
        }
    }

    async function refreshCurrent() {
        try {
            if (state.mode === 'upcoming') {
                state.upcoming = await fetchEvents(false);
            } else {
                state.archive = await fetchEvents(true);
            }
            updateCounts();
            fullRender();
            const upd = document.getElementById('evUpdated');
            if (upd) {
                const t = new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
                upd.textContent = `Обновлено в ${t}`;
            }
        } catch (err) {
            console.error('events: refresh failed', err);
        }
    }

    function fullRender() {
        renderStats();
        renderFeatured();
        renderFilters();
        renderEvents();
    }

    async function initialLoad() {
        try {
            // Параллельно подтянем оба counter'а (upcoming сначала рендерим, archive — для badge)
            const [up, ar] = await Promise.all([
                fetchEvents(false).catch(() => []),
                fetchEvents(true).catch(() => [])
            ]);
            state.upcoming = up;
            state.archive = ar;
            updateCounts();
            fullRender();
            const upd = document.getElementById('evUpdated');
            if (upd) {
                const t = new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
                upd.textContent = `Обновлено в ${t}`;
            }
        } catch (err) {
            console.error('events: initial load failed', err);
            renderError();
        }
    }

    // ============================================================
    // Lifecycle
    // ============================================================

    /**
     * Один делегированный handler на main — для всех .ics-кнопок
     * (featured + cards). Меньше bind/unbind при re-render'ах.
     */
    function bindIcsClicks() {
        document.querySelector('main').addEventListener('click', (e) => {
            const btn = e.target.closest('[data-act="ics"]');
            if (!btn) return;
            const id = parseInt(btn.dataset.eventId, 10);
            if (isNaN(id)) return;
            const ev = currentEvents().find(x => x.id === id);
            if (ev) downloadEventICS(ev);
        });

        const dlAll = document.getElementById('evDownloadAll');
        if (dlAll) {
            dlAll.addEventListener('click', () => downloadAllICS());
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        // применяем initial mode из URL hash. Прямая ссылка
        // /events#archive открывается сразу на архиве.
        const initialMode = window.location.hash === '#archive' ? 'archive' : 'upcoming';
        state.mode = initialMode;
        document.body.classList.toggle('is-archive', initialMode === 'archive');
        syncTabStates();

        bindTabs();
        bindIcsClicks();
        initialLoad();
        setInterval(refreshCurrent, REFRESH_INTERVAL_MS);
        document.addEventListener('visibilitychange', () => {
            if (document.visibilityState === 'visible') refreshCurrent();
        });
    });
})();
