document.addEventListener('DOMContentLoaded', () => {
    let accessToken = null;
    let isRefreshing = false;
    let failedQueue = [];

    const processFailedQueue = (error, token = null) => {
        failedQueue.forEach(prom => {
            if (error) {
                prom.reject(error);
            } else {
                prom.resolve(token);
            }
        });
        failedQueue = [];
    };

    // isLoggingOut guard — handleLogout не должен повторно входить в цикл
    // refreshToken→handleLogout→secureFetch→refreshToken через свой же fetch.
    // Без guard'а fragile: любая будущая правка может вызвать рекурсию.
    let isLoggingOut = false;
    const handleLogout = () => {
        if (isLoggingOut) return;
        isLoggingOut = true;

        // navigate отменяет pending fetch'и → /api/logout не доходил до
        // сервера → refresh-cookie оставалась → перезагрузка /login → secureFetch
        // ловил этот cookie через refreshToken и юзер «возвращался». Решение:
        // `keepalive: true` гарантирует что POST дойдёт даже после navigate.
        // Дополнительно — closing WS до navigate, чтобы не плодить reconnect'ы.
        try {
            fetch('/api/logout', {
                method: 'POST',
                headers: accessToken ? { 'Authorization': `Bearer ${accessToken}` } : {},
                keepalive: true
            }).catch(() => { /* navigate уже идёт, всё равно */ });
        } catch (_) { /* IE / old browsers — ничего не сделать */ }

        try { if (globalWs) globalWs.close(); } catch (_) {}
        accessToken = null;
        window.location.href = '/login';
    };

    const refreshToken = async () => {
        // synchronous capture isRefreshing. Между `if (isRefreshing)` и
        // `isRefreshing = true` НЕ должно быть await/microtask: иначе два
        // параллельных вызова при холодном старте оба пройдут check и оба
        // фактически запустят refresh, ломая optimistic-rotation на сервере.
        if (isRefreshing) {
            return new Promise((resolve, reject) => {
                failedQueue.push({ resolve, reject });
            });
        }
        isRefreshing = true;
        try {
            // E2/H-3: fetchWithTimeout вместо raw fetch — иначе на
            // медленной сети refresh висит без timeout, кнопки disabled навсегда.
            const response = await fetchWithTimeout('/api/refresh-token', { method: 'POST' });
            if (response.status === 429) {
                // Rate-limit на /api/refresh-token (AUTH_LIMITER_MAX). НЕ logout
                // сразу — даём пользователю шанс через короткую паузу. На фронте
                // показываем явный toast вместо генерик «требуется повторный вход».
                if (typeof showToast === 'function') {
                    showToast(
                        'Слишком частые попытки обновления сессии. Подождите пару секунд и повторите действие.',
                        'warning', 6000
                    );
                }
                const e429 = new Error('Refresh rate-limited');
                e429.code = 'RATE_LIMITED';
                processFailedQueue(e429, null);
                throw e429;   // НЕ запускаем handleLogout — пусть юзер retry'нет
            }
            if (!response.ok) {
                throw new Error("Не удалось обновить токен, требуется повторный вход.");
            }
            const { accessToken: newAccessToken } = await response.json();
            accessToken = newAccessToken;
            processFailedQueue(null, newAccessToken);
            return newAccessToken;
        } catch (error) {
            console.error("Ошибка обновления токена:", error);
            // E2/H-3: на RATE_LIMITED НЕ logout — юзер попробует снова. На TIMEOUT
            // — тоже даём шанс (сеть могла упасть на секунду). На прочих ошибках —
            // logout как раньше (refresh-cookie невалиден / сервер вернул 401/403).
            if (error && (error.code === 'RATE_LIMITED' || error.code === 'TIMEOUT')) {
                processFailedQueue(error, null);
                return Promise.reject(error);
            }
            processFailedQueue(error, null);
            handleLogout();
            return Promise.reject(error);
        } finally {
            isRefreshing = false;
        }
    };

    // cap размера файла. Синхронизирован с server.js multer
    // limits.fileSize. Если backend поднимет лимит — поднять и здесь.
    // Применяется в handleFiles / handleDetailFiles до построения FormData,
    // чтобы юзер не ждал минутами upload 1ГБ файла перед server-side 413.
    const MAX_FILE_BYTES = 15 * 1024 * 1024;
    function formatFileSize(bytes) {
        if (bytes < 1024) return bytes + ' Б';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' КБ';
        return (bytes / 1024 / 1024).toFixed(1) + ' МБ';
    }
    /**
     * Фильтрует File[] по размеру. Слишком большие — toast warning, return slice.
     * Возвращает массив подходящих файлов; если всё отсеяно — [].
     */
    function filterByMaxSize(files) {
        const ok = [];
        const tooBig = [];
        for (const f of files) {
            if (f.size > MAX_FILE_BYTES) tooBig.push(f);
            else ok.push(f);
        }
        if (tooBig.length) {
            const names = tooBig.map(f => `«${f.name}» (${formatFileSize(f.size)})`).join(', ');
            showToast(
                `Файл${tooBig.length > 1 ? 'ы' : ''} превышает(-ют) 15 МБ: ${names}. Пропущено.`,
                'warning', 7000
            );
        }
        return ok;
    }

    // таймаут запроса. Без него медленная сеть (мобильный роуминг,
    // Tor, упавший backend) держит UI заблокированным неопределённо долго.
    // 30 сек — компромисс: hash-uploads для крупных файлов могут идти > 10 сек,
    // multipart с PDF-протоколом — чуть быстрее. На fast-инетe запрос укладывается
    // в <2 сек, абортится только если что-то реально зависло.
    const FETCH_TIMEOUT_MS = 30000;

    /**
     * Обёртка fetch + AbortController + опциональное timeout-override через
     * `options.timeoutMs`. На AbortError кидаем понятный для UI Error('timeout').
     */
    async function fetchWithTimeout(url, options = {}) {
        const timeoutMs = options.timeoutMs || FETCH_TIMEOUT_MS;
        // Если caller сам передал signal — связываем оба через AbortSignal.any
        // (Chrome 116+, Firefox 124+, Safari 17.4+) — fallback: используем только наш.
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), timeoutMs);
        const callerSignal = options.signal;
        const signal = (typeof AbortSignal !== 'undefined' && AbortSignal.any && callerSignal)
            ? AbortSignal.any([ctrl.signal, callerSignal])
            : ctrl.signal;
        try {
            return await fetch(url, { ...options, signal });
        } catch (e) {
            if (e && e.name === 'AbortError') {
                const err = new Error('Превышено время ожидания ответа сервера. Проверьте подключение.');
                err.code = 'TIMEOUT';
                throw err;
            }
            throw e;
        } finally {
            clearTimeout(timer);
        }
    }

    const secureFetch = async (url, options = {}) => {
        if (!accessToken) {
            try {
                await refreshToken();
            } catch (e) {
                return Promise.reject(e);
            }
        }
        const requestOptions = {
            ...options,
            headers: { ...options.headers }
        };
        requestOptions.headers['Authorization'] = `Bearer ${accessToken}`;
        let response = await fetchWithTimeout(url, requestOptions);
        if (response.status === 401 || response.status === 403) {
            try {
                const newToken = await refreshToken();
                requestOptions.headers['Authorization'] = `Bearer ${newToken}`;
                response = await fetchWithTimeout(url, requestOptions);
            } catch (error) {
                return Promise.reject(error);
            }
        }
        // уважаем Retry-After на 429/503. Backend rate-limiter
        // присылает заголовок в секундах. Даём UI прозрачно retry один раз
        // (ограничение: max 5 сек ожидания, иначе UX рушится — лучше показать
        // ошибку и дать юзеру нажать ещё раз самостоятельно).
        if ((response.status === 429 || response.status === 503) && !options._retryAfter) {
            const ra = parseInt(response.headers.get('Retry-After') || '0', 10);
            if (ra > 0 && ra <= 5) {
                await new Promise(r => setTimeout(r, ra * 1000));
                return secureFetch(url, { ...options, _retryAfter: true });
            }
            // не смогли retry'ить (Retry-After=0 или >5с) —
            // показываем явный toast вместо генерик «Ошибка сети». Юзер
            // понимает что нужно подождать, а не делает F5/повторный клик.
            if (response.status === 429 && typeof showToast === 'function' && !options._noAutoToast) {
                const waitText = ra > 0 ? ` Попробуйте через ${ra} сек.` : ' Попробуйте чуть позже.';
                showToast('Слишком частые запросы.' + waitText, 'warning', 6000);
            }
        }
        return response;
    };

    /**
     * Показывает security-toast c правильным типом по severity сервера.
     * Используется при ответах с полями severity/category из системы безопасности.
     */
    function showSecurityToast(err) {
        const severity = (err && err.severity) || 'medium';
        const message = (err && err.message) || 'Файл отклонён';
        if (severity === 'soft') {
            // Не атака — просто формат не поддерживается. Жёлтый warning, обычное время.
            showToast(message, 'warning', 6000);
        } else if (severity === 'high') {
            // Высокая опасность (exe/script/обход magic-bytes). Красный, дольше.
            showToast(message, 'error', 9000);
        } else {
            // Medium — несоответствие, но не явная атака.
            showToast(message, 'error', 6000);
        }
    }

    /**
     * Показывает toast-уведомление в правом верхнем углу.
     * @param {string} message — текст уведомления
     * @param {'success'|'error'|'warning'|'info'} type — визуальный тип
     * @param {number} duration — мс до авто-исчезновения (0 = только по клику)
     */
    function showToast(message, type = 'info', duration = 5000) {
        let container = document.getElementById('toastContainer');
        if (!container) {
            container = document.createElement('div');
            container.id = 'toastContainer';
            container.className = 'toast-container';
            document.body.appendChild(container);
        }
        const icons = {
            success: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
            error:   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
            warning: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
            info:    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>'
        };
        const t = document.createElement('div');
        t.className = `toast toast-${type}`;
        // a11y: error/warning — assertive (скрин-ридер прерывает текущее
        // чтение и сразу анонсирует), success/info — polite (ждёт паузы).
        if (type === 'error' || type === 'warning') {
            t.setAttribute('role', 'alert');
            t.setAttribute('aria-live', 'assertive');
        } else {
            t.setAttribute('role', 'status');
            t.setAttribute('aria-live', 'polite');
        }
        t.innerHTML = `
            <span class="toast-icon" aria-hidden="true">${icons[type] || icons.info}</span>
            <div class="toast-body">${sanitizeAndFormatText(message)}</div>
            <button type="button" class="toast-close" aria-label="Закрыть уведомление">×</button>
        `;
        container.appendChild(t);
        // forced reflow для CSS transition при добавлении
        requestAnimationFrame(() => t.classList.add('toast-visible'));

        const remove = () => {
            t.classList.remove('toast-visible');
            t.classList.add('toast-leaving');
            setTimeout(() => t.remove(), 250);
        };
        t.querySelector('.toast-close').addEventListener('click', remove);
        if (duration > 0) {
            setTimeout(remove, duration);
        }
        return remove;
    }

    /**
     * кастомная замена браузерному `confirm()`. Возвращает
     * Promise<boolean>: true если юзер подтвердил, false если отменил.
     *
     * Зачем не confirm(): (1) браузерный alert блокирует JS-thread,
     * нарушает event-loop / WS-pings; (2) выглядит inhumanly — серая
     * системная плашка поверх dark-theme приложения; (3) нельзя стилизовать;
     * (4) на iOS-Safari с PWA вообще приостанавливает page render.
     *
     * Параметры:
     *   title           — заголовок (например «Удалить сообщение?»)
     *   message         — поясняющий текст под заголовком
     *   confirmText     — текст кнопки подтверждения, default «Подтвердить»
     *   cancelText      — текст кнопки отмены, default «Отмена»
     *   danger          — true → primary-кнопка красная (для destructive ops)
     */
    function showConfirm({ title = 'Подтверждение', message = '', confirmText = 'Подтвердить', cancelText = 'Отмена', danger = false } = {}) {
        return new Promise((resolve) => {
            const overlay = document.createElement('div');
            overlay.className = 'confirm-overlay';
            overlay.setAttribute('role', 'dialog');
            overlay.setAttribute('aria-modal', 'true');
            overlay.setAttribute('aria-labelledby', 'confirm-title');
            overlay.innerHTML = `
                <div class="confirm-card">
                    <h2 id="confirm-title" class="confirm-title">${sanitizeAndFormatText(title)}</h2>
                    ${message ? `<p class="confirm-message">${sanitizeAndFormatText(message)}</p>` : ''}
                    <div class="confirm-actions">
                        <button type="button" class="btn-secondary confirm-cancel">${sanitizeAndFormatText(cancelText)}</button>
                        <button type="button" class="${danger ? 'btn-danger' : 'btn-main'} confirm-ok">${sanitizeAndFormatText(confirmText)}</button>
                    </div>
                </div>
            `;
            document.body.appendChild(overlay);
            // forced reflow для CSS transition fade-in
            requestAnimationFrame(() => overlay.classList.add('visible'));

            const close = (result) => {
                overlay.classList.remove('visible');
                setTimeout(() => overlay.remove(), 180);
                resolve(result);
            };
            overlay.querySelector('.confirm-ok').addEventListener('click', () => close(true));
            overlay.querySelector('.confirm-cancel').addEventListener('click', () => close(false));
            overlay.addEventListener('click', e => { if (e.target === overlay) close(false); });

            // a11y: Esc закрывает, фокус на cancel-кнопке (safer-default).
            const okBtn = overlay.querySelector('.confirm-ok');
            const cancelBtn = overlay.querySelector('.confirm-cancel');
            setTimeout(() => cancelBtn.focus(), 0);
            overlay.addEventListener('keydown', e => {
                if (e.key === 'Escape') { e.preventDefault(); close(false); return; }
                if (e.key === 'Enter') { e.preventDefault(); close(true); return; }
                if (e.key === 'Tab') {
                    // Tab-trap между двумя кнопками
                    e.preventDefault();
                    if (document.activeElement === cancelBtn) okBtn.focus();
                    else cancelBtn.focus();
                }
            });
        });
    }

    const sanitizeAndFormatText = (text) => {
        if (!text) return '';
        const tempDiv = document.createElement('div');
        tempDiv.textContent = String(text);
        return tempDiv.innerHTML.replace(/\n/g, '<br>');
    };

    /**
     * Санация HEX-цвета из БД перед использованием в inline-style.
     * До этой проверки в style="background-color: ${cat}22" можно было через
     * специально подобранную строку добавить дополнительные CSS-объявления
     * (CSS-injection). Принимаем только корректный формат #RRGGBB; всё
     * остальное — заменяем на серый по умолчанию.
     */
    const HEX_COLOR_RE = /^#[0-9A-Fa-f]{6}$/;
    /**
     * Жёсткая HEX-валидация + WCAG AA: на dark-theme бейдж показывается
     * с цветом текста = `${cc}` поверх фона `${cc}22` на slate. Если cc
     * слишком тёмный (L < 0.15) — текст растворяется в фоне страницы.
     * Заменяем на нейтральный fallback. На текущей CHECK-constraint в БД
     * (`#RRGGBB`) такие цвета валидны, но визуально неприемлемы.
     */
    function relativeLuminance(hex) {
        const r = parseInt(hex.slice(1, 3), 16) / 255;
        const g = parseInt(hex.slice(3, 5), 16) / 255;
        const b = parseInt(hex.slice(5, 7), 16) / 255;
        const lin = (v) => v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
        return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
    }
    const safeColor = (c) => {
        if (typeof c !== 'string' || !HEX_COLOR_RE.test(c)) return '#94a3b8';
        // Защита от чисто чёрных / очень тёмных цветов на dark-theme.
        return relativeLuminance(c) < 0.15 ? '#94a3b8' : c;
    };

    /**
     * Полное экранирование для HTML-атрибутов и текста.
     * Раньше был `escapeAttr` который экранировал только `"` — это дало
     * stored XSS через category name с одинарной кавычкой в атрибуте
     * `data-cat-edit='...'`. Теперь — все 5 опасных символов.
     */
    const escapeHtml = (str) => {
        if (str === null || str === undefined) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    };
    // Backward-compat alias: оставляем имя escapeAttr для существующих
    // 18+ callsite'ов, теперь экранирует все опасные символы.
    const escapeAttr = escapeHtml;

    function parseJwt(token) {
        try {
            const base64Url = token.split('.')[1];
            const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
            const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
                return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
            }).join(''));
            return JSON.parse(jsonPayload);
        } catch (e) {
            return null;
        }
    }

    /**
     * Безопасный JSON.parse с fallback'ом. Использовать для:
     *   - localStorage / sessionStorage (могут быть corrupt'ы от старой версии)
     *   - WS event.data (сервер мог отправить мусор)
     *   - dataset-атрибуты (теоретически юзер мог подмутить)
     * Прямой JSON.parse кидает SyntaxError → ломает весь UI-flow.
     */
    function safeJsonParse(s, fallback = null) {
        if (typeof s !== 'string' || !s) return fallback;
        try { return JSON.parse(s); }
        catch (_) { return fallback; }
    }

    // безопасные write-обёртки для localStorage/sessionStorage. iOS Safari
    // в Private Mode (а также любой браузер при заполненной квоте) бросает
    // QuotaExceededError на setItem. Без обёртки невинная попытка сохранить
    // viewedRequests / detailState ронит весь handler. Здесь — best-effort
    // write, при ошибке логируем + однократно показываем toast (юзер увидит
    // что состояние «прочитано» сбрасывается, и поймёт почему).
    let _storageQuotaWarned = false;
    function safeStorageSet(storage, key, value) {
        try { storage.setItem(key, value); return true; }
        catch (e) {
            // однократный toast при первом quota-фейле — юзер
            // знает что состояние не сохраняется (важно на iOS Safari Private
            // или при переполненном диске). Дальнейшие фейлы тихо игнорим
            // чтобы не спамить уведомлениями.
            if (!_storageQuotaWarned && typeof showToast === 'function') {
                _storageQuotaWarned = true;
                try { showToast('Не удаётся сохранить состояние просмотра. Очистите кэш браузера.', 'warning', 8000); }
                catch (_) {}
            }
            console.warn('safeStorageSet failed:', e?.name || 'Error', key);
            return false;
        }
    }
    function safeStorageRemove(storage, key) {
        // removeItem тоже throw'ит на iOS Private Mode исторически.
        try { storage.removeItem(key); return true; }
        catch (_) { return false; }
    }

    /**
     * A11y для модалок (WCAG 2.1.2 No Keyboard Trap, СТБ ИСО/МЭК 40500-2012):
     *   - Tab/Shift+Tab циркулирует внутри модалки, не уходит в фон
     *   - Esc закрывает (через .remove() — DOM-cleanup сам сработает)
     *   - При открытии — focus на первый интерактивный элемент
     *   - При закрытии — фокус возвращается на trigger
     *
     * Применять сразу после `document.body.appendChild(overlay)`.
     */
    function setupModalA11y(overlay, opts) {
        // второй аргумент `{ closeFn }` для СТАТИЧЕСКИХ модалок
        // (например, #createRequestModal): они не remove'аются на Esc, а
        // toggle classList.remove('active'). Если closeFn не передан — старое
        // поведение (overlay.remove()).
        // D2/H-3: listener leak fix. Каждый клик «Создать заявку»
        // биндил новый keydown к одному узлу — N открытий → N listener'ов,
        // Tab/Esc отрабатывали по N раз. Теперь:
        // - для статических модалок (closeFn передан) — `_a11yAbortCtrl`
        // хранится на самом DOM-узле; при повторном setup'е старый
        // ctrl.abort() снимает прежний listener, создаём новый.
        // - для динамических (overlay.remove() на Esc) — overlay вообще
        // уничтожается вместе с listener'ом, leak'а нет.
        const closeFn = opts && typeof opts.closeFn === 'function' ? opts.closeFn : null;

        if (closeFn && overlay._a11yAbortCtrl) {
            // Статическая модалка переоткрывается — снимаем прежний listener.
            overlay._a11yAbortCtrl.abort();
            overlay._a11yAbortCtrl = null;
        }

        const FOCUSABLE_SEL = 'a[href], button:not([disabled]), input:not([disabled]), ' +
                              'textarea:not([disabled]), select:not([disabled]), ' +
                              '[tabindex]:not([tabindex="-1"])';
        // Для статических модалок focusables вычисляем при каждом открытии
        // (содержимое могло измениться). Для динамических — один раз на
        // bind, как и раньше.
        const recomputeFocusables = () => {
            const list = overlay.querySelectorAll(FOCUSABLE_SEL);
            return { first: list[0], last: list[list.length - 1] };
        };
        let { first, last } = recomputeFocusables();
        const prevActive = document.activeElement;

        // setTimeout — даём браузеру построить DOM перед фокусом.
        if (first) setTimeout(() => first.focus(), 0);

        // AbortController используется только для статических модалок
        // (динамические — overlay.remove() очищает listener вместе с DOM).
        const abortCtrl = closeFn ? new AbortController() : null;
        if (abortCtrl) overlay._a11yAbortCtrl = abortCtrl;

        // E2/H-7: единая cleanup-функция, отвязывающая listener +
        // возвращающая фокус. Возвращается caller'у, чтобы тот мог вызвать
        // её при ЛЮБОМ способе закрытия (X / backdrop / submit-success), а
        // не только Esc. Раньше abort жил только в Esc-path → между не-Esc
        // close'ом и следующим open'ом keydown-listener остался активен на
        // overlay (для статической модалки overlay живёт в DOM).
        const cleanup = () => {
            if (overlay._a11yAbortCtrl) {
                overlay._a11yAbortCtrl.abort();
                overlay._a11yAbortCtrl = null;
            }
            if (prevActive && typeof prevActive.focus === 'function') {
                prevActive.focus();
            }
        };

        const listenerOpts = abortCtrl ? { signal: abortCtrl.signal } : undefined;
        overlay.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                e.preventDefault();
                if (closeFn) {
                    closeFn();
                    cleanup();
                } else {
                    overlay.remove();
                    if (prevActive && typeof prevActive.focus === 'function') {
                        prevActive.focus();
                    }
                }
                return;
            }
            if (e.key !== 'Tab') return;
            // Для статических модалок refresh focusables — DOM мог измениться
            // (динамические template-rendered элементы внутри).
            if (closeFn) ({ first, last } = recomputeFocusables());
            if (!first || !last) return;
            // Tab-trap
            if (e.shiftKey && document.activeElement === first) {
                last.focus();
                e.preventDefault();
            } else if (!e.shiftKey && document.activeElement === last) {
                first.focus();
                e.preventDefault();
            }
        }, listenerOpts);

        // Только для статических модалок — caller'у может пригодиться
        // (см. createCreateRequestModal usage). Для динамических — overlay.remove()
        // вызывается из Esc-handler'а или caller'а, listener GC'ится с нодой.
        return closeFn ? cleanup : null;
    }

    let user;

    const userNameEl = document.getElementById('userName');
    const userRoleEl = document.getElementById('userRole');
    const listView = document.getElementById('listView');
    const detailView = document.getElementById('detailView');
    const adminView = document.getElementById('adminView');
    const requestsListEl = document.getElementById('requestsList');
    const listTitleEl = document.getElementById('listTitle');
    const loadingMessageEl = document.getElementById('loadingMessage');
    const backToListBtn = document.getElementById('backToListBtn');
    const openModalBtn = document.getElementById('openCreateModalBtn');
    const searchInput = document.getElementById('searchInput');
    const openFilterBtn = document.getElementById('openFilterBtn');
    const filterPanel = document.getElementById('filterPanel');
    const dateCreatedFromInput = document.getElementById('dateCreatedFrom');
    const dateCreatedToInput = document.getElementById('dateCreatedTo');
    const dateUpdatedFromInput = document.getElementById('dateUpdatedFrom');
    const dateUpdatedToInput = document.getElementById('dateUpdatedTo');
    const activeFiltersContainer = document.getElementById('active-filters-container');
    const statusSelectBox = document.getElementById('statusSelectBox');
    const statusDropdown = document.getElementById('statusDropdown');
    const statusOptionsContainer = document.getElementById('statusOptions');
    const advancedFiltersContainer = document.getElementById('advancedFiltersContainer');
    const authorFilterContainer = document.getElementById('authorFilterContainer');
    const authorSelectBox = document.getElementById('authorSelectBox');
    const authorDropdown = document.getElementById('authorDropdown');
    const authorSearchInput = document.getElementById('authorSearch');
    const authorOptionsContainer = document.getElementById('authorOptions');
    // фильтр по категориям.
    const categoryFilterContainer = document.getElementById('categoryFilterContainer');
    const categorySelectBox = document.getElementById('categorySelectBox');
    const categoryDropdown = document.getElementById('categoryDropdown');
    const categoryOptionsContainer = document.getElementById('categoryOptions');
    // фильтр по филиалам (только для Admin/Mod/Approver).
    const branchFilterContainer = document.getElementById('branchFilterContainer');
    const branchSelectBox = document.getElementById('branchSelectBox');
    const branchDropdown = document.getElementById('branchDropdown');
    const branchSearchInput = document.getElementById('branchSearch');
    const branchOptionsContainer = document.getElementById('branchOptions');
    let allBranches = [];
    const createModal = document.getElementById('createRequestModal');
    const createForm = document.getElementById('createRequestForm');

    
    let allRequests = [];
    let currentPage = 1;
    const itemsPerPage = 20;

    let selectedFiles = [];
    let detailViewFiles = [];
    let currentDocumentsInView = [];
    let globalWs = null;
    let commentObserver = null;
    let activityObserver = null;
    const unreadCommentIds = new Set();
    const unreadActivityIds = new Set();
    let isFiltersPopulated = false;
    let eventCategories = [];
    // Typing-indicator state — объявлено в module-scope чтобы handleRouteChange
    // (выше по файлу) мог чистить interval при смене заявки без TDZ-ошибки.
    let _typingTickInterval = null;
    const _typingUsers = new Map();   // userId -> { name, expireAt }
    // предыдущий hash для корректного WS-unsubscribe.
    // hashchange-event firing'ит ПОСЛЕ обновления `window.location.hash` →
    // нельзя через него получить старый. Храним вручную.
    let _prevHash = '';
    let currentViewMode = sessionStorage.getItem('viewMode') || 'list';
    let fcInstance = null;
    // `let`, не `const`. Старый код переприсваивал `chartInstances = {}`
    // в строке 775 при повторном рендере аналитики — TypeError: Assignment to constant.
    // Аналитика крашилась после второго захода. Альтернатива — ключевое удаление,
    // но `= {}` короче и идиоматичнее.
    let chartInstances = {};
    let statsPeriodMonths = 6;          // период по умолчанию для дашборда
    const calendarHiddenCategories = new Set(safeJsonParse(sessionStorage.getItem('calHiddenCats'), []));

    // Пользовательские уведомления (отдельно от admin security alerts).
    // notifs хранит до 30 последних загруженных, unreadCount — суммарный счётчик.
    const notifState = { items: [], unreadCount: 0, loaded: false };

    // Состояние массового выделения заявок для batch-операций.
    const batchState = { selectedIds: new Set() };

    // Доменные константы (роли, статусы) — загружаются с сервера при инициализации.
    // Содержат маппинги: roles { ADMIN: 1, ... }, statuses { NEW: 1, ... } и обратные.
    // До загрузки используются строковые имена ролей в проверках доступа.
    let SYSTEM_CONSTANTS = {
        roles:     {}, roleNames:   {},
        statuses:  {}, statusNames: {}
    };

    let readHistoryBatch = [];
    let historyReadTimer = null;

    async function loadEventCategories() {
        if (eventCategories.length > 0) return eventCategories;
        try {
            const res = await secureFetch('/api/event-categories');
            if (!res.ok) throw new Error('Network error');
            eventCategories = await res.json();
        } catch (e) {
            console.error('Не удалось загрузить категории мероприятий:', e);
        }
        return eventCategories;
    }

    function initCalendarIfNeeded() {
        if (fcInstance) return fcInstance;
        if (typeof FullCalendar === 'undefined') {
            console.error('FullCalendar не загружен (CDN недоступен?)');
            return null;
        }
        const el = document.getElementById('fullCalendar');
        if (!el) return null;

        const STATUS_TO_CLASS = {
            'Новая':              'fc-status-new',
            'На модерации':       'fc-status-moderation',
            'На согласовании':    'fc-status-approval',
            'Одобрена':           'fc-status-approved',
            'Отклонена':          'fc-status-rejected',
            'Требует доработки':  'fc-status-rework'
        };
        const STATUS_TO_ICON = {
            'Новая':              '',
            'На модерации':       '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2.2"><circle cx="8" cy="8" r="5.5"/><path d="M8 5.5v3l2 1.5"/></svg>',
            'На согласовании':    '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M2 8h4l2-4 2 8 2-4h2"/></svg>',
            'Одобрена':           '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M3 8.5l3 3 7-7"/></svg>',
            'Отклонена':          '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M4 4l8 8M12 4l-8 8"/></svg>',
            'Требует доработки':  '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12V4l5 4-5 4z" fill="currentColor"/><path d="M9 12V4"/></svg>'
        };

        // Кастомный tooltip — единственный элемент, переиспользуем для всех событий
        let fcTooltipEl = document.getElementById('fc-tooltip');
        if (!fcTooltipEl) {
            fcTooltipEl = document.createElement('div');
            fcTooltipEl.id = 'fc-tooltip';
            fcTooltipEl.className = 'fc-tooltip';
            document.body.appendChild(fcTooltipEl);
        }
        const showTooltip = (event, mouseEvent) => {
            const p = event.extendedProps;
            const dateStr = new Date(event.start).toLocaleString('ru-RU', { weekday: 'long', day: 'numeric', month: 'long', hour: '2-digit', minute: '2-digit' });
            const ttColor = safeColor(p.categoryColor);
            fcTooltipEl.innerHTML = `
                <div class="fc-tooltip-header" style="background-color: ${ttColor}33; border-left: 3px solid ${ttColor};">
                    <div class="fc-tooltip-title">№${p.requestId} ${sanitizeAndFormatText(event.title)}</div>
                    <div class="fc-tooltip-cat">${sanitizeAndFormatText(p.categoryName || '')}</div>
                </div>
                <div class="fc-tooltip-body">
                    <div class="fc-tooltip-row"><span class="fc-tooltip-key">Когда</span><span>${dateStr}</span></div>
                    <div class="fc-tooltip-row"><span class="fc-tooltip-key">Статус</span><span class="fc-tt-status fc-tt-${(STATUS_TO_CLASS[p.statusName] || '').replace('fc-status-', '')}">${sanitizeAndFormatText(p.statusName || '')}</span></div>
                    ${p.creatorName ? `<div class="fc-tooltip-row"><span class="fc-tooltip-key">Автор</span><span>${sanitizeAndFormatText(p.creatorName)}</span></div>` : ''}
                    ${p.location ? `<div class="fc-tooltip-row"><span class="fc-tooltip-key">Место</span><span>${sanitizeAndFormatText(p.location)}</span></div>` : ''}
                    ${p.attendees ? `<div class="fc-tooltip-row"><span class="fc-tooltip-key">Участников</span><span>${p.attendees}</span></div>` : ''}
                </div>
                <div class="fc-tooltip-foot">Нажмите, чтобы открыть карточку</div>
            `;
            fcTooltipEl.classList.add('visible');
            const rect = fcTooltipEl.getBoundingClientRect();
            const pad = 12;
            let x = mouseEvent.clientX + 16;
            let y = mouseEvent.clientY + 16;
            if (x + rect.width + pad > window.innerWidth)  x = mouseEvent.clientX - rect.width - 16;
            if (y + rect.height + pad > window.innerHeight) y = mouseEvent.clientY - rect.height - 16;
            fcTooltipEl.style.left = Math.max(pad, x) + 'px';
            fcTooltipEl.style.top  = Math.max(pad, y) + 'px';
        };
        const hideTooltip = () => fcTooltipEl.classList.remove('visible');

        // Сводка над календарём ("Май 2026: N мероприятий, из них M антикоррупционных")
        const updateCalendarSummary = (events) => {
            const summaryEl = document.getElementById('fc-summary');
            if (!summaryEl || !events) return;
            const total = events.length;
            const byCat = {};
            events.forEach(e => {
                const c = e.extendedProps?.categoryName;
                if (c) byCat[c] = (byCat[c] || 0) + 1;
            });
            const top = Object.entries(byCat).sort((a, b) => b[1] - a[1])[0];
            const word = (n) => n % 10 === 1 && n % 100 !== 11 ? 'мероприятие' : (n % 10 >= 2 && n % 10 <= 4 && (n % 100 < 10 || n % 100 >= 20) ? 'мероприятия' : 'мероприятий');
            if (total === 0) {
                summaryEl.innerHTML = `<span class="fc-summary-muted">Нет мероприятий в этом периоде</span>`;
            } else {
                summaryEl.innerHTML = `<strong>${total}</strong> ${word(total)}${top ? `, преобладает категория «${sanitizeAndFormatText(top[0])}» (${top[1]})` : ''}`;
            }
        };

        fcInstance = new FullCalendar.Calendar(el, {
            initialView: 'dayGridMonth',
            aspectRatio: 1.8,
            expandRows: true,
            locale: {
                code: 'ru',
                week: { dow: 1, doy: 4 },
                buttonHints: {
                    prev: 'Назад',
                    next: 'Вперёд',
                    today: 'Сегодня'
                },
                viewHint: '$0 представление',
                navLinkHint: 'Перейти к $0',
                moreLinkHint: 'Показать ещё $0 событий',
                allDayText: 'Весь день',
                weekText: 'Нед',
                weekTextLong: 'Неделя',
                closeHint: 'Закрыть',
                timeHint: 'Время',
                eventHint: 'Событие',
                moreLinkText: 'ещё +',
                noEventsText: 'На этот период мероприятий нет'
            },
            firstDay: 1,
            height: 'auto',
            navLinks: true,
            dayMaxEvents: 4,
            displayEventTime: true,
            eventDisplay: 'block',
            eventTimeFormat: { hour: '2-digit', minute: '2-digit', hour12: false, meridiem: false },
            slotLabelFormat: { hour: '2-digit', minute: '2-digit', hour12: false, meridiem: false },
            slotMinTime: '07:00:00',
            slotMaxTime: '20:00:00',
            slotDuration: '00:30:00',
            allDaySlot: false,
            nowIndicator: true,
            scrollTime: '08:00:00',
            slotEventOverlap: false,
            views: {
                timeGridWeek: { dayHeaderFormat: { weekday: 'short', day: '2-digit', month: '2-digit', omitCommas: true } },
                listMonth: { listDayFormat: { weekday: 'long', day: 'numeric', month: 'long' }, listDaySideFormat: false }
            },
            headerToolbar: {
                left: 'prev,next today',
                center: 'title',
                right: 'dayGridMonth,timeGridWeek,listMonth'
            },
            buttonText: {
                today: 'Сегодня',
                month: 'Месяц',
                week: 'Неделя',
                list: 'Список'
            },
            events: async (info, success, failure) => {
                try {
                    const url = `/api/requests/calendar?from=${encodeURIComponent(info.startStr)}&to=${encodeURIComponent(info.endStr)}`;
                    const r = await secureFetch(url);
                    if (!r.ok) throw new Error('Network');
                    const data = await r.json();
                    // Фильтруем по скрытым категориям, выбранным пользователем в легенде
                    const filtered = data.filter(req =>
                        !calendarHiddenCategories.has(String(req.category_id || '0'))
                    );
                    success(filtered.map(req => {
                        const start = new Date(req.planned_date);
                        // визуальная длительность 1 час — чтобы блок в неделя-виде был адекватен
                        const end = new Date(start.getTime() + 60 * 60 * 1000);
                        return {
                            id: String(req.id),
                            title: req.title,
                            start: req.planned_date,
                            end: end.toISOString(),
                            backgroundColor: req.category_color || '#94a3b8',
                            borderColor: req.category_color || '#94a3b8',
                            textColor: '#ffffff',
                            classNames: [STATUS_TO_CLASS[req.status_name] || 'fc-status-new'],
                            extendedProps: {
                                requestId: req.id,
                                categoryName: req.category_name,
                                categoryColor: req.category_color,
                                statusName: req.status_name,
                                creatorName: req.creator_name,
                                location: req.location,
                                attendees: req.expected_attendees
                            }
                        };
                    }));
                } catch (e) {
                    console.error('Ошибка загрузки событий календаря:', e);
                    failure(e);
                }
            },
            eventContent: (arg) => {
                const p = arg.event.extendedProps;
                const time = arg.timeText || '';
                const title = arg.event.title || '';
                const reqId = p.requestId;
                const statusIcon = STATUS_TO_ICON[p.statusName] || '';
                if (arg.view.type === 'listMonth') {
                    // в листинге FC сам красиво рисует — отдаём дефолт
                    return true;
                }
                const wrapper = document.createElement('div');
                wrapper.className = 'fc-ve-content';
                wrapper.innerHTML = `
                    ${time ? `<span class="fc-ve-time">${time}</span>` : ''}
                    <span class="fc-ve-title"><strong>№${reqId}</strong> ${sanitizeAndFormatText(title)}</span>
                    ${statusIcon ? `<span class="fc-ve-status-icon" aria-hidden="true">${statusIcon}</span>` : ''}
                `;
                return { domNodes: [wrapper] };
            },
            eventClick: (info) => {
                info.jsEvent.preventDefault();
                hideTooltip();
                window.location.hash = `#/request/${info.event.id}`;
            },
            eventDidMount: (info) => {
                info.el.removeAttribute('title'); // подавим нативный tooltip — у нас свой
                info.el.addEventListener('mouseenter', e => showTooltip(info.event, e));
                info.el.addEventListener('mousemove',  e => showTooltip(info.event, e));
                info.el.addEventListener('mouseleave', hideTooltip);
            },
            eventsSet: (events) => {
                updateCalendarSummary(events);
                // FullCalendar в timegrid выставляет harness-обёртке inline-стили left/right через
                // JS уже после применения CSS — это не дает событию занять всю ширину колонки.
                // Принудительно затираем эти стили после рендера каждого события.
                requestAnimationFrame(() => {
                    document.querySelectorAll('#fullCalendar .fc-timegrid-event-harness').forEach(h => {
                        h.style.left = '0';
                        h.style.right = '0';
                        h.style.width = '100%';
                        h.style.insetInlineStart = '0';
                        h.style.insetInlineEnd = '0';
                    });
                });
            },
            datesSet: () => {
                // Тоже после смены вида/диапазона
                requestAnimationFrame(() => {
                    document.querySelectorAll('#fullCalendar .fc-timegrid-event-harness').forEach(h => {
                        h.style.left = '0';
                        h.style.right = '0';
                        h.style.width = '100%';
                    });
                });
            }
        });
        fcInstance.render();
        return fcInstance;
    }

    /** Рендерит легенду категорий с возможностью включения/выключения. */
    async function renderCalendarLegend() {
        const legendEl = document.getElementById('fc-legend');
        if (!legendEl) return;
        const cats = await loadEventCategories();
        if (!cats || cats.length === 0) { legendEl.innerHTML = ''; return; }

        const allKey = '__all__';
        legendEl.innerHTML = `
            <span class="fc-legend-label">Категории:</span>
            ${cats.map(c => {
                const hidden = calendarHiddenCategories.has(String(c.id));
                const cc = safeColor(c.color_hex);
                return `
                    <button type="button" class="fc-legend-chip ${hidden ? 'is-off' : ''}"
                            data-cat-id="${c.id}"
                            style="--cat-color: ${cc};">
                        <span class="fc-legend-dot" style="background-color: ${cc};"></span>
                        <span>${sanitizeAndFormatText(c.name)}</span>
                    </button>
                `;
            }).join('')}
            <button type="button" class="fc-legend-reset" data-cat-id="${allKey}">Все</button>
        `;

        legendEl.querySelectorAll('.fc-legend-chip').forEach(btn => {
            btn.addEventListener('click', () => {
                const id = btn.dataset.catId;
                if (calendarHiddenCategories.has(id)) calendarHiddenCategories.delete(id);
                else calendarHiddenCategories.add(id);
                btn.classList.toggle('is-off', calendarHiddenCategories.has(id));
                safeStorageSet(sessionStorage, 'calHiddenCats', JSON.stringify([...calendarHiddenCategories]));
                if (fcInstance) fcInstance.refetchEvents();
            });
        });
        legendEl.querySelector('.fc-legend-reset').addEventListener('click', () => {
            calendarHiddenCategories.clear();
            safeStorageRemove(sessionStorage, 'calHiddenCats');
            renderCalendarLegend();
            if (fcInstance) fcInstance.refetchEvents();
        });
    }

    function setViewMode(mode) {
        if (!['list', 'calendar', 'stats'].includes(mode)) mode = 'list';
        currentViewMode = mode;
        safeStorageSet(sessionStorage, 'viewMode', mode);

        document.querySelectorAll('.view-mode-btn').forEach(btn => {
            const isActive = btn.dataset.viewMode === mode;
            btn.classList.toggle('active', isActive);
            btn.setAttribute('aria-selected', isActive ? 'true' : 'false');
        });

        const listContainer = document.getElementById('listContainer');
        const paginationContainer = document.getElementById('paginationContainer');
        const activeFilters = document.getElementById('active-filters-container');
        const calendarContainer = document.getElementById('calendarContainer');
        const statsContainer = document.getElementById('statsContainer');

        // По умолчанию скрываем все, потом показываем нужный
        listContainer.classList.add('hidden');
        paginationContainer.classList.add('hidden');
        activeFilters.classList.add('hidden');
        calendarContainer.classList.add('hidden');
        statsContainer.classList.add('hidden');

        if (mode === 'calendar') {
            calendarContainer.classList.remove('hidden');
            renderCalendarLegend();
            const cal = initCalendarIfNeeded();
            if (cal) {
                cal.updateSize();
                cal.refetchEvents();
            }
        } else if (mode === 'stats') {
            statsContainer.classList.remove('hidden');
            renderStatsView();
        } else {
            listContainer.classList.remove('hidden');
            paginationContainer.classList.remove('hidden');
            activeFilters.classList.remove('hidden');
        }
    }

    async function renderStatsView() {
        if (typeof Chart === 'undefined') {
            console.error('Chart.js не загружен');
            return;
        }
        const loadingEl = document.querySelector('#statsContainer .stats-loading');
        const contentEl = document.querySelector('#statsContainer .stats-content');

        try {
            const res = await secureFetch(`/api/stats?months=${statsPeriodMonths}`);
            if (!res.ok) throw new Error('HTTP ' + res.status);
            const data = await res.json();

            // баннер scope-визибилити убран по запросу.
            // Юзер и так знает свою роль (виден badge в шапке) — дублирующий
            // hint про «личная статистика / зона ответственности» был лишний.
            // Элемент скрыт через `hidden` в index.html, JS не рендерит innerHTML.

            // KPI
            const k = data.kpi;
            document.getElementById('kpiTotal').textContent = k.total;
            document.getElementById('kpiApproved').textContent = k.approved;
            document.getElementById('kpiInProgress').textContent = k.in_progress;
            const approvedPct = k.total > 0 ? Math.round((k.approved / k.total) * 100) : 0;
            document.getElementById('kpiApprovedPct').textContent = `(${approvedPct}%)`;
            document.getElementById('kpiAvgHours').textContent = k.avg_approval_hours !== null
                ? formatHoursToHuman(k.avg_approval_hours)
                : '—';

            // Глобальные настройки темы Chart.js
            Chart.defaults.color = '#94a3b8';
            Chart.defaults.borderColor = 'rgba(255, 255, 255, 0.06)';
            Chart.defaults.font.family = "'Manrope', sans-serif";

            // Удалить предыдущие инстансы (на случай повторного входа)
            Object.values(chartInstances).forEach(c => c && c.destroy());
            chartInstances = {};

            // 1. Pie/Donut по категориям
            const cats = data.byCategory.filter(c => c.qty > 0);
            chartInstances.categories = new Chart(document.getElementById('chartCategories'), {
                type: 'doughnut',
                data: {
                    labels: cats.map(c => c.name),
                    datasets: [{
                        data: cats.map(c => c.qty),
                        backgroundColor: cats.map(c => c.color_hex),
                        borderColor: '#1e293b',
                        borderWidth: 2,
                        hoverOffset: 8
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: '55%',
                    plugins: {
                        legend: { position: 'right', labels: { padding: 12, boxWidth: 14, font: { size: 12 } } },
                        tooltip: {
                            callbacks: {
                                label: (ctx) => {
                                    const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
                                    const pct = total > 0 ? Math.round((ctx.parsed / total) * 100) : 0;
                                    return ` ${ctx.label}: ${ctx.parsed} (${pct}%)`;
                                }
                            }
                        }
                    }
                }
            });

            // 2. Воронка статусов
            const STATUS_COLORS = {
                'Новая':              '#38bdf8',
                'На модерации':       '#fb923c',
                'На согласовании':    '#eab308',
                'Одобрена':           '#4ade80',
                'Отклонена':          '#f87171',
                'Требует доработки':  '#f87171'
            };
            const stOrder = ['Новая', 'На модерации', 'На согласовании', 'Одобрена', 'Отклонена', 'Требует доработки'];
            const stData = stOrder.map(name => {
                const found = data.byStatus.find(s => s.name === name);
                return { name, qty: found ? found.qty : 0 };
            });
            chartInstances.statuses = new Chart(document.getElementById('chartStatuses'), {
                type: 'bar',
                data: {
                    labels: stData.map(s => s.name),
                    datasets: [{
                        label: 'Количество заявок',
                        data: stData.map(s => s.qty),
                        backgroundColor: stData.map(s => STATUS_COLORS[s.name] || '#94a3b8'),
                        borderRadius: 6,
                        barThickness: 22
                    }]
                },
                options: {
                    indexAxis: 'y',
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { stepSize: 1, precision: 0 } },
                        y: { grid: { display: false } }
                    }
                }
            });

            // 3. Активность по месяцам — линейный график
            const monthLabels = ['янв', 'фев', 'мар', 'апр', 'май', 'июн', 'июл', 'авг', 'сен', 'окт', 'ноя', 'дек'];
            const tlLabels = data.byMonth.map(m => `${monthLabels[m.mn - 1]} ${m.yr}`);
            const tlValues = data.byMonth.map(m => m.qty);
            const ctxTL = document.getElementById('chartTimeline').getContext('2d');
            const grad = ctxTL.createLinearGradient(0, 0, 0, 240);
            grad.addColorStop(0, 'rgba(56, 189, 248, 0.4)');
            grad.addColorStop(1, 'rgba(56, 189, 248, 0)');
            chartInstances.timeline = new Chart(ctxTL, {
                type: 'line',
                data: {
                    labels: tlLabels,
                    datasets: [{
                        label: 'Мероприятий',
                        data: tlValues,
                        borderColor: '#38bdf8',
                        backgroundColor: grad,
                        borderWidth: 2.5,
                        pointRadius: 5,
                        pointHoverRadius: 7,
                        pointBackgroundColor: '#38bdf8',
                        pointBorderColor: '#0f172a',
                        pointBorderWidth: 2,
                        tension: 0.35,
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { grid: { display: false } },
                        y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { stepSize: 1, precision: 0 } }
                    }
                }
            });

            // 4. Топ-10 филиалов
            chartInstances.branches = new Chart(document.getElementById('chartBranches'), {
                type: 'bar',
                data: {
                    labels: data.byBranch.map(b => b.name),
                    datasets: [{
                        label: 'Заявок',
                        data: data.byBranch.map(b => b.qty),
                        backgroundColor: '#38bdf8',
                        borderRadius: 6,
                        barThickness: 24
                    }]
                },
                options: {
                    indexAxis: 'y',
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { stepSize: 1, precision: 0 } },
                        y: { grid: { display: false } }
                    }
                }
            });

            loadingEl.classList.add('hidden');
            contentEl.classList.remove('hidden');

            // Активная кнопка периода + клики
            document.querySelectorAll('.period-btn').forEach(btn => {
                btn.classList.toggle('active', parseInt(btn.dataset.months, 10) === statsPeriodMonths);
                btn.onclick = () => {
                    statsPeriodMonths = parseInt(btn.dataset.months, 10);
                    renderStatsView();
                };
            });
        } catch (err) {
            console.error('Ошибка загрузки статистики:', err);
            loadingEl.textContent = 'Не удалось загрузить статистику';
        }
    }

    function formatHoursToHuman(hours) {
        if (hours == null) return '—';
        if (hours < 1) return `${Math.round(hours * 60)} мин`;
        if (hours < 24) return `${Math.round(hours * 10) / 10} ч`;
        const days = Math.floor(hours / 24);
        const rem = Math.round(hours - days * 24);
        return rem > 0 ? `${days} дн ${rem} ч` : `${days} дн`;
    }

    /**
     * единый формат даты-времени по проекту — `dd.MM.yyyy HH:mm`,
     * без секунд. Для мероприятий и audit-меток секунды лишний шум.
     */
    function formatDateTime(iso) {
        if (!iso) return '—';
        const d = new Date(iso);
        if (isNaN(d.getTime())) return '—';
        const pad = (n) => String(n).padStart(2, '0');
        return `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()} ` +
               `${pad(d.getHours())}:${pad(d.getMinutes())}`;
    }

    /**
     * (доменная логика): конфиг кнопки PDF-протокола.
     *
     * Источник истины — server-side `PDF_PROTOCOL_CONFIG` в config/constants.js,
     * приходит через /api/system-constants. Фронт лишь скрывает/адаптирует
     * кнопку — backend дублирует проверку через `getPdfProtocolAccess()`.
     *
     * Возвращает:
     *   { visible: bool, label: string, hint: string, isDraft: bool }
     *
     * Скрывает кнопку (visible:false) если:
     *   • статус не из набора {APPROVAL, REWORK, APPROVED, REJECTED}
     *   • роль юзера в `deniedRoleKeys` для этого статуса
     *     (по умолчанию: Сотрудник на APPROVAL — не должен видеть бланк
     *     к подписи до принятия решения по своей же заявке).
     */
    function getPdfProtocolConfig(request) {
        if (!request) return { visible: false };
        const statusId = request.status_id;
        // SYSTEM_CONSTANTS.pdfProtocol — карта { STATUS_KEY: {label, hint, isDraft, deniedRoleKeys} }
        const pdfMap = SYSTEM_CONSTANTS?.pdfProtocol || {};
        // Найдём ключ статуса по ID для lookup'а в pdfMap
        const statusKey = Object.keys(SYSTEM_CONSTANTS?.statuses || {})
            .find(k => SYSTEM_CONSTANTS.statuses[k] === statusId);
        const cfg = statusKey ? pdfMap[statusKey] : null;
        if (!cfg) return { visible: false };

        // Найдём ключ роли юзера для проверки deniedRoleKeys
        const userRoleId = SYSTEM_CONSTANTS?.roles
            ? Object.keys(SYSTEM_CONSTANTS.roles).find(k => SYSTEM_CONSTANTS.roleNames[SYSTEM_CONSTANTS.roles[k]] === user.role)
            : null;
        if (userRoleId && Array.isArray(cfg.deniedRoleKeys) && cfg.deniedRoleKeys.includes(userRoleId)) {
            return { visible: false };
        }

        return {
            visible: true,
            label: cfg.label,
            hint: cfg.hint,
            isDraft: !!cfg.isDraft
        };
    }

    /**
     * terminal-статусы immutable — drag-drop файлов и upload
     * скрываются. Server-side guard всё равно отвергнёт upload, но фронт
     * не должен показывать UI-обещание которое не выполнится.
     * Статус-имена синхронизированы с db/00_init_schema.sql (Одобрена ≠ Утверждена).
     */
    function isTerminalStatus(status) {
        return ['Одобрена', 'Отклонена', 'Отозвана'].includes(status);
    }

    function saveState() {
        if (!listView.classList.contains('hidden')) {
            const listState = {
                scrollY: window.scrollY,
                searchValue: searchInput.value,
                selectedStatuses: [...statusOptionsContainer.querySelectorAll('input:checked')].map(cb => cb.value),
                selectedAuthors: [...authorOptionsContainer.querySelectorAll('input:checked')].map(cb => cb.value),
                selectedCategories: categoryOptionsContainer ? [...categoryOptionsContainer.querySelectorAll('input:checked')].map(cb => cb.value) : [],
                selectedBranches: branchOptionsContainer ? [...branchOptionsContainer.querySelectorAll('input:checked')].map(cb => cb.value) : [],
                dateCreatedFrom: dateCreatedFromInput.value,
                dateCreatedTo: dateCreatedToInput.value,
                dateUpdatedFrom: dateUpdatedFromInput.value,
                dateUpdatedTo: dateUpdatedToInput.value,
                currentPage: currentPage
            };
            safeStorageSet(sessionStorage, 'listState', JSON.stringify(listState));
        } else if (!detailView.classList.contains('hidden')) {
            const requestId = window.location.hash.split('/')[2];
            if (!requestId) return;
            const detailState = {
                scrollY: window.scrollY,
                activeTab: detailView.querySelector('.switcher-btn.active')?.dataset.view || 'activity',
                descriptionScroll: detailView.querySelector('.detail-main-content p')?.scrollTop || 0,
                docsScroll: detailView.querySelector('.document-sublist')?.scrollTop || 0,
                activityScroll: detailView.querySelector('.activity-feed')?.scrollTop || 0,
                chatScroll: detailView.querySelector('.chat-feed')?.scrollTop || 0,
            };
            safeStorageSet(sessionStorage, `detailState_${requestId}`, JSON.stringify(detailState));
        }
    }

    function clearState(type, id = null) {
        if (type === 'list') {
            safeStorageRemove(sessionStorage, 'listState');
        } else if (type === 'detail' && id) {
            safeStorageRemove(sessionStorage, `detailState_${id}`);
        }
    }

    function restoreListState() {
        const savedState = safeJsonParse(sessionStorage.getItem('listState'));
        if (!savedState) return;
        currentPage = savedState.currentPage || 1;
        searchInput.value = savedState.searchValue || '';
        dateCreatedFromInput.value = savedState.dateCreatedFrom || '';
        dateCreatedToInput.value = savedState.dateCreatedTo || '';
        dateUpdatedFromInput.value = savedState.dateUpdatedFrom || '';
        dateUpdatedToInput.value = savedState.dateUpdatedTo || '';

        if (isFiltersPopulated) {
            savedState.selectedStatuses?.forEach(statusValue => {
                const checkbox = statusOptionsContainer.querySelector(`input[value="${statusValue}"]`);
                if (checkbox) checkbox.checked = true;
            });
            savedState.selectedAuthors?.forEach(authorId => {
                const checkbox = authorOptionsContainer.querySelector(`input[value="${authorId}"]`);
                if (checkbox) checkbox.checked = true;
            });
            // восстановление выбранных категорий
            if (categoryOptionsContainer) {
                savedState.selectedCategories?.forEach(catId => {
                    const checkbox = categoryOptionsContainer.querySelector(`input[value="${catId}"]`);
                    if (checkbox) checkbox.checked = true;
                });
            }
            // восстановление выбранных филиалов
            if (branchOptionsContainer) {
                savedState.selectedBranches?.forEach(brId => {
                    const checkbox = branchOptionsContainer.querySelector(`input[value="${brId}"]`);
                    if (checkbox) checkbox.checked = true;
                });
            }
        }
        setTimeout(() => window.scrollTo(0, savedState.scrollY || 0), 1);
        clearState('list');
    }

    const ALL_STATUSES = ['Новая', 'На модерации', 'На согласовании', 'Одобрена', 'Отклонена', 'Требует доработки'];
    const singleCheckSVG = `<span class="status-icon"><svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5" /></svg></span>`;
    const doubleCheckSVG = `<span class="status-icon"><svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="m4.5 12.75 6 6 9-13.5" /></svg><svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2.5" stroke="currentColor" style="margin-left: -11px; opacity: 0.8;"><path stroke-linecap="round" stroke-linejoin="round" d="m4.5 12.75 6 6 9-13.5" /></svg></span>`;

    const getFileIcon = (fileName) => {
        const extension = fileName.split('.').pop().toLowerCase();
        const iconMap = {
            'pdf': '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="file-icon-path"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><path d="M10 12v-1a2 2 0 0 1 2-2h1"></path><path d="M13 18h-3a2 2 0 0 1 0-4h3v4Z"></path></svg>',
            'doc': '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="file-icon-path"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><path d="M12 18v-6h-2v6"></path><path d="M12 12h2a2 2 0 1 1 0 4h-2"></path></svg>',
            'xls': '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="file-icon-path"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><line x1="10" y1="9" x2="8" y2="21"></line><line x1="16" y1="9" x2="14" y2="21"></line></svg>',
            'png': '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="file-icon-path"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><circle cx="10" cy="15" r="2"></circle><path d="m20 12-6.25 6.25c-.23.22-.3.3-.45.3H8.5c-.2 0-.3 0-.5-.2S7.8 18 8 17.8l4-4c.2-.2.3-.3.4-.3s.2.1.4.3l2.8 2.8"></path></svg>',
            'zip': '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="file-icon-path"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><path d="M10 12h-1v6h1"></path><path d="M13 12h-1v6h1"></path><path d="M10 15h3"></path></svg>',
        };
        const defaultIcon = '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="file-icon-path"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>';
        const ext = { docx: 'doc', xlsx: 'xls', jpg: 'png', jpeg: 'png', gif: 'png', bmp: 'png', webp: 'png', rar: 'zip', '7z': 'zip' }[extension] || extension;
        return iconMap[ext] || defaultIcon;
    };

    const getDisplayStatus = (realStatus, requestCreatorId, requestId) => {
        const { role: userRole, id: currentUserId } = user;
        if (userRole === 'Согласующий' && realStatus === 'На согласовании') {
            const storageKey = `viewedRequests_${currentUserId}`;
            const viewedIds = safeJsonParse(localStorage.getItem(storageKey), []);
            return viewedIds.includes(requestId.toString()) ? 'На согласовании' : 'Новая';
        }
        if (currentUserId === requestCreatorId && realStatus === 'Новая') {
            return 'На модерации';
        }
        if (userRole === 'Модератор' && realStatus === 'Требует доработки') {
            return 'Отправлена на доработку';
        }
        return realStatus;
    };

    const formatDateSeparator = (date) => {
        const now = new Date();
        const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
        const yesterday = new Date(today);
        yesterday.setDate(yesterday.getDate() - 1);
        const inputDate = new Date(date);
        const inputDay = new Date(inputDate.getFullYear(), inputDate.getMonth(), inputDate.getDate());
        if (inputDay.getTime() === today.getTime()) return 'Сегодня';
        if (inputDay.getTime() === yesterday.getTime()) return 'Вчера';
        return inputDay.toLocaleDateString('ru-RU', { day: 'numeric', month: 'long', year: 'numeric' });
    };

    function setupGlobalWebSocket() {
        if (globalWs) {
            globalWs.close();
        }

        const connect = () => {
            const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            // Без ?token= в URL: токен уйдёт ОТДЕЛЬНЫМ сообщением сразу после open.
            // Это безопаснее: query-string попадает в логи прокси.
            globalWs = new WebSocket(`${wsProtocol}//${window.location.host}`);

            globalWs.onopen = () => {
                // Шаг 1 handshake: шлём auth-сообщение. Сервер ответит auth_ok / auth_error.
                try {
                    globalWs.send(JSON.stringify({ type: 'auth', token: accessToken }));
                } catch (e) {
                    console.error('WS auth send failed:', e);
                }
            };

            globalWs.onmessage = (event) => {
                // Сервер мог отправить мусор / WS-фрейм с не-JSON. Без try/catch
                // SyntaxError ронит handler — следующие сообщения теряются.
                const data = safeJsonParse(event.data);
                if (!data || typeof data !== 'object') return;

                // Принудительный logout при отзыве токена (см. bumpTokenVersion).
                if (data.type === 'auth_revoked') {
                    // глушим reconnect-storm — после auth_revoked онclose
                    // натурально вызовет scheduleReconnect, который ставит
                    // setTimeout(connect, 1s) даже после navigate. Без флага
                    // если navigate не успеет за секунду, новый WS с null token.
                    if (window.__disableReconnect) window.__disableReconnect('auth_revoked');
                    handleLogout();
                    return;
                }

                // сервер выявил message-flood (Block I — H1) и закрывает
                // соединение. Без обработки фронт молча реконнектится в цикле.
                // Останавливаем reconnect и показываем юзеру что произошло.
                if (data.type === 'flood_detected') {
                    if (window.__disableReconnect) window.__disableReconnect('flood_detected');
                    showToast('Слишком частые сообщения по WebSocket — соединение приостановлено.', 'error', 8000);
                    return;
                }

                // Сервер отказал в подписке на канал (например, заявка стала
                // невидима после смены статуса для согласующего, или права
                // отозваны). Информируем юзера и откатываем на список.
                if (data.type === 'subscribe_denied') {
                    showToast('Доступ к заявке отозван.', 'warning');
                    if (window.location.hash.startsWith('#/request/')) {
                        window.location.hash = '';
                    }
                    return;
                }

                // Подписка отозвана сервером после смены статуса заявки —
                // видимость для текущей роли изменилась (например, APPROVER
                // подписался на APPROVAL, заявку перевели в WITHDRAWN). Сервер
                // удалил подписку и шлёт это событие, чтобы фронт не считал
                // отсутствие broadcast'ов багом и закрыл открытую карточку.
                if (data.type === 'subscribe_revoked') {
                    showToast('Доступ к заявке отозван после смены статуса.', 'warning');
                    if (window.location.hash.startsWith('#/request/')) {
                        const channelReqId = (data.channel || '').match(/^request-(\d+)$/)?.[1];
                        const openReqId = window.location.hash.split('/')[2];
                        if (channelReqId && channelReqId === openReqId) {
                            window.location.hash = '';
                        }
                    }
                    return;
                }

                // Обработка handshake: статус «авторизован» + восстановление UI происходят
                // только после auth_ok, не на сыром onopen.
                if (data.type === 'auth_ok') {
                    if (wsConnectionState === 'disconnected') {
                        showConnectionBanner('reconnected');
                        setTimeout(hideConnectionBanner, 2000);
                    }
                    wsConnectionState = 'connected';
                    if (window.__resetReconnect) window.__resetReconnect();
                    handleRouteChange(true);
                    return;
                }
                if (data.type === 'auth_error') {
                    console.error('WS auth_error:', data.message);
                    // access-токен мог истечь — пробуем рефреш и переподключиться.
                    refreshAccessAndReconnectWs();
                    return;
                }

                switch(data.type) {
                    case 'detail_update':
                        if (!detailView.classList.contains('hidden')) {
                           const currentRequestId = window.location.hash.split('/')[2];
                           // если сервер прислал event для конкретной заявки
                           // (data.requestId), убеждаемся что юзер всё ещё на ней.
                           // При быстром переключении A→B detail_update от A
                           // прилетает после смены hash → раньше refreshDynamicContent
                           // делал GET /api/requests/B по newCommentId от A → UI
                           // несоответствие. Теперь дропаем чужие events.
                           if (data.requestId && String(data.requestId) !== String(currentRequestId)) {
                               break;
                           }
                           refreshDynamicContent(currentRequestId, data.newCommentId);
                        }
                        break;
                    case 'list_item_update':
                        if (!listView.classList.contains('hidden')) {
                            updateListItem(data.request);
                        }
                        break;
                    case 'admin_log_update':
                        if (!adminView.classList.contains('hidden') && adminState.currentTab === 'logs') {
                            // Перезапросим текущую страницу — фильтры всё равно учитываются
                            refreshLogsTable();
                        }
                        break;
                    case 'security_alert':
                        handleSecurityAlert(data);
                        break;
                    case 'user_notification':
                        handleUserNotification(data.notification);
                        break;
                    case 'typing': {
                        // фильтр по requestId.
                        // Если юзер копил подписки (баг до этого фикса) или
                        // если в будущем подпишется на >1 заявку — typing с
                        // чужой заявки не должен показываться в текущей.
                        const currentReqId = window.location.hash.startsWith('#/request/')
                            ? window.location.hash.split('/')[2] : null;
                        if (data.requestId && currentReqId && String(data.requestId) !== String(currentReqId)) {
                            break;
                        }
                        showTypingFromOther(data.userId, data.fullName);
                        break;
                    }
                    case 'receipts_updated':
                        if (!detailView.classList.contains('hidden')) {
                            const requestId = window.location.hash.split('/')[2];
                            updateFeeds(requestId);
                        }
                        break;
                }
            };

            globalWs.onclose = () => {
                // Показываем красный баннер. Если соединение восстановится —
                // onopen его перекрасит в зелёный и спрячет.
                wsConnectionState = 'disconnected';
                showConnectionBanner('lost');
                scheduleReconnect();
            };

            globalWs.onerror = (error) => {
                console.error('WebSocket Error:', error);
                globalWs.close();
            };
        }

        /**
         * Reconnect с exponential backoff: задержки 1, 2, 4, 8, 15, 30 секунд,
         * после чего застываем на 30. Если соединение успешно установлено —
         * счётчик сбрасывается. Это снижает нагрузку и на сервер, и на клиента
         * по сравнению со старым «каждые 3 сек навсегда».
         */
        const RECONNECT_DELAYS_MS = [1000, 2000, 4000, 8000, 15000, 30000];
        // circuit-breaker. После CIRCUIT_BREAKER_THRESHOLD
        // подряд провальных попыток (backend down >5 минут) — прекращаем
        // спам и показываем ручную кнопку «Переподключиться». Спасает диск
        // и батарею мобильного клиента, плюс облегчает diagnostic'у.
        // Reset через __resetReconnect (auth_ok после успешного connect).
        const RECONNECT_CIRCUIT_BREAKER_THRESHOLD = 10;
        let reconnectAttempt = 0;
        let reconnectTimer = null;
        // после auth_revoked / flood_detected сервер хочет чтобы мы НЕ
        // переподключались. Без флага onclose спокойно ставит scheduleReconnect
        // → новый WS с null accessToken → 1008 → реконнект-storm.
        //
        // принимаем `reason` для traceability — в DevTools
        // console.warn покажет ПОЧЕМУ disabled (auth_revoked / flood_detected /
        // future causes). Помогает дебажить «почему мой WS не реконнектится».
        let isReconnectDisabled = false;
        window.__disableReconnect = (reason) => {
            isReconnectDisabled = true;
            if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
            if (reason) console.warn('[ws] reconnect disabled:', reason);
        };

        function scheduleReconnect() {
            if (isReconnectDisabled) return;
            if (reconnectTimer) return;
            // circuit-breaker — после N подряд провалов прекращаем
            // backoff и показываем UI-toast с инструкцией.
            if (reconnectAttempt >= RECONNECT_CIRCUIT_BREAKER_THRESHOLD) {
                console.warn(`[ws] circuit-breaker: ${reconnectAttempt} попыток подряд провалились, остановка автореконнекта.`);
                isReconnectDisabled = true;
                // E2/H-4: banner ставим в final state, чтобы он не
                // противоречил toast'у. До фикса banner показывал «Переподключаемся…»
                // вечно, хотя автореконнект отключён.
                showConnectionBanner('failed');
                if (typeof showToast === 'function') {
                    showToast(
                        'Соединение с сервером потеряно. Обновите страницу когда сеть восстановится.',
                        'warning', 0  // 0 = до клика
                    );
                }
                return;
            }
            const delay = RECONNECT_DELAYS_MS[Math.min(reconnectAttempt, RECONNECT_DELAYS_MS.length - 1)];
            reconnectAttempt += 1;
            reconnectTimer = setTimeout(() => {
                reconnectTimer = null;
                connect();
            }, delay);
        }

        // Внутри connect resetReconnect срабатывает при auth_ok ниже.
        // сбрасываем не только attempt-счётчик, но и
        // circuit-breaker флаг (backend проснулся → разрешаем reconnect).
        window.__resetReconnect = () => {
            reconnectAttempt = 0;
            isReconnectDisabled = false;
        };

        connect();
    }

    let wsConnectionState = 'connecting'; // connecting | connected | disconnected

    function showConnectionBanner(state) {
        const banner = document.getElementById('connectionBanner');
        if (!banner) return;
        const text = banner.querySelector('.connection-banner-text');
        if (state === 'reconnected') {
            banner.classList.remove('failed');
            banner.classList.add('reconnected');
            if (text) text.textContent = 'Соединение восстановлено';
        } else if (state === 'failed') {
            // E2/H-4: final state после circuit-breaker.
            // F1/H-3: плюс CSS-класс `.failed` чтобы скрыть
            // spinner — иначе он крутился вечно, противореча тексту
            // «Обновите страницу». Plus красный фон для visual cue.
            banner.classList.remove('reconnected');
            banner.classList.add('failed');
            if (text) text.textContent = 'Соединение потеряно. Обновите страницу когда сеть восстановится.';
        } else {
            banner.classList.remove('reconnected');
            banner.classList.remove('failed');
            if (text) text.textContent = 'Соединение потеряно. Переподключаемся…';
        }
        banner.classList.remove('hidden');
    }

    function hideConnectionBanner() {
        const banner = document.getElementById('connectionBanner');
        if (banner) banner.classList.add('hidden');
    }

    /**
     * Если WS-auth не прошёл (access-токен истёк), пытаемся обновить access
     * через secureFetch (он умеет сам делать /api/refresh-token), потом
     * переподключаемся. Если refresh тоже провалился — secureFetch выкинет на /login.
     */
    async function refreshAccessAndReconnectWs() {
        try {
            const r = await secureFetch('/api/system-constants');
            // secureFetch внутри обновит accessToken при 401.
            if (r.ok && globalWs?.readyState === WebSocket.OPEN) {
                globalWs.send(JSON.stringify({ type: 'auth', token: accessToken }));
            }
        } catch (e) {
            console.error('Не удалось обновить токен для WS:', e);
        }
    }
    
    const handleRouteChange = async (isReconnect = false) => {
        detailViewFiles = [];

        if (commentObserver) { commentObserver.disconnect(); commentObserver = null; }
        if (activityObserver) { activityObserver.disconnect(); activityObserver = null; }
        // Cleanup typing-bar interval — иначе при быстрой навигации между
        // заявками накапливаются «зомби»-таймеры (по 1 сек до следующего тика).
        if (_typingTickInterval) {
            clearInterval(_typingTickInterval);
            _typingTickInterval = null;
        }
        _typingUsers.clear();

        unreadCommentIds.clear();
        unreadActivityIds.clear();

        // prevHash хранится в module-scope (`_prevHash`).
        // Раньше `oldHash = window.location.hash` брал ТЕКУЩИЙ hash (он уже
        // обновился к моменту hashchange-event'а) → unsubscribe слал на тот
        // же канал что и subscribe → старые подписки копились. Юзер,
        // переходивший #/request/31 → #/request/4, оставался подписан на оба
        // и получал typing/broadcasts с обоих.
        const oldHash = _prevHash;
        _prevHash = window.location.hash;   // запоминаем для следующего вызова
        if (globalWs && globalWs.readyState === WebSocket.OPEN) {
             const oldRequestId = oldHash && oldHash.startsWith('#/request/')
                 ? oldHash.split('/')[2] : null;
             if (oldRequestId) globalWs.send(JSON.stringify({ type: 'unsubscribe', channel: `request-${oldRequestId}`}));
             if (oldHash === '#/admin') globalWs.send(JSON.stringify({ type: 'unsubscribe', channel: 'admin-logs' }));
        }

        if (!isReconnect) {
            const activeView = document.querySelector('#listView:not(.hidden), #detailView:not(.hidden), #adminView:not(.hidden)');
            if (activeView) {
                activeView.classList.add('is-fading-out');
            }
            await new Promise(resolve => setTimeout(resolve, 150));
        }

        const hash = window.location.hash;
        const isDetailView = hash.startsWith('#/request/');
        const isAdminView = hash === '#/admin';

        backToListBtn.classList.toggle('is-invisible', !isDetailView && !isAdminView);

        if (isAdminView && user.role === 'Администратор') {
            if (!isReconnect) await renderAdminView();
            if (globalWs && globalWs.readyState === WebSocket.OPEN) {
                globalWs.send(JSON.stringify({ type: 'subscribe', channel: 'admin-logs' }));
            }
        } else if (isDetailView) {
            const requestId = hash.split('/')[2];
            if (!isReconnect) await renderDetailView(requestId);
            if (globalWs && globalWs.readyState === WebSocket.OPEN) {
                 globalWs.send(JSON.stringify({ type: 'subscribe', channel: `request-${requestId}` }));
            }
        } else {
            if (!isReconnect) await renderListView();
        }
        
        if (!isReconnect) {
            const newActiveView = document.querySelector('#listView:not(.hidden), #detailView:not(.hidden), #adminView:not(.hidden)');
            if (newActiveView) {
                newActiveView.classList.remove('is-fading-out');
            }
            document.documentElement.classList.remove('is-loading');
        }
    };

    const renderListView = async () => {
        listView.classList.remove('hidden');
        detailView.classList.add('hidden');
        adminView.classList.add('hidden');
        detailView.innerHTML = '';
        adminView.innerHTML = '';
        listView.classList.add('is-loading-content');
        document.title = 'Заявки — VitEnergo';

        if (!requestsListEl.innerHTML) {
            loadingMessageEl.style.display = 'block';
            loadingMessageEl.textContent = 'Загрузка заявок...';
        }

        document.getElementById('paginationContainer').innerHTML = '';
        switch (user.role) {
            case 'Администратор': listTitleEl.textContent = 'Все заявки'; break;
            case 'Модератор': listTitleEl.textContent = 'Заявки в работе'; break;
            case 'Согласующий': listTitleEl.textContent = 'Заявки на согласование'; break;
            default: listTitleEl.textContent = 'Ваши заявки'; break;
        }

        restoreListState();

        const params = new URLSearchParams({ page: currentPage, pageSize: itemsPerPage });
        if (searchInput.value.trim()) params.append('search', searchInput.value.trim());
        [...statusOptionsContainer.querySelectorAll('input:checked')].forEach(cb => params.append('status', cb.value));
        if (authorOptionsContainer) {
            [...authorOptionsContainer.querySelectorAll('input:checked')].forEach(cb => params.append('authorId', cb.value));
        }
        if (categoryOptionsContainer) {
            [...categoryOptionsContainer.querySelectorAll('input:checked')].forEach(cb => params.append('categoryId', cb.value));
        }
        if (branchOptionsContainer) {
            [...branchOptionsContainer.querySelectorAll('input:checked')].forEach(cb => params.append('branchId', cb.value));
        }
        if (dateCreatedFromInput.value) params.append('createdFrom', dateCreatedFromInput.value);
        if (dateCreatedToInput.value) params.append('createdTo', dateCreatedToInput.value);
        if (dateUpdatedFromInput.value) params.append('updatedFrom', dateUpdatedFromInput.value);
        if (dateUpdatedToInput.value) params.append('updatedTo', dateUpdatedToInput.value);

        try {
            const response = await secureFetch(`/api/requests?${params.toString()}`);
            if (!response.ok) throw new Error('Ошибка сети');
            const { requests, totalItems, uniqueCreators } = await response.json();

            allRequests = requests;
            loadingMessageEl.style.display = 'none';

            if (!isFiltersPopulated) {
                populateFilters(uniqueCreators);
                isFiltersPopulated = true;
                restoreListState();
            }

            updateStatusFilterSelection();
            updateAuthorFilterSelection();
            updateCategoryFilterSelection();
            updateBranchFilterSelection();
            renderRequestListItems(allRequests);
            renderPagination(totalItems);
            updateActiveFilterTags();
            setViewMode(currentViewMode);
        } catch (error) {
            console.error("Ошибка загрузки списка:", error);
            requestsListEl.innerHTML = `<p id="loadingMessage">Ошибка загрузки заявок.</p>`;
        } finally {
            listView.classList.remove('is-loading-content');
        }
    };

    const renderDetailView = async (requestId) => {
        listView.classList.add('hidden');
        detailView.classList.remove('hidden');
        adminView.classList.add('hidden');
        detailView.innerHTML = `<p>Загрузка заявки №${sanitizeAndFormatText(requestId)}...</p>`;
        adminView.innerHTML = '';

        try {
            const [reqRes, documentsRes] = await Promise.all([
                secureFetch(`/api/requests/${requestId}`),
                secureFetch(`/api/requests/${requestId}/documents`)
            ]);

            if (!reqRes.ok) {
                // 404 на /api/requests/:id — заявка либо soft-deleted, либо
                // юзер потерял доступ (soft-delete-user, смена статуса для
                // согласующего). UX: понятный toast + откат на список вместо
                // generic «Не удалось загрузить» + застрявший hash.
                if (reqRes.status === 404) {
                    showToast('Заявка не найдена или была удалена администратором.', 'warning');
                    window.location.hash = '';
                    return;
                }
                throw new Error('Заявка не найдена');
            }
            const request = await reqRes.json();
            currentDocumentsInView = await documentsRes.json();

            // UX: title вкладки = "№ID Заголовок" — нужно при открытии 5 вкладок
            // подряд, чтобы переключаться по Cmd+Tab/Ctrl+Tab.
            const ttl = String(request.title || '').slice(0, 40);
            document.title = `№${request.id} ${ttl} — VitEnergo`;

            if (user.role === 'Согласующий' && request.status_name === 'На согласовании') {
                const storageKey = `viewedRequests_${user.id}`;
                let viewedIds = safeJsonParse(localStorage.getItem(storageKey), []);
                if (!viewedIds.includes(request.id.toString())) {
                    viewedIds.push(request.id.toString());
                    // Soft-cap: храним только последние 500 id'шников. За год
                    // согласующий смотрит ~300 заявок — массив рос без лимита.
                    if (viewedIds.length > 500) viewedIds = viewedIds.slice(-500);
                    safeStorageSet(localStorage, storageKey, JSON.stringify(viewedIds));
                }
            }
            // Авто-смена статуса при просмотре убрана:
            // у модератора в actions-блоке есть явная кнопка «Взять в работу».
            // Открытие карточки больше не приводит к смене статуса заявки.

            const displayStatus = getDisplayStatus(request.status_name, request.creator_id, request.id);
            const statusClass = displayStatus.replace(/ /g, '-').toLowerCase();

            detailView.innerHTML = `
                <div class="detail-grid">
                    <div class="detail-main-column">
                        <div class="detail-main-content">
                            <h3>№${request.id} ${sanitizeAndFormatText(request.title)}</h3>
                            <p>${sanitizeAndFormatText(request.description) || 'Описание отсутствует.'}</p>
                        </div>
                        <div id="documentsContainer">${renderDocumentsBlock(currentDocumentsInView, request.creator_id, request.status_name)}</div>
                    </div>
                    <div class="detail-sidebar">
                        <div class="sidebar-block">
                            <h4>Информация</h4>
                            <div class="info-grid">
                                <span>Статус:</span><div class="status-badge status-${statusClass}">${displayStatus}</div>
                                ${request.category_name ? (() => { const cc = safeColor(request.category_color); return `<span>Категория:</span><span class="category-badge" style="background-color: ${cc}22; color: ${cc}; border: 1px solid ${cc}55;">${sanitizeAndFormatText(request.category_name)}</span>`; })() : ''}
                                <span>Автор:</span><span>${sanitizeAndFormatText(request.creator_name)}</span>
                                ${request.branch_name ? `<span>Филиал:</span><span>${sanitizeAndFormatText(request.branch_name)}</span>` : ''}
                                <span>Создана:</span><span>${formatDateTime(request.created_at)}</span>
                                <span>Мероприятие:</span><span>${formatDateTime(request.planned_date)}</span>
                                ${request.location ? `<span>Место:</span><span>${sanitizeAndFormatText(request.location)}</span>` : ''}
                                ${request.responsible_person ? `<span>Ответственный:</span><span>${sanitizeAndFormatText(request.responsible_person)}</span>` : ''}
                                ${request.expected_attendees ? `<span>Участников:</span><span>${request.expected_attendees}</span>` : ''}
                            </div>
                            ${(() => {
                                const pdfCfg = getPdfProtocolConfig(request);
                                if (!pdfCfg.visible) return '';
                                const draftCls = pdfCfg.isDraft ? ' btn-print-pdf-draft' : '';
                                const draftBadge = pdfCfg.isDraft
                                    ? '<span class="pdf-draft-tag">черновик</span>'
                                    : '';
                                return `
                            <button class="btn-print-pdf${draftCls}" data-request-id="${request.id}" title="${escapeAttr(pdfCfg.hint)}">
                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>
                                <span>${escapeAttr(pdfCfg.label)}</span>${draftBadge}
                            </button>`;
                            })()}
                        </div>
                        <div id="actionsContainer">${renderActionsBlock(request)}</div>
                        <div class="sidebar-block">
                            <div class="view-switcher">
                                <button class="switcher-btn active" data-view="activity">Лента событий</button>
                                <button class="switcher-btn" data-view="chat">Чат</button>
                            </div>
                            <div id="activityPane" class="activity-pane active-pane">
                                <div class="activity-feed"></div>
                            </div>
                            <div id="chatPane" class="chat-pane">
                                <div class="chat-feed"></div>
                                <form id="commentForm" class="comment-form">
                                    <div id="replyPreview" class="reply-preview hidden">
                                        <span class="reply-preview-text">Ответ на сообщение</span>
                                        <button type="button" class="reply-preview-close" title="Отменить" aria-label="Отменить ответ на сообщение">×</button>
                                    </div>
                                    <textarea name="comment_text" placeholder="Написать комментарий..." required></textarea>
                                    <button type="submit" class="btn-main">Отправить</button>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>`;

            const activityFeed = detailView.querySelector('.activity-feed');
            const chatFeed = detailView.querySelector('.chat-feed');

            activityObserver = setupIntersectionObserver(activityFeed, unreadActivityIds, 'activity');
            commentObserver = setupIntersectionObserver(chatFeed, unreadCommentIds, 'chat');

            await updateFeeds(requestId, true);

            const savedState = safeJsonParse(sessionStorage.getItem(`detailState_${requestId}`));
            if (savedState) {
                const sidebarBlock = detailView.querySelector('.view-switcher')?.closest('.sidebar-block');
                // Whitelist: activeTab подставляется в querySelector — без
                // валидации можно пробросить `]` или ` *` и поломать DOM-запрос
                // (если кто-то подмутил sessionStorage через DevTools).
                const TAB_WHITELIST = ['activity', 'chat'];
                const safeTab = TAB_WHITELIST.includes(savedState.activeTab) ? savedState.activeTab : null;
                if (sidebarBlock && safeTab && safeTab !== 'activity') {
                    sidebarBlock.querySelector('.switcher-btn.active')?.classList.remove('active');
                    sidebarBlock.querySelector('.activity-pane.active-pane')?.classList.remove('active-pane');
                    sidebarBlock.querySelector(`[data-view="${safeTab}"]`)?.classList.add('active');
                    sidebarBlock.querySelector(`#${safeTab}Pane`)?.classList.add('active-pane');
                }
                setTimeout(() => {
                    const descriptionEl = detailView.querySelector('.detail-main-content p');
                    if (descriptionEl) descriptionEl.scrollTop = savedState.descriptionScroll || 0;
                    const docsEl = detailView.querySelector('.document-sublist');
                    if (docsEl) docsEl.scrollTop = savedState.docsScroll || 0;
                    const activityFeedEl = detailView.querySelector('.activity-feed');
                    if (activityFeedEl) activityFeedEl.scrollTop = savedState.activityScroll || 0;
                    const chatFeedEl = detailView.querySelector('.chat-feed');
                    if (chatFeedEl && unreadCommentIds.size === 0) {
                        chatFeedEl.scrollTop = savedState.chatScroll || 0;
                    }
                    window.scrollTo(0, savedState.scrollY || 0);
                }, 0);
                clearState('detail', requestId);
            }
        } catch (error) {
            console.error(error);
            detailView.innerHTML = `<p>Не удалось загрузить данные заявки.</p>`;
        }
    };

    /* =========================================================================
       Центр администрирования — 4 вкладки:
         summary  — KPI безопасности и live-feed
         logs     — журнал событий с расширенной фильтрацией
         users    — управление пользователями + security-state
         files    — файловый аудит (FileUploadAttempts)
       ========================================================================= */
    const adminState = {
        currentTab: sessionStorage.getItem('adminTab') || 'summary',
        users: [], roles: [], branches: [],
        logs: [], totalLogs: 0, logsPage: 1,
        logsFilters: { actions: [], userIds: [], dateFrom: '', dateTo: '', search: '' },
        eventTypes: [],
        attempts: [], totalAttempts: 0, attemptsPage: 1,
        attemptsFilters: { severity: 'all', wasClean: 'all', search: '' },
        summary: null,
        unreadAlerts: 0
    };

    const renderAdminView = async () => {
        listView.classList.add('hidden');
        detailView.classList.add('hidden');
        adminView.classList.remove('hidden');
        document.title = 'Админ-центр — VitEnergo';

        if (adminState.users.length === 0) {
            const [rolesRes, branchesRes] = await Promise.all([
                secureFetch('/api/roles'),
                secureFetch('/api/branches')
            ]);
            adminState.roles    = await rolesRes.json();
            adminState.branches = await branchesRes.json();
        }

        adminView.innerHTML = `
            <div class="admin-tabs-bar">
                <button class="admin-tab-btn" data-tab="summary">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
                    Сводка
                </button>
                <button class="admin-tab-btn" data-tab="logs">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
                    Журнал событий
                </button>
                <button class="admin-tab-btn" data-tab="users">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
                    Пользователи
                </button>
                <button class="admin-tab-btn" data-tab="files">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
                    Файловый аудит
                </button>
                <button class="admin-tab-btn" data-tab="categories">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/><line x1="7" y1="7" x2="7.01" y2="7"/></svg>
                    Категории
                </button>
                <button class="admin-tab-btn" data-tab="pii">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
                    ПДн-аудит
                </button>
            </div>
            <div id="admin-tab-content"></div>`;

        adminView.querySelectorAll('.admin-tab-btn').forEach(btn => {
            btn.addEventListener('click', () => switchAdminTab(btn.dataset.tab));
        });

        await switchAdminTab(adminState.currentTab);
    };

    async function switchAdminTab(tabName) {
        adminState.currentTab = tabName;
        safeStorageSet(sessionStorage, 'adminTab', tabName);
        adminView.querySelectorAll('.admin-tab-btn').forEach(b =>
            b.classList.toggle('active', b.dataset.tab === tabName)
        );
        const content = document.getElementById('admin-tab-content');
        if (!content) return;
        content.innerHTML = '<div class="admin-loading">Загрузка…</div>';
        try {
            if (tabName === 'summary')      await renderSummaryTab(content);
            else if (tabName === 'logs')    await renderLogsTab(content);
            else if (tabName === 'users')   await renderUsersTab(content);
            else if (tabName === 'files')   await renderFilesTab(content);
            else if (tabName === 'categories') await renderCategoriesTab(content);
            else if (tabName === 'pii')        await renderPiiAuditTab(content);
        } catch (e) {
            console.error('Ошибка вкладки админки:', e);
            content.innerHTML = '<p class="admin-error">Не удалось загрузить раздел</p>';
        }
    }

    /* ----- Вкладка «Сводка» ----- */
    async function renderSummaryTab(container) {
        const res = await secureFetch('/api/admin/security-summary');
        if (!res.ok) throw new Error('summary');
        const data = await res.json();
        adminState.summary = data;
        const k = data.kpi;

        container.innerHTML = `
            <div class="admin-summary-grid">
                <div class="admin-kpi-card kpi-blue">
                    <div class="kpi-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/></svg></div>
                    <div><div class="kpi-value">${k.total_users}</div><div class="kpi-label">Всего пользователей</div></div>
                </div>
                <div class="admin-kpi-card kpi-green">
                    <div class="kpi-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg></div>
                    <div><div class="kpi-value">${k.active_users}</div><div class="kpi-label">Активных</div></div>
                </div>
                <div class="admin-kpi-card kpi-orange">
                    <div class="kpi-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg></div>
                    <div><div class="kpi-value">${k.temp_locked}</div><div class="kpi-label">Заблокированы временно</div></div>
                </div>
                <div class="admin-kpi-card kpi-red">
                    <div class="kpi-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></div>
                    <div><div class="kpi-value">${k.hard_locked}</div><div class="kpi-label">Заблокированы постоянно</div></div>
                </div>
                <div class="admin-kpi-card kpi-violet">
                    <div class="kpi-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg></div>
                    <div><div class="kpi-value">${k.violations_24h}</div><div class="kpi-label">Нарушений за 24ч <span class="kpi-sub">(7д: ${k.violations_7d})</span></div></div>
                </div>
                <div class="admin-kpi-card kpi-cyan">
                    <div class="kpi-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg></div>
                    <div><div class="kpi-value">${k.uploads_24h}</div><div class="kpi-label">Попыток загрузки за 24ч</div></div>
                </div>
            </div>
            <div class="admin-quick-actions">
                <button type="button" class="btn-secondary" id="openSwaggerBtn" title="OpenAPI 3.0 документация всех эндпоинтов">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
                    <span>API-документация (Swagger)</span>
                </button>
                <a href="/events" target="_blank" rel="noopener" class="btn-secondary" title="Публичная витрина одобренных мероприятий">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>
                    <span>Публичная витрина /events</span>
                </a>
            </div>
            <div class="admin-summary-feed">
                <h3 class="admin-section-title">
                    <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>
                    Последние события безопасности
                </h3>
                <div id="adminLiveFeed" class="admin-feed">
                    ${data.recentAlerts.length === 0
                        ? '<p class="admin-feed-empty">Алертов безопасности нет — система спокойна.</p>'
                        : data.recentAlerts.map(renderAlertItem).join('')}
                </div>
            </div>`;

        adminState.unreadAlerts = 0;
        updateBellBadge();

        // Открытие Swagger UI: сначала просим сервер выдать docs-cookie,
        // потом открываем /api-docs/ в новой вкладке.
        const swaggerBtn = document.getElementById('openSwaggerBtn');
        if (swaggerBtn) {
            swaggerBtn.addEventListener('click', async () => {
                swaggerBtn.disabled = true;
                try {
                    const r = await secureFetch('/api/admin/api-docs-session', { method: 'POST' });
                    if (!r.ok) throw new Error('session');
                    window.open('/api-docs/', '_blank', 'noopener');
                    showToast('Swagger UI открыт в новой вкладке (доступ 10 мин)', 'success', 5000);
                } catch (e) {
                    showToast('Не удалось открыть Swagger UI', 'error');
                } finally {
                    swaggerBtn.disabled = false;
                }
            });
        }
    }

    function renderAlertItem(alert) {
        const time = new Date(alert.attempted_at).toLocaleString('ru-RU');
        const severity = alert.reason && alert.reason.startsWith('[high/') ? 'high' :
                         alert.reason && alert.reason.startsWith('[medium/') ? 'medium' : 'low';
        return `
            <div class="admin-alert admin-alert-${severity}">
                <div class="admin-alert-time">${time}</div>
                <div class="admin-alert-body">
                    <div class="admin-alert-user">${sanitizeAndFormatText(alert.user_name)} <span class="admin-alert-ip">${sanitizeAndFormatText(alert.ip_address || '?')}</span></div>
                    <div class="admin-alert-file">📎 ${sanitizeAndFormatText(alert.file_name)}</div>
                    <div class="admin-alert-reason">${sanitizeAndFormatText(alert.reason || '')}</div>
                </div>
            </div>`;
    }

    /* ----- Вкладка «Журнал событий» ----- */
    async function renderLogsTab(container) {
        if (adminState.eventTypes.length === 0) {
            const r = await secureFetch('/api/admin/log-event-types');
            adminState.eventTypes = await r.json();
        }
        if (adminState.users.length === 0) {
            const r = await secureFetch('/api/admin/users');
            adminState.users = await r.json();
        }

        const filters = adminState.logsFilters;
        container.innerHTML = `
            <div class="admin-filters-bar">
                <div class="admin-filter-group">
                    <label>Тип события</label>
                    <div class="custom-multiselect admin-multiselect" id="logTypeMs">
                        <div class="select-box"><span id="logTypeLabel">${filters.actions.length ? `Выбрано: ${filters.actions.length}` : 'Все типы'}</span><svg class="arrow" viewBox="0 0 20 20" fill="currentColor"><path d="M5.29 7.29a1 1 0 011.42 0L10 10.59l3.29-3.3a1 1 0 111.42 1.42l-4 4a1 1 0 01-1.42 0l-4-4a1 1 0 010-1.42z"/></svg></div>
                        <div class="multiselect-dropdown">
                            <div class="multiselect-options" id="logTypeOptions">
                                ${adminState.eventTypes.map(t => `
                                    <label><input type="checkbox" value="${escapeAttr(t.name)}" ${filters.actions.includes(t.name) ? 'checked' : ''}><span class="custom-checkbox"></span><span>${sanitizeAndFormatText(t.name)} <span class="ms-count">${t.qty}</span></span></label>
                                `).join('')}
                            </div>
                        </div>
                    </div>
                </div>
                <div class="admin-filter-group">
                    <label>Период</label>
                    <div class="admin-date-range">
                        <input type="date" id="logDateFrom" value="${filters.dateFrom || ''}">
                        <span>—</span>
                        <input type="date" id="logDateTo" value="${filters.dateTo || ''}">
                    </div>
                </div>
                <div class="admin-filter-group admin-filter-grow">
                    <label>Поиск по описанию</label>
                    <input type="text" id="logSearch" placeholder="Например: calc.pdf или IP" value="${escapeAttr(filters.search || '')}">
                </div>
                <div class="admin-filter-actions">
                    <button class="btn-secondary" id="logFiltersReset">Сбросить</button>
                </div>
            </div>
            <div class="admin-table-wrap">
                <div class="admin-table-meta" id="logsMeta">Загрузка…</div>
                <table class="admin-table log-table">
                    <thead><tr><th>Время</th><th>Пользователь</th><th>Событие</th><th>Детали</th><th>Заявка</th></tr></thead>
                    <tbody id="logsTbody"></tbody>
                </table>
                <div class="admin-pagination-container" id="logsPagination"></div>
            </div>`;

        // events
        bindMultiselect('logTypeMs', () => {
            filters.actions = [...container.querySelectorAll('#logTypeOptions input:checked')].map(c => c.value);
            container.querySelector('#logTypeLabel').textContent = filters.actions.length ? `Выбрано: ${filters.actions.length}` : 'Все типы';
            adminState.logsPage = 1;
            refreshLogsTable();
        });
        container.querySelector('#logDateFrom').addEventListener('change', e => { filters.dateFrom = e.target.value; adminState.logsPage = 1; refreshLogsTable(); });
        container.querySelector('#logDateTo').addEventListener('change',   e => { filters.dateTo   = e.target.value; adminState.logsPage = 1; refreshLogsTable(); });

        let searchTimer;
        container.querySelector('#logSearch').addEventListener('input', e => {
            filters.search = e.target.value;
            clearTimeout(searchTimer);
            searchTimer = setTimeout(() => { adminState.logsPage = 1; refreshLogsTable(); }, 300);
        });
        container.querySelector('#logFiltersReset').addEventListener('click', () => {
            adminState.logsFilters = { actions: [], userIds: [], dateFrom: '', dateTo: '', search: '' };
            adminState.logsPage = 1;
            switchAdminTab('logs');
        });

        await refreshLogsTable();
    }

    async function refreshLogsTable() {
        const f = adminState.logsFilters;
        const params = new URLSearchParams({ page: adminState.logsPage, pageSize: 50 });
        f.actions.forEach(a => params.append('action', a));
        f.userIds.forEach(id => params.append('userId', id));
        if (f.dateFrom) params.append('dateFrom', f.dateFrom);
        if (f.dateTo) {
            const dt = new Date(f.dateTo); dt.setHours(23, 59, 59);
            params.append('dateTo', dt.toISOString());
        }
        if (f.search) params.append('search', f.search);

        const r = await secureFetch(`/api/admin/logs?${params}`);
        const d = await r.json();
        adminState.logs = d.logs;
        adminState.totalLogs = d.totalItems;

        const tbody = document.getElementById('logsTbody');
        const meta  = document.getElementById('logsMeta');
        if (!tbody) return;

        meta.textContent = `Найдено: ${d.totalItems} записей`;
        tbody.innerHTML = d.logs.length === 0
            ? `<tr><td colspan="5" class="admin-empty">Записей не найдено</td></tr>`
            : d.logs.map(renderLogRow).join('');

        const pag = document.getElementById('logsPagination');
        pag.innerHTML = renderAdminPagination(d.totalItems, adminState.logsPage, 'logs');
        pag.querySelectorAll('.page-item').forEach(b => b.addEventListener('click', () => {
            const p = parseInt(b.dataset.page, 10);
            if (!isNaN(p) && p > 0) { adminState.logsPage = p; refreshLogsTable(); }
        }));
    }

    function renderLogRow(log) {
        const cls = log.event_type.replace(/[ /]/g, '-').toLowerCase();
        const isSecurity = ['Опасный файл отклонён', 'Нарушение безопасности', 'Временная блокировка', 'Постоянная блокировка', 'Неудачный вход', 'Снятие блокировки'].includes(log.event_type);
        return `
            <tr class="${isSecurity ? 'log-row-security' : ''}">
                <td class="log-time">${new Date(log.event_time).toLocaleString('ru-RU')}</td>
                <td>${sanitizeAndFormatText(log.user_name) || 'Система'}</td>
                <td><span class="log-type log-type-${cls}">${sanitizeAndFormatText(log.event_type)}</span></td>
                <td class="details-cell">${sanitizeAndFormatText(log.details) || '-'}</td>
                <td class="request-id-cell">${log.request_id ? `<a href="#/request/${log.request_id}">№${log.request_id}</a>` : '-'}</td>
            </tr>`;
    }

    /* ----- Вкладка «Пользователи» ----- */
    async function renderUsersTab(container) {
        const r = await secureFetch('/api/admin/users');
        adminState.users = await r.json();

        const adminRole = adminState.roles.find(rr => rr.name === 'Администратор');
        const adminRoleId = adminRole ? adminRole.id : -1;

        container.innerHTML = `
            <div class="admin-toolbar">
                <button class="btn-main btn-create-user" id="btnCreateUser">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                    Создать пользователя
                </button>
            </div>
            <div class="admin-table-wrap">
                <table class="admin-table users-table">
                    <thead><tr><th>ID</th><th>ФИО</th><th>Email</th><th>Роль</th><th>Филиал</th><th>Безопасность</th><th>Активен</th><th>Действие</th></tr></thead>
                    <tbody>
                        ${adminState.users.map(u => renderUserRow(u, adminState.roles, adminState.branches, adminRoleId)).join('')}
                    </tbody>
                </table>
            </div>`;

        document.getElementById('btnCreateUser')?.addEventListener('click', openCreateUserModal);
    }

    function openCreateUserModal() {
        const adminRole = adminState.roles.find(rr => rr.name === 'Администратор');
        const adminRoleId = adminRole ? adminRole.id : -1;

        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay active';
        overlay.id = 'createUserOverlay';
        overlay.innerHTML = `
            <div class="modal-content modal-create" style="max-width: 540px;">
                <form id="createUserForm" novalidate autocomplete="off">
                    <header class="modal-header">
                        <div class="modal-header-text">
                            <h2 class="modal-title">Создание учётной записи</h2>
                            <p class="modal-subtitle">Учётная запись будет создана в активном состоянии. Пользователю необходимо передать логин и пароль через защищённый канал.</p>
                        </div>
                        <button type="button" class="modal-close-btn" id="cuClose" aria-label="Закрыть">
                            <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                        </button>
                    </header>
                    <div class="modal-body">
                        <section class="form-section">
                            <div class="input-group">
                                <label for="cu_fio" class="field-label">ФИО <span class="req-marker">*</span></label>
                                <input type="text" id="cu_fio" name="fio" required placeholder="Иванов Иван Иванович" maxlength="200">
                                <div class="form-error-message"></div>
                            </div>
                            <div class="input-row">
                                <div class="input-group">
                                    <label for="cu_email" class="field-label">Корпоративная почта <span class="req-marker">*</span></label>
                                    <input type="email" id="cu_email" name="email" required placeholder="i.ivanov@vitebskenergo.by" maxlength="200">
                                    <div class="form-error-message"></div>
                                </div>
                                <div class="input-group">
                                    <label for="cu_role" class="field-label">Роль <span class="req-marker">*</span></label>
                                    <select id="cu_role" name="role_id" required>
                                        ${adminState.roles.filter(r => r.id !== adminRoleId).map(r =>
                                            `<option value="${r.id}" ${r.name === 'Сотрудник' ? 'selected' : ''}>${sanitizeAndFormatText(r.name)}</option>`
                                        ).join('')}
                                    </select>
                                </div>
                            </div>
                            <div class="input-group">
                                <label for="cu_branch" class="field-label">Филиал</label>
                                <select id="cu_branch" name="branch_id">
                                    <option value="">— не указан (центральный аппарат) —</option>
                                    ${adminState.branches.map(b => `<option value="${b.id}">${sanitizeAndFormatText(b.name)}</option>`).join('')}
                                </select>
                            </div>
                            <div class="input-group">
                                <label for="cu_password" class="field-label">Временный пароль <span class="req-marker">*</span></label>
                                <input type="text" id="cu_password" name="password" required placeholder="Минимум 10 символов: буквы, цифры, спецсимвол" minlength="10">
                                <div class="form-error-message"></div>
                                <button type="button" class="btn-secondary btn-gen-password" id="cuGenPwd" style="margin-top:8px;font-size:12px;height:32px;padding:0 12px;">Сгенерировать пароль</button>
                            </div>
                        </section>
                        <div id="cuError" class="server-message error"></div>
                    </div>
                    <footer class="modal-actions">
                        <button type="button" class="btn-secondary" id="cuCancel">Отмена</button>
                        <button type="submit" class="btn-main">Создать</button>
                    </footer>
                </form>
            </div>`;
        document.body.appendChild(overlay);
        setupModalA11y(overlay);

        const close = () => overlay.remove();
        document.getElementById('cuClose').addEventListener('click', close);
        document.getElementById('cuCancel').addEventListener('click', close);
        overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });

        // Генератор пароля: длина 14, гарантированно содержит требуемые группы
        document.getElementById('cuGenPwd').addEventListener('click', () => {
            const u = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
            const l = 'abcdefghjkmnpqrstuvwxyz';
            const d = '23456789';
            const s = '@$!%*#?&';
            const all = u + l + d + s;
            const pick = (set) => set[Math.floor(Math.random() * set.length)];
            let arr = [pick(u), pick(l), pick(d), pick(s)];
            for (let i = 0; i < 10; i++) arr.push(pick(all));
            arr = arr.sort(() => Math.random() - 0.5);
            const pwd = arr.join('');
            const input = document.getElementById('cu_password');
            input.type = 'text';
            input.value = pwd;
        });

        document.getElementById('createUserForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const errBox = document.getElementById('cuError');
            errBox.textContent = '';
            errBox.classList.remove('visible');

            const fd = new FormData(e.target);
            const data = Object.fromEntries(fd.entries());
            data.login = data.email; // login = email по умолчанию

            const submitBtn = e.target.querySelector('button[type="submit"]');
            submitBtn.disabled = true;
            submitBtn.textContent = 'Создание...';

            try {
                const r = await secureFetch('/api/admin/users', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                if (!r.ok) {
                    const err = await r.json();
                    errBox.textContent = err.message || 'Ошибка создания';
                    errBox.classList.add('visible');
                    showToast(err.message || 'Ошибка создания пользователя', 'error');
                } else {
                    showToast('Пользователь создан. Передайте логин и пароль по защищённому каналу.', 'success', 8000);
                    close();
                    if (adminState.currentTab === 'users') {
                        renderUsersTab(document.getElementById('admin-tab-content'));
                    }
                }
            } catch (err) {
                errBox.textContent = 'Ошибка сети';
                errBox.classList.add('visible');
            } finally {
                submitBtn.disabled = false;
                submitBtn.textContent = 'Создать';
            }
        });
    }

    function renderUserRow(u, roles, branches, adminRoleId) {
        const isUserAdmin = u.role_id === adminRoleId;
        const isSelf = u.id === user.id;
        let secCell;
        if (!u.is_active) {
            secCell = `<span class="sec-badge sec-hard">⛔ Заблокирован</span>`;
        } else if (u.locked_until && new Date(u.locked_until) > new Date()) {
            const until = new Date(u.locked_until).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
            secCell = `<span class="sec-badge sec-temp">🔒 До ${until}</span> <button class="btn-unlock" data-unlock="${u.id}" title="Снять блокировку" aria-label="Снять блокировку с пользователя">×</button>`;
        } else if (u.violations_24h > 0) {
            secCell = `<span class="sec-badge sec-warn">⚠ ${u.violations_24h} за 24ч</span>`;
        } else {
            secCell = `<span class="sec-badge sec-ok">✓ OK</span>`;
        }

        // ФИО и email — редактируемые input'ы (кроме админа: его профиль не меняем через UI).
        const fioCell = isUserAdmin
            ? `<span>${sanitizeAndFormatText(u.full_name)}</span>`
            : `<input type="text" class="cell-input fio-input" data-original-value="${escapeAttr(u.full_name)}" value="${escapeAttr(u.full_name)}" maxlength="200">`;
        const emailCell = isUserAdmin
            ? `<span>${sanitizeAndFormatText(u.email)}</span>`
            : `<input type="email" class="cell-input email-input" data-original-value="${escapeAttr(u.email)}" value="${escapeAttr(u.email)}" maxlength="200">`;

        // убираем inline-стили — теперь все 3 кнопки
        // (Сохранить / Сбросить пароль / Удалить) в одной строке через
        // `.user-row-actions` с равной высотой 32px (см. dashboard.css).
        const resetBtn = (!isUserAdmin && !isSelf)
            ? `<button class="btn-row-action btn-reset-pwd" data-reset-pwd="${u.id}" title="Сбросить пароль и выгнать пользователя со всех устройств">Сбросить пароль</button>`
            : '';
        const deleteBtn = (!isUserAdmin && !isSelf)
            ? `<button class="btn-row-action btn-row-danger btn-user-delete" data-user-delete="${u.id}" data-user-name="${escapeAttr(u.full_name)}" title="Удалить (soft-delete: данные сохраняются)">Удалить</button>`
            : '';

        return `
            <tr data-user-id="${u.id}">
                <td><span class="user-id-cell">#${u.id}</span></td>
                <td>${fioCell}</td>
                <td>${emailCell}</td>
                <td>
                    <select class="role-select" data-original-value="${u.role_id}" ${isUserAdmin || isSelf ? 'disabled' : ''}>
                        ${roles.map(r => `<option value="${r.id}" ${u.role_id === r.id ? 'selected' : ''} ${r.id === adminRoleId ? 'disabled' : ''}>${sanitizeAndFormatText(r.name)}</option>`).join('')}
                    </select>
                </td>
                <td>
                    <select class="branch-select" data-original-value="${u.branch_id || ''}">
                        <option value="">- Не указан -</option>
                        ${branches.map(b => `<option value="${b.id}" ${u.branch_id === b.id ? 'selected' : ''}>${sanitizeAndFormatText(b.name)}</option>`).join('')}
                    </select>
                </td>
                <td class="sec-cell">${secCell}</td>
                <td>
                    <label class="toggle-switch">
                        <input type="checkbox" class="status-toggle" data-original-value="${u.is_active}" ${u.is_active ? 'checked' : ''} ${isSelf ? 'disabled' : ''}>
                        <span class="slider"></span>
                    </label>
                </td>
                <td>
                    <div class="user-row-actions">
                        <button class="btn-row-action btn-row-save btn-save" disabled>Сохранить</button>
                        ${resetBtn}
                        ${deleteBtn}
                    </div>
                </td>
            </tr>`;
    }

    /* ----- Вкладка «Файловый аудит» ----- */
    async function renderFilesTab(container) {
        const f = adminState.attemptsFilters;
        container.innerHTML = `
            <div class="admin-filters-bar">
                <div class="admin-filter-group">
                    <label>Уровень</label>
                    <select id="attSeverity">
                        <option value="all" ${f.severity === 'all' ? 'selected' : ''}>Все</option>
                        <option value="soft" ${f.severity === 'soft' ? 'selected' : ''}>Soft (формат не поддерживается)</option>
                        <option value="medium" ${f.severity === 'medium' ? 'selected' : ''}>Medium (mismatch)</option>
                        <option value="high" ${f.severity === 'high' ? 'selected' : ''}>High (опасный файл)</option>
                    </select>
                </div>
                <div class="admin-filter-group">
                    <label>Результат</label>
                    <select id="attClean">
                        <option value="all" ${f.wasClean === 'all' ? 'selected' : ''}>Все</option>
                        <option value="true" ${f.wasClean === 'true' ? 'selected' : ''}>Принят</option>
                        <option value="false" ${f.wasClean === 'false' ? 'selected' : ''}>Отклонён</option>
                    </select>
                </div>
                <div class="admin-filter-group admin-filter-grow">
                    <label>Поиск по имени файла или причине</label>
                    <input type="text" id="attSearch" placeholder="Например: .exe или mime_mismatch" value="${escapeAttr(f.search || '')}">
                </div>
                <div class="admin-filter-actions">
                    <button class="btn-secondary" id="attReset">Сбросить</button>
                </div>
            </div>
            <div class="admin-table-wrap">
                <div class="admin-table-meta" id="attMeta">Загрузка…</div>
                <table class="admin-table att-table">
                    <thead><tr><th>Время</th><th>Пользователь</th><th>IP</th><th>Файл</th><th>Заявленный MIME</th><th>Реальный MIME</th><th>Статус</th><th>Причина</th></tr></thead>
                    <tbody id="attTbody"></tbody>
                </table>
                <div class="admin-pagination-container" id="attPagination"></div>
            </div>`;

        container.querySelector('#attSeverity').addEventListener('change', e => { f.severity = e.target.value; adminState.attemptsPage = 1; refreshAttempts(); });
        container.querySelector('#attClean').addEventListener('change',    e => { f.wasClean = e.target.value; adminState.attemptsPage = 1; refreshAttempts(); });
        let t;
        container.querySelector('#attSearch').addEventListener('input', e => {
            f.search = e.target.value; clearTimeout(t);
            t = setTimeout(() => { adminState.attemptsPage = 1; refreshAttempts(); }, 300);
        });
        container.querySelector('#attReset').addEventListener('click', () => {
            adminState.attemptsFilters = { severity: 'all', wasClean: 'all', search: '' };
            adminState.attemptsPage = 1;
            switchAdminTab('files');
        });

        await refreshAttempts();
    }

    async function refreshAttempts() {
        const f = adminState.attemptsFilters;
        const params = new URLSearchParams({ page: adminState.attemptsPage, pageSize: 50 });
        if (f.severity !== 'all') params.append('severity', f.severity);
        if (f.wasClean  !== 'all') params.append('wasClean', f.wasClean);
        if (f.search) params.append('search', f.search);

        const r = await secureFetch(`/api/admin/file-attempts?${params}`);
        const d = await r.json();
        adminState.attempts = d.attempts;
        adminState.totalAttempts = d.totalItems;

        const tbody = document.getElementById('attTbody');
        const meta  = document.getElementById('attMeta');
        if (!tbody) return;
        meta.textContent = `Найдено: ${d.totalItems} попыток загрузки`;
        tbody.innerHTML = d.attempts.length === 0
            ? `<tr><td colspan="8" class="admin-empty">Попыток не найдено</td></tr>`
            : d.attempts.map(renderAttemptRow).join('');

        const pag = document.getElementById('attPagination');
        pag.innerHTML = renderAdminPagination(d.totalItems, adminState.attemptsPage, 'att');
        pag.querySelectorAll('.page-item').forEach(b => b.addEventListener('click', () => {
            const p = parseInt(b.dataset.page, 10);
            if (!isNaN(p) && p > 0) { adminState.attemptsPage = p; refreshAttempts(); }
        }));
    }

    /* ----- Вкладка «Категории» ----- */

    /* ----- Вкладка «ПДн-аудит» (compliance закон РБ №99-З) ----- */
    async function renderPiiAuditTab(container) {
        // UI: дисклеймер про №99-З убран по запросу.
        container.innerHTML = `
            <div class="admin-table-wrap">
                <div class="admin-table-meta" id="piiMeta">Загрузка…</div>
                <table class="admin-table">
                    <thead>
                        <tr>
                            <th>Время</th>
                            <th>Кто смотрел</th>
                            <th>Действие</th>
                            <th>Цель</th>
                            <th>IP</th>
                            <th>Доп.</th>
                        </tr>
                    </thead>
                    <tbody id="piiTbody"></tbody>
                </table>
                <div class="admin-pagination-container" id="piiPagination"></div>
            </div>`;

        await refreshPiiAudit(1);
    }

    async function refreshPiiAudit(page) {
        const r = await secureFetch(`/api/admin/pii-audit?page=${page}&pageSize=50`);
        const d = await r.json();
        const tbody = document.getElementById('piiTbody');
        const meta  = document.getElementById('piiMeta');
        if (!tbody) return;
        meta.textContent = `Найдено: ${d.totalItems} записей`;

        const ACTION_LABELS = {
            list_users:        'Просмотр списка пользователей',
            view_file_attempts:'Просмотр файлового аудита',
            update_user:       'Изменение данных пользователя',
            download_document: 'Скачивание документа'
        };
        tbody.innerHTML = d.items.length === 0
            ? '<tr><td colspan="6" class="admin-empty">Записей нет</td></tr>'
            : d.items.map(a => `
                <tr>
                    <td class="log-time">${new Date(a.accessed_at).toLocaleString('ru-RU')}</td>
                    <td>${sanitizeAndFormatText(a.user_name || `id=${a.user_id}`)}</td>
                    <td>${sanitizeAndFormatText(ACTION_LABELS[a.action] || a.action)}</td>
                    <td>${a.target_type || '—'}${a.target_id ? ` #${a.target_id}` : ''}</td>
                    <td><code>${sanitizeAndFormatText(a.ip_address || '—')}</code></td>
                    <td class="details-cell">${sanitizeAndFormatText(a.extra_meta || '—')}</td>
                </tr>`).join('');

        const pag = document.getElementById('piiPagination');
        pag.innerHTML = renderAdminPagination(d.totalItems, page, 'pii');
        pag.querySelectorAll('.page-item').forEach(b => b.addEventListener('click', () => {
            const p = parseInt(b.dataset.page, 10);
            if (!isNaN(p) && p > 0) refreshPiiAudit(p);
        }));
    }

    async function renderCategoriesTab(container) {
        let categories = [];
        try {
            const r = await secureFetch('/api/admin/categories');
            if (!r.ok) throw new Error('load');
            categories = await r.json();
        } catch (e) {
            container.innerHTML = `<p class="admin-error">Не удалось загрузить категории.</p>`;
            return;
        }

        container.innerHTML = `
            <div class="admin-toolbar">
                <button class="btn-main" id="btnCreateCategory">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                    Добавить категорию
                </button>
                <!-- Раунд 11 UI: «Всего: N» убрано по запросу. -->
            </div>
            <div class="admin-table-wrap">
                <table class="admin-table cat-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Название</th>
                            <th>Цвет</th>
                            <th>Используется</th>
                            <th>Активна</th>
                            <th>Действия</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${categories.map(renderCategoryRow).join('')}
                    </tbody>
                </table>
            </div>`;

        document.getElementById('btnCreateCategory').addEventListener('click', () => openCategoryModal());
    }

    function renderCategoryRow(c) {
        return `
            <tr data-cat-id="${c.id}">
                <td><span class="user-id-cell">#${c.id}</span></td>
                <td>${sanitizeAndFormatText(c.name)}</td>
                <td>
                    <span class="cat-color-swatch" style="background-color: ${safeColor(c.color_hex)}; border: 1px solid ${safeColor(c.color_hex)};"></span>
                    <code>${escapeAttr(c.color_hex)}</code>
                </td>
                <td>${c.usage_count > 0 ? `${c.usage_count} заявок` : '<span style="color:var(--text-muted)">не используется</span>'}</td>
                <td>
                    <span class="sec-badge ${c.is_active ? 'sec-ok' : 'sec-hard'}">
                        ${c.is_active ? '✓ Активна' : '⛔ Отключена'}
                    </span>
                </td>
                <td>
                    <button class="btn-secondary btn-cat-edit" data-cat-edit="${escapeHtml(JSON.stringify(c))}" style="font-size:12px;height:28px;padding:0 10px;">Редактировать</button>
                    ${c.usage_count === 0 ? `<button class="btn-secondary btn-cat-delete" data-cat-delete="${c.id}" data-cat-name="${escapeAttr(c.name)}" style="font-size:12px;height:28px;padding:0 10px;color:var(--error-color);border-color:rgba(248,113,113,0.3);">Удалить</button>` : ''}
                </td>
            </tr>`;
    }

    function openCategoryModal(existing = null) {
        const isEdit = !!existing;
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay active';
        overlay.id = 'categoryOverlay';
        const initialName = existing?.name || '';
        const initialColor = existing?.color_hex || '#38bdf8';
        const initialActive = existing ? existing.is_active : 1;
        overlay.innerHTML = `
            <div class="modal-content modal-create" style="max-width: 480px;">
                <header class="modal-header">
                    <div class="modal-header-text">
                        <h2 class="modal-title">${isEdit ? 'Редактирование категории' : 'Новая категория'}</h2>
                        <p class="modal-subtitle">Категория используется в карточках заявок и в фильтре календаря.</p>
                    </div>
                    <button type="button" class="modal-close-btn" id="catClose" aria-label="Закрыть">
                        <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                    </button>
                </header>
                <div class="modal-body">
                    <div class="input-group">
                        <label for="catName" class="field-label">Название <span class="req-marker">*</span></label>
                        <input type="text" id="catName" required maxlength="100" value="${escapeAttr(initialName)}" placeholder="Например: Тренинг">
                    </div>
                    <div class="input-row">
                        <div class="input-group">
                            <label for="catColor" class="field-label">Цвет <span class="req-marker">*</span></label>
                            <input type="color" id="catColor" value="${escapeAttr(initialColor)}" style="height:42px;width:100%;padding:2px;cursor:pointer;">
                        </div>
                        ${isEdit ? `
                        <div class="input-group">
                            <label class="field-label">Активна</label>
                            <label class="toggle-switch" style="margin-top:8px;">
                                <input type="checkbox" id="catActive" ${initialActive ? 'checked' : ''}>
                                <span class="slider"></span>
                            </label>
                        </div>` : ''}
                    </div>
                    <div class="form-error-message" id="catErr"></div>
                </div>
                <footer class="modal-actions">
                    <button type="button" class="btn-secondary" id="catCancel">Отмена</button>
                    <button type="button" class="btn-main" id="catSubmit">${isEdit ? 'Сохранить' : 'Создать'}</button>
                </footer>
            </div>`;
        document.body.appendChild(overlay);
        setupModalA11y(overlay);

        const close = () => overlay.remove();
        document.getElementById('catClose').addEventListener('click', close);
        document.getElementById('catCancel').addEventListener('click', close);
        overlay.addEventListener('click', e => { if (e.target === overlay) close(); });

        document.getElementById('catSubmit').addEventListener('click', async () => {
            const name = document.getElementById('catName').value.trim();
            const color = document.getElementById('catColor').value;
            const isActive = isEdit ? document.getElementById('catActive').checked : true;
            const errEl = document.getElementById('catErr');
            errEl.textContent = '';
            if (name.length < 2) {
                errEl.textContent = 'Название должно быть хотя бы 2 символа';
                return;
            }

            try {
                const url = isEdit ? `/api/admin/categories/${existing.id}` : '/api/admin/categories';
                const method = isEdit ? 'PUT' : 'POST';
                const r = await secureFetch(url, {
                    method,
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name, color_hex: color, is_active: isActive })
                });
                const d = await r.json();
                if (!r.ok) {
                    errEl.textContent = d.message || 'Ошибка';
                    return;
                }
                showToast(isEdit ? 'Категория обновлена' : 'Категория создана', 'success');
                close();
                renderCategoriesTab(document.getElementById('admin-tab-content'));
                // Сбросим кеш категорий на фронте, чтобы модалка заявки получила свежие.
                eventCategories = [];
            } catch (e) {
                errEl.textContent = 'Ошибка сети';
            }
        });
    }

    function renderAttemptRow(a) {
        const sevMatch = (a.reason || '').match(/^\[(\w+)\//);
        const severity = sevMatch ? sevMatch[1] : (a.was_clean ? 'clean' : 'medium');
        return `
            <tr class="att-row att-row-${severity}">
                <td class="log-time">${new Date(a.attempted_at).toLocaleString('ru-RU')}</td>
                <td>${sanitizeAndFormatText(a.user_name)}</td>
                <td><code>${sanitizeAndFormatText(a.ip_address || '-')}</code></td>
                <td>${sanitizeAndFormatText(a.file_name)}</td>
                <td><code>${sanitizeAndFormatText(a.claimed_mime || '-')}</code></td>
                <td><code>${sanitizeAndFormatText(a.actual_mime || '-')}</code></td>
                <td>${a.was_clean ? '<span class="att-status att-status-clean">Принят</span>' : '<span class="att-status att-status-rejected">Отклонён</span>'}</td>
                <td class="details-cell">${sanitizeAndFormatText(a.reason || '-')}</td>
            </tr>`;
    }

    /* ----- Common ----- */
    function bindMultiselect(id, onChange) {
        const ms = document.getElementById(id);
        if (!ms) return;
        const box = ms.querySelector('.select-box');
        const dropdown = ms.querySelector('.multiselect-dropdown');
        // CSS показывает dropdown по `.multiselect-dropdown.visible`
        // (см. dashboard.css:1277). Раньше bindMultiselect ставил `.open` только
        // на родителе → dropdown оставался display:none → фильтр «Тип события»
        // молча игнорировал клики.
        box.addEventListener('click', e => {
            e.stopPropagation();
            ms.classList.toggle('open');
            if (dropdown) dropdown.classList.toggle('visible');
        });
        ms.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.addEventListener('change', onChange));
        document.addEventListener('click', e => {
            if (!ms.contains(e.target)) {
                ms.classList.remove('open');
                if (dropdown) dropdown.classList.remove('visible');
            }
        });
    }

    /* ----- Bell-иконка и security_alert handler ----- */
    function handleSecurityAlert(alert) {
        // Toast независимо от того, открыта ли админка
        if (user?.role === 'Администратор') {
            const sevText = alert.severity === 'high' ? 'Высокий' : alert.severity === 'medium' ? 'Средний' : 'Низкий';
            const lockMsg = alert.hardLocked ? ' (юзер постоянно заблокирован!)' :
                            alert.tempLocked ? ' (юзер временно заблокирован)' : '';
            showToast(
                `🚨 Уровень: ${sevText}. ${alert.user.name} — попытка загрузить «${alert.fileName}»${lockMsg}`,
                alert.severity === 'high' || alert.hardLocked ? 'error' : 'warning',
                8000
            );
            adminState.unreadAlerts = (adminState.unreadAlerts || 0) + 1;
            updateBellBadge();
        }

        // Если открыта админка — обновим текущую вкладку
        if (!adminView.classList.contains('hidden')) {
            if (adminState.currentTab === 'summary') {
                renderSummaryTab(document.getElementById('admin-tab-content'));
            } else if (adminState.currentTab === 'files') {
                refreshAttempts();
            } else if (adminState.currentTab === 'logs') {
                refreshLogsTable();
            } else if (adminState.currentTab === 'users') {
                // обновлять таблицу юзеров не нужно срочно — пусть видит при следующем переключении
            }
        }
    }

    function updateBellBadge() {
        const bell = document.getElementById('adminBell');
        if (!bell) return;
        const badge = bell.querySelector('.bell-badge');
        const n = adminState.unreadAlerts || 0;
        if (n > 0) {
            bell.classList.add('has-alerts');
            badge.textContent = n > 99 ? '99+' : n;
            badge.style.display = '';
        } else {
            bell.classList.remove('has-alerts');
            badge.textContent = '';
            badge.style.display = 'none';
        }
    }

    /* ----- Пользовательский bell для всех ролей (события на заявках) ----- */

    const NOTIF_ICONS = {
        status_changed:        'С',
        new_comment:           '💬',
        new_document:          '📎',
        returned_for_rework:   '↺'
    };

    function formatNotifTime(iso) {
        const d = new Date(iso);
        const now = new Date();
        const diffMs = now - d;
        const diffMin = Math.floor(diffMs / 60000);
        if (diffMin < 1) return 'только что';
        if (diffMin < 60) return `${diffMin} мин назад`;
        const diffH = Math.floor(diffMin / 60);
        if (diffH < 24) return `${diffH} ч назад`;
        const diffD = Math.floor(diffH / 24);
        if (diffD < 7) return `${diffD} дн назад`;
        return d.toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
    }

    function updateUserBellBadge() {
        const bell = document.getElementById('userBell');
        if (!bell) return;
        const badge = bell.querySelector('.user-bell-badge');
        const n = notifState.unreadCount || 0;
        if (n > 0) {
            bell.classList.add('has-unread');
            badge.textContent = n > 99 ? '99+' : n;
        } else {
            bell.classList.remove('has-unread');
            badge.textContent = '';
        }
        const markAllBtn = document.getElementById('bellMarkAll');
        if (markAllBtn) markAllBtn.disabled = n === 0;
    }

    function renderUserBellList() {
        const list = document.getElementById('userBellList');
        if (!list) return;
        if (!notifState.items.length) {
            list.innerHTML = '<div class="bell-empty">Нет уведомлений</div>';
            return;
        }
        list.innerHTML = notifState.items.map(n => {
            const unreadClass = n.is_read ? '' : 'unread';
            const icon = NOTIF_ICONS[n.type] || '•';
            const reqId = n.request_id ? `data-request-id="${n.request_id}"` : '';
            return `
                <div class="bell-item ${unreadClass}" data-notif-id="${n.id}" ${reqId}>
                    <span class="bell-item-icon t-${n.type}">${icon}</span>
                    <div class="bell-item-body">
                        <div class="bell-item-text">${sanitizeAndFormatText(n.message)}</div>
                        <div class="bell-item-time">${formatNotifTime(n.created_at)}</div>
                    </div>
                    <span class="bell-item-dot"></span>
                </div>`;
        }).join('');
    }

    async function loadUserNotifications() {
        try {
            const r = await secureFetch('/api/notifications?pageSize=30');
            if (!r.ok) return;
            const d = await r.json();
            notifState.items = d.items || [];
            notifState.unreadCount = (d.items || []).filter(x => !x.is_read).length;
            // Если на сервере непрочитанных больше чем в первых 30 — берём «честный» счётчик
            const cr = await secureFetch('/api/notifications/unread-count');
            if (cr.ok) {
                const cd = await cr.json();
                notifState.unreadCount = cd.unread || 0;
            }
            notifState.loaded = true;
            updateUserBellBadge();
            renderUserBellList();
        } catch (e) {
            console.error('Не удалось загрузить уведомления:', e);
        }
    }

    function handleUserNotification(n) {
        if (!n) return;
        // rolling-merge — сервер для new_comment/new_document
        // делает UPDATE вместо INSERT если уже есть unread от того же actor'а
        // в той же заявке. ID остаётся прежним → находим существующий item,
        // удаляем со старой позиции, unshift'аем заново (подъём наверх с
        // новым preview). Badge не инкрементим: пользователь уже знает.
        const existingIdx = notifState.items.findIndex(x => x.id === n.id);
        if (existingIdx >= 0) {
            const old = notifState.items[existingIdx];
            notifState.items.splice(existingIdx, 1);
            notifState.items.unshift(n);
            // Если старая была прочитана, а новая нет — счётчик += 1
            // (edge-case: юзер прочитал, потом пришло новое сообщение).
            if (old.is_read && !n.is_read) notifState.unreadCount += 1;
            updateUserBellBadge();
            renderUserBellList();
            return;
        }
        notifState.items.unshift(n);
        if (notifState.items.length > 30) notifState.items.length = 30;
        if (!n.is_read) notifState.unreadCount += 1;
        updateUserBellBadge();
        renderUserBellList();

        // если юзер УЖЕ на детали этой заявки — toast/sound/
        // desktop-notif не показываем. Юзер видит новое сообщение прямо в чате
        // → дублирующее всплывающее «N в чате заявки №X» только мешает (мелькает
        // у того кто открыл чат). Notification всё равно сохраняется в
        // bell-panel — историю не теряем. Подавляем только UI-spam.
        const onCurrentRequest = !detailView.classList.contains('hidden')
            && n.request_id
            && String(n.request_id) === String(window.location.hash.split('/')[2]);
        if (onCurrentRequest) return;

        showToast(n.message, 'info', 5000);
        // Аудио + desktop-нотификация — пользователь сидит на другой вкладке
        // и должен узнать о новом событии без переключения сюда.
        playNotificationPing();
        showDesktopNotification(n);
    }

    /* ----- Звук + Web Notifications API ----- */

    let _audioCtx = null;
    let _soundEnabled = localStorage.getItem('notifSound') !== 'off';
    function getAudioCtx() {
        if (!_audioCtx) {
            try { _audioCtx = new (window.AudioContext || window.webkitAudioContext)(); }
            catch (e) { _audioCtx = null; }
        }
        return _audioCtx;
    }

    /**
     * Короткий двух-нотный ping через WebAudio — не требует mp3-файла.
     * Не звучит до первого пользовательского взаимодействия (ограничение
     * браузеров на autoplay) — это нормально, через 1-2 клика по UI ctx
     * разблокируется и дальше работает.
     */
    function playNotificationPing() {
        if (!_soundEnabled) return;
        const ctx = getAudioCtx();
        if (!ctx) return;
        try {
            // Резюмируем если был suspended (Chrome требует gesture)
            if (ctx.state === 'suspended') ctx.resume().catch(() => {});
            const t0 = ctx.currentTime;
            const tone = (freq, start, dur) => {
                const osc = ctx.createOscillator();
                const gain = ctx.createGain();
                osc.type = 'sine';
                osc.frequency.value = freq;
                gain.gain.setValueAtTime(0, t0 + start);
                gain.gain.linearRampToValueAtTime(0.18, t0 + start + 0.02);
                gain.gain.linearRampToValueAtTime(0, t0 + start + dur);
                osc.connect(gain);
                gain.connect(ctx.destination);
                osc.start(t0 + start);
                osc.stop(t0 + start + dur + 0.05);
            };
            tone(880,  0,    0.08);
            tone(1320, 0.08, 0.10);
        } catch (e) { /* ignore */ }
    }

    /**
     * Desktop-нотификация (Web Notifications API). Показывается только когда
     * вкладка В ФОНЕ (document.hidden) — на активной вкладке достаточно toast'а.
     * Permission запрашивается лениво при первом событии.
     */
    let _desktopAsked = false;
    function showDesktopNotification(n) {
        if (!('Notification' in window)) return;
        if (!document.hidden) return; // активная вкладка — desktop не нужен

        if (Notification.permission === 'granted') {
            try {
                const notif = new Notification('Витебскэнерго: новое уведомление', {
                    body: (n.message || '').slice(0, 200),
                    icon: '/favicon.ico',
                    tag: `vitenergo-${n.id}`
                });
                notif.onclick = () => {
                    window.focus();
                    if (n.request_id) window.location.hash = `#/request/${n.request_id}`;
                    notif.close();
                };
            } catch (e) { /* ignore */ }
        } else if (Notification.permission !== 'denied' && !_desktopAsked) {
            _desktopAsked = true;
            Notification.requestPermission().catch(() => {});
        }
    }

    // Toggle звука: пользователь может выключить через клик на bell-иконке
    // долгим тапом, или явно через пункт в bell-панели (см. ниже в HTML).
    window.toggleNotificationSound = () => {
        _soundEnabled = !_soundEnabled;
        safeStorageSet(localStorage, 'notifSound', _soundEnabled ? 'on' : 'off');
        showToast(`Звук уведомлений: ${_soundEnabled ? 'включён' : 'выключён'}`, 'info', 2500);
        return _soundEnabled;
    };

    function toggleUserBellPanel(forceState) {
        const panel = document.getElementById('userBellPanel');
        if (!panel) return;
        const willOpen = typeof forceState === 'boolean' ? forceState : panel.classList.contains('hidden');
        if (willOpen) {
            panel.classList.remove('hidden');
            // Если ещё не грузили — подгрузим
            if (!notifState.loaded) loadUserNotifications();
            else renderUserBellList();
        } else {
            panel.classList.add('hidden');
        }
    }

    async function markNotificationsRead(ids) {
        if (!ids || ids.length === 0) return;
        try {
            await secureFetch('/api/notifications/mark-read', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ids })
            });
            for (const n of notifState.items) {
                if (ids.includes(n.id) && !n.is_read) {
                    n.is_read = true;
                }
            }
            notifState.unreadCount = Math.max(0, notifState.unreadCount - ids.length);
            updateUserBellBadge();
            renderUserBellList();
        } catch (e) {
            console.error('Не удалось отметить как прочитанное:', e);
        }
    }

    async function markAllNotificationsRead() {
        try {
            await secureFetch('/api/notifications/mark-all-read', { method: 'POST' });
            for (const n of notifState.items) n.is_read = true;
            notifState.unreadCount = 0;
            updateUserBellBadge();
            renderUserBellList();
        } catch (e) {
            console.error('Не удалось отметить всё прочитанным:', e);
        }
    }

    function renderAdminPagination(totalItems, currentPage, _prefix = 'p') {
        const pageSize = 50;
        if (totalItems <= pageSize) return '';
        const totalPages = Math.ceil(totalItems / pageSize);
        const window = 3;
        const start = Math.max(1, currentPage - window);
        const end = Math.min(totalPages, currentPage + window);

        let html = `<button class="page-item prev" data-page="${currentPage - 1}" ${currentPage === 1 ? 'disabled' : ''}>&laquo;</button>`;
        if (start > 1) html += `<button class="page-item" data-page="1">1</button>${start > 2 ? '<span class="page-ellipsis">…</span>' : ''}`;
        for (let i = start; i <= end; i++) {
            html += `<button class="page-item ${i === currentPage ? 'active' : ''}" data-page="${i}">${i}</button>`;
        }
        if (end < totalPages) html += `${end < totalPages - 1 ? '<span class="page-ellipsis">…</span>' : ''}<button class="page-item" data-page="${totalPages}">${totalPages}</button>`;
        html += `<button class="page-item next" data-page="${currentPage + 1}" ${currentPage === totalPages ? 'disabled' : ''}>&raquo;</button>`;
        return html;
    }
    
    function updateListItem(request) {
        const item = document.querySelector(`.request-item[data-request-id="${request.id}"]`);
        if (!item) return;

        const displayStatus = getDisplayStatus(request.status, request.creator_id, request.id);
        const statusClass = displayStatus.replace(/ /g, '-').toLowerCase();

        const badge = item.querySelector('.status-badge');
        badge.className = `status-badge status-${statusClass}`;
        badge.textContent = displayStatus;

        const catColor = safeColor(request.category_color);
        item.style.borderLeftColor = catColor;

        const plannedShort = request.planned_date ? formatDateTime(request.planned_date) : '';
        const categoryBadge = request.category_name
            ? `<span class="category-mini-badge" style="background-color: ${catColor}22; color: ${catColor}; border: 1px solid ${catColor}55;">${sanitizeAndFormatText(request.category_name)}</span>`
            : '';
        item.querySelector('p').innerHTML = `${categoryBadge}<span class="request-meta">Создатель: ${sanitizeAndFormatText(request.creator_name)}${plannedShort ? ` • Мероприятие: ${plannedShort}` : ''}</span>`;

        // Обновляем индикаторы файлов/комментариев
        const sideEl = item.querySelector('.request-side');
        if (sideEl) {
            const counts = renderCountIcons(request);
            const existingCounts = sideEl.querySelector('.request-counts');
            if (counts) {
                if (existingCounts) existingCounts.innerHTML = counts;
                else sideEl.insertAdjacentHTML('afterbegin', `<div class="request-counts">${counts}</div>`);
            } else if (existingCounts) {
                existingCounts.remove();
            }
        }

        item.classList.add('new-activity');
    }

    function resetToFirstPageAndRender() {
        currentPage = 1;
        renderListView();
    }

    function renderPagination(totalItems) {
        const paginationContainer = document.getElementById('paginationContainer');
        paginationContainer.innerHTML = '';
        if (totalItems <= itemsPerPage) return;

        const totalPages = Math.ceil(totalItems / itemsPerPage);
        let paginationHtml = `<button class="page-item prev" ${currentPage === 1 ? 'disabled' : ''}>&laquo; Назад</button>`;
        for (let i = 1; i <= totalPages; i++) {
            paginationHtml += `<button class="page-item ${i === currentPage ? 'active' : ''}" data-page="${i}">${i}</button>`;
        }
        paginationHtml += `<button class="page-item next" ${currentPage === totalPages ? 'disabled' : ''}>Вперед &raquo;</button>`;
        paginationContainer.innerHTML = paginationHtml;
    }

    const renderCountIcons = (req) => {
        const items = [];
        if (req.docs_count > 0) {
            items.push(`<span class="count-chip" title="Документов: ${req.docs_count}">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="12" height="12"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                ${req.docs_count}
            </span>`);
        }
        if (req.comments_count > 0) {
            items.push(`<span class="count-chip" title="Комментариев: ${req.comments_count}">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="12" height="12"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
                ${req.comments_count}
            </span>`);
        }
        return items.join('');
    };

    const renderRequestListItems = (requests) => {
        const canBatch = canUseBatch();
        if (canBatch) requestsListEl.classList.add('batch-mode');
        else requestsListEl.classList.remove('batch-mode');

        if (requests && requests.length > 0) {
            requestsListEl.innerHTML = requests.map(req => {
                const displayStatus = getDisplayStatus(req.status, req.creator_id, req.id);
                const statusClass = displayStatus.replace(/ /g, '-').toLowerCase();
                const hasUnreadActivity = req.has_unread_activity === 1;
                const hasUnreadComments = req.has_unread_comments === 1;
                const newClass = (hasUnreadActivity || hasUnreadComments) ? 'new-activity' : '';
                const catColor = safeColor(req.category_color);
                const plannedShort = req.planned_date ? formatDateTime(req.planned_date) : '';
                const categoryBadge = req.category_name
                    ? `<span class="category-mini-badge" style="background-color: ${catColor}22; color: ${catColor}; border: 1px solid ${catColor}55;">${sanitizeAndFormatText(req.category_name)}</span>`
                    : '';
                const counts = renderCountIcons(req);
                const isSelected = batchState.selectedIds.has(req.id);
                const checkbox = canBatch
                    ? `<input type="checkbox" class="request-checkbox" data-batch-id="${req.id}" ${isSelected ? 'checked' : ''}>`
                    : '';
                return `
                    <li class="request-item ${newClass} ${isSelected ? 'batch-selected' : ''}" data-request-id="${req.id}" style="border-left: 4px solid ${catColor};">
                        ${checkbox}
                        <div>
                            <h3>№${req.id} ${sanitizeAndFormatText(req.title)}</h3>
                            <p>${categoryBadge}<span class="request-meta">Создатель: ${sanitizeAndFormatText(req.creator_name)}${plannedShort ? ` • Мероприятие: ${plannedShort}` : ''}</span></p>
                        </div>
                        <div class="request-side">
                            ${counts ? `<div class="request-counts">${counts}</div>` : ''}
                            <div class="status-badge status-${statusClass}">${displayStatus}</div>
                        </div>
                    </li>`;
            }).join('');
        } else {
            requestsListEl.innerHTML = `<p id="loadingMessage">Заявок, соответствующих фильтрам, не найдено.</p>`;
        }
        updateBatchBar();
    };

    /**
     * Может ли текущая роль использовать batch-операции?
     * Сотрудник только для своих REWORK — на демо это малоценно, не показываем.
     */
    function canUseBatch() {
        // batch-смена статусов отключена по запросу.
        // Чекбоксы у заявок не рендерятся, batchActionBar остаётся hidden.
        // Серверный /api/requests/batch-status в коде остался — если в будущем
        // решим вернуть, достаточно вернуть проверку ролей.
        return false;
    }

    /**
     * Список доступных целевых статусов для batch — по роли.
     */
    function getBatchTargetStatuses() {
        const S = SYSTEM_CONSTANTS.statuses;
        const SN = SYSTEM_CONSTANTS.statusNames;
        if (!user) return [];
        const role = user.role;
        let ids = [];
        if (role === 'Модератор') ids = [S.APPROVAL, S.REJECTED, S.REWORK, S.MODERATION];
        else if (role === 'Согласующий') ids = [S.APPROVED, S.REJECTED, S.REWORK];
        else if (role === 'Администратор') ids = [S.MODERATION, S.APPROVAL, S.APPROVED, S.REJECTED, S.REWORK];
        return ids.map(id => ({ id, name: SN[id] || `#${id}` }));
    }

    function updateBatchBar() {
        const bar = document.getElementById('batchActionBar');
        const countEl = document.getElementById('batchCount');
        const select  = document.getElementById('batchStatusSelect');
        const applyBtn = document.getElementById('batchApplyBtn');
        if (!bar || !countEl || !select || !applyBtn) return;

        const canBatch = canUseBatch();
        const n = batchState.selectedIds.size;
        if (!canBatch || n === 0) {
            bar.classList.add('hidden');
            return;
        }
        bar.classList.remove('hidden');
        countEl.textContent = `Выбрано: ${n}`;

        // Заполняем селект целевых статусов один раз
        if (!select.dataset.populated) {
            const opts = getBatchTargetStatuses();
            select.innerHTML = opts.map((s, i) =>
                `<option value="${s.id}" ${i === 0 ? 'selected' : ''}>${s.name}</option>`
            ).join('');
            select.dataset.populated = '1';
        }
        applyBtn.disabled = false;
    }

    function clearBatchSelection() {
        batchState.selectedIds.clear();
        document.querySelectorAll('.request-checkbox:checked').forEach(cb => { cb.checked = false; });
        document.querySelectorAll('.request-item.batch-selected').forEach(li => li.classList.remove('batch-selected'));
        updateBatchBar();
    }

    async function applyBatchStatus() {
        const select = document.getElementById('batchStatusSelect');
        const applyBtn = document.getElementById('batchApplyBtn');
        if (!select || !applyBtn) return;
        const newStatusId = parseInt(select.value, 10);
        const ids = Array.from(batchState.selectedIds);
        if (ids.length === 0 || isNaN(newStatusId)) return;

        // REWORK для batch требует общую причину.
        let details = '';
        if (newStatusId === SYSTEM_CONSTANTS.statuses.REWORK) {
            const reason = await promptReworkReason();
            if (reason === null) return;
            details = reason;
        } else {
            const targetName = select.options[select.selectedIndex].text;
            if (!confirm(`Применить статус «${targetName}» к ${ids.length} заявкам?`)) return;
        }

        applyBtn.disabled = true;
        applyBtn.textContent = 'Применение…';
        try {
            const r = await secureFetch('/api/requests/batch-status', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ids, newStatusId, details })
            });
            const d = await r.json();
            if (!r.ok) {
                showToast(d.message || 'Не удалось применить', 'error');
            } else {
                const okN = d.ok || 0;
                const failN = d.failed || 0;
                if (failN === 0) {
                    showToast(`Готово. Изменено заявок: ${okN}`, 'success');
                } else {
                    showToast(`Изменено: ${okN}. Пропущено: ${failN} (несоответствие статусу).`, 'warning', 7000);
                }
                clearBatchSelection();
                resetToFirstPageAndRender();
            }
        } catch (e) {
            showToast('Ошибка сети при batch-применении', 'error');
        } finally {
            applyBtn.disabled = false;
            applyBtn.textContent = 'Применить';
        }
    }

    const populateFilters = (uniqueCreators = []) => {
        const checkIcon = `<svg viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M13.3333 4L5.99999 11.3333L2.66666 8" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
        statusOptionsContainer.innerHTML = ALL_STATUSES.map(status =>
            `<label><input type="checkbox" value="${escapeAttr(status)}"><span class="custom-checkbox">${checkIcon}</span><span>${status}</span></label>`
        ).join('');

        // populate filter по категориям. eventCategories
        // подгружаются лениво (loadEventCategories) — здесь дёргаем без await,
        // если уже загружено — рендерим сразу; иначе fetch + перерендер.
        const renderCategoryOptions = () => {
            categoryOptionsContainer.innerHTML = (eventCategories || [])
                .filter(c => c.is_active !== false && c.is_active !== 0)
                .map(c => {
                    const safeColor = /^#[0-9A-Fa-f]{6}$/.test(c.color_hex) ? c.color_hex : '#94a3b8';
                    return `<label><input type="checkbox" value="${c.id}" data-name="${escapeAttr(c.name)}"><span class="custom-checkbox">${checkIcon}</span><span class="cat-dot" style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${safeColor};margin-right:6px;vertical-align:middle"></span><span>${sanitizeAndFormatText(c.name)}</span></label>`;
                }).join('');
        };
        if (eventCategories.length > 0) {
            renderCategoryOptions();
        } else {
            loadEventCategories().then(renderCategoryOptions).catch(() => {});
        }

        if (['Администратор', 'Модератор', 'Согласующий'].includes(user.role)) {
            authorOptionsContainer.innerHTML = uniqueCreators.map(({ creator_id, creator_name }) =>
                `<label><input type="checkbox" value="${creator_id}" data-name="${escapeAttr(creator_name)}"><span class="custom-checkbox">${checkIcon}</span><span>${sanitizeAndFormatText(creator_name)}</span></label>`
            ).join('');
            // 'flex' вместо 'block' — чтобы CSS-правило
            // `#advancedFiltersContainer { display: flex; gap: 20px }` сработало
            // (inline-стиль 'block' имеет выше specificity и убивает gap).
            advancedFiltersContainer.style.display = 'flex';

            // branches lazy-load при первом open'е filter'а.
            // /api/branches публичный (any auth) — в этом проекте branches видны
            // не как security-данные, а как организационная структура.
            const renderBranchOptions = () => {
                branchOptionsContainer.innerHTML = (allBranches || []).map(b =>
                    `<label><input type="checkbox" value="${b.id}" data-name="${escapeAttr(b.name)}"><span class="custom-checkbox">${checkIcon}</span><span>${sanitizeAndFormatText(b.name)}</span></label>`
                ).join('');
            };
            if (allBranches.length > 0) {
                renderBranchOptions();
            } else {
                secureFetch('/api/branches').then(r => r.ok ? r.json() : []).then(list => {
                    allBranches = Array.isArray(list) ? list : [];
                    renderBranchOptions();
                }).catch(() => {});
            }
        } else {
            advancedFiltersContainer.style.display = 'none';
        }
    };

    const updateActiveFilterTags = () => {
        activeFiltersContainer.innerHTML = '';
        let filterCount = 0;
        // value берётся из dataset.* атрибута → браузер ДЕКОДИРУЕТ HTML entities
        // при чтении (обратное к escapeAttr на write). Если ФИО содержит
        // `<img onerror=...>`, в `data-name="..."` хранится `&lt;img...&gt;`,
        // но `cb.dataset.name` возвращает сырой `<img...>`. innerHTML += без
        // повторного escape = stored XSS на админ→модератор. Защита: escapeHtml
        // на всех динамических полях шаблона.
        const createTag = (key, value, type, val = '') =>
            `<div class="filter-tag">
                <span class="key">${escapeHtml(key)}:</span> <span class="value">${escapeHtml(value)}</span>
                <button data-filter-type="${escapeHtml(type)}" data-filter-value="${escapeHtml(val)}" aria-label="Снять фильтр ${escapeHtml(key)}">&times;</button>
            </div>`;

        const selectedStatuses = [...statusOptionsContainer.querySelectorAll('input:checked')].map(cb => cb.value);
        if (selectedStatuses.length > 0) {
            filterCount += selectedStatuses.length;
            selectedStatuses.forEach(s => activeFiltersContainer.innerHTML += createTag('Статус', s, 'status', s));
        }
        if (authorOptionsContainer) {
            const selectedAuthors = [...authorOptionsContainer.querySelectorAll('input:checked')];
            if (selectedAuthors.length > 0) {
                filterCount += selectedAuthors.length;
                selectedAuthors.forEach(cb => activeFiltersContainer.innerHTML += createTag('Автор', cb.dataset.name, 'author', cb.value));
            }
        }
        // tag для категорий
        if (categoryOptionsContainer) {
            const selectedCats = [...categoryOptionsContainer.querySelectorAll('input:checked')];
            if (selectedCats.length > 0) {
                filterCount += selectedCats.length;
                selectedCats.forEach(cb => activeFiltersContainer.innerHTML += createTag('Категория', cb.dataset.name, 'category', cb.value));
            }
        }
        // tag для филиалов
        if (branchOptionsContainer) {
            const selectedBranches = [...branchOptionsContainer.querySelectorAll('input:checked')];
            if (selectedBranches.length > 0) {
                filterCount += selectedBranches.length;
                selectedBranches.forEach(cb => activeFiltersContainer.innerHTML += createTag('Филиал', cb.dataset.name, 'branch', cb.value));
            }
        }
        if (dateCreatedFromInput.value) {
            filterCount++;
            activeFiltersContainer.innerHTML += createTag('Создана от', dateCreatedFromInput.value, 'dateCreatedFrom');
        }
        if (dateCreatedToInput.value) {
            filterCount++;
            activeFiltersContainer.innerHTML += createTag('Создана до', dateCreatedToInput.value, 'dateCreatedTo');
        }
        if (dateUpdatedFromInput.value) {
            filterCount++;
            activeFiltersContainer.innerHTML += createTag('Обновлена от', dateUpdatedFromInput.value, 'dateUpdatedFrom');
        }
        if (dateUpdatedToInput.value) {
            filterCount++;
            activeFiltersContainer.innerHTML += createTag('Обновлена до', dateUpdatedToInput.value, 'dateUpdatedTo');
        }
        if (filterCount > 0) {
            activeFiltersContainer.innerHTML += `<button class="btn-reset-all">Сбросить все</button>`;
        }
        activeFiltersContainer.classList.toggle('visible', filterCount > 0);

        const badge = openFilterBtn.querySelector('.notification-badge');
        if (filterCount > 0) {
            if (badge) {
                badge.textContent = filterCount;
            } else {
                openFilterBtn.insertAdjacentHTML('beforeend', `<span class="notification-badge">${filterCount}</span>`);
            }
        } else {
            if (badge) badge.remove();
        }
    };

    function handleDetailFiles(files) {
        // client-side size cap. Файлы >15МБ — skip + toast.
        const filtered = filterByMaxSize(files);
        for (const file of filtered) {
            if (!detailViewFiles.some(f => f.name === file.name && f.size === file.size)) {
                detailViewFiles.push(file);
            }
        }
        updateDetailFileList();
    }

    function updateDetailFileList() {
        const uploader = document.getElementById('detailFileUploader');
        if (!uploader) return;
        const fileListContainer = uploader.querySelector('#detail-file-list-container');
        const uploadForm = uploader.querySelector('#uploadForm');

        uploader.classList.toggle('has-files', detailViewFiles.length > 0);
        uploadForm.classList.toggle('hidden', detailViewFiles.length === 0);

        fileListContainer.innerHTML = detailViewFiles.map((file, index) =>
            `<li class="file-list-item">
                <span class="file-icon">${getFileIcon(file.name)}</span>
                <span class="file-list-item-name" title="${escapeAttr(file.name)}">${sanitizeAndFormatText(file.name)}</span>
                <button type="button" class="file-list-item-remove" data-index="${index}" aria-label="Убрать файл из загрузки">&times;</button>
            </li>`
        ).join('');
    }

    const refreshDynamicContent = async (requestId, forceScrollChat = false) => {
        if (detailView.classList.contains('hidden') || !document.getElementById('activityPane')) return;
        try {
            const [reqRes, documentsRes] = await Promise.all([
                secureFetch(`/api/requests/${requestId}`),
                secureFetch(`/api/requests/${requestId}/documents`)
            ]);
            if (!reqRes.ok || !documentsRes.ok) return;

            const request = await reqRes.json();
            currentDocumentsInView = await documentsRes.json();

            const displayStatus = getDisplayStatus(request.status_name, request.creator_id, request.id);
            const statusClass = displayStatus.replace(/ /g, '-').toLowerCase();
            const statusBadge = detailView.querySelector('.info-grid .status-badge');
            if (statusBadge) {
                statusBadge.className = `status-badge status-${statusClass}`;
                statusBadge.textContent = displayStatus;
            }
            const actionsContainer = detailView.querySelector('#actionsContainer');
            if (actionsContainer) {
                actionsContainer.innerHTML = renderActionsBlock(request);
            }
            const documentsContainer = detailView.querySelector('#documentsContainer');
            if (documentsContainer) {
                documentsContainer.innerHTML = renderDocumentsBlock(currentDocumentsInView, request.creator_id, request.status_name);
            }
            await updateFeeds(requestId, forceScrollChat);
        } catch (error) {
            console.error("Ошибка при обновлении:", error);
        }
    };

    const updateFeeds = async (requestId, forceScroll = false) => {
        const [historyRes, commentsRes] = await Promise.all([
            secureFetch(`/api/requests/${requestId}/history`),
            secureFetch(`/api/requests/${requestId}/comments`)
        ]);
        if (!historyRes.ok || !commentsRes.ok) return;

        const history = await historyRes.json();
        const comments = await commentsRes.json();

        unreadActivityIds.clear();
        history.forEach(item => {
            if (item.is_read === 0) unreadActivityIds.add(item.id);
        });

        unreadCommentIds.clear();
        comments.forEach(item => {
            const readers = item.readers ? item.readers.split(',').map(id => parseInt(id, 10)) : [];
            if (item.user_id !== user.id && !readers.includes(user.id)) {
                unreadCommentIds.add(item.id);
            }
        });

        const activityFeed = detailView.querySelector('.activity-feed');
        if (activityFeed) {
            let historyHtml = '';
            let lastHistoryDate = null;
            history.forEach(item => {
                const itemDate = new Date(item.timestamp).toDateString();
                if (itemDate !== lastHistoryDate) {
                    historyHtml += `<div class="date-separator"><span>${formatDateSeparator(item.timestamp)}</span></div>`;
                    lastHistoryDate = itemDate;
                }
                historyHtml += renderFeedItem(item);
            });
            activityFeed.innerHTML = historyHtml || `<p class="no-items-message">Событий еще нет.</p>`;
        }
        const chatFeed = detailView.querySelector('.chat-feed');
        if (chatFeed) {
            // Сортировка по времени + группировка consecutive-сообщений одного автора
            // (Telegram-стиль: соседние bubble одного юзера склеиваются визуально).
            const sorted = comments.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
            let commentsHtml = '';
            let lastChatDate = null;
            const GROUP_GAP_MS = 5 * 60 * 1000; // если разрыв < 5 мин — считаем «продолжением»
            for (let i = 0; i < sorted.length; i++) {
                const item = sorted[i];
                const prev = sorted[i - 1];
                const itemDate = new Date(item.created_at).toDateString();
                if (itemDate !== lastChatDate) {
                    commentsHtml += `<div class="date-separator"><span>${formatDateSeparator(item.created_at)}</span></div>`;
                    lastChatDate = itemDate;
                }
                // group: тот же автор, prev не reply (после reply начинаем новую группу
                // — визуально reply создаёт «разрыв»), item не reply, оба не удалены,
                // разница времени < 5 мин, дата та же.
                const isGrouped = prev
                    && prev.user_id === item.user_id
                    && !item.reply_to_id
                    && !prev.reply_to_id
                    && !prev.deleted_at
                    && !item.deleted_at
                    && (new Date(item.created_at) - new Date(prev.created_at)) < GROUP_GAP_MS
                    && new Date(prev.created_at).toDateString() === itemDate;
                commentsHtml += renderChatItem(item, user.id, isGrouped);
            }
            chatFeed.innerHTML = commentsHtml || `<p class="no-items-message">Комментариев еще нет.</p>`;
        }

        updateBadge('activity', unreadActivityIds.size);
        updateBadge('chat', unreadCommentIds.size);

        if (forceScroll || (chatFeed && (chatFeed.scrollTop + chatFeed.clientHeight >= chatFeed.scrollHeight - 50))) {
            setTimeout(() => {
                if (chatFeed) chatFeed.scrollTop = chatFeed.scrollHeight;
            }, 50);
        }

        if (activityFeed) {
            activityFeed.querySelector('.unread-separator')?.remove();
            let firstUnreadActivity = null;
            if (unreadActivityIds.size > 0) {
                for (const item of activityFeed.querySelectorAll('.feed-item[data-item-id]')) {
                    if (unreadActivityIds.has(parseInt(item.dataset.itemId, 10))) {
                        firstUnreadActivity = item;
                        break;
                    }
                }
            }
            if (firstUnreadActivity) {
                const separator = document.createElement('div');
                separator.className = 'unread-separator';
                separator.innerHTML = `<span>Новые события</span>`;
                firstUnreadActivity.before(separator);
                if (detailView.querySelector('.switcher-btn[data-view="activity"].active')) {
                    separator.scrollIntoView({ behavior: 'smooth', block: 'center' });
                }
            } else if (forceScroll && detailView.querySelector('.switcher-btn[data-view="activity"].active')) {
                activityFeed.scrollTop = activityFeed.scrollHeight;
            }
        }
        if (activityObserver && activityFeed) {
            unreadActivityIds.forEach(id => {
                const el = activityFeed.querySelector(`[data-item-id="${id}"]`);
                if (el) activityObserver.observe(el);
            });
        }
        if (commentObserver && chatFeed) {
            unreadCommentIds.forEach(id => {
                const el = chatFeed.querySelector(`[data-item-id="${id}"]`);
                if (el) commentObserver.observe(el);
            });
        }

        // если chat-pane активен в момент refresh'а
        // (новое сообщение пришло во время открытого чата) — bulk-mark всех
        // unread сразу, не ждём IntersectionObserver.
        const chatActive = detailView.querySelector('.switcher-btn[data-view="chat"].active');
        if (chatActive && unreadCommentIds.size > 0) {
            markAllChatRead();   // Раунд 11: убрали setTimeout, см. switcher-handler
        }
    };

    const renderDocumentsBlock = (documents, creatorId, status) => {
        // Подписанный протокол согласования вытаскиваем в отдельную секцию —
        // он обычно один и важен. Остальные документы группируем по
        // загрузившему: автор vs остальные участники.
        const signedProtocols = documents.filter(d => d.is_signed_protocol === true || d.is_signed_protocol === 1);
        const regularDocs = documents.filter(d => !(d.is_signed_protocol === true || d.is_signed_protocol === 1));
        const creatorFiles = regularDocs.filter(d => d.uploaded_by_id === creatorId);
        const otherFiles = regularDocs.filter(d => d.uploaded_by_id !== creatorId);

        const renderList = (docs) => docs.map(d =>
            `<li class="document-item">
                <span class="file-icon">${getFileIcon(d.file_name)}</span>
                <div class="file-info">
                    <a href="/api/documents/${d.id}/download" class="document-download-link" data-filename="${escapeAttr(d.file_name)}">${sanitizeAndFormatText(d.file_name)}</a>
                    <div class="document-item-meta">
                        Загрузил: ${sanitizeAndFormatText(d.uploaded_by_name)} | ${new Date(d.uploaded_at).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' })}
                    </div>
                </div>
            </li>`
        ).join('');

        const signedHtml = (signedProtocols.length > 0)
            ? `<div class="signed-protocol-block">
                <div class="document-list-header">
                    <h5>📜 Подписанный протокол согласования</h5>
                </div>
                <ul class="document-sublist">${renderList(signedProtocols)}</ul>
              </div>`
            : '';

        const archiveIcon = `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M20.25 7.5l-.625 10.632a2.25 2.25 0 01-2.247 2.118H6.622a2.25 2.25 0 01-2.247-2.118L3.75 7.5m8.25 3v6.75m0 0l-3-3m3 3l3-3M3.375 7.5h17.25c.621 0 1.125-.504 1.125-1.125v-1.5c0-.621-.504-1.125-1.125-1.125H3.375c-.621 0-1.125.504-1.125-1.125v1.5c0 .621.504 1.125 1.125 1.125z" /></svg>`;
        const downloadIcon = `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" /></svg>`;

        const creatorHtml = (creatorFiles.length > 0) ?
            `<div>
                <div class="document-list-header">
                    <h5>Файлы от создателя</h5>
                    <div class="button-group">
                        <button class="btn-download-archive" data-doc-ids="${creatorFiles.map(d => d.id).join(',')}" title="Скачать архивом (ZIP)">${archiveIcon}<span>Архив</span></button>
                        <button class="btn-download-all" data-doc-ids="${creatorFiles.map(d => d.id).join(',')}" title="Скачать все по отдельности">${downloadIcon}<span>Все</span></button>
                    </div>
                </div>
                <ul class="document-sublist">${renderList(creatorFiles)}</ul>
            </div>` : '';

        const otherHtml = (otherFiles.length > 0) ?
            `<div>
                <div class="document-list-header">
                    <h5>Файлы от участников</h5>
                    <div class="button-group">
                        <button class="btn-download-archive" data-doc-ids="${otherFiles.map(d => d.id).join(',')}" title="Скачать архивом (ZIP)">${archiveIcon}<span>Архив</span></button>
                        <button class="btn-download-all" data-doc-ids="${otherFiles.map(d => d.id).join(',')}" title="Скачать все по отдельности">${downloadIcon}<span>Все</span></button>
                    </div>
                </div>
                <ul class="document-sublist">${renderList(otherFiles)}</ul>
            </div>` : '';

        // для terminal-статусов (Утверждена/Отклонена/Отозвана)
        // upload запрещён на сервере и UI-обещание не должно появляться.
        const uploaderHtml = isTerminalStatus(status) ? '' : `
                <div class="detail-file-uploader" id="detailFileUploader">
                    <ul id="detail-file-list-container" class="file-list"></ul>
                    <div class="uploader-footer">
                        <label for="detail_req_files" class="uploader-prompt">
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                            <span>Перетащите файлы или <strong>нажмите для выбора</strong></span>
                        </label>
                    </div>
                    <form id="uploadForm" class="upload-form hidden">
                        <input type="file" id="detail_req_files" name="documentFiles" multiple class="hidden">
                        <button type="submit" class="btn-main">Загрузить выбранные файлы</button>
                    </form>
                </div>`;

        return `
            <div class="detail-block-files">
                <h4>Прикрепленные файлы</h4>
                <div class="document-lists-container">
                    ${signedHtml}
                    ${creatorHtml || otherHtml ? creatorHtml + otherHtml : (signedHtml ? '' : '<p class="no-files-message">Файлов еще нет.</p>')}
                </div>${uploaderHtml}
            </div>`;
    };

    const renderActionsBlock = (request) => {
        let actionsHtml = '';
        const { role } = user;
        const { status_id, creator_id } = request;
        const S = SYSTEM_CONSTANTS.statuses;
        const RN = SYSTEM_CONSTANTS.roleNames;
        const R  = SYSTEM_CONSTANTS.roles;

        if (role === RN[R.MODERATOR]) {
            if (status_id === S.NEW) {
                actionsHtml = `<button id="changeStatusBtn" data-new-status="${S.MODERATION}" data-details="Заявка взята в работу" class="btn-main">Взять в работу</button>`;
            } else if (status_id === S.MODERATION) {
                actionsHtml = `
                    <select id="statusSelect">
                        <option value="${S.APPROVAL}">Отправить на согласование</option>
                        <option value="${S.REWORK}">Вернуть на доработку</option>
                        <option value="${S.REJECTED}">Отклонить</option>
                    </select>
                    <button id="changeStatusBtn" class="btn-main">Применить</button>`;
            }
        } else if (role === RN[R.APPROVER] && status_id === S.APPROVAL) {
            actionsHtml = `
                <select id="statusSelect">
                    <option value="${S.APPROVED}">Одобрить</option>
                    <option value="${S.REWORK}">Вернуть на доработку</option>
                    <option value="${S.REJECTED}">Отклонить</option>
                </select>
                <button id="changeStatusBtn" class="btn-main">Применить</button>`;
        } else if (user.id === creator_id && status_id === S.REWORK) {
            actionsHtml = `
                <p>Заявка возвращена. Внесите изменения и отправьте повторно.</p>
                <button id="changeStatusBtn" data-new-status="${S.MODERATION}" data-details="Заявка повторно отправлена на модерацию" class="btn-main">Отправить повторно</button>`;
        }

        // Кнопка «Отозвать» — только автор, только пока заявка в статусе «Новая»
        // (никто из проверяющих ещё не работал). После взятия модератором
        // отзыв запрещён — нужно отклонять через стандартный workflow.
        if (user.id === creator_id && status_id === S.NEW) {
            const withdrawBtn = `<button id="withdrawBtn" class="btn-secondary btn-withdraw" data-new-status="${S.WITHDRAWN}" data-details="Заявка отозвана автором" style="margin-top:8px;">Отозвать заявку</button>`;
            actionsHtml = (actionsHtml || '<p class="actions-empty-hint">Заявка ожидает первичной обработки модератором.</p>') + withdrawBtn;
        }

        if (actionsHtml) {
            return `<div class="sidebar-block actions"><h4>Действия</h4>${actionsHtml}</div>`;
        }
        return '';
    };

    const renderFeedItem = (item) => `
        <div class="feed-item" data-item-id="${item.id}">
            <div class="avatar">${(item.full_name || 'С').substring(0, 1)}</div>
            <div class="content">
                <div>
                    <span class="author">${sanitizeAndFormatText(item.full_name) || 'Система'}</span>
                    <span class="timestamp">${formatDateTime(item.timestamp)}</span>
                </div>
                <p><strong>${sanitizeAndFormatText(item.action)}</strong><br>${sanitizeAndFormatText(item.details) || ''}</p>
            </div>
        </div>`;

    /**
     * Парсит reactions_raw из БД (формат "👍:3;❤️:5;👍:7") в Map<emoji, Set<userId>>.
     */
    function parseReactions(raw) {
        const map = new Map();
        if (!raw) return map;
        for (const part of raw.split(';')) {
            const [emoji, uid] = part.split(':');
            if (!emoji || !uid) continue;
            if (!map.has(emoji)) map.set(emoji, new Set());
            map.get(emoji).add(parseInt(uid, 10));
        }
        return map;
    }

    function renderReactionsBar(item, currentUserId) {
        const reactions = parseReactions(item.reactions_raw);
        if (reactions.size === 0) return '';
        const chips = [];
        for (const [emoji, users] of reactions) {
            const mine = users.has(currentUserId);
            chips.push(`<button type="button" class="chat-reaction ${mine ? 'mine' : ''}" data-react-emoji="${escapeAttr(emoji)}" data-comment-id="${item.id}" title="${users.size} реакций">${emoji} ${users.size}</button>`);
        }
        return `<div class="chat-reactions">${chips.join('')}</div>`;
    }

    /**
     * детект системных action-сообщений в чате (например,
     * auto-comment при возврате на доработку). Backend пишет с sentinel-
     * префиксом `__sys__:<action>\n<payload>`; backwards-compat также
     * распознаёт старый формат «🔄 Заявка возвращена на доработку. Причина: ».
     * Возвращает {action, payload} или null если это обычное сообщение.
     */
    function parseSystemMessage(text) {
        if (!text) return null;
        if (text.startsWith('__sys__:')) {
            const nl = text.indexOf('\n');
            if (nl > 8) {
                return {
                    action: text.slice('__sys__:'.length, nl),
                    payload: text.slice(nl + 1)
                };
            }
            return { action: text.slice('__sys__:'.length), payload: '' };
        }
        // Legacy-формат до раунда 11 — старые записи в БД.
        const legacy = /^🔄 Заявка возвращена на доработку\. Причина: ([\s\S]+)$/.exec(text);
        if (legacy) return { action: 'rework', payload: legacy[1] };
        return null;
    }

    const SYS_ACTION_META = {
        rework: {
            title: 'Возврат на доработку',
            icon: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="1 4 1 10 7 10"/><polyline points="23 20 23 14 17 14"/><path d="M20.49 9A9 9 0 0 0 5.64 5.64L1 10m22 4l-4.64 4.36A9 9 0 0 1 3.51 15"/></svg>`
        }
    };

    const renderChatItem = (item, currentUserId, isGrouped = false) => {
        const isSelf = item.user_id === currentUserId;
        const isDeleted = !!item.deleted_at;

        // Удалённое сообщение — плейсхолдер. Контента нет, но мы не теряем
        // позицию в ленте (важно если на него были reply).
        if (isDeleted) {
            return `
                <div class="chat-bubble deleted ${isSelf ? 'self' : ''}" data-item-id="${item.id}">
                    <p class="deleted-placeholder"><em>Сообщение удалено</em></p>
                    <span class="timestamp-status">
                        <span>${new Date(item.created_at).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })}</span>
                    </span>
                </div>`;
        }

        // системные action-сообщения (rework и т.п.) — отдельная
        // верстка card-with-divider, центрированная, не bubble. Помогает
        // визуально отделить «действия» от «разговора».
        const sysMsg = parseSystemMessage(item.comment_text);
        if (sysMsg && SYS_ACTION_META[sysMsg.action]) {
            const meta = SYS_ACTION_META[sysMsg.action];
            const time = new Date(item.created_at).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
            const author = sanitizeAndFormatText(item.full_name || '—');
            const payloadHtml = sysMsg.payload
                ? `<blockquote class="chat-sys-payload">${sanitizeAndFormatText(sysMsg.payload)}</blockquote>`
                : '';
            return `
                <div class="chat-sys-event" data-item-id="${item.id}" data-sys-action="${sysMsg.action}">
                    <div class="chat-sys-divider"><span class="chat-sys-title">${meta.icon}${meta.title}</span></div>
                    ${payloadHtml}
                    <div class="chat-sys-meta">${author} · ${time}</div>
                </div>`;
        }

        let statusIcon = '';
        if (isSelf) {
            const readers = item.readers ? item.readers.split(',').map(Number) : [];
            statusIcon = readers.some(r => r !== currentUserId) ? doubleCheckSVG : singleCheckSVG;
        }

        // Цитата (reply): показываем компактный блок с автором и обрезанным текстом
        // родительского сообщения. Клик по цитате — скролл к оригиналу.
        let replyHtml = '';
        if (item.reply_to_id) {
            const parentDeleted = !!item.reply_to_deleted_at;
            // Если родитель — system-action (rework), в цитате показываем
            // человекочитаемое название действия, а не sentinel-префикс.
            const rawParent = item.reply_to_text || '';
            const parentSys = parseSystemMessage(rawParent);
            const cleanParent = parentSys && SYS_ACTION_META[parentSys.action]
                ? `${SYS_ACTION_META[parentSys.action].title}: ${parentSys.payload || ''}`.trim().replace(/:\s*$/, '')
                : rawParent;
            const parentText = parentDeleted
                ? '<em>сообщение удалено</em>'
                : sanitizeAndFormatText(cleanParent.slice(0, 100)) +
                  (cleanParent.length > 100 ? '…' : '');
            const parentAuthor = sanitizeAndFormatText(item.reply_to_user_name || '—');
            replyHtml = `
                <div class="chat-reply-quote" data-scroll-to="${item.reply_to_id}" title="Перейти к исходному сообщению">
                    <span class="chat-reply-author">${parentAuthor}</span>
                    <span class="chat-reply-text">${parentText}</span>
                </div>`;
        }

        const editedMark = item.edited_at ? '<span class="chat-edited" title="Отредактировано">(изм.)</span>' : '';

        // Иконки действий — только для своих сообщений (delete также для админа).
        // SVG-иконки вместо emoji. На некоторых сборках Windows/Chrome
        // U+1F5D1 (🗑 Wastebasket) не имеет glyph-фолбэка → button рендерится
        // визуально пустой. SVG монохромные — стилизуются через `currentColor`,
        // подхватывают `:hover` цвет.
        const isAdminUser = user.role === 'Администратор';
        const canDelete = isSelf || isAdminUser;
        const ICON_REACT  = `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="M8 14s1.5 2 4 2 4-2 4-2"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/></svg>`;
        const ICON_REPLY  = `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="9 17 4 12 9 7"/><path d="M20 18v-2a4 4 0 0 0-4-4H4"/></svg>`;
        const ICON_EDIT   = `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>`;
        const ICON_DELETE = `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v2"/></svg>`;
        const actionsHtml = `
            <div class="chat-actions">
                <button type="button" class="chat-action-btn" data-action="react" data-item-id="${item.id}" title="Реакция" aria-label="Добавить реакцию">${ICON_REACT}</button>
                <button type="button" class="chat-action-btn" data-action="reply" data-item-id="${item.id}" title="Ответить" aria-label="Ответить на сообщение">${ICON_REPLY}</button>
                ${isSelf ? `<button type="button" class="chat-action-btn" data-action="edit" data-item-id="${item.id}" title="Редактировать" aria-label="Редактировать сообщение">${ICON_EDIT}</button>` : ''}
                ${canDelete ? `<button type="button" class="chat-action-btn chat-action-danger" data-action="delete" data-item-id="${item.id}" title="Удалить" aria-label="Удалить сообщение">${ICON_DELETE}</button>` : ''}
            </div>`;

        const groupedClass = isGrouped ? 'grouped' : '';
        const reactionsBar = renderReactionsBar(item, currentUserId);

        const timeStr = new Date(item.created_at).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
        const timestampHtml = `<span class="timestamp-status"><span>${timeStr}</span>${editedMark}${statusIcon}</span>`;

        // (final): Telegram-style adaptive layout.
        // • Без реакций → timestamp float'ится в правом-нижнем углу текста
        // (compact, без пустой строки)
        // • С реакциями → footer-row с реакциями слева и timestamp справа
        // (парность вместо «осиротевшего» левого блока с пустым правым)
        const bodyHtml = reactionsBar
            ? `<p data-content="text">${sanitizeAndFormatText(item.comment_text)}</p>
               <div class="chat-bubble-footer">${reactionsBar}${timestampHtml}</div>`
            : `<p data-content="text">${sanitizeAndFormatText(item.comment_text)}${timestampHtml}</p>`;

        return `
            <div class="${isSelf ? 'chat-bubble self' : 'chat-bubble'} ${groupedClass}" data-item-id="${item.id}">
                ${!isGrouped && !isSelf ? `<span class="author">${sanitizeAndFormatText(item.full_name)}</span>` : ''}
                ${replyHtml}
                ${bodyHtml}
                ${actionsHtml}
            </div>`;
    };

    // Состояние reply: на какое сообщение отвечаем сейчас. Виден preview-бар над
    // полем ввода. Сбрасывается после отправки или клика на «×».
    let replyingTo = null;

    /**
     * Toggle реакции через POST /api/comments/:id/reactions.
     */
    async function sendReaction(commentId, emoji) {
        try {
            const r = await secureFetch(`/api/comments/${commentId}/reactions`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ emoji })
            });
            if (!r.ok) {
                const d = await r.json().catch(() => ({}));
                showToast(d.message || 'Реакция не сохранена', 'error');
            }
            // detail_update прилетит через WS, перерендерит чат сам.
        } catch (e) {
            showToast('Ошибка сети при реакции', 'error');
        }
    }

    /**
     * Мини-picker emoji-реакций. Появляется над кнопкой 😊, закрывается
     * по клику в любом месте.
     */
    function openReactionPicker(anchorBtn, commentId) {
        // Удалить старый picker если есть
        document.querySelectorAll('.reaction-picker').forEach(p => p.remove());

        const picker = document.createElement('div');
        picker.className = 'reaction-picker';
        const REACTIONS = ['👍', '❤️', '😂', '😢', '🔥', '👏'];
        picker.innerHTML = REACTIONS.map(e =>
            `<button type="button" class="reaction-pick-btn" data-emoji="${e}">${e}</button>`
        ).join('');
        document.body.appendChild(picker);

        const rect = anchorBtn.getBoundingClientRect();
        picker.style.position = 'fixed';
        picker.style.top  = (rect.top - 44) + 'px';
        picker.style.left = Math.min(rect.left, window.innerWidth - 280) + 'px';

        picker.addEventListener('click', (e) => {
            const btn = e.target.closest('.reaction-pick-btn');
            if (!btn) return;
            sendReaction(commentId, btn.dataset.emoji);
            picker.remove();
        });

        const closeOnce = (ev) => {
            if (!picker.contains(ev.target) && ev.target !== anchorBtn) {
                picker.remove();
                document.removeEventListener('click', closeOnce);
            }
        };
        // setTimeout чтобы текущий click event'а bubble'нулся прежде чем мы повесим listener
        setTimeout(() => document.addEventListener('click', closeOnce), 50);
    }

    /**
     * Typing indicator: при вводе в textarea рассылаем WS-событие 'typing'
     * не чаще раза в 3 секунды, отображаем входящие 5 секунд.
     */
    let _typingSentAt = 0;
    function notifyTypingFromMe() {
        const now = Date.now();
        if (now - _typingSentAt < 3000) return;
        _typingSentAt = now;
        if (globalWs?.readyState === WebSocket.OPEN) {
            try { globalWs.send(JSON.stringify({ type: 'typing' })); } catch (_) {}
        }
    }

    // _typingUsers объявлен в module-scope выше (для handleRouteChange cleanup).
    function showTypingFromOther(userId, fullName) {
        if (!userId || userId === user.id) return;
        _typingUsers.set(userId, { name: fullName, expireAt: Date.now() + 5000 });
        ensureTypingTick();
        renderTypingBar();
    }
    function renderTypingBar() {
        const chatPane = detailView.querySelector('.chat-pane');
        if (!chatPane) {
            // Чат закрыт — гасим interval, чтобы не молотить вхолостую раз в секунду.
            if (_typingTickInterval) { clearInterval(_typingTickInterval); _typingTickInterval = null; }
            _typingUsers.clear();
            return;
        }
        let bar = chatPane.querySelector('.chat-typing-bar');
        // Чистим протухшие
        const now = Date.now();
        for (const [uid, info] of _typingUsers) {
            if (info.expireAt < now) _typingUsers.delete(uid);
        }
        if (_typingUsers.size === 0) {
            if (bar) bar.remove();
            // Никто не печатает — interval больше не нужен, перезапустится на next event.
            if (_typingTickInterval) { clearInterval(_typingTickInterval); _typingTickInterval = null; }
            return;
        }
        if (!bar) {
            bar = document.createElement('div');
            bar.className = 'chat-typing-bar';
            const form = chatPane.querySelector('.comment-form');
            if (form) chatPane.insertBefore(bar, form);
            else chatPane.appendChild(bar);
        }
        const names = Array.from(_typingUsers.values()).map(x => sanitizeAndFormatText(x.name)).join(', ');
        bar.innerHTML = `<span class="typing-dots">${names} печатает<span>.</span><span>.</span><span>.</span></span>`;
    }
    // _typingTickInterval объявлен в module-scope выше. Запускаем
    // только когда есть кто-то печатающий (раньше крутился навсегда).
    function ensureTypingTick() {
        if (_typingTickInterval) return;
        _typingTickInterval = setInterval(renderTypingBar, 1000);
    }

    function sendHistoryReadBatch(requestId) {
        if (readHistoryBatch.length === 0) return;
        const idsToSend = [...new Set(readHistoryBatch)];
        readHistoryBatch = [];
        secureFetch(`/api/requests/${requestId}/history/mark-read`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ historyIds: idsToSend }),
        }).catch(err => console.error('Не удалось отметить историю как прочтённую:', err));
    }

    const setupIntersectionObserver = (feed, unreadSet, type) => {
        if (!feed) return null;
        const observer = new IntersectionObserver((entries) => {
            const visibleUnreadIds = [];
            const newlyVisibleHistoryIds = [];
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const itemId = parseInt(entry.target.dataset.itemId, 10);
                    if (unreadSet.has(itemId)) {
                        unreadSet.delete(itemId);
                        updateBadge(type, unreadSet.size);
                        observer.unobserve(entry.target);
                        if (type === 'chat') {
                            visibleUnreadIds.push(itemId);
                        } else if (type === 'activity') {
                            newlyVisibleHistoryIds.push(itemId);
                        }
                    }
                }
            });
            if (visibleUnreadIds.length > 0 && globalWs?.readyState === WebSocket.OPEN) {
                globalWs.send(JSON.stringify({ type: 'messages_read', messageIds: visibleUnreadIds }));
            }
            if (newlyVisibleHistoryIds.length > 0) {
                readHistoryBatch.push(...newlyVisibleHistoryIds);
                clearTimeout(historyReadTimer);
                const requestId = window.location.hash.split('/')[2];
                historyReadTimer = setTimeout(() => sendHistoryReadBatch(requestId), 1500);
            }
            // threshold 0.5 вместо 0.8.
            // Длинные сообщения (выше viewport'а chat-feed) при 0.8 НИКОГДА
            // не достигают порога → IntersectionObserver не помечает их
            // прочитанными → badge на заявке всегда «новое». 0.5 = половина
            // bubble в viewport — для длинных сообщений достижимо при scroll'е.
        }, { root: feed, threshold: 0.5 });
        return observer;
    };

    /**
     * явный bulk-mark всех непрочитанных при открытии чата.
     * IntersectionObserver работает только когда сообщение уже в viewport ПОСЛЕ
     * scroll'а. Если юзер кликает на «Чат», видит сообщения, но scroll-position
     * не движется (контент компактный) — observer может не сработать вовсе для
     * сообщений выше viewport. Здесь принудительно отправляем messages_read для
     * ВСЕХ unread в текущей заявке.
     */
    function markAllChatRead() {
        if (!unreadCommentIds || unreadCommentIds.size === 0) return;
        const ids = Array.from(unreadCommentIds);
        unreadCommentIds.clear();
        updateBadge('chat', 0);
        // disconnect observer'а ПЕРЕД отправкой.
        // Без этого race: scrollIntoView smooth-анимация триггерит observer,
        // он шлёт messages_read с 1-3 ids → server cooldown 200ms активен →
        // наш bulk-send с остальными 27 ids ОТБРАСЫВАЕТСЯ. Disconnect
        // гарантирует что server увидит только ОДИН наш bulk-call.
        if (commentObserver) {
            commentObserver.disconnect();
        }
        if (globalWs?.readyState === WebSocket.OPEN) {
            globalWs.send(JSON.stringify({ type: 'messages_read', messageIds: ids }));
        }
    }

    const updateBadge = (type, count) => {
        const button = detailView.querySelector(`.switcher-btn[data-view="${type}"]`);
        if (!button) return;
        let badge = button.querySelector('.notification-badge');
        if (count > 0) {
            if (!badge) {
                badge = document.createElement('span');
                badge.className = 'notification-badge';
                button.appendChild(badge);
            }
            badge.textContent = count;
        } else {
            if (badge) badge.remove();
        }
    };

    async function downloadAllIndividually(docIds, button) {
        button.disabled = true;
        const originalText = button.querySelector('span').textContent;
        button.querySelector('span').textContent = 'Скачивание...';
        const filesToDownload = currentDocumentsInView.filter(doc => docIds.includes(doc.id.toString()));
        const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

        for (const doc of filesToDownload) {
            try {
                const res = await secureFetch(`/api/documents/${doc.id}/download`);
                if (!res.ok) throw new Error(`Ошибка загрузки ${doc.file_name}`);

                const blob = await res.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.style.display = 'none';
                a.href = url;
                a.download = doc.file_name;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                a.remove();
                await delay(300);
            } catch (error) {
                console.error('Ошибка скачивания файла:', error);
                showToast(`Не удалось скачать файл: ${doc.file_name}`, 'error');
            }
        }
        button.disabled = false;
        button.querySelector('span').textContent = originalText;
    }

    async function downloadAsZip(docIds, button) {
        button.disabled = true;
        const originalText = button.querySelector('span').textContent;
        button.querySelector('span').textContent = 'Архивация...';
        try {
            const url = `/api/documents/download-archive?ids=${docIds.join(',')}`;
            const response = await secureFetch(url);
            if (!response.ok) {
                throw new Error(`Ошибка сервера: ${response.statusText}`);
            }
            const blob = await response.blob();
            const downloadUrl = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = downloadUrl;
            a.download = `archive-${Date.now()}.zip`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(downloadUrl);
            a.remove();
        } catch (error) {
            console.error('Ошибка при скачивании архива:', error);
            showToast('Не удалось скачать архив.', 'error');
        } finally {
            button.disabled = false;
            button.querySelector('span').textContent = originalText;
        }
    }

    function modalHandlers() {
        const reqTitleInput = document.getElementById('req_title');
        const reqDescriptionInput = document.getElementById('req_description');
        const fileUploader = document.getElementById('fileUploader');
        const fileListContainer = document.getElementById('file-list-container');
        const uploaderPrompt = document.querySelector('#createRequestModal .uploader-prompt');
        const addMoreBtn = document.getElementById('addMoreBtn');
        const fileInput = document.getElementById('req_files');
        const reqDate = document.getElementById('req_date');
        const dateErrorMessage = document.querySelector('#createRequestModal .date-error-message');
        const reqCategorySelect = document.getElementById('req_category');
        const reqLocationInput = document.getElementById('req_location');
        const reqAttendeesInput = document.getElementById('req_attendees');
        const reqResponsibleInput = document.getElementById('req_responsible');
        const categoryColorIndicator = document.getElementById('categoryColorIndicator');

        const updateCategoryIndicator = () => {
            const selected = reqCategorySelect.options[reqCategorySelect.selectedIndex];
            const color = selected?.dataset.color || 'transparent';
            categoryColorIndicator.style.backgroundColor = color;
        };

        const populateCategoriesIfNeeded = async () => {
            if (reqCategorySelect.options.length > 1) return;
            const cats = await loadEventCategories();
            cats.forEach(c => {
                const opt = document.createElement('option');
                opt.value = c.id;
                opt.textContent = c.name;
                opt.dataset.color = c.color_hex;
                reqCategorySelect.appendChild(opt);
            });
        };

        reqCategorySelect.addEventListener('change', async () => {
            updateCategoryIndicator();
            const errEl = reqCategorySelect.closest('.input-group').querySelector('.form-error-message');
            if (reqCategorySelect.value) {
                reqCategorySelect.classList.remove('error');
                if (errEl) errEl.style.display = 'none';
            }
            // Автозаполнение из шаблона — только если поля ещё пустые,
            // чтобы не перетереть то что юзер уже ввёл руками.
            await applyTemplateIfEmpty(reqCategorySelect.value);
        });

        // Подгрузка шаблона по категории и автозаполнение пустых полей формы.
        async function applyTemplateIfEmpty(categoryId) {
            if (!categoryId) return;
            try {
                const r = await secureFetch(`/api/templates/${categoryId}`);
                if (!r.ok) return;
                const tpl = await r.json();
                if (!tpl) return;

                const titleInput = document.getElementById('req_title');
                const descInput  = document.getElementById('req_description');
                if (titleInput && !titleInput.value.trim() && tpl.default_title) {
                    titleInput.value = tpl.default_title;
                }
                if (descInput && !descInput.value.trim() && tpl.default_description) {
                    descInput.value = tpl.default_description;
                }
                if (reqLocationInput && !reqLocationInput.value.trim() && tpl.default_location) {
                    reqLocationInput.value = tpl.default_location;
                }
                if (reqResponsibleInput && !reqResponsibleInput.value.trim() && tpl.default_responsible) {
                    reqResponsibleInput.value = tpl.default_responsible;
                }
                if (reqAttendeesInput && !reqAttendeesInput.value.trim() && tpl.default_attendees) {
                    reqAttendeesInput.value = tpl.default_attendees;
                }
                showToast('Шаблон применён. Отредактируйте под ваше мероприятие.', 'info', 4000);
            } catch (e) {
                console.error('Не удалось загрузить шаблон:', e);
            }
        }

        const validateDate = () => {
            const selected = new Date(reqDate.value);
            if (reqDate.value && selected < new Date()) {
                dateErrorMessage.textContent = 'Нельзя выбрать прошедшую дату.';
                dateErrorMessage.style.display = 'block';
                reqDate.classList.add('error');
                return false;
            } else {
                dateErrorMessage.style.display = 'none';
                reqDate.classList.remove('error');
                return true;
            }
        };

        const clearContentErrorIfValid = () => {
            if (reqDescriptionInput.value.trim() !== '' || selectedFiles.length > 0) {
                const err = reqDescriptionInput.parentElement.querySelector('.form-error-message');
                reqDescriptionInput.classList.remove('error');
                fileUploader.classList.remove('error');
                err.style.display = 'none';
            }
        };

        openModalBtn.addEventListener('click', async () => {
            const now = new Date();
            now.setMinutes(now.getMinutes() - now.getTimezoneOffset());
            reqDate.min = now.toISOString().slice(0, 16);
            await populateCategoriesIfNeeded();
            reqCategorySelect.selectedIndex = 0; // сбросить на «Выберите категорию...» (autofill safeguard)
            updateCategoryIndicator();
            createModal.classList.add('active');
            // a11y для статической модалки. Без него Tab уходил
            // в фон, Esc не закрывал. Бекенд: setupModalA11y с closeFn вместо
            // remove() — модалка живёт в DOM, переключаем classList.
            // E2/H-7: сохраняем cleanup-callback от setupModalA11y.
            // closeCreateModal внизу его вызовет — abort'ит keydown listener
            // во ВСЕХ путях закрытия (X / backdrop / Esc / submit-success),
            // не только Esc.
            const a11yCleanup = setupModalA11y(createModal, {
                closeFn: () => createModal.classList.remove('active')
            });
            createModal._a11yCleanup = a11yCleanup;
        });
        const closeCreateModal = () => {
            createModal.classList.remove('active');
            // Снимаем keydown listener — иначе он висит на скрытой модалке
            // до следующего open'а. Не security-issue (overlay скрыт CSS'ом),
            // но грязно. Идемпотентно: cleanup сам no-op'ится если ctrl уже
            // abort'нут или не был создан.
            if (typeof createModal._a11yCleanup === 'function') {
                createModal._a11yCleanup();
                createModal._a11yCleanup = null;
            }
        };
        document.getElementById('closeCreateModalBtn').addEventListener('click', closeCreateModal);
        document.getElementById('closeCreateModalCross')?.addEventListener('click', closeCreateModal);
        createModal.addEventListener('click', e => {
            if (e.target === createModal) closeCreateModal();
        });

        reqDate.addEventListener('input', validateDate);

        reqTitleInput.addEventListener('input', () => {
            if (reqTitleInput.value.trim() !== '') {
                reqTitleInput.classList.remove('error');
                reqTitleInput.parentElement.querySelector('.form-error-message').style.display = 'none';
            }
        });
        reqDescriptionInput.addEventListener('input', clearContentErrorIfValid);

        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(ev =>
            fileUploader.addEventListener(ev, e => { e.preventDefault(); e.stopPropagation(); })
        );
        ['dragenter', 'dragover'].forEach(ev =>
            fileUploader.addEventListener(ev, () => fileUploader.classList.add('dragover'))
        );
        ['dragleave', 'drop'].forEach(ev =>
            fileUploader.addEventListener(ev, () => fileUploader.classList.remove('dragover'))
        );

        fileUploader.addEventListener('drop', e => handleFiles(e.dataTransfer.files));
        fileInput.addEventListener('change', e => handleFiles(e.target.files));
        addMoreBtn.addEventListener('click', () => fileInput.click());

        function handleFiles(files) {
            // client-side size cap. Файлы >15МБ — skip + toast.
            const filtered = filterByMaxSize(files);
            for (const file of filtered) {
                if (!selectedFiles.some(f => f.name === file.name && f.size === file.size)) {
                    selectedFiles.push(file);
                }
            }
            updateFileList();
            clearContentErrorIfValid();
        }

        function updateFileList() {
            fileUploader.classList.toggle('has-files', selectedFiles.length > 0);
            uploaderPrompt.classList.toggle('hidden', selectedFiles.length > 0);
            addMoreBtn.classList.toggle('hidden', selectedFiles.length === 0);
            fileListContainer.innerHTML = selectedFiles.map((file, index) =>
                `<li class="file-list-item">
                    <span class="file-icon">${getFileIcon(file.name)}</span>
                    <span class="file-list-item-name" title="${escapeAttr(file.name)}">${sanitizeAndFormatText(file.name)}</span>
                    <button type="button" class="file-list-item-remove" data-index="${index}" aria-label="Убрать файл из загрузки">&times;</button>
                </li>`
            ).join('');
        }
        fileListContainer.addEventListener('click', e => {
            if (e.target.classList.contains('file-list-item-remove')) {
                selectedFiles.splice(parseInt(e.target.dataset.index, 10), 1);
                updateFileList();
                clearContentErrorIfValid();
            }
        });
        createForm.addEventListener('submit', async e => {
            e.preventDefault();
            const titleError = reqTitleInput.parentElement.querySelector('.form-error-message');
            const descriptionError = reqDescriptionInput.parentElement.querySelector('.form-error-message');
            const categoryError = reqCategorySelect.closest('.input-group').querySelector('.form-error-message');
            let isFormValid = true;

            reqTitleInput.classList.remove('error');
            titleError.style.display = 'none';
            reqDescriptionInput.classList.remove('error');
            fileUploader.classList.remove('error');
            descriptionError.style.display = 'none';
            reqDate.classList.remove('error');
            dateErrorMessage.style.display = 'none';
            reqCategorySelect.classList.remove('error');
            if (categoryError) categoryError.style.display = 'none';

            if (reqTitleInput.value.trim() === '') {
                titleError.textContent = 'Пожалуйста, введите название мероприятия.';
                titleError.style.display = 'block';
                reqTitleInput.classList.add('error');
                isFormValid = false;
            }
            if (!reqCategorySelect.value) {
                if (categoryError) {
                    categoryError.textContent = 'Пожалуйста, выберите категорию мероприятия.';
                    categoryError.style.display = 'block';
                }
                reqCategorySelect.classList.add('error');
                isFormValid = false;
            }
            if (!reqDate.value) {
                dateErrorMessage.textContent = 'Пожалуйста, укажите дату и время.';
                dateErrorMessage.style.display = 'block';
                reqDate.classList.add('error');
                isFormValid = false;
            } else if (!validateDate()) {
                isFormValid = false;
            }
            if (reqDescriptionInput.value.trim() === '' && selectedFiles.length === 0) {
                descriptionError.textContent = 'Необходимо добавить описание или прикрепить хотя бы один файл.';
                descriptionError.style.display = 'block';
                reqDescriptionInput.classList.add('error');
                fileUploader.classList.add('error');
                isFormValid = false;
            }
            if (!isFormValid) return;

            const formData = new FormData();
            formData.append('title', reqTitleInput.value);
            formData.append('description', reqDescriptionInput.value);
            formData.append('planned_date', reqDate.value);
            formData.append('category_id', reqCategorySelect.value);
            if (reqLocationInput.value.trim()) formData.append('location', reqLocationInput.value.trim());
            if (reqAttendeesInput.value) formData.append('expected_attendees', reqAttendeesInput.value);
            if (reqResponsibleInput.value.trim()) formData.append('responsible_person', reqResponsibleInput.value.trim());
            selectedFiles.forEach(f => formData.append('documentFiles', f));

            const submitBtn = createForm.querySelector('button[type="submit"]');
            submitBtn.disabled = true;
            submitBtn.textContent = 'Отправка...';

            const modalErr = document.getElementById('modalErrorMessage');
            modalErr.textContent = '';
            modalErr.classList.remove('visible');

            try {
                    const res = await secureFetch('/api/requests', { method: 'POST', body: formData });
                    if (!res.ok) {
                        const err = await res.json();
                        if (res.status === 403 && err.locked_until) {
                            showToast(err.message, 'error', 9000);
                            setTimeout(() => window.location.href = '/login', 2500);
                            return;
                        }
                        // Сообщение от сервера показываем в модалке (рядом с формой) и тоастом
                        const msg = err.message || 'Не удалось создать заявку';
                        modalErr.textContent = msg;
                        modalErr.classList.add('visible');
                        if (err.severity) {
                            showSecurityToast(err);
                        } else {
                            showToast(msg, 'error', 6000);
                        }
                    } else {
                        // E2/H-7: closeCreateModal вместо raw classList.remove
                        // — отвязывает keydown-listener вместе со скрытием модалки.
                        closeCreateModal();
                        createForm.reset();
                        selectedFiles = [];
                        updateFileList();
                        updateCategoryIndicator();
                        resetToFirstPageAndRender();
                        showToast('Заявка успешно создана', 'success');
                    }
                } catch (err) {
                    modalErr.textContent = 'Ошибка сети. Попробуйте снова.';
                    modalErr.classList.add('visible');
                    showToast('Ошибка сети', 'error');
                } finally {
                    submitBtn.disabled = false;
                    submitBtn.textContent = 'Отправить заявку';
                }
        });
    }

    document.getElementById('logoutButton').addEventListener('click', handleLogout);

    backToListBtn.addEventListener('click', () => { window.location.hash = ''; });

    document.querySelectorAll('.view-mode-btn').forEach(btn => {
        btn.addEventListener('click', () => setViewMode(btn.dataset.viewMode));
    });

    requestsListEl.addEventListener('click', (e) => {
        // Чекбокс batch — обрабатываем отдельно, не открываем заявку.
        const cb = e.target.closest('.request-checkbox');
        if (cb) {
            e.stopPropagation();
            const id = parseInt(cb.dataset.batchId, 10);
            if (Number.isInteger(id)) {
                if (cb.checked) batchState.selectedIds.add(id);
                else batchState.selectedIds.delete(id);
                cb.closest('.request-item')?.classList.toggle('batch-selected', cb.checked);
                updateBatchBar();
            }
            return;
        }
        const item = e.target.closest('.request-item');
        if (item) {
            window.location.hash = `#/request/${item.dataset.requestId}`;
        }
    });

    // Batch action-bar
    document.addEventListener('click', (e) => {
        if (e.target.id === 'batchApplyBtn') {
            applyBatchStatus();
        } else if (e.target.id === 'batchClearBtn') {
            clearBatchSelection();
        }
    });

    searchInput.addEventListener('input', () => {
        clearTimeout(searchInput.timer);
        searchInput.timer = setTimeout(resetToFirstPageAndRender, 400);
    });

    filterPanel.addEventListener('change', (e) => {
        if (e.target.type === 'date' || e.target.type === 'checkbox') {
            resetToFirstPageAndRender();
        }
    });

    openFilterBtn.addEventListener('click', () => filterPanel.classList.toggle('active'));

    /**
     * Экспорт списка заявок в Excel. Берёт текущие активные фильтры и
     * формирует тот же query-string, что использует /api/requests.
     * Скачивание идёт через временный <a download> + objectURL.
     */
    document.getElementById('exportExcelBtn')?.addEventListener('click', async () => {
        const btn = document.getElementById('exportExcelBtn');
        btn.disabled = true;
        const old = btn.innerHTML;
        btn.innerHTML = '<span>Подготовка…</span>';
        try {
            const params = new URLSearchParams();
            if (searchInput.value.trim()) params.append('search', searchInput.value.trim());
            [...statusOptionsContainer.querySelectorAll('input:checked')].forEach(cb => params.append('status', cb.value));
            if (authorOptionsContainer) {
                [...authorOptionsContainer.querySelectorAll('input:checked')].forEach(cb => params.append('authorId', cb.value));
            }
            if (categoryOptionsContainer) {
                [...categoryOptionsContainer.querySelectorAll('input:checked')].forEach(cb => params.append('categoryId', cb.value));
            }
            if (branchOptionsContainer) {
                [...branchOptionsContainer.querySelectorAll('input:checked')].forEach(cb => params.append('branchId', cb.value));
            }
            if (dateCreatedFromInput.value) params.append('createdFrom', dateCreatedFromInput.value);
            if (dateCreatedToInput.value)   params.append('createdTo',   dateCreatedToInput.value);
            if (dateUpdatedFromInput.value) params.append('updatedFrom', dateUpdatedFromInput.value);
            if (dateUpdatedToInput.value)   params.append('updatedTo',   dateUpdatedToInput.value);

            const r = await secureFetch(`/api/requests/export.xlsx?${params}`);
            if (!r.ok) {
                const err = await r.json().catch(() => ({}));
                throw new Error(err.message || 'Ошибка экспорта');
            }
            const blob = await r.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `vitenergo-requests-${new Date().toISOString().slice(0, 10)}.xlsx`;
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);
            showToast('Файл сохранён', 'success');
        } catch (e) {
            showToast('Не удалось скачать: ' + e.message, 'error');
        } finally {
            btn.disabled = false;
            btn.innerHTML = old;
        }
    });

    document.addEventListener('click', e => {
        const pageBtn = e.target.closest('#listView .page-item');
        if (pageBtn && !pageBtn.disabled) {
            if (pageBtn.classList.contains('prev')) {
                currentPage--;
            } else if (pageBtn.classList.contains('next')) {
                currentPage++;
            } else {
                currentPage = parseInt(pageBtn.dataset.page, 10);
            }
            renderListView();
            return;
        }

        const filterTagBtn = e.target.closest('.filter-tag button, .btn-reset-all');
        if (filterTagBtn) {
            if (filterTagBtn.classList.contains('btn-reset-all')) {
                searchInput.value = '';
                [...statusOptionsContainer.querySelectorAll('input:checked')].forEach(cb => cb.checked = false);
                if (authorOptionsContainer) [...authorOptionsContainer.querySelectorAll('input:checked')].forEach(cb => cb.checked = false);
                if (categoryOptionsContainer) [...categoryOptionsContainer.querySelectorAll('input:checked')].forEach(cb => cb.checked = false);
                if (branchOptionsContainer) [...branchOptionsContainer.querySelectorAll('input:checked')].forEach(cb => cb.checked = false);
                dateCreatedFromInput.value = '';
                dateCreatedToInput.value = '';
                dateUpdatedFromInput.value = '';
                dateUpdatedToInput.value = '';
            } else {
                const { filterType, filterValue } = filterTagBtn.dataset;
                if (filterType === 'status') {
                    statusOptionsContainer.querySelector(`input[value="${filterValue}"]`).checked = false;
                }
                if (filterType === 'author') {
                    authorOptionsContainer.querySelector(`input[value="${filterValue}"]`).checked = false;
                }
                if (filterType === 'category' && categoryOptionsContainer) {
                    const cb = categoryOptionsContainer.querySelector(`input[value="${filterValue}"]`);
                    if (cb) cb.checked = false;
                }
                if (filterType === 'branch' && branchOptionsContainer) {
                    const cb = branchOptionsContainer.querySelector(`input[value="${filterValue}"]`);
                    if (cb) cb.checked = false;
                }
                if (filterType === 'dateCreatedFrom') dateCreatedFromInput.value = '';
                if (filterType === 'dateCreatedTo') dateCreatedToInput.value = '';
                if (filterType === 'dateUpdatedFrom') dateUpdatedFromInput.value = '';
                if (filterType === 'dateUpdatedTo') dateUpdatedToInput.value = '';
            }
            resetToFirstPageAndRender();
            return;
        }

        if (!filterPanel.contains(e.target) && !openFilterBtn.contains(e.target)) {
            filterPanel.classList.remove('active');
        }
        if (authorFilterContainer && !authorFilterContainer.contains(e.target)) {
            authorDropdown.classList.remove('visible');
            authorSelectBox.classList.remove('open');
        }
        if (statusSelectBox && !statusSelectBox.closest('.filter-panel').contains(e.target) && !e.target.closest('.select-box')) {
            statusDropdown.classList.remove('visible');
            statusSelectBox.classList.remove('open');
        }
        // close category dropdown при клике вне filter-panel.
        if (categoryFilterContainer && !categoryFilterContainer.contains(e.target)) {
            categoryDropdown.classList.remove('visible');
            categorySelectBox.classList.remove('open');
        }
        // close branch dropdown.
        if (branchFilterContainer && !branchFilterContainer.contains(e.target)) {
            branchDropdown.classList.remove('visible');
            branchSelectBox.classList.remove('open');
        }
    });

    const updateStatusFilterSelection = () => {
        const selected = [...statusOptionsContainer.querySelectorAll('input:checked')];
        const placeholder = statusSelectBox.querySelector('span');
        if (selected.length === 0) {
            placeholder.textContent = 'Все статусы';
        } else if (selected.length <= 2) {
            placeholder.textContent = selected.map(cb => cb.value).join(', ');
        } else {
            placeholder.textContent = `Выбрано: ${selected.length}`;
        }
    };
    statusSelectBox.addEventListener('click', () => {
        statusDropdown.classList.toggle('visible');
        statusSelectBox.classList.toggle('open');
    });

    // click + selection display для категории-фильтра.
    const updateCategoryFilterSelection = () => {
        if (!categorySelectBox) return;
        const selected = [...categoryOptionsContainer.querySelectorAll('input:checked')];
        const placeholder = categorySelectBox.querySelector('span');
        if (selected.length === 0) {
            placeholder.textContent = 'Все категории';
        } else if (selected.length <= 2) {
            placeholder.textContent = selected.map(cb => cb.dataset.name).join(', ');
        } else {
            placeholder.textContent = `Выбрано: ${selected.length}`;
        }
    };
    if (categorySelectBox) {
        categorySelectBox.addEventListener('click', () => {
            categoryDropdown.classList.toggle('visible');
            categorySelectBox.classList.toggle('open');
        });
    }

    // branch-filter dropdown.
    const updateBranchFilterSelection = () => {
        if (!branchSelectBox) return;
        const selected = [...branchOptionsContainer.querySelectorAll('input:checked')];
        const placeholder = branchSelectBox.querySelector('span');
        if (selected.length === 0) {
            placeholder.textContent = 'Все филиалы';
        } else if (selected.length <= 2) {
            placeholder.textContent = selected.map(cb => cb.dataset.name).join(', ');
        } else {
            placeholder.textContent = `Выбрано: ${selected.length}`;
        }
    };
    if (branchSelectBox) {
        branchSelectBox.addEventListener('click', () => {
            branchDropdown.classList.toggle('visible');
            branchSelectBox.classList.toggle('open');
            if (branchDropdown.classList.contains('visible') && branchSearchInput) {
                branchSearchInput.focus();
                branchSearchInput.value = '';
                branchOptionsContainer.querySelectorAll('label').forEach(l => l.style.display = '');
            }
        });
    }
    // Live-search в branch dropdown'е (как у author).
    if (branchSearchInput) {
        branchSearchInput.addEventListener('input', () => {
            const q = branchSearchInput.value.toLowerCase().trim();
            branchOptionsContainer.querySelectorAll('label').forEach(l => {
                const txt = l.textContent.toLowerCase();
                l.style.display = q && !txt.includes(q) ? 'none' : '';
            });
        });
    }

    const updateAuthorFilterSelection = () => {
        if (!authorSelectBox) return;
        const selected = [...authorOptionsContainer.querySelectorAll('input:checked')];
        const placeholder = authorSelectBox.querySelector('span');
        if (selected.length === 0) {
            placeholder.textContent = 'Все авторы';
        } else if (selected.length <= 2) {
            placeholder.textContent = selected.map(cb => cb.dataset.name).join(', ');
        } else {
            placeholder.textContent = `Выбрано: ${selected.length}`;
        }
    };

    if (authorSelectBox) {
        authorSelectBox.addEventListener('click', () => {
            authorDropdown.classList.toggle('visible');
            authorSelectBox.classList.toggle('open');
            if (authorDropdown.classList.contains('visible')) {
                authorSearchInput.focus();
                authorSearchInput.value = '';
                authorOptionsContainer.querySelectorAll('label').forEach(label => label.style.display = '');
            }
        });
        authorSearchInput.addEventListener('input', () => {
            const query = authorSearchInput.value.toLowerCase();
            let hasResults = false;
            authorOptionsContainer.querySelectorAll('label').forEach(label => {
                const name = label.querySelector('span').textContent.toLowerCase();
                const isVisible = name.includes(query);
                label.style.display = isVisible ? '' : 'none';
                if (isVisible) hasResults = true;
            });
            const noResultsEl = authorOptionsContainer.querySelector('.no-results');
            if (!hasResults && !noResultsEl) {
                authorOptionsContainer.insertAdjacentHTML('beforeend', `<div class="no-results">Не найдено</div>`);
            } else if (hasResults && noResultsEl) {
                noResultsEl.remove();
            }
        });
    }

    adminView.addEventListener('click', async (e) => {
        const target = e.target;
        // Переключение вкладок теперь обрабатывается напрямую в renderAdminView
        // через btn.addEventListener — здесь не нужен старый обработчик.

        if (target.closest('.btn-unlock')) {
            const btn = target.closest('.btn-unlock');
            const userId = btn.dataset.unlock;
            btn.disabled = true;
            try {
                const r = await secureFetch(`/api/admin/users/${userId}/unlock`, { method: 'POST' });
                if (!r.ok) {
                    const err = await r.json();
                    throw new Error(err.message || 'Ошибка');
                }
                showToast('Блокировка снята', 'success');
                if (adminState.currentTab === 'users') renderUsersTab(document.getElementById('admin-tab-content'));
            } catch (err) {
                showToast('Не удалось снять блокировку: ' + err.message, 'error');
                btn.disabled = false;
            }
            return;
        }

        if (target.closest('.btn-save')) {
            const saveButton = target.closest('.btn-save');
            const row = saveButton.closest('tr');
            const userId = row.dataset.userId;
            const roleSelect = row.querySelector('.role-select');
            const branchSelect = row.querySelector('.branch-select');
            const statusToggle = row.querySelector('.status-toggle');
            const fioInput = row.querySelector('.fio-input');
            const emailInput = row.querySelector('.email-input');

            const data = {
                role_id: parseInt(roleSelect.value, 10),
                branch_id: branchSelect.value ? parseInt(branchSelect.value, 10) : null,
                is_active: statusToggle.checked
            };
            if (fioInput) data.full_name = fioInput.value.trim();
            if (emailInput) data.email = emailInput.value.trim();

            saveButton.disabled = true;
            saveButton.textContent = '...';

            try {
                const response = await secureFetch(`/api/admin/users/${userId}`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.message || 'Ошибка сохранения');
                }

                roleSelect.dataset.originalValue = data.role_id;
                branchSelect.dataset.originalValue = data.branch_id || '';
                statusToggle.dataset.originalValue = data.is_active;
                if (fioInput)   fioInput.dataset.originalValue   = data.full_name;
                if (emailInput) emailInput.dataset.originalValue = data.email;

                saveButton.classList.add('success');
                saveButton.textContent = '✓';
                setTimeout(() => {
                    saveButton.classList.remove('success');
                    saveButton.textContent = 'Сохранить';
                }, 2000);
            } catch (error) {
                console.error('Ошибка при сохранении пользователя:', error);
                showToast('Не удалось сохранить изменения: ' + error.message, 'error');
                saveButton.disabled = false;
                saveButton.textContent = 'Сохранить';
            }
            return;
        }

        if (target.closest('.btn-cat-edit')) {
            const btn = target.closest('.btn-cat-edit');
            // соответствие CLAUDE.md #27 — никаких прямых JSON.parse
            // на user-content. data-cat-edit рендерится сервером и проходит
            // escapeAttr, но safeJsonParse — единый паттерн для всех мест.
            const data = safeJsonParse(btn.dataset.catEdit, null);
            if (data) {
                openCategoryModal(data);
            } else {
                showToast('Не удалось открыть редактор: данные категории повреждены', 'error');
            }
            return;
        }

        if (target.closest('.btn-cat-delete')) {
            const btn = target.closest('.btn-cat-delete');
            const id = btn.dataset.catDelete;
            const name = btn.dataset.catName;
            if (!(await showConfirm({ title: 'Удалить категорию?', message: `«${name}»\nДействие нельзя отменить (применимо только если категория не используется).`, confirmText: 'Удалить', danger: true }))) return;
            try {
                const r = await secureFetch(`/api/admin/categories/${id}`, { method: 'DELETE' });
                const d = await r.json();
                if (!r.ok) throw new Error(d.message || 'Ошибка');
                showToast('Категория удалена', 'success');
                renderCategoriesTab(document.getElementById('admin-tab-content'));
                eventCategories = [];
            } catch (e) {
                showToast('Не удалось удалить: ' + e.message, 'error');
            }
            return;
        }

        if (target.closest('.btn-user-delete')) {
            const btn = target.closest('.btn-user-delete');
            const userId = btn.dataset.userDelete;
            const userName = btn.dataset.userName;
            if (!(await showConfirm({ title: 'Удалить пользователя?', message: `«${userName}»\n\nИсторические данные (заявки, комментарии, журнал) будут сохранены. Пользователь не сможет войти в систему.`, confirmText: 'Удалить', danger: true }))) return;
            btn.disabled = true;
            const oldText = btn.textContent;
            btn.textContent = '...';
            try {
                const r = await secureFetch(`/api/admin/users/${userId}`, { method: 'DELETE' });
                const d = await r.json();
                if (!r.ok) throw new Error(d.message || 'Ошибка');
                showToast(d.message || 'Пользователь удалён', 'success', 6000);
                renderUsersTab(document.getElementById('admin-tab-content'));
            } catch (e) {
                showToast('Не удалось удалить: ' + e.message, 'error');
                btn.disabled = false;
                btn.textContent = oldText;
            }
            return;
        }

        if (target.closest('.btn-reset-pwd')) {
            const btn = target.closest('.btn-reset-pwd');
            const userId = btn.dataset.resetPwd;
            const row = btn.closest('tr');
            const userName = row.querySelector('.fio-input')?.value || '(без имени)';
            if (!(await showConfirm({ title: 'Сбросить пароль?', message: `«${userName}»\n\nПользователь будет выгнан со всех устройств. Новый пароль будет показан один раз.`, confirmText: 'Сбросить пароль', danger: true }))) return;
            btn.disabled = true;
            const oldText = btn.textContent;
            btn.textContent = '...';
            try {
                const r = await secureFetch(`/api/admin/users/${userId}/reset-password`, { method: 'POST' });
                const d = await r.json();
                if (!r.ok) throw new Error(d.message || 'Ошибка');
                showResetPasswordModal(userName, d.newPassword);
            } catch (e) {
                showToast('Не удалось сбросить пароль: ' + e.message, 'error');
            } finally {
                btn.disabled = false;
                btn.textContent = oldText;
            }
            return;
        }
        // Кнопки пагинации обрабатываются в самих вкладках (refreshLogsTable / refreshAttempts)
    });

    adminView.addEventListener('change', (e) => {
        const target = e.target;
        if (target.matches('.role-select, .branch-select, .status-toggle, .fio-input, .email-input')) {
            const row = target.closest('tr');
            checkUserRowDirty(row);
        }
    });
    adminView.addEventListener('input', (e) => {
        if (e.target.matches('.fio-input, .email-input')) {
            checkUserRowDirty(e.target.closest('tr'));
        }
    });

    function checkUserRowDirty(row) {
        if (!row) return;
        const saveButton = row.querySelector('.btn-save');
        if (!saveButton) return;
        const roleSelect = row.querySelector('.role-select');
        const branchSelect = row.querySelector('.branch-select');
        const statusToggle = row.querySelector('.status-toggle');
        const fioInput = row.querySelector('.fio-input');
        const emailInput = row.querySelector('.email-input');
        let isChanged = false;
        if (roleSelect && roleSelect.value !== roleSelect.dataset.originalValue) isChanged = true;
        if (branchSelect && branchSelect.value !== branchSelect.dataset.originalValue) isChanged = true;
        if (statusToggle && statusToggle.checked.toString() !== statusToggle.dataset.originalValue) isChanged = true;
        if (fioInput && fioInput.value.trim() !== fioInput.dataset.originalValue) isChanged = true;
        if (emailInput && emailInput.value.trim() !== emailInput.dataset.originalValue) isChanged = true;
        saveButton.disabled = !isChanged;
    }

    function showResetPasswordModal(userName, password) {
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay active';
        overlay.id = 'resetPwdOverlay';
        overlay.innerHTML = `
            <div class="modal-content modal-create" style="max-width: 480px;">
                <header class="modal-header">
                    <div class="modal-header-text">
                        <h2 class="modal-title">Пароль сброшен</h2>
                        <p class="modal-subtitle">Передайте новый пароль пользователю «${sanitizeAndFormatText(userName)}» по защищённому каналу. Этот пароль показывается ОДИН раз.</p>
                    </div>
                </header>
                <div class="modal-body">
                    <div class="input-group">
                        <label class="field-label">Новый пароль</label>
                        <input type="text" id="rstPwdValue" value="${escapeAttr(password)}" readonly style="font-family:monospace;font-size:15px;letter-spacing:0.5px;">
                    </div>
                </div>
                <footer class="modal-actions">
                    <button type="button" class="btn-secondary" id="rstPwdCopy">Скопировать</button>
                    <button type="button" class="btn-main" id="rstPwdClose">Готово</button>
                </footer>
            </div>`;
        document.body.appendChild(overlay);
        setupModalA11y(overlay);
        const close = () => overlay.remove();
        document.getElementById('rstPwdClose').addEventListener('click', close);
        document.getElementById('rstPwdCopy').addEventListener('click', () => {
            const inp = document.getElementById('rstPwdValue');
            inp.select();
            try {
                navigator.clipboard.writeText(inp.value);
                showToast('Скопировано в буфер обмена', 'success');
            } catch (e) {
                document.execCommand('copy');
            }
        });
    }

    detailView.addEventListener('click', async (e) => {
        const target = e.target;
        if (target.classList.contains('file-list-item-remove')) {
            detailViewFiles.splice(parseInt(target.dataset.index, 10), 1);
            updateDetailFileList();
            return;
        }

        const requestId = window.location.hash.split('/')[2];
        const switcherBtn = target.closest('.switcher-btn');
        if (switcherBtn) {
            e.preventDefault();
            if (switcherBtn.classList.contains('active')) return;

            const viewToActivate = switcherBtn.dataset.view;
            const parentBlock = switcherBtn.closest('.sidebar-block');
            parentBlock.querySelectorAll('.switcher-btn').forEach(btn => btn.classList.remove('active'));
            switcherBtn.classList.add('active');
            parentBlock.querySelectorAll('.activity-pane, .chat-pane').forEach(pane => pane.classList.remove('active-pane'));
            const newPane = parentBlock.querySelector(`#${viewToActivate}Pane`);
            newPane.classList.add('active-pane');

            if (viewToActivate === 'chat') {
                const chatFeed = newPane.querySelector('.chat-feed');
                if (chatFeed) {
                    chatFeed.querySelector('.unread-separator')?.remove();
                    let firstUnreadElement = null;
                    if (unreadCommentIds.size > 0) {
                        const allBubbles = chatFeed.querySelectorAll('.chat-bubble[data-item-id]');
                        for (const bubble of allBubbles) {
                            if (unreadCommentIds.has(parseInt(bubble.dataset.itemId, 10))) {
                                firstUnreadElement = bubble;
                                break;
                            }
                        }
                    }
                    if (firstUnreadElement) {
                        const separator = document.createElement('div');
                        separator.className = 'unread-separator';
                        separator.innerHTML = `<span>Новые сообщения</span>`;
                        firstUnreadElement.before(separator);
                        separator.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    } else {
                        chatFeed.scrollTop = chatFeed.scrollHeight;
                    }
                    // НЕМЕДЛЕННЫЙ markAllChatRead вместо
                    // setTimeout(800ms). Юзер кликнул «Чат» — он явно намерен
                    // прочитать. Раньше задержка 800ms имела race с scroll-
                    // анимацией: если markAllChatRead срабатывал ДО того как
                    // IntersectionObserver успел зафиксировать сообщения,
                    // часть unread'ов терялась.
                    markAllChatRead();
                }
            } else if (viewToActivate === 'activity') {
                const activityFeed = newPane.querySelector('.activity-feed');
                if (activityFeed) {
                    activityFeed.querySelector('.unread-separator')?.scrollIntoView({ behavior: 'smooth', block: 'center' });
                }
            }
            return;
        }
        const downloadAllBtn = target.closest('.btn-download-all');
        if (downloadAllBtn) {
            const docIds = downloadAllBtn.dataset.docIds.split(',');
            await downloadAllIndividually(docIds, downloadAllBtn);
            return;
        }
        const downloadArchiveBtn = target.closest('.btn-download-archive');
        if (downloadArchiveBtn) {
            const docIds = downloadArchiveBtn.dataset.docIds.split(',');
            await downloadAsZip(docIds, downloadArchiveBtn);
            return;
        }

        const printPdfBtn = target.closest('.btn-print-pdf');
        if (printPdfBtn) {
            const reqId = printPdfBtn.dataset.requestId;
            const originalHtml = printPdfBtn.innerHTML;
            printPdfBtn.disabled = true;
            printPdfBtn.innerHTML = '<span>Формирование…</span>';
            try {
                const r = await secureFetch(`/api/requests/${reqId}/pdf`);
                if (!r.ok) {
                    const err = await r.json().catch(() => ({}));
                    showToast(err.message || 'Не удалось сформировать PDF', 'error');
                    return;
                }
                const blob = await r.blob();
                const url = URL.createObjectURL(blob);
                window.open(url, '_blank');
                setTimeout(() => URL.revokeObjectURL(url), 60000);
                showToast('PDF-протокол открыт в новой вкладке', 'success');
            } catch (err) {
                showToast('Ошибка сети при формировании PDF', 'error');
            } finally {
                printPdfBtn.disabled = false;
                printPdfBtn.innerHTML = originalHtml;
            }
            return;
        }

        if (target.closest('.document-download-link')) {
            e.preventDefault();
            const link = target.closest('.document-download-link');
            const url = link.href,
                filename = link.dataset.filename || 'download';
            if (link.classList.contains('downloading')) return;

            link.classList.add('downloading');
            const originalText = link.textContent;
            link.textContent = 'Скачивание...';

            try {
                const r = await secureFetch(url);
                if (!r.ok) throw new Error(`Ошибка ${r.status}`);
                const blob = await r.blob();
                const downloadUrl = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.style.display = 'none';
                a.href = downloadUrl;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(downloadUrl);
                a.remove();
            } catch (err) {
                showToast('Не удалось скачать файл: ' + err.message, 'error');
            } finally {
                link.textContent = originalText;
                link.classList.remove('downloading');
            }
            return;
        }

        // Отзыв заявки автором — отдельный путь с подтверждением.
        if (target.closest('#withdrawBtn')) {
            const btn = target.closest('#withdrawBtn');
            if (!(await showConfirm({ title: 'Отозвать заявку?', message: 'Действие необратимо — после отзыва заявка переходит в терминальный статус «Отозвана» и не может быть возвращена в работу.', confirmText: 'Отозвать', danger: true }))) return;
            const newStatusId = btn.dataset.newStatus;
            const details = btn.dataset.details || 'Заявка отозвана автором';
            btn.disabled = true;
            try {
                const r = await secureFetch(`/api/requests/${requestId}/status`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ newStatusId, details })
                });
                if (!r.ok) {
                    const err = await r.json();
                    showToast(err.message || 'Не удалось отозвать заявку', 'error');
                    btn.disabled = false;
                } else {
                    showToast('Заявка отозвана', 'success');
                }
            } catch (e) {
                showToast('Ошибка сети при отзыве заявки', 'error');
                btn.disabled = false;
            }
            return;
        }

        if (target.closest('#changeStatusBtn')) {
            const btn = target.closest('#changeStatusBtn');
            let newStatusId, details;
            const select = document.getElementById('statusSelect');
            if (select) {
                newStatusId = select.value;
                // НЕ берём текст option ("Одобрить" — глагол), а
                // оставляем пустым — сервер сам подставит canonical status name
                // («Одобрена») в auto-generated `Статус: «...».`. Иначе
                // PDF-протокол не мог найти approver'а в history через keyword-
                // matching (искал «одобрена», в details было «одобрить»).
                details = '';
            } else {
                newStatusId = btn.dataset.newStatus;
                details = btn.dataset.details || '';
            }

            // Если это «Вернуть на доработку» (REWORK) — нужна обязательная
            // причина возврата. Показываем модалку, причина уйдёт в чат заявки.
            const reworkId = SYSTEM_CONSTANTS.statuses.REWORK;
            if (parseInt(newStatusId, 10) === reworkId) {
                const reason = await promptReworkReason();
                if (reason === null) return; // отмена
                details = reason;
            }

            // При одобрении (APPROVED) согласующий может приложить подписанный
            // протокол согласования (PDF/скан) — это и есть «отдать документ
            // обратно с подписью» в реальном бизнес-сценарии. Файл опционален.
            const approvedId = SYSTEM_CONSTANTS.statuses.APPROVED;
            const isApprover = user.role === 'Согласующий' || user.role === 'Администратор';
            let signedFile = null;
            if (parseInt(newStatusId, 10) === approvedId && isApprover) {
                signedFile = await promptSignedProtocolUpload();
                if (signedFile === false) return; // явная отмена
                // null = одобрить без файла (валидно)
            }

            if (newStatusId) {
                btn.disabled = true;
                try {
                    // Сначала загружаем подписанный протокол (если есть),
                    // потом меняем статус — порядок важен: при ошибке uploads
                    // мы НЕ меняем статус заявки.
                    if (signedFile) {
                        const fd = new FormData();
                        fd.append('documentFiles', signedFile);
                        const up = await secureFetch(`/api/requests/${requestId}/documents?signed=true`, {
                            method: 'POST',
                            body: fd
                        });
                        if (!up.ok) {
                            const err = await up.json().catch(() => ({}));
                            showToast(err.message || 'Не удалось загрузить подписанный протокол', 'error');
                            btn.disabled = false;
                            return;
                        }
                    }

                    const r = await secureFetch(`/api/requests/${requestId}/status`, {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ newStatusId, details })
                    });
                    if (!r.ok) {
                        const err = await r.json();
                        showToast(err.message || 'Не удалось изменить статус', 'error');
                        btn.disabled = false;
                    } else if (signedFile) {
                        showToast('Заявка одобрена, подписанный протокол прикреплён.', 'success', 5000);
                    }
                } catch (err) {
                    showToast('Ошибка сети при изменении статуса', 'error');
                    btn.disabled = false;
                }
            }
            return;
        }
    });

    /**
     * Модалка прикрепления подписанного протокола при одобрении.
     * Возвращает Promise:
     *   - File: загрузить этот файл как signed_protocol и одобрить
     *   - null: одобрить без файла
     *   - false: отмена (не одобрять)
     */
    function promptSignedProtocolUpload() {
        return new Promise((resolve) => {
            const overlay = document.createElement('div');
            overlay.className = 'modal-overlay active';
            overlay.id = 'signedProtocolOverlay';
            // вместо 3-кнопочного «Отмена / Без файла /
            // С файлом» — drag-drop zone + адаптивный primary-button. Лейбл
            // submit меняется в зависимости от того, выбран ли файл.
            // Это снижает когнитивную нагрузку (1 действие на состояние, а
            // не 2 параллельных choice'а), и убирает уродливый native input.
            overlay.innerHTML = `
                <div class="modal-content modal-create" style="max-width: 540px;">
                    <header class="modal-header">
                        <div class="modal-header-text">
                            <h2 class="modal-title">Одобрение заявки</h2>
                            <p class="modal-subtitle">При желании приложите подписанный протокол согласования. Он будет прикреплён к заявке как «Подписанный протокол».</p>
                        </div>
                        <button type="button" class="modal-close-btn" id="spClose" aria-label="Закрыть">
                            <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                        </button>
                    </header>
                    <div class="modal-body">
                        <div class="sp-dropzone" id="spDropzone" role="button" tabindex="0" aria-label="Прикрепить подписанный протокол">
                            <div class="sp-dropzone-empty" id="spEmpty">
                                <div class="sp-dropzone-icon">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                                </div>
                                <div class="sp-dropzone-text">
                                    <strong>Перетащите файл</strong> или <span class="sp-link">нажмите для выбора</span>
                                </div>
                                <div class="sp-dropzone-hint">PDF, JPG, PNG, TIFF · до 15 МБ</div>
                            </div>
                            <div class="sp-dropzone-filled hidden" id="spFilled">
                                <div class="sp-file-card">
                                    <div class="sp-file-icon" id="spFileIcon"></div>
                                    <div class="sp-file-meta">
                                        <div class="sp-file-name" id="spFileName"></div>
                                        <div class="sp-file-size" id="spFileSize"></div>
                                    </div>
                                    <button type="button" class="sp-file-remove" id="spFileRemove" aria-label="Убрать файл" title="Убрать файл">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                                    </button>
                                </div>
                            </div>
                            <input type="file" id="spFile" class="hidden" accept=".pdf,.jpg,.jpeg,.png,.tiff,.tif">
                        </div>
                        <div class="form-error-message" id="spErr"></div>
                    </div>
                    <footer class="modal-actions">
                        <button type="button" class="btn-secondary" id="spCancel">Отмена</button>
                        <button type="button" class="btn-main" id="spSubmit">Одобрить</button>
                    </footer>
                </div>`;
            document.body.appendChild(overlay);
            setupModalA11y(overlay);

            const close = (val) => { overlay.remove(); resolve(val); };
            const dropzone   = document.getElementById('spDropzone');
            const fileInput  = document.getElementById('spFile');
            const emptyEl    = document.getElementById('spEmpty');
            const filledEl   = document.getElementById('spFilled');
            const fileIconEl = document.getElementById('spFileIcon');
            const fileNameEl = document.getElementById('spFileName');
            const fileSizeEl = document.getElementById('spFileSize');
            const submitBtn  = document.getElementById('spSubmit');
            const errEl      = document.getElementById('spErr');

            let pickedFile = null;

            const setState = (file) => {
                pickedFile = file;
                errEl.textContent = '';
                if (file) {
                    emptyEl.classList.add('hidden');
                    filledEl.classList.remove('hidden');
                    dropzone.classList.add('has-file');
                    fileIconEl.innerHTML = getFileIcon(file.name);
                    fileNameEl.textContent = file.name;
                    fileNameEl.title = file.name;
                    fileSizeEl.textContent = formatFileSize(file.size);
                } else {
                    emptyEl.classList.remove('hidden');
                    filledEl.classList.add('hidden');
                    dropzone.classList.remove('has-file');
                    try { fileInput.value = ''; } catch (_) { /* IE-legacy */ }
                }
            };

            const validateAndSet = (file) => {
                if (!file) return;
                if (file.size > MAX_FILE_BYTES) {
                    errEl.textContent = `Файл превышает 15 МБ (${formatFileSize(file.size)}).`;
                    return;
                }
                const ext = file.name.toLowerCase().split('.').pop();
                if (!['pdf', 'jpg', 'jpeg', 'png', 'tiff', 'tif'].includes(ext)) {
                    errEl.textContent = 'Допустимые форматы: PDF, JPG, PNG, TIFF.';
                    return;
                }
                setState(file);
            };

            // Клик по dropzone (но не по filled-карточке) → открыть file-picker.
            dropzone.addEventListener('click', (e) => {
                if (e.target.closest('.sp-file-remove')) return;
                if (e.target.closest('.sp-file-card')) return;
                fileInput.click();
            });
            // Keyboard a11y: Enter/Space на dropzone в empty-state.
            dropzone.addEventListener('keydown', (e) => {
                if (pickedFile) return;
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    fileInput.click();
                }
            });

            // Drag-drop поверх dropzone'а.
            ['dragenter', 'dragover'].forEach(ev => {
                dropzone.addEventListener(ev, (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    dropzone.classList.add('dragover');
                });
            });
            ['dragleave', 'drop'].forEach(ev => {
                dropzone.addEventListener(ev, (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    dropzone.classList.remove('dragover');
                });
            });
            dropzone.addEventListener('drop', (e) => {
                const f = e.dataTransfer?.files?.[0];
                if (f) validateAndSet(f);
            });

            fileInput.addEventListener('change', () => {
                validateAndSet(fileInput.files[0]);
            });

            document.getElementById('spFileRemove').addEventListener('click', (e) => {
                e.stopPropagation();
                setState(null);
            });

            document.getElementById('spClose').addEventListener('click', () => close(false));
            document.getElementById('spCancel').addEventListener('click', () => close(false));
            overlay.addEventListener('click', (e) => { if (e.target === overlay) close(false); });

            submitBtn.addEventListener('click', () => {
                // pickedFile === null → одобрить без файла, иначе — с файлом.
                close(pickedFile || null);
            });
        });
    }

    /**
     * Модалка ввода причины возврата на доработку.
     * Возвращает Promise<string|null>: текст причины либо null если отменили.
     */
    function promptReworkReason() {
        return new Promise((resolve) => {
            const overlay = document.createElement('div');
            overlay.className = 'modal-overlay active';
            overlay.id = 'reworkReasonOverlay';
            overlay.innerHTML = `
                <div class="modal-content modal-create" style="max-width: 480px;">
                    <header class="modal-header">
                        <div class="modal-header-text">
                            <h2 class="modal-title">Причина возврата</h2>
                            <p class="modal-subtitle">Эта причина будет видна автору заявки в чате.</p>
                        </div>
                        <button type="button" class="modal-close-btn" id="rrClose" aria-label="Закрыть">
                            <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                        </button>
                    </header>
                    <div class="modal-body">
                        <div class="input-group">
                            <label for="rrReason" class="field-label">Что нужно исправить? <span class="req-marker">*</span></label>
                            <textarea id="rrReason" rows="4" placeholder="Например: уточните цель мероприятия и приложите смету" maxlength="500"></textarea>
                            <div class="form-error-message" id="rrErr"></div>
                        </div>
                    </div>
                    <footer class="modal-actions">
                        <button type="button" class="btn-secondary" id="rrCancel">Отмена</button>
                        <button type="button" class="btn-main" id="rrSubmit">Вернуть на доработку</button>
                    </footer>
                </div>`;
            document.body.appendChild(overlay);
            setupModalA11y(overlay);

            const close = (val) => { overlay.remove(); resolve(val); };
            const reasonInput = document.getElementById('rrReason');
            reasonInput.focus();

            document.getElementById('rrClose').addEventListener('click', () => close(null));
            document.getElementById('rrCancel').addEventListener('click', () => close(null));
            overlay.addEventListener('click', (e) => { if (e.target === overlay) close(null); });

            document.getElementById('rrSubmit').addEventListener('click', () => {
                const txt = reasonInput.value.trim();
                if (txt.length < 3) {
                    document.getElementById('rrErr').textContent = 'Опишите хотя бы одной фразой (минимум 3 символа).';
                    return;
                }
                close(txt);
            });
        });
    }

    /**
     * Модалка профиля: данные юзера, история входов, форма смены пароля.
     */
    async function openProfileModal() {
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay active';
        overlay.id = 'profileOverlay';
        overlay.innerHTML = `
            <div class="modal-content modal-create" style="max-width: 560px;">
                <header class="modal-header">
                    <div class="modal-header-text">
                        <h2 class="modal-title">Мой профиль</h2>
                        <p class="modal-subtitle">Учётная запись и недавняя активность.</p>
                    </div>
                    <button type="button" class="modal-close-btn" id="prClose" aria-label="Закрыть">
                        <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                    </button>
                </header>
                <div class="modal-body" id="prBody">
                    <div class="admin-loading">Загрузка профиля…</div>
                </div>
            </div>`;
        document.body.appendChild(overlay);
        setupModalA11y(overlay);

        // Закрытие: × в шапке, Esc (через setupModalA11y), клик по overlay-фону.
        // Дублирующая кнопка «Закрыть» в footer'е удалена — лишняя для UX.
        const close = () => overlay.remove();
        document.getElementById('prClose').addEventListener('click', close);
        overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });

        let profile;
        try {
            const r = await secureFetch('/api/profile/me');
            if (!r.ok) throw new Error('load');
            profile = await r.json();
        } catch (e) {
            document.getElementById('prBody').innerHTML = `<p class="admin-error">Не удалось загрузить профиль</p>`;
            return;
        }

        const u = profile.user;
        const recent = profile.recentLogins || [];
        const loginsHtml = recent.length
            ? recent.map(l => `
                <li>
                    <span class="login-time">${new Date(l.login_time).toLocaleString('ru-RU')}</span>
                    <span class="login-ip">${sanitizeAndFormatText(l.ip_address || '—')}</span>
                </li>`).join('')
            : '<li class="admin-empty">История входов пуста</li>';

        document.getElementById('prBody').innerHTML = `
            <div class="profile-info-grid">
                <span class="label">ФИО</span>      <span class="value">${sanitizeAndFormatText(u.full_name)}</span>
                <span class="label">Email</span>    <span class="value">${sanitizeAndFormatText(u.email)}</span>
                <span class="label">Логин</span>    <span class="value">${sanitizeAndFormatText(u.login)}</span>
                <span class="label">Роль</span>     <span class="value">${sanitizeAndFormatText(u.role_name)}</span>
                <span class="label">Филиал</span>   <span class="value">${u.branch_name ? sanitizeAndFormatText(u.branch_name) : '<span class="value" style="color:var(--text-muted)">— не указан —</span>'}</span>
                <span class="label">Первый вход</span> <span class="value">${u.first_login_at ? new Date(u.first_login_at).toLocaleDateString('ru-RU') : '—'}</span>
            </div>

            <div class="profile-section-title">Последние входы</div>
            <ul class="profile-logins profile-logins-capped">${loginsHtml}</ul>

            <div class="profile-section-title">Смена пароля</div>
            <form id="prPwdForm" class="profile-pwd-form" autocomplete="off">
                <div class="input-group">
                    <label for="pr_old" class="field-label">Текущий пароль <span class="req-marker">*</span></label>
                    <input type="password" id="pr_old" required autocomplete="current-password">
                    <div class="form-error-message" id="prOldErr" role="alert" aria-live="polite"></div>
                </div>
                <div class="input-group">
                    <label for="pr_new" class="field-label">Новый пароль <span class="req-marker">*</span></label>
                    <input type="password" id="pr_new" required minlength="10" autocomplete="new-password" placeholder="Минимум 10 символов: буквы, цифры, спецсимвол">
                    <div class="form-error-message" id="prNewErr" role="alert" aria-live="polite"></div>
                </div>
                <div class="input-group">
                    <label for="pr_new2" class="field-label">Повторите новый пароль <span class="req-marker">*</span></label>
                    <input type="password" id="pr_new2" required minlength="10" autocomplete="new-password">
                    <div class="form-error-message" id="prPwdErr" role="alert" aria-live="polite"></div>
                </div>
                <div class="profile-pwd-footer">
                    <button type="submit" class="btn-main profile-pwd-submit">Сменить пароль</button>
                </div>
            </form>`;

        // Live-валидация: показываем «не совпадают» сразу при вводе во второе поле
        // или при изменении первого. Раньше это становилось видно ТОЛЬКО при submit'е.
        const oldEl  = document.getElementById('pr_old');
        const newEl  = document.getElementById('pr_new');
        const new2El = document.getElementById('pr_new2');
        const oldErr = document.getElementById('prOldErr');
        const newErr = document.getElementById('prNewErr');
        const matchErr = document.getElementById('prPwdErr');

        const checkMatch = () => {
            if (new2El.value && newEl.value !== new2El.value) {
                matchErr.textContent = 'Подтверждение пароля не совпадает.';
            } else {
                matchErr.textContent = '';
            }
        };
        const checkLength = () => {
            if (newEl.value && newEl.value.length < 10) {
                newErr.textContent = 'Минимум 10 символов.';
            } else {
                newErr.textContent = '';
            }
            checkMatch();
        };
        newEl.addEventListener('input', checkLength);
        new2El.addEventListener('input', checkMatch);
        // Когда юзер начинает править старый пароль после ошибки 401 — стираем
        // подсказку «Текущий пароль введён неверно».
        oldEl.addEventListener('input', () => { oldErr.textContent = ''; });

        document.getElementById('prPwdForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const oldP = oldEl.value;
            const newP = newEl.value;
            const newP2 = new2El.value;
            // Чистим все три ошибки перед попыткой submit'а
            oldErr.textContent = '';
            newErr.textContent = '';
            matchErr.textContent = '';

            // Клиентская валидация — раньше сообщения только в одном поле
            // и без display:block (form-error-message:not(:empty) теперь это
            // решает в CSS, но ошибки также распределены по полям, чтобы юзер
            // видел проблему рядом с проблемным input'ом).
            if (!oldP) {
                oldErr.textContent = 'Введите текущий пароль.';
                oldEl.focus();
                return;
            }
            if (newP.length < 10) {
                newErr.textContent = 'Минимум 10 символов.';
                newEl.focus();
                return;
            }
            if (newP === oldP) {
                newErr.textContent = 'Новый пароль должен отличаться от текущего.';
                newEl.focus();
                return;
            }
            if (newP !== newP2) {
                matchErr.textContent = 'Подтверждение пароля не совпадает.';
                new2El.focus();
                return;
            }

            const submitBtn = e.target.querySelector('button[type="submit"]');
            submitBtn.disabled = true;
            submitBtn.textContent = 'Смена…';
            try {
                const r = await secureFetch('/api/profile/me/password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ oldPassword: oldP, newPassword: newP })
                });
                const data = await r.json().catch(() => ({}));
                if (!r.ok) {
                    // Маршрутизируем серверную ошибку к нужному полю.
                    // 401/403 от /api/profile/me/password обычно «старый пароль неверный»
                    // (см. сервер). 400 — слабый/некорректный новый.
                    const msg = data.message || 'Не удалось сменить пароль';
                    if (r.status === 401 || r.status === 403 || /текущ|старый|неверн/i.test(msg)) {
                        oldErr.textContent = msg;
                        oldEl.focus();
                    } else if (r.status === 400) {
                        newErr.textContent = msg;
                        newEl.focus();
                    } else {
                        matchErr.textContent = msg;
                    }
                    return;
                }
                // Сервер выдал свежий access-токен (после bumpTokenVersion для
                // текущей сессии). Обновляем in-memory переменную, чтобы
                // следующие fetch'и не получили 401 от своего же отозванного tv.
                if (data.accessToken) {
                    accessToken = data.accessToken;
                }
                showToast('Пароль успешно обновлён.', 'success', 4000);
                // Не закрываем модалку — юзер видит свежий список входов и
                // может закрыть когда захочет. Чистим поля паролей.
                oldEl.value = '';
                newEl.value = '';
                new2El.value = '';
                oldEl.focus();
            } catch (err) {
                matchErr.textContent = 'Ошибка сети. Проверьте соединение.';
            } finally {
                submitBtn.disabled = false;
                submitBtn.textContent = 'Сменить пароль';
            }
        });
    }

    detailView.addEventListener('change', e => {
        if (e.target.id === 'detail_req_files') {
            handleDetailFiles(e.target.files);
        }
    });

    detailView.addEventListener('submit', async (e) => {
        const requestId = window.location.hash.split('/')[2];
        if (e.target.id === 'uploadForm') {
            e.preventDefault();
            if (detailViewFiles.length === 0) {
                showToast('Сначала выберите или перетащите файлы', 'warning');
                return;
            }
            const formData = new FormData();
            detailViewFiles.forEach(f => formData.append('documentFiles', f));
            const btn = e.target.querySelector('button');
            btn.textContent = 'Загрузка...';
            btn.disabled = true;
            try {
                const r = await secureFetch(`/api/requests/${requestId}/documents`, { method: 'POST', body: formData });
                if (r.ok) {
                    detailViewFiles = [];
                    updateDetailFileList();
                    showToast('Файлы успешно загружены', 'success');
                } else {
                    const err = await r.json();
                    if (r.status === 403 && err.locked_until) {
                        showToast(err.message, 'error', 9000);
                        setTimeout(() => window.location.href = '/login', 2500);
                    } else if (err.severity) {
                        showSecurityToast(err);
                    } else {
                        showToast(err.message || 'Не удалось загрузить файлы', 'error', 6000);
                    }
                }
            } catch (err) {
                showToast('Ошибка сети при загрузке файлов', 'error');
            } finally {
                btn.textContent = 'Загрузить выбранные файлы';
                btn.disabled = false;
            }
        }
        if (e.target.id === 'commentForm') {
            e.preventDefault();
            const form = e.target;
            const textarea = form.querySelector('textarea');
            const text = textarea.value;
            const data = { comment_text: text };
            if (!data.comment_text.trim()) return;
            if (replyingTo) data.reply_to_id = replyingTo.id;

            const btn = form.querySelector('button');
            btn.disabled = true;

            // убрали optimistic pending-bubble. Раньше bubble
            // с надписью «отправляется…» вставлялся сразу до сетевого ответа,
            // потом WS detail_update перерисовывал чат целиком — старый pending
            // удалялся, новый normal-bubble отрисовывался → видимое мерцание
            // у отправителя на быстрой сети. Теперь форма очищается сразу
            // (UX-feedback: юзер видит что input очистился, кнопка disabled),
            // а сообщение появится через WS refresh ~50-200мс. На медленной
            // сети btn остаётся disabled до finally — двойного submit'а не будет.
            const chatFeed = detailView.querySelector('.chat-feed');
            // Сохраняем для возможного восстановления при ошибке.
            const replyingToBackup = replyingTo;
            form.reset();
            setReplyingTo(null);

            try {
                const response = await secureFetch(`/api/requests/${requestId}/comments`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                if (response.ok) {
                    textarea.focus();
                } else {
                    const err = await response.json().catch(() => ({}));
                    // Восстанавливаем что юзер ввёл — чтобы переотправил.
                    textarea.value = text;
                    setReplyingTo(replyingToBackup);
                    showToast(err.message || 'Не удалось добавить комментарий', 'error');
                }
            } catch (err) {
                textarea.value = text;
                setReplyingTo(replyingToBackup);
                showToast('Ошибка сети при отправке комментария', 'error');
            } finally {
                btn.disabled = false;
                // Скроллим чат вниз — на случай если WS-refresh уже добавил
                // сообщение, а scroll-position остался выше.
                if (chatFeed) chatFeed.scrollTop = chatFeed.scrollHeight;
            }
        }
    });

    /**
     * Управление reply-режимом: показ/скрытие preview-бара над textarea.
     * Передаём всё сообщение целиком — берём из него имя автора и текст для превью.
     */
    function setReplyingTo(item) {
        replyingTo = item;
        const preview = document.getElementById('replyPreview');
        const textEl  = preview?.querySelector('.reply-preview-text');
        if (!preview || !textEl) return;
        if (!item) {
            preview.classList.add('hidden');
            return;
        }
        const author = item.full_name || '—';
        const snippet = (item.comment_text || '').slice(0, 80);
        textEl.innerHTML = `<strong>В ответ ${sanitizeAndFormatText(author)}:</strong> ${sanitizeAndFormatText(snippet)}${(item.comment_text || '').length > 80 ? '…' : ''}`;
        preview.classList.remove('hidden');
    }

    // Делегированный handler по чату: reply / edit / delete + переход на цитируемое.
    detailView.addEventListener('click', async (e) => {
        // Клик на цитату-reply → плавный скролл к оригиналу.
        // Цитата может ссылаться и на bubble, и на system-event (rework-card).
        const quote = e.target.closest('.chat-reply-quote');
        if (quote) {
            const targetId = quote.dataset.scrollTo;
            const target = detailView.querySelector(
                `.chat-bubble[data-item-id="${targetId}"], .chat-sys-event[data-item-id="${targetId}"]`
            );
            if (target) {
                target.scrollIntoView({ behavior: 'smooth', block: 'center' });
                target.classList.add('chat-bubble-flash');
                setTimeout(() => target.classList.remove('chat-bubble-flash'), 1200);
            }
            return;
        }

        // Клик по уже стоящей реакции — toggle (снять или поставить).
        const reactionChip = e.target.closest('.chat-reaction');
        if (reactionChip) {
            const cid = parseInt(reactionChip.dataset.commentId, 10);
            const emoji = reactionChip.dataset.reactEmoji;
            await sendReaction(cid, emoji);
            return;
        }

        const actionBtn = e.target.closest('.chat-action-btn');
        if (!actionBtn) return;

        const action = actionBtn.dataset.action;
        const itemId = parseInt(actionBtn.dataset.itemId, 10);
        const bubble = actionBtn.closest('.chat-bubble');
        if (!bubble) return;

        // React: открываем мини-picker рядом с кнопкой
        if (action === 'react') {
            openReactionPicker(actionBtn, itemId);
            return;
        }

        // Reply: вытягиваем данные из bubble (имя, текст), включаем reply-режим
        if (action === 'reply') {
            const author = bubble.querySelector('.author')?.textContent || user.fullName;
            const text   = bubble.querySelector('p[data-content="text"]')?.textContent || '';
            setReplyingTo({ id: itemId, full_name: author, comment_text: text });
            const ta = detailView.querySelector('#commentForm textarea');
            if (ta) ta.focus();
            return;
        }

        // Edit: inline-редактирование. Заменяем <p> на textarea + кнопки Save/Cancel.
        if (action === 'edit') {
            startInlineEdit(bubble, itemId);
            return;
        }

        if (action === 'delete') {
            const ok = await showConfirm({
                title: 'Удалить сообщение?',
                message: 'Сообщение будет помечено как удалённое и исчезнет из чата. Действие необратимо.',
                confirmText: 'Удалить',
                cancelText: 'Отмена',
                danger: true
            });
            if (!ok) return;
            try {
                const r = await secureFetch(`/api/comments/${itemId}`, { method: 'DELETE' });
                if (!r.ok) {
                    const d = await r.json().catch(() => ({}));
                    throw new Error(d.message || 'Ошибка');
                }
                // detail_update прилетит через WS, фронт перерендерит чат сам.
                // Локально для скорости можем тоже обновить:
                const requestId = window.location.hash.split('/')[2];
                if (requestId) updateFeeds(requestId);
            } catch (err) {
                showToast('Не удалось удалить: ' + err.message, 'error');
            }
        }
    });

    /**
     * Inline-редактирование сообщения: <p> → <textarea> + Save/Cancel.
     */
    function startInlineEdit(bubble, itemId) {
        const p = bubble.querySelector('p[data-content="text"]');
        if (!p) return;
        if (bubble.classList.contains('editing')) return;
        bubble.classList.add('editing');

        const oldText = p.textContent;
        const editor = document.createElement('div');
        editor.className = 'chat-inline-editor';
        // Textarea breakout fix: раньше внутрь шаблона подставлялся
        // `${escapeAttr(oldText)}` — escapeAttr экранирует только `"`, но не `<`.
        // Если в сообщении было `</textarea><img src=x>`, шаблонный парсер
        // закрывал textarea и инжектил DOM. Сейчас текст ставим через
        // `ta.value` — это property assignment, парсер не запускается.
        editor.innerHTML = `
            <textarea class="chat-inline-textarea" maxlength="5000"></textarea>
            <div class="chat-inline-actions">
                <button type="button" class="btn-secondary chat-inline-cancel" style="font-size:11px;height:26px;padding:0 8px;">Отмена</button>
                <button type="button" class="btn-main chat-inline-save"     style="font-size:11px;height:26px;padding:0 8px;">Сохранить</button>
            </div>`;
        p.replaceWith(editor);
        const ta = editor.querySelector('textarea');
        ta.value = oldText;
        ta.focus();
        ta.setSelectionRange(ta.value.length, ta.value.length);

        const cleanup = (newP) => {
            bubble.classList.remove('editing');
            editor.replaceWith(newP);
        };

        editor.querySelector('.chat-inline-cancel').addEventListener('click', () => {
            const restored = document.createElement('p');
            restored.dataset.content = 'text';
            restored.innerHTML = sanitizeAndFormatText(oldText);
            cleanup(restored);
        });

        editor.querySelector('.chat-inline-save').addEventListener('click', async () => {
            const newText = ta.value.trim();
            if (!newText) {
                showToast('Сообщение не может быть пустым', 'warning');
                return;
            }
            if (newText === oldText) {
                const restored = document.createElement('p');
                restored.dataset.content = 'text';
                restored.innerHTML = sanitizeAndFormatText(oldText);
                cleanup(restored);
                return;
            }
            try {
                const r = await secureFetch(`/api/comments/${itemId}`, {
                    method: 'PATCH',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ comment_text: newText })
                });
                if (!r.ok) {
                    const d = await r.json().catch(() => ({}));
                    throw new Error(d.message || 'Ошибка');
                }
                // detail_update прилетит через WS, перерисует.
                showToast('Сообщение обновлено', 'success');
            } catch (err) {
                showToast('Не удалось обновить: ' + err.message, 'error');
                const restored = document.createElement('p');
                restored.dataset.content = 'text';
                restored.innerHTML = sanitizeAndFormatText(oldText);
                cleanup(restored);
            }
        });
    }

    // Закрытие reply-preview по «×»
    document.addEventListener('click', (e) => {
        if (e.target.classList?.contains('reply-preview-close')) {
            setReplyingTo(null);
        }
    });

    detailView.addEventListener('keydown', (e) => {
        if (e.target.matches('#commentForm textarea')) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                const form = e.target.closest('form');
                const button = form.querySelector('button[type="submit"]');
                if (button && !button.disabled) {
                    button.click();
                }
            }
        }
    });

    // Typing-indicator: на каждый input в textarea чата шлём WS-сообщение
    // (с дебаунсом раз в 3 сек внутри notifyTypingFromMe).
    detailView.addEventListener('input', (e) => {
        if (e.target.matches('#commentForm textarea')) {
            notifyTypingFromMe();
        }
    });

    detailView.addEventListener('dragenter', e => {
        const u = e.target.closest('#detailFileUploader');
        if (u) {
            e.preventDefault();
            e.stopPropagation();
            u.classList.add('dragover');
        }
    }, false);

    detailView.addEventListener('dragover', e => {
        if (e.target.closest('#detailFileUploader')) {
            e.preventDefault();
            e.stopPropagation();
        }
    }, false);

    detailView.addEventListener('dragleave', e => {
        const u = e.target.closest('#detailFileUploader');
        if (u) {
            e.preventDefault();
            e.stopPropagation();
            u.classList.remove('dragover');
        }
    }, false);

    detailView.addEventListener('drop', e => {
        const u = e.target.closest('#detailFileUploader');
        if (u) {
            e.preventDefault();
            e.stopPropagation();
            u.classList.remove('dragover');
            handleDetailFiles(e.dataTransfer.files);
        }
    }, false);

    modalHandlers();

    (async () => {
        try {
            // E2/H-3: bootstrap fetch через fetchWithTimeout. Без
            // таймаута на медленной сети initial-load висел бесконечно;
            // на 429 (агрессивный rate-limit) → handleLogout → бесконечный
            // цикл «логин → refresh 429 → logout → /login». Если 429 —
            // показываем явный toast и retry через 3 сек (один раз).
            let response = await fetchWithTimeout('/api/refresh-token', { method: 'POST' });
            if (response.status === 429) {
                if (typeof showToast === 'function') {
                    showToast(
                        'Слишком частые попытки. Повторим автоматически через 3 секунды…',
                        'warning', 4000
                    );
                }
                await new Promise(r => setTimeout(r, 3000));
                response = await fetchWithTimeout('/api/refresh-token', { method: 'POST' });
            }
            if (!response.ok) {
                throw new Error("Не удалось обновить сессию.");
            }
            const { accessToken: newAccessToken } = await response.json();
            accessToken = newAccessToken;

            user = parseJwt(accessToken);
            if (!user) throw new Error("Не удалось декодировать токен");

            // Загружаем доменные константы (роли, статусы) с сервера.
            // Кэшируется на 5 минут на клиенте через Cache-Control.
            try {
                const cRes = await secureFetch('/api/system-constants');
                if (cRes.ok) SYSTEM_CONSTANTS = await cRes.json();
            } catch (e) {
                console.error('Не удалось загрузить системные константы:', e);
            }

            userNameEl.textContent = user.fullName;
            // Аватарка из инициалов: «Иванов Иван Иванович» → «ИИ»
            const initials = (user.fullName || '·')
                .trim().split(/\s+/).slice(0, 2)
                .map(w => w[0]?.toUpperCase() || '')
                .join('') || '·';
            const avatarEl = document.getElementById('userAvatar');
            if (avatarEl) avatarEl.textContent = initials;

            // Открытие модалки профиля по клику на блок «аватарка + имя»
            const profileBtn = document.getElementById('userProfileBtn');
            if (profileBtn) {
                profileBtn.addEventListener('click', (e) => {
                    // Если у админа есть отдельная навигация по клику на имя — даём ей сработать
                    if (user.role === 'Администратор' && e.target.id === 'userName') return;
                    openProfileModal();
                });
            }

            userRoleEl.textContent = user.role;
            const roleClassMap = {
                'Администратор': 'role-admin',
                'Модератор': 'role-moderator',
                'Согласующий': 'role-approver',
                'Сотрудник': 'role-employee'
            };
            userRoleEl.classList.add(roleClassMap[user.role] || 'role-employee');

            if (user.role === 'Администратор') {
                userNameEl.classList.add('admin');
                userNameEl.title = 'Перейти в панель администратора';
                userNameEl.addEventListener('click', (e) => {
                    e.preventDefault();
                    window.location.hash = '#/admin';
                });

                // adminBell удалён из UI — переход в админку через клик по
                // имени пользователя (см. userNameEl.addEventListener выше).
            }

            // === Универсальный bell (события на заявках) — для всех ролей ===
            const userBell = document.getElementById('userBell');
            const userBellPanel = document.getElementById('userBellPanel');
            const userBellList  = document.getElementById('userBellList');
            const bellMarkAllBtn = document.getElementById('bellMarkAll');

            if (userBell) {
                userBell.addEventListener('click', (e) => {
                    e.stopPropagation();
                    toggleUserBellPanel();
                });
            }
            // Закрытие по клику вне панели
            document.addEventListener('click', (e) => {
                if (!userBellPanel || userBellPanel.classList.contains('hidden')) return;
                if (e.target.closest('#userBellWrap')) return;
                toggleUserBellPanel(false);
            });
            if (bellMarkAllBtn) {
                bellMarkAllBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    markAllNotificationsRead();
                });
            }
            const soundBtn = document.getElementById('bellSoundToggle');
            if (soundBtn) {
                const refreshSoundBtn = () => {
                    const enabled = localStorage.getItem('notifSound') !== 'off';
                    // Toggle через data-атрибут: CSS показывает нужный SVG.
                    soundBtn.dataset.muted = enabled ? 'false' : 'true';
                    soundBtn.title = enabled ? 'Звук уведомлений включён' : 'Звук уведомлений выключен';
                };
                refreshSoundBtn();
                soundBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    window.toggleNotificationSound();
                    refreshSoundBtn();
                });
            }
            if (userBellList) {
                userBellList.addEventListener('click', async (e) => {
                    const item = e.target.closest('.bell-item');
                    if (!item) return;
                    const notifId = parseInt(item.dataset.notifId, 10);
                    const reqId   = item.dataset.requestId;
                    if (!Number.isNaN(notifId)) {
                        await markNotificationsRead([notifId]);
                    }
                    if (reqId) {
                        toggleUserBellPanel(false);
                        window.location.hash = `#/request/${reqId}`;
                    }
                });
            }
            // Первичная загрузка
            loadUserNotifications();

            setupGlobalWebSocket();

            // При возврате к вкладке (после idle / переключения) — догружаем
            // unread-count. WS-уведомления могли не дойти если соединение
            // было разорвано в фоне, либо браузер кэшировал event'ы.
            document.addEventListener('visibilitychange', () => {
                if (!document.hidden) {
                    loadUserNotifications();
                }
            });

            window.addEventListener('beforeunload', saveState);
            window.addEventListener('hashchange', () => {
                saveState();
                handleRouteChange();
            });

            await handleRouteChange();

        } catch (error) {
            console.error("Ошибка инициализации:", error);
            handleLogout();
        }
    })();
});