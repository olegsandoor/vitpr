/**
 * 404.js — клиентский скрипт страницы 404.
 *
 * Размещён отдельным файлом (а не inline `onclick=`), чтобы соблюдать
 * строгий CSP `script-src 'self'; script-src-attr 'none'` — inline-handlers
 * блокируются.
 */
(function () {
    'use strict';
    document.addEventListener('DOMContentLoaded', () => {
        const btn = document.getElementById('nfBackBtn');
        if (!btn) return;
        btn.addEventListener('click', () => {
            // history.back() работает только если есть откуда возвращаться.
            // Иначе — мягкий fallback на главную страницу.
            if (window.history.length > 1) {
                window.history.back();
            } else {
                window.location.href = '/';
            }
        });
    });
})();
