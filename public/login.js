document.addEventListener('DOMContentLoaded', () => {
    const wrapper = document.getElementById('authWrapper');
    const loginForm = document.getElementById('loginForm');

    function setContainerHeight() {
        const activeForm = document.querySelector('.auth-form.active');
        if (activeForm) {
            setTimeout(() => {
                wrapper.style.height = activeForm.scrollHeight + 'px';
            }, 50);
        }
    }

    function displayServerMessage(formId, message, isSuccess) {
        const container = document.getElementById(`${formId}ServerMessage`);
        if (!container) return;
        container.textContent = message;
        container.className = 'server-message';
        if (message) {
            container.classList.add(isSuccess ? 'success' : 'error');
            container.style.display = 'block';
        } else {
            container.style.display = 'none';
        }
        setContainerHeight();
    }

    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const submitButton = loginForm.querySelector('.btn-main');
        const formData = new FormData(loginForm);
        const data = Object.fromEntries(formData.entries());

        submitButton.disabled = true;
        displayServerMessage('login', '', false);

        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            const result = await response.json();

            if (response.ok) {
                submitButton.classList.add('success');
                submitButton.textContent = 'Успешно!';
                setTimeout(() => window.location.href = '/', 800);
            } else {
                displayServerMessage('login', result.message || 'Произошла ошибка', false);
                submitButton.disabled = false;
            }
        } catch (error) {
            displayServerMessage('login', 'Ошибка сети. Попробуйте снова.', false);
            submitButton.disabled = false;
        }
    });

    // «Забыли пароль» — пока без email-сервиса показываем инструкцию.
    // Когда подключим nodemailer, эта кнопка будет генерировать reset-токен.
    document.getElementById('forgotPassBtn')?.addEventListener('click', () => {
        const overlay = document.createElement('div');
        overlay.className = 'forgot-overlay';
        // role/aria для screen-reader'ов.
        overlay.setAttribute('role', 'dialog');
        overlay.setAttribute('aria-modal', 'true');
        overlay.setAttribute('aria-label', 'Восстановление доступа');
        overlay.innerHTML = `
            <div class="forgot-card">
                <h2>Восстановление доступа</h2>
                <p>В системе действует политика централизованного управления учётными записями.</p>
                <p>Для сброса пароля обратитесь к администратору ИС либо в отдел информационных технологий РУП «Витебскэнерго»:</p>
                <ul>
                    <li>📞 Тел.: <strong>(0212) 67-22-22</strong> доб. 245</li>
                    <li>📧 Email: <strong>support@vitebsk.energo.by</strong></li>
                    <li>📍 Каб. 312, ул. Правды, 30</li>
                </ul>
                <p class="forgot-note">Назовите свою корпоративную почту — администратор сгенерирует временный пароль и передаст его по защищённому каналу.</p>
                <button class="btn-main" id="forgotClose">Понятно</button>
            </div>
        `;
        document.body.appendChild(overlay);
        const prevActive = document.activeElement;
        const close = () => {
            overlay.remove();
            if (prevActive && typeof prevActive.focus === 'function') prevActive.focus();
        };
        overlay.querySelector('#forgotClose').addEventListener('click', close);
        overlay.addEventListener('click', e => { if (e.target === overlay) close(); });

        // a11y — Esc, Tab-trap, начальный фокус. Без хелпера —
        // login.js не имеет setupModalA11y из dashboard.js. Inline-реализация.
        const FOCUSABLE_SEL = 'a[href], button:not([disabled]), input:not([disabled]), ' +
                              'textarea:not([disabled]), select:not([disabled]), ' +
                              '[tabindex]:not([tabindex="-1"])';
        const focusables = overlay.querySelectorAll(FOCUSABLE_SEL);
        const first = focusables[0];
        const last = focusables[focusables.length - 1];
        if (first) setTimeout(() => first.focus(), 0);
        overlay.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                e.preventDefault();
                close();
                return;
            }
            if (e.key !== 'Tab' || !first || !last) return;
            if (e.shiftKey && document.activeElement === first) {
                last.focus();
                e.preventDefault();
            } else if (!e.shiftKey && document.activeElement === last) {
                first.focus();
                e.preventDefault();
            }
        });
    });

    window.addEventListener('load', setContainerHeight);
    window.addEventListener('resize', setContainerHeight);
});
