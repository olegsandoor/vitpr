document.addEventListener('DOMContentLoaded', () => {
    const wrapper = document.getElementById('authWrapper');
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');
    const switchToRegisterBtn = document.getElementById('switchToRegister');
    const switchToLoginBtn = document.getElementById('switchToLogin');
    
    function setContainerHeight() {
        const activeForm = document.querySelector('.auth-form.active');
        if (activeForm) {
            setTimeout(() => {
                wrapper.style.height = activeForm.scrollHeight + 'px';
            }, 50);
        }
    }
    
    function toggleForms(target) {
        const isRegister = target === 'register';
        loginForm.classList.toggle('active', !isRegister);
        registerForm.classList.toggle('active', isRegister);
        setContainerHeight();
        const activeForm = isRegister ? registerForm : loginForm;
        setTimeout(() => {
            activeForm.querySelector('h1').focus();
        }, 50);
    }
    switchToRegisterBtn.addEventListener('click', () => toggleForms('register'));
    switchToLoginBtn.addEventListener('click', () => toggleForms('login'));
    
    const customSelect = document.getElementById('customBranchSelect');
    const hiddenSelect = document.getElementById('r_branch');
    const optionsContainer = registerForm.querySelector('.custom-options-container');
    const selectedPlaceholder = customSelect.querySelector('.custom-select-placeholder');
    
    customSelect.addEventListener('click', () => {
        customSelect.classList.toggle('open');
        const hasValue = !!hiddenSelect.value;
        customSelect.closest('.input-group').classList.toggle('focused', customSelect.classList.contains('open') || hasValue);
    });
    
    async function loadBranches() {
        try {
            const response = await fetch('/api/branches');
            if (!response.ok) throw new Error('Network error');
            const branches = await response.json();
            optionsContainer.innerHTML = '';
            
            hiddenSelect.innerHTML = '<option value="" disabled selected></option>';
            selectedPlaceholder.textContent = ''; 

            branches.forEach(branch => {
                const nativeOption = document.createElement('option');
                nativeOption.value = branch.id;
                nativeOption.textContent = branch.name;
                hiddenSelect.appendChild(nativeOption);
                
                const customOption = document.createElement('div');
                customOption.classList.add('custom-option');
                customOption.textContent = branch.name;
                customOption.dataset.value = branch.id;
                optionsContainer.appendChild(customOption);
                
                customOption.addEventListener('click', () => {
                    selectedPlaceholder.textContent = customOption.textContent;
                    selectedPlaceholder.title = customOption.textContent;
                    hiddenSelect.value = customOption.dataset.value;
                    hiddenSelect.dispatchEvent(new Event('change', { bubbles: true })); 
                    customSelect.classList.remove('open');
                    customSelect.closest('.input-group').classList.add('focused');
                    validateField(hiddenSelect);
                });
            });
        } catch (error) {
            console.error('Ошибка загрузки филиалов:', error);
            selectedPlaceholder.textContent = 'Ошибка загрузки';
        }
    }
    window.addEventListener('click', e => {
        if (!customSelect.contains(e.target)) {
            customSelect.classList.remove('open');
            if (!hiddenSelect.value) {
                customSelect.closest('.input-group').classList.remove('focused');
            }
        }
    });
    
    const fields = {
        fio: document.getElementById('r_fio'),
        email: document.getElementById('r_email'),
        branch_id: hiddenSelect,
        password: document.getElementById('r_pass'),
        password_confirm: document.getElementById('r_pass_confirm')
    };

    function setErrorMessage(field, message, isValid) {
        const inputGroup = field.closest('.input-group');
        const errorContainer = inputGroup.querySelector('.error-message');
        const elementToStyle = (field.tagName === 'SELECT' || field === hiddenSelect) ? customSelect : field;

        if (message) {
            errorContainer.textContent = message;
            errorContainer.classList.add('visible');
            elementToStyle.classList.add('error');
            elementToStyle.classList.remove('success');
        } else {
            errorContainer.textContent = '';
            errorContainer.classList.remove('visible');
            elementToStyle.classList.remove('error');
            if (isValid) {
                elementToStyle.classList.add('success');
            } else {
                elementToStyle.classList.remove('success');
            }
        }
        setContainerHeight();
    }
    
    function validateField(field) {
        const { id, value } = field;
        let message = '';
        let isValid = false;
        
        const currentId = field.tagName === 'SELECT' ? 'r_branch' : id;

        switch (currentId) {
            case 'r_fio': isValid = value.trim().length >= 5; message = isValid ? '' : 'ФИО должно быть не менее 5 символов.'; break;
            case 'r_email': isValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value); message = isValid ? '' : 'Введите корректный email.'; break;
            case 'r_branch': isValid = !!value && value !== ''; message = isValid ? '' : 'Выберите ваш филиал.'; break; 
            case 'r_pass':
                if (value.length < 10) message = 'Пароль минимум 10 символов.';
                else if (!/[a-zа-я]/i.test(value)) message = 'Пароль должен содержать букву.';
                else if (!/\d/.test(value)) message = 'Пароль должен содержать цифру.';
                else if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]+/.test(value)) message = 'Пароль должен содержать спецсимвол.';
                else isValid = true;
                if(fields.password_confirm.value) validateField(fields.password_confirm);
                break;
            case 'r_pass_confirm': isValid = value && value === fields.password.value; message = isValid ? '' : 'Пароли не совпадают.'; break;
            default: isValid = true;
        }
        
        setErrorMessage(field, message, isValid);
        return isValid;
    }

    Object.values(fields).forEach(field => {
        const eventType = (field.tagName === 'SELECT' || field.id === 'r_branch') ? 'change' : 'input';
        field.addEventListener(eventType, () => validateField(field));
    });
    
    function displayServerMessage(formId, message, isSuccess) {
        const container = document.getElementById(`${formId}ServerMessage`);
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
                //sessionStorage.setItem('accessToken', result.accessToken);

                submitButton.classList.add('success');
                submitButton.textContent = 'Успешно!';
                setTimeout(() => window.location.href = '/', 1000);
            } else {
                displayServerMessage('login', result.message || 'Произошла ошибка', false);
                submitButton.disabled = false;
            }
        } catch (error) {
            displayServerMessage('login', 'Ошибка сети. Попробуйте снова.', false);
            submitButton.disabled = false;
        }
    });
    
    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        let isFormValid = true;
        
        Object.values(fields).forEach(field => {
            if (!validateField(field)) isFormValid = false;
        });

        if (!isFormValid) {
             displayServerMessage('register', 'Пожалуйста, исправьте ошибки в форме.', false);
             return;
        }

        const formData = new FormData(registerForm);
        const data = Object.fromEntries(formData.entries());

        try {
            const response = await fetch('/api/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            const result = await response.json();
            if (response.ok) {
                displayServerMessage('register', result.message, true);
                registerForm.reset();
                selectedPlaceholder.textContent = '';
                customSelect.closest('.input-group').classList.remove('focused');
                
                Object.values(fields).forEach(field => {
                    const el = (field.tagName === 'SELECT' || field === hiddenSelect) ? customSelect : field;
                    el.classList.remove('success', 'error');
                    const group = el.closest('.input-group');
                    if(group) {
                         const err = group.querySelector('.error-message');
                         if(err) err.classList.remove('visible');
                    }
                });
                 setTimeout(() => toggleForms('login'), 3000);
            } else {
                 displayServerMessage('register', result.message || 'Произошла ошибка', false);
            }
        } catch (err) {
             displayServerMessage('register', 'Ошибка сети. Попробуйте снова.', false);
        }
    });
    window.addEventListener('load', () => { setContainerHeight(); loadBranches(); });
    window.addEventListener('resize', setContainerHeight);
});