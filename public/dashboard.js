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

    const handleLogout = () => {
        secureFetch('/api/logout', { method: 'POST' });
        accessToken = null;
        window.location.href = '/login';
    };

    const refreshToken = async () => {
        if (isRefreshing) {
            return new Promise((resolve, reject) => {
                failedQueue.push({ resolve, reject });
            });
        }
        isRefreshing = true;
        try {
            const response = await fetch('/api/refresh-token', { method: 'POST' });
            if (!response.ok) {
                throw new Error("Не удалось обновить токен, требуется повторный вход.");
            }
            const { accessToken: newAccessToken } = await response.json();
            accessToken = newAccessToken;
            processFailedQueue(null, newAccessToken);
            return newAccessToken;
        } catch (error) {
            console.error("Ошибка обновления токена:", error);
            processFailedQueue(error, null);
            handleLogout();
            return Promise.reject(error);
        } finally {
            isRefreshing = false;
        }
    };

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
        let response = await fetch(url, requestOptions);
        if (response.status === 401 || response.status === 403) {
            try {
                const newToken = await refreshToken();
                requestOptions.headers['Authorization'] = `Bearer ${newToken}`;
                response = await fetch(url, requestOptions);
            } catch (error) {
                return Promise.reject(error);
            }
        }
        return response;
    };

    const sanitizeAndFormatText = (text) => {
        if (!text) return '';
        const tempDiv = document.createElement('div');
        tempDiv.textContent = String(text);
        return tempDiv.innerHTML.replace(/\n/g, '<br>');
    };

    const escapeAttr = (str) => {
        if (!str) return '';
        return String(str).replace(/"/g, '&quot;');
    };

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
    let unreadCommentIds = new Set();
    let unreadActivityIds = new Set();
    let isFiltersPopulated = false;

    let readHistoryBatch = [];
    let historyReadTimer = null;

    function saveState() {
        if (!listView.classList.contains('hidden')) {
            const listState = {
                scrollY: window.scrollY,
                searchValue: searchInput.value,
                selectedStatuses: [...statusOptionsContainer.querySelectorAll('input:checked')].map(cb => cb.value),
                selectedAuthors: [...authorOptionsContainer.querySelectorAll('input:checked')].map(cb => cb.value),
                dateCreatedFrom: dateCreatedFromInput.value,
                dateCreatedTo: dateCreatedToInput.value,
                dateUpdatedFrom: dateUpdatedFromInput.value,
                dateUpdatedTo: dateUpdatedToInput.value,
                currentPage: currentPage
            };
            sessionStorage.setItem('listState', JSON.stringify(listState));
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
            sessionStorage.setItem(`detailState_${requestId}`, JSON.stringify(detailState));
        }
    }

    function clearState(type, id = null) {
        if (type === 'list') {
            sessionStorage.removeItem('listState');
        } else if (type === 'detail' && id) {
            sessionStorage.removeItem(`detailState_${id}`);
        }
    }

    function restoreListState() {
        const savedListStateJSON = sessionStorage.getItem('listState');
        if (!savedListStateJSON) return;

        const savedState = JSON.parse(savedListStateJSON);
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
            const viewedIds = JSON.parse(localStorage.getItem(storageKey)) || [];
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
            globalWs = new WebSocket(`${wsProtocol}//${window.location.host}?token=${accessToken}`);

            globalWs.onopen = () => {
                console.log('Global WebSocket Connected');
                handleRouteChange(true);
            };

            globalWs.onmessage = (event) => {
                const data = JSON.parse(event.data);
                
                switch(data.type) {
                    case 'detail_update':
                        if (!detailView.classList.contains('hidden')) {
                           const requestId = window.location.hash.split('/')[2];
                           refreshDynamicContent(requestId, data.newCommentId);
                        }
                        break;
                    case 'list_item_update':
                        if (!listView.classList.contains('hidden')) {
                            updateListItem(data.request);
                        }
                        break;
                    case 'admin_log_update':
                        if (!adminView.classList.contains('hidden') && document.getElementById('logs-pane')?.classList.contains('active')) {
                             updateAdminLogs(data.log);
                        }
                        break;
                    case 'receipts_updated':
                        if (!detailView.classList.contains('hidden')) {
                            const requestId = window.location.hash.split('/')[2];
                            updateFeeds(requestId);
                        }
                        break;
                }
            };

            globalWs.onclose = () => {
                console.log('Global WebSocket Disconnected. Reconnecting in 3 seconds...');
                setTimeout(connect, 3000);
            };

            globalWs.onerror = (error) => {
                console.error('WebSocket Error:', error);
                globalWs.close();
            };
        }
        connect();
    }
    
    const handleRouteChange = async (isReconnect = false) => {
        detailViewFiles = [];
        
        if (commentObserver) { commentObserver.disconnect(); commentObserver = null; }
        if (activityObserver) { activityObserver.disconnect(); activityObserver = null; }
        
        unreadCommentIds.clear();
        unreadActivityIds.clear();
        
        const oldHash = window.location.hash;
        if (globalWs && globalWs.readyState === WebSocket.OPEN) {
             const oldRequestId = oldHash.split('/')[2];
             if(oldRequestId) globalWs.send(JSON.stringify({ type: 'unsubscribe', channel: `request-${oldRequestId}`}));
             if(oldHash === '#/admin') globalWs.send(JSON.stringify({ type: 'unsubscribe', channel: 'admin-logs' }));
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
            renderRequestListItems(allRequests);
            renderPagination(totalItems);
            updateActiveFilterTags();
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

            if (!reqRes.ok) throw new Error('Заявка не найдена');
            const request = await reqRes.json();
            currentDocumentsInView = await documentsRes.json();

            if (user.role === 'Согласующий' && request.status_name === 'На согласовании') {
                const storageKey = `viewedRequests_${user.id}`;
                let viewedIds = JSON.parse(localStorage.getItem(storageKey)) || [];
                if (!viewedIds.includes(request.id.toString())) {
                    viewedIds.push(request.id.toString());
                    localStorage.setItem(storageKey, JSON.stringify(viewedIds));
                }
            }
            if (user.role === 'Модератор' && request.status_id === 1) {
                secureFetch(`/api/requests/${requestId}/status`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ newStatusId: 2, details: 'Заявка автоматически взята в работу' })
                }).catch(err => console.error("Ошибка авто-взятия в работу:", err));
            }

            const displayStatus = getDisplayStatus(request.status_name, request.creator_id, request.id);
            const statusClass = displayStatus.replace(/ /g, '-').toLowerCase();

            detailView.innerHTML = `
                <div class="detail-grid">
                    <div class="detail-main-column">
                        <div class="detail-main-content">
                            <h3>№${request.id} ${sanitizeAndFormatText(request.title)}</h3>
                            <p>${sanitizeAndFormatText(request.description) || 'Описание отсутствует.'}</p>
                        </div>
                        <div id="documentsContainer">${renderDocumentsBlock(currentDocumentsInView, request.creator_id)}</div>
                    </div>
                    <div class="detail-sidebar">
                        <div class="sidebar-block">
                            <h4>Информация</h4>
                            <div class="info-grid">
                                <span>Статус:</span><div class="status-badge status-${statusClass}">${displayStatus}</div>
                                <span>Автор:</span><span>${sanitizeAndFormatText(request.creator_name)}</span>
                                ${request.branch_name ? `<span>Филиал:</span><span>${sanitizeAndFormatText(request.branch_name)}</span>` : ''}
                                <span>Создана:</span><span>${new Date(request.created_at).toLocaleString('ru-RU')}</span>
                                <span>Мероприятие:</span><span>${new Date(request.planned_date).toLocaleString('ru-RU')}</span>
                            </div>
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

            const savedDetailStateJSON = sessionStorage.getItem(`detailState_${requestId}`);
            if (savedDetailStateJSON) {
                const savedState = JSON.parse(savedDetailStateJSON);
                const sidebarBlock = detailView.querySelector('.view-switcher')?.closest('.sidebar-block');
                if (sidebarBlock && savedState.activeTab && savedState.activeTab !== 'activity') {
                    sidebarBlock.querySelector('.switcher-btn.active')?.classList.remove('active');
                    sidebarBlock.querySelector('.activity-pane.active-pane')?.classList.remove('active-pane');
                    sidebarBlock.querySelector(`[data-view="${savedState.activeTab}"]`)?.classList.add('active');
                    sidebarBlock.querySelector(`#${savedState.activeTab}Pane`)?.classList.add('active-pane');
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

    let adminState = { users: [], roles: [], branches: [], logs: [], totalLogs: 0, logsCurrentPage: 1 };

    const renderAdminView = async () => {
        listView.classList.add('hidden');
        detailView.classList.add('hidden');
        adminView.classList.remove('hidden');
        adminView.innerHTML = '<p>Загрузка панели администратора...</p>';
        try {
            const [usersRes, rolesRes, branchesRes, logsRes] = await Promise.all([
                secureFetch('/api/admin/users'),
                secureFetch('/api/roles'),
                secureFetch('/api/branches'),
                secureFetch(`/api/admin/logs?page=${adminState.logsCurrentPage}`)
            ]);
            adminState.users = await usersRes.json();
            adminState.roles = await rolesRes.json();
            adminState.branches = await branchesRes.json();
            const logsData = await logsRes.json();
            adminState.logs = logsData.logs;
            adminState.totalLogs = logsData.totalItems;

            const adminHtml = `
                <div class="admin-tabs">
                    <button class="switcher-btn admin-tab-btn active" data-tab="users">Управление пользователями</button>
                    <button class="switcher-btn admin-tab-btn" data-tab="logs">Системные логи</button>
                </div>
                <div id="users-pane" class="admin-pane active">
                    <div class="admin-table-container">${renderUsersTable(adminState.users, adminState.roles, adminState.branches)}</div>
                </div>
                <div id="logs-pane" class="admin-pane">
                    <div class="admin-table-container">
                        ${renderLogsTable(adminState.logs)}
                        <div class="admin-pagination-container">${renderAdminPagination(adminState.totalLogs, adminState.logsCurrentPage)}</div>
                    </div>
                </div>`;
            adminView.innerHTML = adminHtml;
        } catch (error) {
            console.error("Ошибка загрузки данных для админ-панели:", error);
            adminView.innerHTML = '<p class="error-message">Не удалось загрузить данные.</p>';
        }
    };

    function renderUsersTable(users, roles, branches) {
        const adminRole = roles.find(r => r.name === 'Администратор');
        const adminRoleId = adminRole ? adminRole.id : -1;
        return `
            <table class="admin-table users-table">
                <thead><tr><th>ID</th><th>ФИО</th><th>Email</th><th>Роль</th><th>Филиал</th><th>Активен</th><th>Действие</th></tr></thead>
                <tbody>
                    ${users.map(u => {
                        const isUserAdmin = u.role_id === adminRoleId;
                        return `
                            <tr data-user-id="${u.id}">
                                <td><span class="user-id-cell">#${u.id}</span></td>
                                <td>${sanitizeAndFormatText(u.full_name)}</td>
                                <td>${sanitizeAndFormatText(u.email)}</td>
                                <td>
                                    <select class="role-select" data-original-value="${u.role_id}" ${isUserAdmin || u.id === user.id ? 'disabled' : ''}>
                                        ${roles.map(r => `<option value="${r.id}" ${u.role_id === r.id ? 'selected' : ''} ${r.id === adminRoleId ? 'disabled' : ''}>${r.name}</option>`).join('')}
                                    </select>
                                </td>
                                <td>
                                    <select class="branch-select" data-original-value="${u.branch_id || ''}">
                                        <option value="">- Не указан -</option>
                                        ${branches.map(b => `<option value="${b.id}" ${u.branch_id === b.id ? 'selected' : ''}>${sanitizeAndFormatText(b.name)}</option>`).join('')}
                                    </select>
                                </td>
                                <td>
                                    <label class="toggle-switch">
                                        <input type="checkbox" class="status-toggle" data-original-value="${u.is_active}" ${u.is_active ? 'checked' : ''} ${u.id === user.id ? 'disabled' : ''}>
                                        <span class="slider"></span>
                                    </label>
                                </td>
                                <td><button class="btn-save" disabled>Сохранить</button></td>
                            </tr>`;
                    }).join('')}
                </tbody>
            </table>`;
    }

    function renderLogsTable(logs) {
        return `
            <table class="admin-table log-table">
                <thead><tr><th>Время</th><th>Пользователь</th><th>Событие</th><th>Детали</th><th>Заявка</th></tr></thead>
                <tbody>
                    ${logs.map(log => {
                        const eventTypeClass = log.event_type.replace(/ /g, '-').toLowerCase();
                        return `
                            <tr>
                                <td>${new Date(log.event_time).toLocaleString('ru-RU')}</td>
                                <td>${sanitizeAndFormatText(log.user_name) || 'Система'}</td>
                                <td><span class="log-type log-type-${eventTypeClass}">${sanitizeAndFormatText(log.event_type)}</span></td>
                                <td class="details-cell">${sanitizeAndFormatText(log.details) || '-'}</td>
                                <td class="request-id-cell">${log.request_id ? `<a href="#/request/${log.request_id}">№${log.request_id}</a>` : '-'}</td>
                            </tr>`;
                    }).join('')}
                </tbody>
            </table>`;
    }

    function renderAdminPagination(totalItems, currentPage) {
        const pageSize = 50;
        if (totalItems <= pageSize) return '';

        const totalPages = Math.ceil(totalItems / pageSize);
        let paginationHtml = `<div class="pagination-container"><button class="page-item prev" data-page="${currentPage - 1}" ${currentPage === 1 ? 'disabled' : ''}>&laquo; Назад</button>`;
        for (let i = 1; i <= totalPages; i++) {
            paginationHtml += `<button class="page-item ${i === currentPage ? 'active' : ''}" data-page="${i}">${i}</button>`;
        }
        paginationHtml += `<button class="page-item next" data-page="${currentPage + 1}" ${currentPage === totalPages ? 'disabled' : ''}>Вперед &raquo;</button></div>`;
        return paginationHtml;
    }

    async function refreshAdminLogs(page) {
        adminState.logsCurrentPage = parseInt(page, 10);
        const logsContainer = document.getElementById('logs-pane');
        if (!logsContainer) return;

        logsContainer.innerHTML = '<p>Загрузка логов...</p>';
        try {
            const logsRes = await secureFetch(`/api/admin/logs?page=${adminState.logsCurrentPage}`);
            if (!logsRes.ok) throw new Error('Ошибка сети при загрузке логов');

            const logsData = await logsRes.json();
            adminState.logs = logsData.logs;
            adminState.totalLogs = logsData.totalItems;
            logsContainer.innerHTML = `
                <div class="admin-table-container">
                    ${renderLogsTable(adminState.logs)}
                    <div class="admin-pagination-container">${renderAdminPagination(adminState.totalLogs, adminState.logsCurrentPage)}</div>
                </div>`;
        } catch (error) {
            console.error(error);
            logsContainer.innerHTML = '<p class="error-message">Ошибка загрузки логов.</p>';
        }
    }
    
    function updateListItem(request) {
        const item = document.querySelector(`.request-item[data-request-id="${request.id}"]`);
        if (!item) return;

        const displayStatus = getDisplayStatus(request.status, request.creator_id, request.id);
        const statusClass = displayStatus.replace(/ /g, '-').toLowerCase();

        const badge = item.querySelector('.status-badge');
        badge.className = `status-badge status-${statusClass}`;
        badge.textContent = displayStatus;
        
        item.querySelector('p').textContent = `Создатель: ${sanitizeAndFormatText(request.creator_name)} | Обновлено: ${new Date(request.updated_at).toLocaleString('ru-RU')}`;
        
        item.classList.add('new-activity');
    }
    
    function updateAdminLogs(log) {
        const tableBody = document.querySelector('.log-table tbody');
        if (!tableBody) return;

        const eventTypeClass = log.event_type.replace(/ /g, '-').toLowerCase();
        const newRow = `
            <tr>
                <td>${new Date(log.event_time).toLocaleString('ru-RU')}</td>
                <td>${sanitizeAndFormatText(log.user_name) || 'Система'}</td>
                <td><span class="log-type log-type-${eventTypeClass}">${sanitizeAndFormatText(log.event_type)}</span></td>
                <td class="details-cell">${sanitizeAndFormatText(log.details) || '-'}</td>
                <td class="request-id-cell">${log.request_id ? `<a href="#/request/${log.request_id}">№${log.request_id}</a>` : '-'}</td>
            </tr>`;
        
        tableBody.insertAdjacentHTML('afterbegin', newRow);
        
        tableBody.rows[0].style.backgroundColor = 'rgba(56, 189, 248, 0.2)';
        setTimeout(() => {
            if(tableBody.rows[0]) tableBody.rows[0].style.backgroundColor = '';
        }, 2000);
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

    const renderRequestListItems = (requests) => {
        if (requests && requests.length > 0) {
            requestsListEl.innerHTML = requests.map(req => {
                const displayStatus = getDisplayStatus(req.status, req.creator_id, req.id);
                const statusClass = displayStatus.replace(/ /g, '-').toLowerCase();
                const hasUnreadActivity = req.has_unread_activity === 1;
                const hasUnreadComments = req.has_unread_comments === 1;
                const newClass = (hasUnreadActivity || hasUnreadComments) ? 'new-activity' : '';
                return `
                    <li class="request-item ${newClass}" data-request-id="${req.id}">
                        <div>
                            <h3>№${req.id} ${sanitizeAndFormatText(req.title)}</h3>
                            <p>Создатель: ${sanitizeAndFormatText(req.creator_name)} | Обновлено: ${new Date(req.updated_at).toLocaleString('ru-RU')}</p>
                        </div>
                        <div class="status-badge status-${statusClass}">${displayStatus}</div>
                    </li>`;
            }).join('');
        } else {
            requestsListEl.innerHTML = `<p id="loadingMessage">Заявок, соответствующих фильтрам, не найдено.</p>`;
        }
    };

    const populateFilters = (uniqueCreators = []) => {
        const checkIcon = `<svg viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M13.3333 4L5.99999 11.3333L2.66666 8" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
        statusOptionsContainer.innerHTML = ALL_STATUSES.map(status =>
            `<label><input type="checkbox" value="${escapeAttr(status)}"><span class="custom-checkbox">${checkIcon}</span><span>${status}</span></label>`
        ).join('');

        if (['Администратор', 'Модератор', 'Согласующий'].includes(user.role)) {
            authorOptionsContainer.innerHTML = uniqueCreators.map(({ creator_id, creator_name }) =>
                `<label><input type="checkbox" value="${creator_id}" data-name="${escapeAttr(creator_name)}"><span class="custom-checkbox">${checkIcon}</span><span>${sanitizeAndFormatText(creator_name)}</span></label>`
            ).join('');
            advancedFiltersContainer.style.display = 'block';
        } else {
            advancedFiltersContainer.style.display = 'none';
        }
    };

    const updateActiveFilterTags = () => {
        activeFiltersContainer.innerHTML = '';
        let filterCount = 0;
        const createTag = (key, value, type, val = '') =>
            `<div class="filter-tag">
                <span class="key">${key}:</span> <span class="value">${value}</span>
                <button data-filter-type="${type}" data-filter-value="${val}">&times;</button>
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
        for (const file of files) {
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
                <button type="button" class="file-list-item-remove" data-index="${index}">&times;</button>
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
                documentsContainer.innerHTML = renderDocumentsBlock(currentDocumentsInView, request.creator_id);
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
            let commentsHtml = '';
            let lastChatDate = null;
            comments.sort((a, b) => new Date(a.created_at) - new Date(b.created_at)).forEach(item => {
                const itemDate = new Date(item.created_at).toDateString();
                if (itemDate !== lastChatDate) {
                    commentsHtml += `<div class="date-separator"><span>${formatDateSeparator(item.created_at)}</span></div>`;
                    lastChatDate = itemDate;
                }
                commentsHtml += renderChatItem(item, user.id);
            });
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
    };

    const renderDocumentsBlock = (documents, creatorId) => {
        const creatorFiles = documents.filter(d => d.uploaded_by_id === creatorId);
        const otherFiles = documents.filter(d => d.uploaded_by_id !== creatorId);

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

        return `
            <div class="detail-block-files">
                <h4>Прикрепленные файлы</h4>
                <div class="document-lists-container">
                    ${creatorHtml || otherHtml ? creatorHtml + otherHtml : '<p class="no-files-message">Файлов еще нет.</p>'}
                </div>
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
                </div>
            </div>`;
    };

    const renderActionsBlock = (request) => {
        let actionsHtml = '';
        const { role } = user;
        const { status_id, creator_id } = request;

        if (role === 'Модератор') {
            if (status_id === 1) {
                actionsHtml = `<button id="changeStatusBtn" data-new-status="2" data-details="Заявка взята в работу" class="btn-main">Взять в работу</button>`;
            } else if (status_id === 2) {
                actionsHtml = `
                    <select id="statusSelect">
                        <option value="3">Отправить на согласование</option>
                        <option value="6">Вернуть на доработку</option>
                        <option value="5">Отклонить</option>
                    </select>
                    <button id="changeStatusBtn" class="btn-main">Применить</button>`;
            }
        } else if (role === 'Согласующий' && status_id === 3) {
            actionsHtml = `
                <select id="statusSelect">
                    <option value="4">Одобрить</option>
                    <option value="6">Вернуть на доработку</option>
                    <option value="5">Отклонить</option>
                </select>
                <button id="changeStatusBtn" class="btn-main">Применить</button>`;
        } else if (user.id === creator_id && status_id === 6) {
            actionsHtml = `
                <p>Заявка возвращена. Внесите изменения и отправьте повторно.</p>
                <button id="changeStatusBtn" data-new-status="2" data-details="Заявка повторно отправлена на модерацию" class="btn-main">Отправить повторно</button>`;
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
                    <span class="timestamp">${new Date(item.timestamp).toLocaleString('ru-RU')}</span>
                </div>
                <p><strong>${sanitizeAndFormatText(item.action)}</strong><br>${sanitizeAndFormatText(item.details) || ''}</p>
            </div>
        </div>`;

    const renderChatItem = (item, currentUserId) => {
        const isSelf = item.user_id === currentUserId;
        let statusIcon = '';
        if (isSelf) {
            const readers = item.readers ? item.readers.split(',').map(Number) : [];
            statusIcon = readers.some(r => r !== currentUserId) ? doubleCheckSVG : singleCheckSVG;
        }
        return `
            <div class="${isSelf ? 'chat-bubble self' : 'chat-bubble'}" data-item-id="${item.id}">
                ${!isSelf ? `<span class="author">${sanitizeAndFormatText(item.full_name)}</span>` : ''}
                <p>${sanitizeAndFormatText(item.comment_text)}</p>
                <span class="timestamp-status">
                    <span>${new Date(item.created_at).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })}</span>
                    ${statusIcon}
                </span>
            </div>`;
    };

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
            let newlyVisibleHistoryIds = [];
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
        }, { root: feed, threshold: 0.8 });
        return observer;
    };

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
                alert(`Не удалось скачать файл: ${doc.file_name}`);
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
            alert('Не удалось скачать архив.');
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

        openModalBtn.addEventListener('click', () => {
            const now = new Date();
            now.setMinutes(now.getMinutes() - now.getTimezoneOffset());
            reqDate.min = now.toISOString().slice(0, 16);
            createModal.classList.add('active');
        });
        document.getElementById('closeCreateModalBtn').addEventListener('click', () => createModal.classList.remove('active'));
        createModal.addEventListener('click', e => {
            if (e.target === createModal) createModal.classList.remove('active');
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
            for (const file of files) {
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
                    <button type="button" class="file-list-item-remove" data-index="${index}">&times;</button>
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
            let isFormValid = true;

            reqTitleInput.classList.remove('error');
            titleError.style.display = 'none';
            reqDescriptionInput.classList.remove('error');
            fileUploader.classList.remove('error');
            descriptionError.style.display = 'none';
            reqDate.classList.remove('error');
            dateErrorMessage.style.display = 'none';

            if (reqTitleInput.value.trim() === '') {
                titleError.textContent = 'Пожалуйста, введите название мероприятия.';
                titleError.style.display = 'block';
                reqTitleInput.classList.add('error');
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
            selectedFiles.forEach(f => formData.append('documentFiles', f));

            const submitBtn = createForm.querySelector('button[type="submit"]');
            submitBtn.disabled = true;
            submitBtn.textContent = 'Отправка...';

            try {
                    const res = await secureFetch('/api/requests', { method: 'POST', body: formData });
                    if (!res.ok) {
                        const err = await res.json();
                        if (res.status === 403) {
                            alert(err.message || 'Ваш аккаунт был заблокирован из-за подозрительной активности.');
                            window.location.href = '/login';
                            return;
                        }
                        document.getElementById('modalErrorMessage').textContent = err.message || 'Произошла ошибка.';
                        document.getElementById('modalErrorMessage').classList.add('visible');
                    } else {
                        createModal.classList.remove('active');
                        createForm.reset();
                        selectedFiles = [];
                        updateFileList();
                        resetToFirstPageAndRender();
                    }
                } catch (err) {
                    document.getElementById('modalErrorMessage').textContent = 'Ошибка сети. Попробуйте снова.';
                    document.getElementById('modalErrorMessage').classList.add('visible');
                } finally {
                    submitBtn.disabled = false;
                    submitBtn.textContent = 'Отправить';
                }
        });
    }

    document.getElementById('logoutButton').addEventListener('click', handleLogout);

    backToListBtn.addEventListener('click', () => { window.location.hash = ''; });

    requestsListEl.addEventListener('click', (e) => {
        const item = e.target.closest('.request-item');
        if (item) {
            window.location.hash = `#/request/${item.dataset.requestId}`;
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
        if (target.closest('.admin-tab-btn')) {
            const tabButton = target.closest('.admin-tab-btn');
            if (tabButton.classList.contains('active')) return;

            document.querySelector('.admin-tab-btn.active').classList.remove('active');
            document.querySelector('.admin-pane.active').classList.remove('active');
            tabButton.classList.add('active');
            document.getElementById(`${tabButton.dataset.tab}-pane`).classList.add('active');
            return;
        }

        if (target.closest('.btn-save')) {
            const saveButton = target.closest('.btn-save');
            const row = saveButton.closest('tr');
            const userId = row.dataset.userId;
            const roleSelect = row.querySelector('.role-select');
            const branchSelect = row.querySelector('.branch-select');
            const statusToggle = row.querySelector('.status-toggle');
            const data = {
                role_id: parseInt(roleSelect.value, 10),
                branch_id: branchSelect.value ? parseInt(branchSelect.value, 10) : null,
                is_active: statusToggle.checked
            };

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

                saveButton.classList.add('success');
                saveButton.textContent = '✓';
                setTimeout(() => {
                    saveButton.classList.remove('success');
                    saveButton.textContent = 'Сохранить';
                }, 2000);
            } catch (error) {
                console.error('Ошибка при сохранении пользователя:', error);
                alert('Не удалось сохранить изменения: ' + error.message);
                saveButton.disabled = false;
                saveButton.textContent = 'Сохранить';
            }
            return;
        }
        if (target.closest('.admin-pagination-container .page-item')) {
            const pageButton = target.closest('.page-item');
            if (pageButton.disabled) return;
            const page = pageButton.dataset.page;
            await refreshAdminLogs(page);
        }
    });

    adminView.addEventListener('change', (e) => {
        const target = e.target;
        if (target.matches('.role-select, .branch-select, .status-toggle')) {
            const row = target.closest('tr');
            const saveButton = row.querySelector('.btn-save');
            const roleSelect = row.querySelector('.role-select');
            const branchSelect = row.querySelector('.branch-select');
            const statusToggle = row.querySelector('.status-toggle');
            const isChanged = roleSelect.value !== roleSelect.dataset.originalValue ||
                branchSelect.value !== branchSelect.dataset.originalValue ||
                statusToggle.checked.toString() !== statusToggle.dataset.originalValue;
            saveButton.disabled = !isChanged;
        }
    });

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
                alert('Не удалось скачать файл. ' + err.message);
            } finally {
                link.textContent = originalText;
                link.classList.remove('downloading');
            }
            return;
        }

        if (target.closest('#changeStatusBtn')) {
            const btn = target.closest('#changeStatusBtn');
            let newStatusId, details;
            const select = document.getElementById('statusSelect');
            if (select) {
                newStatusId = select.value;
                details = `Статус изменен на "${select.options[select.selectedIndex].text}"`;
            } else {
                newStatusId = btn.dataset.newStatus;
                details = btn.dataset.details || `Статус изменен`;
            }

            if (newStatusId) {
                btn.disabled = true;
                try {
                    const r = await secureFetch(`/api/requests/${requestId}/status`, {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ newStatusId, details })
                    });
                    if (!r.ok) {
                        const err = await r.json();
                        alert(`Ошибка: ${err.message}`);
                        btn.disabled = false;
                    }
                } catch (err) {
                    alert('Ошибка сети.');
                    btn.disabled = false;
                }
            }
            return;
        }
    });

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
                alert('Сначала выберите или перетащите файлы.');
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
                } else {
                    const err = await r.json();
                    alert(`Ошибка: ${err.message}`);
                }
            } catch (err) {
                alert('Ошибка сети.');
            } finally {
                btn.textContent = 'Загрузить выбранные файлы';
                btn.disabled = false;
            }
        }
        if (e.target.id === 'commentForm') {
            e.preventDefault();
            const form = e.target;
            const textarea = form.querySelector('textarea');
            const data = { comment_text: textarea.value };
            if (!data.comment_text.trim()) return;

            const btn = form.querySelector('button');
            btn.disabled = true;
            try {
                const response = await secureFetch(`/api/requests/${requestId}/comments`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                if (response.ok) {
                    form.reset();
                    textarea.focus();
                } else {
                    alert('Не удалось добавить комментарий.');
                }
            } catch (err) {
                alert('Ошибка сети.');
            } finally {
                btn.disabled = false;
            }
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
            const response = await fetch('/api/refresh-token', { method: 'POST' });
            if (!response.ok) {
                throw new Error("Не удалось обновить сессию.");
            }
            const { accessToken: newAccessToken } = await response.json();
            accessToken = newAccessToken;

            user = parseJwt(accessToken);
            if (!user) throw new Error("Не удалось декодировать токен");

            userNameEl.textContent = user.fullName;
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
            }

            setupGlobalWebSocket(); 

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