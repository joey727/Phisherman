document.addEventListener('DOMContentLoaded', () => {
    // Icons (Lucide Style)
    const ICONS = {
        shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
        check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
        alert: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
        info: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>'
    };

    // UI Elements
    const loadingView = document.getElementById('loading');
    const domainLabel = document.getElementById('domain-name');
    const shieldIcon = document.getElementById('shield-icon');
    const statusBadge = document.getElementById('status-badge');

    const verdictText = document.getElementById('verdict-text');
    const verdictSub = document.getElementById('verdict-subtitle');

    const scoreVal = document.getElementById('score-value');
    const threatVal = document.getElementById('threat-level');
    const detailsList = document.getElementById('details-list');

    const retryBtn = document.getElementById('retry-btn');

    // Initialize Analysis
    init();

    retryBtn.addEventListener('click', () => init());

    async function init() {
        loadingView.classList.remove('hidden');

        try {
            const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
            if (!tabs || tabs.length === 0) throw new Error("No active tab.");

            const url = new URL(tabs[0].url);
            domainLabel.textContent = url.hostname;

            chrome.runtime.sendMessage(
                { type: 'ANALYZE_URL', url: url.toString() },
                (response) => {
                    setTimeout(() => {
                        loadingView.classList.add('hidden');
                        if (chrome.runtime.lastError || !response || !response.success) {
                            showError(response?.error || "Connection Fault");
                            return;
                        }
                        renderResult(response.data);
                    }, 400);
                }
            );
        } catch (err) {
            loadingView.classList.add('hidden');
            showError(err.message);
        }
    }

    function showError(msg) {
        verdictText.textContent = "Analysis failed";
        verdictSub.textContent = msg;
        shieldIcon.innerHTML = ICONS.shield;
        shieldIcon.querySelector('svg').style.color = 'var(--text-muted)';
        statusBadge.innerHTML = ICONS.alert;
        statusBadge.className = 'status-badge bg-danger';
    }

    function renderResult(data) {
        const { score, verdict, reasons } = data;

        let colorClass = 'safe';
        let badgeColor = 'bg-safe';
        let badgeIcon = ICONS.check;
        let title = 'Site is secure';
        let sub = 'Phisherman has not found any threats';

        if (verdict === 'phishing') {
            colorClass = 'danger';
            badgeColor = 'bg-danger';
            badgeIcon = ICONS.alert;
            title = 'Site is dangerous';
            sub = 'Phisherman recommends leaving immediately';
        } else if (verdict === 'suspicious') {
            colorClass = 'warning';
            badgeColor = 'bg-warning';
            badgeIcon = ICONS.alert;
            title = 'Site is suspicious';
            sub = 'Exercise caution while browsing';
        }

        // Apply to UI
        shieldIcon.innerHTML = ICONS.shield;
        const svg = shieldIcon.querySelector('svg');
        svg.setAttribute('stroke', `var(--${colorClass})`);
        svg.style.color = `var(--${colorClass})`;

        statusBadge.innerHTML = badgeIcon;
        statusBadge.className = `status-badge ${badgeColor}`;

        verdictText.textContent = title;
        verdictText.className = `verdict-title ${colorClass}`;
        verdictSub.textContent = sub;

        scoreVal.textContent = score !== undefined ? `${score}` : '--';
        scoreVal.className = `stat-value ${colorClass}`;

        threatVal.textContent = verdict.toUpperCase();
        threatVal.className = `stat-value ${colorClass}`;

        // Render details
        detailsList.innerHTML = '';
        if (reasons && reasons.length > 0) {
            reasons.forEach(r => {
                const div = document.createElement('div');
                div.className = 'detail-row';
                div.innerHTML = `${ICONS.info} <span>${r}</span>`;
                detailsList.appendChild(div);
            });
        } else {
            const div = document.createElement('div');
            div.className = 'detail-row';
            div.innerHTML = `${ICONS.check} <span>No active threats detected.</span>`;
            detailsList.appendChild(div);
        }
    }
});
