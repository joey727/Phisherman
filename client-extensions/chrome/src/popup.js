document.addEventListener('DOMContentLoaded', () => {
    // UI Elements
    const loadingView = document.getElementById('loading');
    const resultView = document.getElementById('result');
    const errorView = document.getElementById('error');
    const errorMsg = document.getElementById('error-msg');
    const retryBtn = document.getElementById('retry-btn');

    const verdictText = document.getElementById('verdict-text');
    const verdictIcon = document.getElementById('verdict-icon');
    const scoreValue = document.getElementById('score-value');
    const scoreRing = document.getElementById('score-ring');
    const detailsList = document.getElementById('details-list');

    // Helper to switch views
    function showView(view) {
        [loadingView, resultView, errorView].forEach(v => v.classList.add('hidden'));
        view.classList.remove('hidden');
    }

    // Initialize Analysis
    init();

    retryBtn.addEventListener('click', () => {
        init();
    });

    async function init() {
        showView(loadingView);

        try {
            const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
            if (!tabs || tabs.length === 0) {
                throw new Error("No active tab found.");
            }
            const currentUrl = tabs[0].url;

            // Send message to background script to analyze
            chrome.runtime.sendMessage(
                { type: 'ANALYZE_URL', url: currentUrl },
                (response) => {
                    if (chrome.runtime.lastError) {
                        console.error(chrome.runtime.lastError);
                        showError("Could not connect to background service.");
                        return;
                    }

                    if (!response || !response.success) {
                        showError(response?.error || "Analysis failed.");
                        return;
                    }

                    renderResult(response.data);
                }
            );
        } catch (err) {
            console.error(err);
            showError(err.message);
        }
    }

    function showError(msg) {
        errorMsg.textContent = msg;
        showView(errorView);
    }

    function renderResult(data) {
        const { score, verdict, reasons } = data;

        // Reset classes
        verdictText.className = '';
        scoreRing.className = 'score-ring';

        const VERDICT_MAP = {
            phishing: { theme: 'danger', icon: '⚠️', label: 'Unsafe' },
            suspicious: { theme: 'warning', icon: '✋', label: 'Suspicious' },
            safe: { theme: 'safe', icon: '🛡️', label: 'Safe' }
        };

        // Fallback to safe if backend sends unknown verdict
        const verdictUI = VERDICT_MAP[verdict] ?? VERDICT_MAP.safe;

        // Reset UI state
        verdictText.className = '';
        scoreRing.className = 'score-ring';

        // Apply verdict UI
        verdictText.textContent = verdictUI.label;
        verdictText.classList.add(verdictUI.theme);

        verdictIcon.textContent = verdictUI.icon;

        scoreValue.textContent = String(score);
        scoreRing.classList.add(verdictUI.theme);

        // Render reasons
        detailsList.innerHTML = '';

        if (Array.isArray(reasons) && reasons.length > 0) {
            for (const reason of reasons) {
                const item = document.createElement('div');
                item.className = 'detail-item';
                item.textContent = reason;
                detailsList.appendChild(item);
            }
        } else {
            const item = document.createElement('div');
            item.className = 'detail-item';
            item.textContent = 'No specific flags detected.';
            detailsList.appendChild(item);
        }

        showView(resultView);
    }
});
