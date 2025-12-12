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
        const { score, verdict, reasons, details } = data;

        // Reset classes
        verdictText.className = '';
        scoreRing.className = 'score-ring';

        let themeClass = 'safe';
        let iconChar = '🛡️';
        let verdictLabel = 'Safe';

        if (verdict === 'danger') {
            themeClass = 'danger';
            iconChar = '⚠️';
            verdictLabel = 'Unsafe';
        } else if (verdict === 'warning') {
            themeClass = 'warning';
            iconChar = '✋';
            verdictLabel = 'Suspicious';
        }

        verdictText.textContent = verdictLabel;
        verdictText.classList.add(themeClass);

        verdictIcon.textContent = iconChar;

        scoreValue.textContent = score;
        scoreRing.classList.add(themeClass);

        // Render details
        detailsList.innerHTML = '';

        // Reasons
        if (reasons && reasons.length > 0) {
            reasons.forEach(r => {
                const item = document.createElement('div');
                item.className = 'detail-item';
                item.innerHTML = `<span>${r}</span>`;
                detailsList.appendChild(item);
            });
        } else {
            const item = document.createElement('div');
            item.className = 'detail-item';
            item.textContent = 'No specific flags detected.';
            detailsList.appendChild(item);
        }

        showView(resultView);
    }
});
