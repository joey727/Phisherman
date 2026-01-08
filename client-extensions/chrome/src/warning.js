document.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const targetUrl = urlParams.get('url');
    const urlDisplay = document.getElementById('url-display');

    if (targetUrl) {
        urlDisplay.textContent = targetUrl;
    }

    document.getElementById('back-btn').addEventListener('click', () => {
        window.history.back();
        // If no history, close or go to a safe spot
        setTimeout(() => {
            window.location.href = 'https://google.com';
        }, 100);
    });

    document.getElementById('proceed-btn').addEventListener('click', () => {
        if (confirm("This site is flagged as dangerous. Are you sure you want to proceed?")) {
            // Whitelist temporarily and proceed
            chrome.runtime.sendMessage({ type: 'WHITELIST_URL', url: targetUrl }, () => {
                window.location.replace(targetUrl);
            });
        }
    });
});
