// Simple example: when a tab is updated, query backend and create a notification on phishing verdict.
//
// IMPORTANT: keep auto-scan optional in UI. This service worker is intentionally minimal.
const BACKEND_URL = 'http://localhost:4000/api/check';

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    try {
        if (!changeInfo.url) return;
        const url = changeInfo.url;
        // Optional: skip until user enables auto-scan
        const cfg = await chrome.storage.sync.get(['autoscans_enabled', 'phisherman_api_key']);
        if (!cfg.autoscans_enabled) return;

        const headers = { 'Content-Type': 'application/json' };
        if (cfg.phisherman_api_key) headers['x-api-key'] = cfg.phisherman_api_key;

        const res = await fetch(BACKEND_URL, {
            method: 'POST',
            headers,
            body: JSON.stringify({ url })
        });
        if (!res.ok) return;
        const data = await res.json();
        if (data.verdict === 'phishing') {
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'src/icons/icon48.png',
                title: 'Phisherman warning',
                message: `Phishing detected: ${new URL(url).hostname}`
            });
        }
    } catch (err) {
        // silent failure in service worker
        console.error('Phisherman worker error', err);
    }
});
