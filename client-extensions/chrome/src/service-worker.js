// Simple example: when a tab is updated, query backend and create a notification on phishing verdict.
//
// IMPORTANT: keep auto-scan optional in UI. This service worker is intentionally minimal.
const BACKEND_URL = 'http://localhost:4000/api/check';

// intercept navigation
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId !== 0) return; // only main frame

    const url = details.url;
    if (!url.startsWith("http")) return;

    // Avoid infinite loop
    if (url.includes("warning.html")) return;
    try {
        const verdict = await analyzeUrl(url);

        if (verdict.verdict === "danger") {
        // Store blocked URL
        await chrome.storage.session.set({
            blockedUrl: url,
            verdict
        });

        // Redirect to warning page
        chrome.tabs.update(details.tabId, {
            url: chrome.runtime.getURL("warning.html")
        });
        }
    } catch (err) {
        console.error("Background analysis failed:", err);
    }
});


// 1. Listen for messages from the popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'ANALYZE_URL') {
        handleAnalyzeUrl(message.url)
            .then(sendResponse)
            .catch(err => sendResponse({ success: false, error: err.message }));
        return true; // Keep the message channel open for async response
    }
});

async function handleAnalyzeUrl(url) {
    try {
        const cfg = await chrome.storage.sync.get(['phisherman_api_key']);
        const headers = { 'Content-Type': 'application/json' };
        if (cfg.phisherman_api_key) headers['x-api-key'] = cfg.phisherman_api_key;

        const res = await fetch(BACKEND_URL, {
            method: 'POST',
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url })
        });

        if (!res.ok) {
            throw new Error(`Server error: ${res.status}`);
        }

        const data = await res.json();
        return { success: true, data };
    } catch (err) {
        console.error('Analysis error:', err);
        throw err;
    }
}

// 2. Also keep the auto-scan logic if desired, or reuse the helper
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    try {
        if (!changeInfo.url) return;
        const url = changeInfo.url;

        const cfg = await chrome.storage.sync.get(['autoscans_enabled']);
        if (!cfg.autoscans_enabled) return;

        // Reuse the same helper logic, but we don't need to send a response anywhere
        // We just notify if phishing
        const result = await handleAnalyzeUrl(url);
        if (result.data && result.data.verdict === 'phishing') {
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'src/icons/icon48.png',
                title: 'Phisherman warning',
                message: `Phishing detected: ${new URL(url).hostname}`
            });
        }
    } catch (err) {
        // silent failure in service worker auto-scan
        console.error('Phisherman worker error', err);
    }
});
