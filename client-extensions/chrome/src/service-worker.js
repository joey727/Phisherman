// Simple example: when a tab is updated, query backend and create a notification on phishing verdict.
//
// IMPORTANT: keep auto-scan optional in UI. This service worker is intentionally minimal.
const BACKEND_URL = 'https://phisherman-5r1o.onrender.com/api/check';


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

// Session-based whitelist to avoid re-scanning the same URL
const sessionWhitelist = new Set();

// intercept navigation
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId !== 0) return; // only main frame

    const url = details.url;
    if (!url.startsWith("http")) return;

    // Exclude internal/extension pages
    if (url.includes(chrome.runtime.id)) return;
    if (url.includes("warning.html")) return;

    // Check if scans are enabled
    const cfg = await chrome.storage.sync.get(['autoscans_enabled']);
    if (!cfg.autoscans_enabled) return;

    // Check whitelist
    if (sessionWhitelist.has(url)) return;

    // Background Scan (Non-blocking)
    handleAnalyzeUrl(url).then(result => {
        if (result && result.data && (result.data.verdict === 'phishing' || result.data === 'phishing')) {
            // Threat detected, redirect the tab to warning page
            chrome.tabs.update(details.tabId, {
                url: chrome.runtime.getURL(`src/warning.html?url=${encodeURIComponent(url)}`)
            });
        } else {
            // URL is safe, whitelist it for the rest of the session
            sessionWhitelist.add(url);
        }
    }).catch(err => {
        console.error("Background scan failed:", err);
    });
});


// 1. Listen for messages
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'ANALYZE_URL') {
        handleAnalyzeUrl(message.url)
            .then(sendResponse)
            .catch(err => sendResponse({ success: false, error: err.message }));
        return true; // Keep the message channel open for async response
    }

    if (message.type === 'WHITELIST_URL') {
        if (message.url) {
            sessionWhitelist.add(message.url);
            sendResponse({ success: true });
        } else {
            sendResponse({ success: false });
        }
    }
});



// 2. Also keep the auto-scan logic if desired, or reuse the helper
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    try {
        if (!changeInfo.url) return;
        const url = changeInfo.url;

        const cfg = await chrome.storage.sync.get(['autoscans_enabled']);
        if (!cfg.autoscans_enabled) return;

        // Skip if already scanned/whitelisted this session
        if (sessionWhitelist.has(url)) return;

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
