const scanBtn = document.getElementById('scanBtn');
const urlInput = document.getElementById('urlInput');
const result = document.getElementById('result');

async function getActiveTabUrl() {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    return tabs[0]?.url || '';
}

async function callPhishermanApi(url) {
    if (!url) throw new Error('No url provided');
    // BACKEND_URL: change to your deployed or local backend
    // Using localhost:4000 as per backend default port
    const BACKEND_URL = 'http://localhost:4000/api/check';
    // If your API requires a key, put it in extension storage and *never* commit it.
    const apiKey = await chrome.storage.sync.get('phisherman_api_key').then(r => r.phisherman_api_key);

    const headers = { 'Content-Type': 'application/json' };
    if (apiKey) headers['x-api-key'] = apiKey;

    try {
        const resp = await fetch(BACKEND_URL, {
            method: 'POST',
            headers,
            body: JSON.stringify({ url })
        });
        console.log('API Response status:', resp.status);
        if (!resp.ok) throw new Error(`API error: ${resp.status}`);
        return resp.json();
    } catch (error) {
        console.error('Fetch error:', error);
        throw error;
    }
}

function showResult(data) {
    // expected data: { verdict: 'safe'|'suspicious'|'phishing', details: '...' }
    result.textContent = '';
    const div = document.createElement('div');
    div.textContent = data.details?.error || `Verdict: ${data.verdict || 'unknown'}`;
    div.className = data.verdict ? `status-${data.verdict}` : '';
    result.appendChild(div);

    // Show reasons if any
    if (data.reasons && data.reasons.length > 0) {
        const ul = document.createElement('ul');
        data.reasons.forEach(reason => {
            const li = document.createElement('li');
            li.textContent = reason;
            ul.appendChild(li);
        });
        result.appendChild(ul);
    }
}

scanBtn.addEventListener('click', async () => {
    try {
        result.textContent = 'Scanning…';
        const provided = urlInput.value.trim();
        const url = provided || await getActiveTabUrl();
        console.log('Scanning URL:', url);
        const response = await callPhishermanApi(url);
        console.log('Scan result:', response);
        showResult(response);
    } catch (err) {
        result.textContent = `Error: ${err.message}`;
    }
});
