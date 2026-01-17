document.addEventListener('DOMContentLoaded', () => {
    const apiKeyInput = document.getElementById('apiKey');
    const autoScanCheckbox = document.getElementById('autoScan');
    const saveBtn = document.getElementById('save');
    const status = document.getElementById('status');

    // Load saved settings
    chrome.storage.sync.get(['phisherman_api_key', 'autoscans_enabled'], (items) => {
        if (items.phisherman_api_key) {
            apiKeyInput.value = items.phisherman_api_key;
        }
        if (items.autoscans_enabled !== undefined) {
            autoScanCheckbox.checked = items.autoscans_enabled;
        } else {
            // Default to true if not set
            autoScanCheckbox.checked = true;
        }
    });

    // Save settings
    saveBtn.addEventListener('click', () => {
        const apiKey = apiKeyInput.value.trim();
        const autoScan = autoScanCheckbox.checked;

        chrome.storage.sync.set({
            phisherman_api_key: apiKey,
            autoscans_enabled: autoScan
        }, () => {
            status.textContent = 'Settings saved.';
            setTimeout(() => {
                status.textContent = '';
            }, 2000);
        });
    });
});
