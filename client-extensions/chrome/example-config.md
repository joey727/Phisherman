# Example config & development notes

- BACKEND_URL: update src/popup.js and src/service-worker.js to point at your Phisherman backend (local or deployed).
- API keys: do NOT hardcode secrets into repository. Use chrome.storage.sync or environment-based build steps.

For local testing, you can run the backend and set `phisherman_api_key` in Chrome extension storage via DevTools or a small options page.
