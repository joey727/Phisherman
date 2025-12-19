document.addEventListener("DOMContentLoaded", async () => {
  const { blockedUrl, verdict } =
    await chrome.storage.session.get(["blockedUrl", "verdict"]);

  const reasonEl = document.getElementById("reason");
  if (reasonEl) {
    reasonEl.textContent =
      (verdict && verdict.reasons ? verdict.reasons.join(", ") : null) || "This site is unsafe.";
  }

  const continueBtn = document.getElementById("continue");
  if (continueBtn) {
    continueBtn.onclick = async () => {
      await chrome.storage.session.remove(["blockedUrl", "verdict"]);
      chrome.tabs.update({ url: blockedUrl });
    };
  }

  const backBtn = document.getElementById("back");
  if (backBtn) {
    backBtn.onclick = () => {
      chrome.tabs.goBack();
    };
  }
});
