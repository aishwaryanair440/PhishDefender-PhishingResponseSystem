// ============================================================
// content.js
// Injected into Gmail pages by the browser extension
// Extracts email data from the Gmail DOM
// Sends extracted data back to popup.js via background.js
// ============================================================

// ──────────────────────────────────────────────────────────
// MESSAGE LISTENER
// ──────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'extractEmail') {
        try {
            const emailData = extractEmailFromDOM();
            sendResponse(emailData);
        } catch (e) {
            console.error('[content] Extraction error:', e);
            sendResponse({
                error: `Failed to extract email: ${e.message}`
            });
        }
    }
    // Required for async sendResponse
    return true;
});
