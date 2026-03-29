// ============================================================
// background.js
// Service worker for the Phishing Detector extension
// Bridges content.js and the Python Flask backend
// Handles API calls, storage, and notifications
// ============================================================

const SERVER_URL    = 'http://127.0.0.1:5000';
const TIMEOUT_MS    = 120000; // 2 minutes (threat intel APIs are slow)

// ──────────────────────────────────────────────────────────
// INSTALL AND ACTIVATE
// ──────────────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener((details) => {
    console.log('[background] Extension installed:', details.reason);

    // Set default storage values on install
    chrome.storage.local.set({
        lastResult      : null,
        scanHistory     : [],
        settings        : {
            autoScan        : false,
            notifications   : true,
            reportOnSuspicious: true
        }
    });

    console.log('[background] Default storage values set');
});

// ──────────────────────────────────────────────────────────
// MESSAGE LISTENER
// Main router for all messages from popup.js and content.js
// ──────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    console.log(`[background] Message received: ${message.action}`);

    switch (message.action) {

        case 'analyzeEmail':
            handleAnalyzeEmail(message.emailData)
                .then(result => sendResponse(result))
                .catch(err  => sendResponse({
                    error: err.message || 'Analysis failed'
                }));
            return true; // Keep channel open for async

        case 'newEmailDetected':
            handleNewEmailDetected(message.url);
            return false;

        case 'getHistory':
            getHistory()
                .then(history => sendResponse({ history }))
                .catch(err    => sendResponse({ error: err.message }));
            return true;

        case 'clearHistory':
            clearHistory()
                .then(() => sendResponse({ success: true }))
                .catch(err => sendResponse({ error: err.message }));
            return true;

        case 'checkServer':
            checkServerStatus()
                .then(status => sendResponse(status))
                .catch(err   => sendResponse({ online: false }));
            return true;

        default:
            console.warn(`[background] Unknown action: ${message.action}`);
            sendResponse({ error: `Unknown action: ${message.action}` });
            return false;
    }
});

