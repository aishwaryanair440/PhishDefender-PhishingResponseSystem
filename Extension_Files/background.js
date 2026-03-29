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

// ──────────────────────────────────────────────────────────
// CORE — ANALYZE EMAIL
// ──────────────────────────────────────────────────────────

async function handleAnalyzeEmail(emailData) {
    console.log('[background] Starting email analysis...');

    // ── Validate input ────────────────────────────────────
    if (!emailData) {
        throw new Error('No email data provided');
    }

    if (!emailData.subject && !emailData.body) {
        throw new Error(
            'Email has no subject or body to analyze'
        );
    }

    // ── Check server is running ───────────────────────────
    const serverStatus = await checkServerStatus();
    if (!serverStatus.online) {
        throw new Error(
            'Backend server is offline. ' +
            'Please run python app.py and try again.'
        );
    }

    // ── Send to Flask backend ─────────────────────────────
    console.log('[background] Sending to Flask backend...');

    const response = await fetchWithTimeout(
        `${SERVER_URL}/analyze`,
        {
            method  : 'POST',
            headers : { 'Content-Type': 'application/json' },
            body    : JSON.stringify({
                subject     : emailData.subject   || '',
                body        : emailData.body       || '',
                sender      : emailData.sender     || '',
                receiver    : emailData.receiver   || '',
                headers     : emailData.headers    || {},
                urls        : emailData.urls       || [],
                timestamp   : emailData.timestamp  || new Date().toISOString(),
                source      : emailData.source     || 'gmail'
            })
        },
        TIMEOUT_MS
    );

    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(
            errorData.error ||
            `Server returned HTTP ${response.status}`
        );
    }

    const result = await response.json();

    console.log(
        `[background] Analysis complete — ` +
        `Verdict: ${result.verdict} | ` +
        `Score: ${result.threat_score}`
    );

    // ── Save to history ───────────────────────────────────
    await saveToHistory(emailData, result);

    // ── Send notification if threat detected ──────────────
    const settings = await getSettings();
    if (settings.notifications) {
        await sendNotification(result, emailData);
    }

    return result;
}

// ──────────────────────────────────────────────────────────
// NEW EMAIL DETECTED
// ──────────────────────────────────────────────────────────

async function handleNewEmailDetected(url) {
    console.log('[background] New email detected:', url);

    // Check auto-scan setting
    const settings = await getSettings();
    if (!settings.autoScan) {
        console.log('[background] Auto-scan disabled — skipping');
        return;
    }

    // If auto-scan is enabled get active tab
    // and trigger extraction automatically
    try {
        const [tab] = await chrome.tabs.query({
            active          : true,
            currentWindow   : true
        });

        if (!tab) return;

        // Wait for Gmail to fully render the email
        await sleep(1500);

        const emailData = await chrome.tabs.sendMessage(
            tab.id,
            { action: 'extractEmail' }
        );

        if (emailData && !emailData.error) {
            const result = await handleAnalyzeEmail(emailData);
            // Store result for popup
            await chrome.storage.local.set({
                lastResult: result
            });
        }

    } catch (e) {
        console.warn('[background] Auto-scan failed:', e.message);
    }
}

