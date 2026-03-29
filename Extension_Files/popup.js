// ============================================================
// popup.js
// Handles all UI logic for the extension popup
// Communicates with background.js and displays results
// ============================================================

const SERVER_URL = 'http://127.0.0.1:5000';

// ──────────────────────────────────────────────────────────
// STATE
// ──────────────────────────────────────────────────────────

let currentResult   = null;
let reportUrl       = null;
let serverOnline    = false;

// ──────────────────────────────────────────────────────────
// INITIALISATION
// ──────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', async () => {
    await checkServerStatus();
    await loadLastResult();
});

// ──────────────────────────────────────────────────────────
// SERVER STATUS CHECK
// ──────────────────────────────────────────────────────────

async function checkServerStatus() {
    const dot   = document.getElementById('status-dot');
    const text  = document.getElementById('status-text');

    try {
        const response = await fetch(`${SERVER_URL}/ping`, {
            method  : 'GET',
            signal  : AbortSignal.timeout(3000)
        });

        if (response.ok) {
            serverOnline    = true;
            dot.className   = 'status-dot online';
            text.textContent= 'Online';
            hideElement('offline-banner');
        } else {
            throw new Error('Server returned error');
        }

    } catch (e) {
        serverOnline    = false;
        dot.className   = 'status-dot offline';
        text.textContent= 'Offline';
        showElement('offline-banner');
        disableScanButton();
    }
}

// ──────────────────────────────────────────────────────────
// LOAD LAST RESULT FROM STORAGE
// ──────────────────────────────────────────────────────────

async function loadLastResult() {
    try {
        const stored = await chrome.storage.local.get('lastResult');
        if (stored.lastResult) {
            currentResult = stored.lastResult;
            renderResults(currentResult);
        }
    } catch (e) {
        console.error('[popup] Failed to load last result:', e);
    }
}

// ──────────────────────────────────────────────────────────
// SCAN BUTTON
// ──────────────────────────────────────────────────────────

async function startScan() {
    if (!serverOnline) {
        showError('Backend server is offline. Run python app.py first.');
        return;
    }

    showLoading('Connecting to Gmail...');
    disableScanButton();

    try {
        // Get active tab
        const [tab] = await chrome.tabs.query({
            active          : true,
            currentWindow   : true
        });

        if (!tab || !tab.url.includes('mail.google.com')) {
            showError(
                'Please open an email in Gmail first, ' +
                'then click Scan Email.'
            );
            enableScanButton();
            return;
        }

        // Send message to content script to extract email
        updateLoadingStep('Extracting email content...');

        const emailData = await chrome.tabs.sendMessage(
            tab.id,
            { action: 'extractEmail' }
        );

        if (!emailData || emailData.error) {
            showError(
                emailData?.error ||
                'Could not extract email. ' +
                'Please open a specific email in Gmail.'
            );
            enableScanButton();
            return;
        }

        // Send to background for analysis
        updateLoadingStep('Running ML analysis...');

        const result = await chrome.runtime.sendMessage({
            action      : 'analyzeEmail',
            emailData   : emailData
        });

        if (result.error) {
            showError(result.error);
            enableScanButton();
            return;
        }

        // Store result and render
        currentResult = result;
        await chrome.storage.local.set({ lastResult: result });

        updateLoadingStep('Rendering results...');
        renderResults(result);
        enableScanButton();

    } catch (e) {
        console.error('[popup] Scan error:', e);
        showError(
            'Could not connect to the Gmail page. ' +
            'Try refreshing Gmail and scanning again.'
        );
        enableScanButton();
    }
}


