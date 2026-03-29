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
