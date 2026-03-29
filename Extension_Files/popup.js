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
