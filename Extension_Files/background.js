// ============================================================
// background.js
// Service worker for the Phishing Detector extension
// Bridges content.js and the Python Flask backend
// Handles API calls, storage, and notifications
// ============================================================

const SERVER_URL    = 'http://127.0.0.1:5000';
const TIMEOUT_MS    = 120000; // 2 minutes (threat intel APIs are slow)
