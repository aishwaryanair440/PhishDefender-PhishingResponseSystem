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
    updateProgress(10);
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
        updateProgress(30);
         await new Promise(resolve => setTimeout(resolve, 500));

        const gmailResponse =
    await chrome.runtime.sendMessage({
        action: 'fetchGmailEmail'
    });

if (
    !gmailResponse.success
) {
    showError(
        gmailResponse.error
    );

    enableScanButton();
    return;
}

const emailData =
    gmailResponse.emailData;

        // Send to background for analysis
        updateLoadingStep('Running ML analysis...');
        updateProgress(60);
         await new Promise(resolve => setTimeout(resolve, 500));

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
        updateLoadingStep('Checking threat intelligence...');
        updateProgress(80);

        currentResult = result;
        await chrome.storage.local.set({ lastResult: result });

       updateLoadingStep('Preparing results...');
       updateProgress(95);

       renderResults(result);

        updateProgress(100);
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

// ──────────────────────────────────────────────────────────
// RENDER RESULTS
// ──────────────────────────────────────────────────────────

function renderResults(result) {
    hideElement('idle-state');
    hideElement('loading-state');
    hideElement('error-state');
    showElement('results-container');

    renderVerdictBanner(result);
    renderEmailMetadata(result);
    renderHeaderAuth(result);
    renderMLScores(result);
    renderFlags(result);
    renderIOCs(result);
    renderURLResults(result);
    renderTriggeredRules(result);
    renderActions(result);
    renderReport(result);
}


// ──────────────────────────────────────────────────────────
// VERDICT BANNER
// ──────────────────────────────────────────────────────────

function renderVerdictBanner(result) {
    const verdict   = result.verdict  || 'unknown';
    const score     = result.threat_score || 0;
    const summary   = result.summary  || '';

    const banner    = document.getElementById('verdict-banner');
    const icon      = document.getElementById('verdict-icon');
    const text      = document.getElementById('verdict-text');
    const scoreVal  = document.getElementById('score-value');
    const scoreBar  = document.getElementById('score-bar-fill');
    const summaryEl = document.getElementById('verdict-summary');

    // Set verdict class
    banner.className = `verdict-banner fade-in ${verdict}`;

    // Set icon
    const icons = {
        malicious   : '&#9888;',
        suspicious  : '&#9888;',
        benign      : '&#10003;'
    };
    icon.innerHTML      = icons[verdict] || '&#9679;';
    text.textContent    = verdict.toUpperCase();
    scoreVal.textContent= score;
    summaryEl.textContent = summary;

    // Animate score bar
    setTimeout(() => {
        scoreBar.style.width = `${score}%`;
    }, 100);
}


// ──────────────────────────────────────────────────────────
// EMAIL METADATA
// ──────────────────────────────────────────────────────────

function renderEmailMetadata(result) {
    const email = result.email || {};
    const feats = email.text_features || {};

    setText('meta-sender',
        email.sender || 'N/A'
    );
    setText('meta-subject',
        email.subject || 'N/A'
    );
    setText('meta-urls',
        `${email.url_count || 0} URL(s) found`
    );
    setText('meta-keywords',
        `${feats.keyword_count || 0} phishing keyword(s) detected`
    );
    setText('meta-html',
        feats.has_html ? 'HTML content detected' : 'No HTML content'
    );
}


// ──────────────────────────────────────────────────────────
// HEADER AUTHENTICATION
// ──────────────────────────────────────────────────────────

function renderHeaderAuth(result) {
    const headers   = result.headers || {};

    // SPF
    setAuthResult('auth-spf',  headers.spf  || 'unknown');
    setAuthResult('auth-dkim', headers.dkim || 'unknown');
    setAuthResult('auth-dmarc',headers.dmarc|| 'unknown');

    setText('meta-ip',
        headers.originating_ip || 'Not found'
    );
    setText('meta-replyto',
        headers.reply_to_mismatch
            ? 'MISMATCH DETECTED'
            : 'Matches sender'
    );

    // Color reply-to text
    const replyEl = document.getElementById('meta-replyto');
    if (replyEl) {
        replyEl.style.color = headers.reply_to_mismatch
            ? 'var(--red)'
            : 'var(--green)';
    }
}

function setAuthResult(elementId, result) {
    const el = document.getElementById(elementId);
    if (!el) return;

    el.textContent  = result.toUpperCase();
    el.className    = `auth-result ${result.toLowerCase()}`;
}


// ──────────────────────────────────────────────────────────
// ML SCORES
// ──────────────────────────────────────────────────────────

function renderMLScores(result) {
    const ml = result.ml || {};

    renderMLBar(
        'ml-email-bar',
        'ml-email-val',
        ml.email_probability || 0
    );
    renderMLBar(
        'ml-url-bar',
        'ml-url-val',
        ml.url_probability || 0
    );
    renderMLBar(
        'ml-combined-bar',
        'ml-combined-val',
        ml.combined_probability || 0
    );
}

function renderMLBar(barId, valId, probability) {
    const bar   = document.getElementById(barId);
    const val   = document.getElementById(valId);
    if (!bar || !val) return;

    const pct   = Math.round(probability * 100);

    // Color based on probability
    let fillClass = 'ml-score-fill-low';
    if (probability >= 0.85) {
        fillClass = 'ml-score-fill-high';
    } else if (probability >= 0.5) {
        fillClass = 'ml-score-fill-medium';
    }

    bar.className   = `ml-score-bar-fill ${fillClass}`;
    val.textContent = `${pct}%`;
    val.style.color = probability >= 0.85
        ? 'var(--red)'
        : probability >= 0.5
            ? 'var(--orange)'
            : 'var(--green)';

    setTimeout(() => {
        bar.style.width = `${pct}%`;
    }, 150);
}


// ──────────────────────────────────────────────────────────
// FLAGS
// ──────────────────────────────────────────────────────────

function renderFlags(result) {
    const flags     = result.email?.flags || [];
    const list      = document.getElementById('flags-list');
    const badge     = document.getElementById('flags-badge');

    badge.textContent = flags.length;
    badge.className   = `card-badge ${flags.length > 0
        ? 'warning' : ''}`;

    if (!flags.length) {
        list.innerHTML = '<div class="empty-state">No flags raised</div>';
        return;
    }

    list.innerHTML = flags.map(flag => `
        <div class="flag-item">
            <div class="flag-dot"></div>
            ${escapeHtml(flag)}
        </div>
    `).join('');
}


// ──────────────────────────────────────────────────────────
// IOCs
// ──────────────────────────────────────────────────────────

function renderIOCs(result) {
    const iocs      = result.iocs || [];
    const list      = document.getElementById('ioc-list');
    const badge     = document.getElementById('ioc-badge');

    badge.textContent = iocs.length;
    badge.className   = `card-badge ${iocs.length > 0
        ? 'danger' : ''}`;

    if (!iocs.length) {
        list.innerHTML = '<div class="empty-state">No IOCs identified</div>';
        return;
    }

    list.innerHTML = iocs.map(ioc => `
        <div class="ioc-item">
            <div class="ioc-top">
                <span class="ioc-type">
                    ${escapeHtml(ioc.type || '')}
                </span>
                <span class="ioc-severity ${
                    (ioc.severity || 'info').toLowerCase()
                }">
                    ${escapeHtml(ioc.severity || 'info')}
                </span>
            </div>
            <div class="ioc-value">
                ${escapeHtml(ioc.value || '')}
            </div>
            <div class="ioc-detail">
                ${escapeHtml(ioc.detail || '')}
                &mdash; ${escapeHtml(ioc.source || '')}
            </div>
        </div>
    `).join('');
}


// ──────────────────────────────────────────────────────────
// URL RESULTS
// ──────────────────────────────────────────────────────────

function renderURLResults(result) {
    const urlResults    = result.threat_intel?.url_results || [];
    const list          = document.getElementById('url-list');
    const badge         = document.getElementById('url-badge');
    const maliciousCount= urlResults.filter(u => u.malicious).length;

    badge.textContent   = urlResults.length;
    badge.className     = `card-badge ${maliciousCount > 0
        ? 'danger' : ''}`;

    if (!urlResults.length) {
        list.innerHTML  =
            '<div class="empty-state">No URLs found in email</div>';
        return;
    }

    list.innerHTML = urlResults.map(url => `
        <div class="url-item ${url.malicious ? 'malicious' : ''}">
            <div class="url-top">
                <span class="url-value">
                    ${escapeHtml(
                        url.url?.length > 55
                            ? url.url.substring(0, 55) + '...'
                            : url.url || ''
                    )}
                </span>
                <span class="url-status ${
                    url.malicious ? 'malicious' : 'clean'
                }">
                    ${url.malicious ? 'MALICIOUS' : 'CLEAN'}
                </span>
            </div>
            <div class="url-detection">
                Detections: ${escapeHtml(url.detection_ratio || '0/0')}
                ${url.error
                    ? '&nbsp;&mdash;&nbsp;' + escapeHtml(url.error)
                    : ''}
            </div>
        </div>
    `).join('');
}


// ──────────────────────────────────────────────────────────
// TRIGGERED RULES
// ──────────────────────────────────────────────────────────

function renderTriggeredRules(result) {
    const rules     = result.rules?.triggered || [];
    const list      = document.getElementById('rules-list');
    const badge     = document.getElementById('rules-badge');

    badge.textContent = rules.length;

    if (!rules.length) {
        list.innerHTML  =
            '<div class="empty-state">No rules triggered</div>';
        return;
    }

    list.innerHTML = rules.map(rule => `
        <div class="rule-item">
            <div class="rule-severity-dot ${
                (rule.severity || 'low').toLowerCase()
            }"></div>
            <div class="rule-info">
                <div class="rule-name">
                    ${escapeHtml(rule.rule || '')}
                </div>
                <div class="rule-description">
                    ${escapeHtml(rule.description || '')}
                </div>
            </div>
            <div class="rule-weight">
                +${rule.weight || 0}
            </div>
        </div>
    `).join('');
}


// ──────────────────────────────────────────────────────────
// RECOMMENDED ACTIONS
// ──────────────────────────────────────────────────────────

function renderActions(result) {
    const actions   = result.rules?.actions || [];
    const list      = document.getElementById('actions-list');

    if (!actions.length) {
        list.innerHTML  =
            '<div class="empty-state">No actions recommended</div>';
        return;
    }

    list.innerHTML = actions.map((action, index) => `
        <div class="action-item">
            <span class="action-number">${index + 1}</span>
            ${escapeHtml(action)}
        </div>
    `).join('');
}


// ──────────────────────────────────────────────────────────
// INCIDENT REPORT
// ──────────────────────────────────────────────────────────

function renderReport(result) {
    const report        = result.report || {};
    const reportWrap    = document.getElementById('report-card-wrap');
    const statusEl      = document.getElementById('report-status');
    const downloadBtn   = document.getElementById('download-report-btn');

    if (report.generated && report.download_url) {
        showElement('report-card-wrap');
        reportUrl               = report.download_url;
        statusEl.textContent    = `Report generated: ${
            report.filename || 'incident_report.pdf'
        }`;
        statusEl.style.color    = 'var(--green)';
        showElement('download-report-btn');
        downloadBtn.style.display = 'flex';
    } else {
        hideElement('report-card-wrap');
    }
}

async function downloadReport() {
    if (!reportUrl) return;

    try {
        await chrome.tabs.create({ url: reportUrl });
    } catch (e) {
        console.error('[popup] Download error:', e);
    }
}


// ──────────────────────────────────────────────────────────
// CARD TOGGLE
// ──────────────────────────────────────────────────────────

function toggleCard(cardId) {
    const body      = document.getElementById(cardId);
    const toggle    = document.getElementById(`${cardId}-toggle`);
    if (!body) return;

    const isHidden  = body.classList.contains('hidden');

    if (isHidden) {
        body.classList.remove('hidden');
        if (toggle) toggle.classList.add('open');
    } else {
        body.classList.add('hidden');
        if (toggle) toggle.classList.remove('open');
    }
}


// ──────────────────────────────────────────────────────────
// STATES
// ──────────────────────────────────────────────────────────

function showLoading(message) {
    hideElement('idle-state');
    hideElement('error-state');
    hideElement('results-container');
    showElement('loading-state');

    const loadingText = document.querySelector('.loading-text');
    if (loadingText) {
        loadingText.textContent = message || 'Analysing email...';
    }
}
function updateProgress(percent) {
    const bar = document.getElementById('progress-bar');

    if (bar) {
        bar.style.width = `${percent}%`;
    }
}

function updateLoadingStep(step) {
    const stepEl = document.getElementById('loading-step');
    if (stepEl) stepEl.textContent = step;
}

function showError(message) {
    hideElement('idle-state');
    hideElement('loading-state');
    hideElement('results-container');
    showElement('error-state');

    const msgEl = document.getElementById('error-message');
    if (msgEl) msgEl.textContent = message;
}

function showIdle() {
    hideElement('loading-state');
    hideElement('error-state');
    hideElement('results-container');
    showElement('idle-state');
}


// ──────────────────────────────────────────────────────────
// SCAN BUTTON HELPERS
// ──────────────────────────────────────────────────────────

function disableScanButton() {
    const btn = document.getElementById('scan-btn');
    if (btn) {
        btn.disabled        = true;
        btn.innerHTML = '⏳ Scanning...';
    }
}

function enableScanButton() {
    const btn = document.getElementById('scan-btn');
    if (btn) {
        btn.disabled        = false;
        btn.innerHTML       = '&#128269; Scan Email';
    }
}


// ──────────────────────────────────────────────────────────
// DOM HELPERS
// ──────────────────────────────────────────────────────────

function showElement(id) {
    const el = document.getElementById(id);
    if (el) el.style.display = '';
}

function hideElement(id) {
    const el = document.getElementById(id);
    if (el) el.style.display = 'none';
}

function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g,  '&amp;')
        .replace(/</g,  '&lt;')
        .replace(/>/g,  '&gt;')
        .replace(/"/g,  '&quot;')
        .replace(/'/g,  '&#039;');
}
