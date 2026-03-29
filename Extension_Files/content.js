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

// ──────────────────────────────────────────────────────────
// MAIN EXTRACTION FUNCTION
// ──────────────────────────────────────────────────────────

function extractEmailFromDOM() {

    // ── Check if an email is open ─────────────────────────
    const emailContainer = findEmailContainer();

    if (!emailContainer) {
        return {
            error: 'No email is open. Please click on an email to open it first.'
        };
    }

    // ── Extract all fields ────────────────────────────────
    const subject   = extractSubject();
    const sender    = extractSender(emailContainer);
    const receiver  = extractReceiver();
    const body      = extractBody(emailContainer);
    const headers   = extractHeaders(emailContainer);
    const urls      = extractURLsFromBody(body);

    // ── Validate minimum data ─────────────────────────────
    if (!subject && !body) {
        return {
            error: 'Could not extract email content. Try scrolling to fully load the email.'
        };
    }

    console.log('[content] Email extracted successfully');
    console.log(`[content] Subject  : ${subject?.substring(0, 60)}`);
    console.log(`[content] Sender   : ${sender}`);
    console.log(`[content] Body len : ${body?.length}`);
    console.log(`[content] URLs     : ${urls.length}`);

    return {
        subject     : subject   || '',
        sender      : sender    || '',
        receiver    : receiver  || '',
        body        : body      || '',
        headers     : headers   || {},
        urls        : urls      || [],
        timestamp   : new Date().toISOString(),
        source      : 'gmail'
    };
}

// ──────────────────────────────────────────────────────────
// EMAIL CONTAINER DETECTION
// ──────────────────────────────────────────────────────────

function findEmailContainer() {
    // Gmail uses several possible selectors
    // depending on view mode and version
    const selectors = [
        'div[role="main"] div[data-message-id]',
        'div[role="main"] .a3s',
        'div[role="main"] .ii.gt',
        'div[role="main"] .AO',
        '.nH .if',
        'div[data-legacy-message-id]'
    ];

    for (const selector of selectors) {
        const el = document.querySelector(selector);
        if (el) return el;
    }

    return null;
}

