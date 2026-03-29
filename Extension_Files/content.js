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

// ──────────────────────────────────────────────────────────
// SUBJECT EXTRACTION
// ──────────────────────────────────────────────────────────

function extractSubject() {
    const selectors = [
        'h2[data-thread-perm-id]',
        'h2.hP',
        'span[data-thread-perm-id]',
        'div[role="main"] h2',
        '.ha h2',
        'title'
    ];

    for (const selector of selectors) {
        const el = document.querySelector(selector);
        if (el && el.textContent.trim()) {
            let subject = el.textContent.trim();

            // Remove Gmail prefix like "Inbox" or tab names
            subject = subject
                .replace(/^(Inbox|Sent|Drafts|Spam)\s*[-–]\s*/i, '')
                .replace(/ - Gmail$/, '')
                .trim();

            if (subject) return subject;
        }
    }

    return '';
}

// ──────────────────────────────────────────────────────────
// RECEIVER EXTRACTION
// ──────────────────────────────────────────────────────────

function extractReceiver() {
    const selectors = [
        'span.g2[email]',
        'span[data-hovercard-id].g2',
        '.hb span[email]'
    ];

    for (const selector of selectors) {
        const el = document.querySelector(selector);
        if (el) {
            const email = el.getAttribute('email') ||
                          el.getAttribute('data-hovercard-id');
            if (email && email.includes('@')) {
                return email.trim();
            }
        }
    }

    return '';
}

// ──────────────────────────────────────────────────────────
// BODY EXTRACTION
// ──────────────────────────────────────────────────────────

function extractBody(container) {
    const bodySelectors = [
        // Primary Gmail body selectors
        '.a3s.aiL',
        '.a3s',
        '.ii.gt .a3s',
        'div[role="main"] .ii.gt',
        // Fallback selectors
        '.Am.Al.editable',
        '[data-message-id] .ii',
        '.nH .ii'
    ];

    for (const selector of bodySelectors) {
        const el = document.querySelector(selector);
        if (el && el.textContent.trim().length > 10) {

            // Get HTML for processing
            const rawHtml   = el.innerHTML;

            // Get plain text
            let plainText   = el.innerText || el.textContent;

            // Clean up excessive whitespace
            plainText = plainText
                .replace(/\r\n/g, '\n')
                .replace(/\n{3,}/g, '\n\n')
                .replace(/[ \t]+/g, ' ')
                .trim();

            return plainText;
        }
    }

    // Last resort — get all visible text from main area
    const main = document.querySelector('div[role="main"]');
    if (main) {
        return main.innerText
            ?.replace(/\n{3,}/g, '\n\n')
            ?.trim() || '';
    }

    return '';
}

// ──────────────────────────────────────────────────────────
// HEADER EXTRACTION
// ──────────────────────────────────────────────────────────

function extractHeaders(container) {
    const headers = {};

    try {
        // ── SPF / DKIM / DMARC ────────────────────────────
        // Gmail shows authentication results in the
        // "Show original" view but we can infer from
        // security warnings and visible indicators

        // Check for Gmail security warning icons
        const securityIcons = document.querySelectorAll(
            '.a3s [data-tooltip*="security"], ' +
            '.a3s [title*="security"], ' +
            'img[src*="security"]'
        );

        // Check for muted sender warning
        const mutedWarning = document.querySelector(
            '.adn.ads'
        );

        // Check for phishing warning banner
        const phishingBanner = document.querySelector(
            '[data-message-id] .bBe, ' +
            '.J-K8-K8-KF-KF, ' +
            '.phishing-warning'
        );

        if (phishingBanner) {
            headers.gmail_phishing_warning = true;
        }

        // ── Extract from "Show original" if available ──────
        // Try to get auth results from visible header details
        const detailsBtn = document.querySelector(
            '.T-I.J-J5-Ji.aav.T-I-ax7'
        );

        // ── Sender details ────────────────────────────────
        // Extract via-domain (indicates spoofing potential)
        const viaDomain = document.querySelector(
            '.go .ml'
        );
        if (viaDomain) {
            headers.via_domain = viaDomain.textContent
                ?.replace('via', '').trim();
        }

        // ── Reply-To extraction ───────────────────────────
        const showDetails = document.querySelector(
            '.ajx, .adn'
        );
        if (showDetails) {
            const detailText = showDetails.textContent || '';

            // Extract Reply-To if visible
            const replyToMatch = detailText.match(
                /reply-to[:\s]+([^\s,<>]+@[^\s,<>]+)/i
            );
            if (replyToMatch) {
                headers['reply-to'] = replyToMatch[1].trim();
            }

            // Extract Received (for IP)
            const receivedMatch = detailText.match(
                /received[:\s]+.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i
            );
            if (receivedMatch) {
                headers['received'] = receivedMatch[0];
            }
        }

        // ── Try expanded header panel ─────────────────────
        const headerPanel = document.querySelector(
            '.header-detail, .expanded-header'
        );
        if (headerPanel) {
            const headerText = headerPanel.textContent || '';
            parseAuthHeaders(headerText, headers);
        }

        // ── Gmail security indicators ─────────────────────
        // Red lock icon = encryption issue
        const redLock = document.querySelector(
            'img[src*="lock_open"], ' +
            '.T-I-J3[aria-label*="not encrypted"]'
        );
        if (redLock) {
            headers.encryption_warning = true;
        }

    } catch (e) {
        console.warn('[content] Header extraction error:', e);
    }

    return headers;
}

function parseAuthHeaders(text, headers) {
    // SPF
    const spfMatch = text.match(
        /spf[=:\s]+(pass|fail|neutral|softfail|none)/i
    );
    if (spfMatch) {
        headers['received-spf'] = spfMatch[0];
    }

    // DKIM
    const dkimMatch = text.match(
        /dkim[=:\s]+(pass|fail|neutral|none)/i
    );
    if (dkimMatch) {
        headers['dkim-signature'] = dkimMatch[0];
    }

    // DMARC
    const dmarcMatch = text.match(
        /dmarc[=:\s]+(pass|fail|none)/i
    );
    if (dmarcMatch) {
        headers['authentication-results'] = dmarcMatch[0];
    }

    // Originating IP
    const ipMatch = text.match(
        /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/
    );
    if (ipMatch) {
        headers['received'] = ipMatch[0];
    }
}
