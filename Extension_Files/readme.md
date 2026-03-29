## Browser Extension — Deep Dive

### `manifest.json`
Uses Manifest V3 (MV3) — the current and future
standard for Chrome extensions. MV3 replaces background
pages with service workers, tightens the Content
Security Policy, and restricts remote code execution.

**Key permissions:**
- `activeTab` — access to the current Gmail tab
- `storage` — persist scan results and history
- `scripting` — inject content.js into Gmail pages
- `tabs` — query and communicate with tabs
- `notifications` — push phishing alerts

**host_permissions:**
- `https://mail.google.com/*` — required to inject
  content.js into Gmail
- `http://127.0.0.1:5000/*` — required to allow the
  service worker to fetch from the local Flask server

**Why MV3:** MV3 is required for new extensions
submitted to the Chrome Web Store. Building with MV3
from the start means the extension is forward-compatible
and follows current best practices.

---
### `content.js`
Injected into every Gmail page. Its sole responsibility
is reading the Gmail DOM.

**Why Gmail DOM extraction is complex:**
Gmail is a single-page application that dynamically
renders email content using JavaScript. It does not
use simple static HTML that can be parsed with a URL.
The actual email content lives in deeply nested div
elements with dynamic class names that change between
Gmail versions.

The content script tries multiple CSS selectors in
priority order — if the first one fails, it falls back
to the next. This makes the extraction robust against
Gmail UI updates.

**Gmail redirect URL decoding:**
When Gmail renders links in emails it wraps them in
`https://www.google.com/url?q=<real_url>` redirect
URLs. The content script detects these wrappers and
extracts the real destination URL using the
`URLSearchParams` API. This is critical — without this
step, VirusTotal would scan the Google redirect URL
rather than the actual phishing destination.

**MutationObserver:**
The DOM observer watches for changes in the main Gmail
area and fires a `newEmailDetected` message to the
background service worker whenever a new email is
opened. This enables the auto-scan feature to trigger
analysis without the user having to click the scan
button manually.

---



