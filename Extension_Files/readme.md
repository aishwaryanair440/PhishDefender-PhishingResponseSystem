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
### `background.js`
The service worker that acts as the central coordinator
for the extension.

**Why a service worker:**
MV3 requires background pages to be implemented as
service workers. A service worker is a JavaScript
file that runs in the background independent of any
open tab or popup. It starts on demand and terminates
when idle, which is more resource-efficient than a
persistent background page.

**Timeout handling:**
`fetchWithTimeout()` wraps every API call with an
`AbortController`. The main analysis call has a
2-minute timeout because VirusTotal URL scanning
involves multiple HTTP round trips with polling delays
between them. A 10-second timeout would cause most
scans to fail. The timeout error message explains this
to the user clearly.

**Scan history:**
Each completed scan is saved to `chrome.storage.local`
as a history entry containing the verdict, score,
sender, subject, IOC count, and report URL. The history
is capped at 50 entries to prevent unbounded storage
growth. This means the user can review their most
recent 50 email scans directly from the extension.

**Notifications:**
For malicious emails, Chrome notifications are sent
with `requireInteraction: true` which keeps the
notification visible until the user explicitly
dismisses it. For suspicious emails the notification
auto-dismisses. This distinction matches the urgency
level of each verdict.

---




