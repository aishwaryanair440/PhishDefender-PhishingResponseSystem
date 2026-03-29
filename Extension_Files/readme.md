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


