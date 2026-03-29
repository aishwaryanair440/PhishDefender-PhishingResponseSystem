## Backend Modules — Deep Dive

### `config.py`
Central configuration file storing all API keys, file
paths, Flask settings, scoring thresholds, and keyword
lists. Every other module imports from here rather than
hardcoding values. This means changing the Flask port,
adding an API key, or adjusting the malicious threshold
requires editing exactly one file.

**Why this approach:** It mirrors the configuration
management patterns used in real production systems
where environment-specific values are always centralized
and never scattered across source files.

---

### `email_parser.py`
The first module called in the pipeline. Accepts the
raw JSON payload from the extension and returns a
fully-structured parsed email object.

**Key design decisions:**

- **Sender normalization:** Handles both
  `John Doe <john@example.com>` and plain
  `john@example.com` formats by trying the angle
  bracket pattern first then falling back to raw
  email regex. This is necessary because Gmail
  renders sender strings inconsistently.

- **Body cleaning:** Uses BeautifulSoup to strip HTML
  tags before extracting text. Many phishing emails
  use HTML to hide the actual text content from
  simple string matching.

  - **URL enrichment:** Each extracted URL gets 15
  metadata fields computed locally — HTTPS status,
  IP-as-domain flag, subdomain depth, suspicious TLD
  check, URL length, path length, query parameters.
  This local enrichment happens before the VirusTotal
  scan so the rules engine has URL signal even if the
  API call fails.

- **Text cleaning mirrors training:** The
  `clean_text_for_ml()` function in this file is an
  exact copy of the cleaning pipeline used in the
  notebook. This is critical — if the inference-time
  cleaning differs from the training-time cleaning,
  the TF-IDF vocabulary will not align and the model
  will receive incorrect token frequencies. Subject
  is repeated twice (as in training) to give it more
  weight in the TF-IDF matrix.

  - **Flag extraction:** Human-readable red flag strings
  are generated from the parsed data. These appear in
  both the popup UI and the PDF report, making the
  results interpretable to non-technical users.

---
