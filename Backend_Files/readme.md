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

### `threat_intel.py`
Handles all external API communication with VirusTotal
and AbuseIPDB.

**VirusTotal URL scanning flow:**
1. POST the URL to `/api/v3/urls` to submit it
2. Receive an analysis ID in the response
3. Poll `/api/v3/analyses/{id}` every 5 seconds
4. Wait for status to change from `queued` to
   `completed`
5. Parse the `stats` block for malicious,
   suspicious, harmless, and undetected engine counts

**Why two steps:** VirusTotal does not return results
immediately. It queues the URL for analysis by 70+
antivirus and threat intelligence engines. The polling
mechanism handles this async process transparently.

**Rate limiting:** The free VirusTotal tier allows
4 requests per minute. A `time.sleep(15)` between URL
scans respects this limit. If a 429 rate limit response
is received the code waits 60 seconds and retries.

**AbuseIPDB:** A single GET request to `/api/v2/check`
returns an abuse confidence percentage (0-100) along
with country, ISP, total report count, and whether the
IP is a known Tor exit node.

**Error handling:** Every API call is wrapped in
try-catch with retry logic and clean error return
objects. The pipeline never crashes due to an API
failure — it simply records the error and continues
with whatever data it has.

---

### `rules_engine.py`
The decision-making core of the platform. Takes outputs
from all other modules and combines them into a final
verdict.

**Why rule-based on top of ML:**
ML models produce probabilities, not verdicts. A 0.73
phishing probability from the email model alone might
not be enough to block an email. But if that same email
also has a malicious URL confirmed by VirusTotal, a
failed DKIM check, and an IP flagged by AbuseIPDB —
the combined signal is unambiguous. The rules engine
makes these combinations explicit and auditable.

**Scoring architecture:**
```
Header rules    → up to 53 points
URL rules       → up to 80 points
IP rules        → up to 75 points
Text rules      → up to 23 points
ML rules        → up to 60 points
                   Total capped at 100
```

**Weight design rationale:**
- VirusTotal confirmed malicious URL = 30 points each
  (capped at 60). A single confirmed malicious URL is
  nearly decisive on its own.
- ML model high confidence (≥85%) = 30 points. Strong
  ML signal is treated equivalently to a confirmed
  malicious URL since the model achieved >98% F1.
- SPF/DKIM/DMARC failures = 10 points each. These are
  necessary but not sufficient on their own since many
  legitimate small business emails fail these checks.
- All three auth failures together add 15 bonus points
  since the combination is a much stronger signal than
  any individual failure.

**Verdict thresholds (configurable in config.py):**
- 70+ → Malicious
- 40-69 → Suspicious
- 0-39 → Benign

---
### `ml_classifier.py`
Loads all model files once at server startup and keeps
them in module-level memory. This is a critical
performance optimization — loading LightGBM models
from disk takes several seconds. If they were loaded on
every request the server would be unusably slow.

**Email model inference pipeline:**
1. Clean text using `clean_text_for_ml()` — exact
   replica of notebook preprocessing
2. Transform cleaned text through the loaded TF-IDF
   vectorizer to get a sparse matrix of 5,000 features
3. Extract all 13 hand-crafted features in the exact
   same order used during training
4. Stack TF-IDF sparse matrix + hand features into one
   5,013-wide sparse matrix
5. Pass to LightGBM for prediction
6. Return phishing probability as float

**URL model inference pipeline:**
1. Map parsed URL object fields to the 50 column names
   from the training dataset
2. Build a pandas DataFrame with exactly those columns
   in exactly the right order
3. Scale using the loaded StandardScaler
4. Pass to LightGBM for prediction
5. Return phishing probability as float

**Score combination:**
When URLs are present the two probabilities are combined
as a weighted average: 60% email + 40% URL. The email
model gets higher weight because it has more context —
it sees the full message, not just one link. When no
URLs are found the email model score is used directly.

**Why this weighting:** In practice, phishing emails
almost always contain malicious links. When a URL is
present and the URL model scores it highly, that
corroborates the email model. When no URLs are present,
the phishing is likely text-based social engineering
which the email model is specifically trained to detect.

---


