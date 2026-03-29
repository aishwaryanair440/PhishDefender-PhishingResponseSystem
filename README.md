# PhishDefender-PhishingResponseSystem

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0.3-lightgrey?style=flat-square&logo=flask)
![LightGBM](https://img.shields.io/badge/LightGBM-GPU%20Accelerated-green?style=flat-square)
![XGBoost](https://img.shields.io/badge/XGBoost-GPU%20Accelerated-orange?style=flat-square)
![Chrome Extension](https://img.shields.io/badge/Chrome-Extension%20MV3-yellow?style=flat-square&logo=googlechrome)
![License](https://img.shields.io/badge/License-MIT-red?style=flat-square)

> An end-to-end AI-powered phishing detection and response
> platform built as a Chrome browser extension.
> Combines machine learning, threat intelligence APIs,
> and rule-based automation to detect, analyze, and respond
> to phishing emails in real time directly inside Gmail.

---
## Table of Contents

1. [Problem Statement](#1-problem-statement)
2. [Proposed Solution](#2-proposed-solution)
3. [How It Works — Architecture Overview](#3-how-it-works--architecture-overview)
4. [Project Structure](#4-project-structure)
5. [Tech Stack](#5-tech-stack)
6. [Datasets Used](#6-datasets-used)
7. [Machine Learning Pipeline](#7-machine-learning-pipeline)
8. [Backend Modules — Deep Dive](#8-backend-modules--deep-dive)
9. [Browser Extension — Deep Dive](#9-browser-extension--deep-dive)
10. [API Endpoints](#10-api-endpoints)
11. [Threat Scoring System](#11-threat-scoring-system)
12. [Installation and Setup](#12-installation-and-setup)
13. [Running the Project](#13-running-the-project)
14. [Loading the Extension](#14-loading-the-extension)
15. [How to Use](#15-how-to-use)
16. [Free Deployment Alternatives](#16-free-deployment-alternatives)
17. [Resume Highlights](#17-resume-highlights)
18. [Known Limitations](#18-known-limitations)
19. [Future Improvements](#19-future-improvements)
20. [License](#20-license)

---
## 1. Problem Statement

Phishing attacks remain one of the most prevalent and
damaging forms of cybercrime worldwide. According to
industry reports, over 3.4 billion phishing emails are
sent every single day, and phishing is responsible for
more than 90% of all data breaches globally.

Despite the existence of spam filters and basic email
security tools, modern phishing attacks have become
increasingly sophisticated. Attackers now craft emails
that:

- Pass SPF, DKIM, and DMARC authentication checks by
  abusing legitimate email infrastructure
- Use legitimate URL shorteners and redirect chains to
  hide malicious destinations from static filters
- Employ social engineering tactics that exploit urgency,
  fear, and authority to bypass human judgment
- Target individuals specifically using information
  harvested from social media (spear phishing)
- Deploy payloads with advanced capabilities including
  keylogging, screen capture, memory inspection, and
  GUI spoofing

The core problem is that existing solutions operate
reactively — they either block known bad domains using
static blocklists, or they rely entirely on human
judgment which is prone to error under social pressure.
Neither approach scales well against zero-day phishing
campaigns that use freshly registered domains and
never-before-seen payloads.

Additionally, most enterprise-grade phishing detection
tools are expensive, require complex IT infrastructure,
and are inaccessible to individual users, small
organizations, and security students who need to learn
these concepts hands-on.

There is a clear need for an intelligent, automated,
real-time phishing detection system that:

- Operates at the point of attack (the inbox itself)
- Combines multiple detection signals rather than
  relying on a single method
- Is accessible and free to deploy
- Produces actionable, human-readable output including
  identified IOCs and recommended responses
- Can be extended and improved as new attack patterns
  emerge

---
## 2. Proposed Solution

This project proposes a full-stack AI-powered phishing
detection platform delivered as a Chrome browser
extension with a Python backend.

The core philosophy of the solution is
**defence in depth** — rather than relying on any single
detection method, the platform layers five independent
detection signals and combines them into a unified
threat score:

| Layer | Method | Signal Type |
|-------|--------|-------------|
| 1 | Email header analysis | SPF, DKIM, DMARC, Reply-To |
| 2 | LightGBM email classifier | NLP + text features |
| 3 | LightGBM URL classifier | Structural URL features |
| 4 | VirusTotal API | External threat intelligence |
| 5 | AbuseIPDB API | IP reputation intelligence |

The five signals are then fed into a rule-based triage
engine that assigns weighted scores to each signal and
produces a final verdict of **Malicious**,
**Suspicious**, or **Benign** with a score from 0 to 100.

For malicious and suspicious emails the platform
automatically generates a professional PDF incident
report containing all identified Indicators of
Compromise (IOCs), the full rule trace, ML model
confidence scores, and recommended response actions —
exactly the kind of output a real SOC analyst would
produce after investigating a phishing alert.

The architecture is deliberately split into two layers:

- **Browser Extension (JavaScript)** — a thin layer that
  reads the open email from the Gmail DOM and displays
  results. It contains no ML logic and no API keys.
- **Python Backend (Flask)** — handles all intelligence
  processing including ML inference, API calls, rule
  evaluation, and report generation. This is where the
  real work happens and where all sensitive credentials
  are stored.

This split architecture means the extension itself is
lightweight, fast, and secure — it simply reads and
displays. All the heavy computation runs on the Python
side which can be improved, extended, or replaced
without touching the extension code.

---
## 3. How It Works — Architecture Overview
```
┌─────────────────────────────────────────────────────┐
│                  GMAIL (Browser)                     │
│                                                     │
│  User opens email → content.js reads the Gmail DOM  │
│  Extracts: subject, sender, body, URLs, headers     │
└────────────────────┬────────────────────────────────┘
                     │ chrome.runtime.sendMessage
                     ▼
┌─────────────────────────────────────────────────────┐
│              background.js (Service Worker)          │
│                                                     │
│  Receives extracted email data                      │
│  POSTs to Python backend via fetch()                │
│  Handles timeout, retry, notifications, storage     │
└────────────────────┬────────────────────────────────┘
                     │ POST /analyze (JSON)
                     ▼
┌─────────────────────────────────────────────────────┐
│              app.py (Flask Server)                   │
│                                                     │
│  Step 1 → email_parser.py                           │
│           Parse headers, extract URLs, clean text   │
│                                                     │
│  Step 2 → ml_classifier.py                         │
│           LightGBM email model (TF-IDF + features)  │
│           LightGBM URL model (structural features)  │
│           Combined probability score                │
│                                                     │
│  Step 3 → threat_intel.py                          │
│           VirusTotal URL scanning                   │
│           VirusTotal IP reputation                  │
│           AbuseIPDB IP abuse confidence             │
│                                                     │
│  Step 4 → rules_engine.py                          │
│           Weight all signals → 0-100 threat score   │
│           Determine verdict (malicious/suspicious)  │
│           Build IOC list and recommended actions    │
│                                                     │
│  Step 5 → report_generator.py (if threat detected)  │
│           Generate professional PDF incident report  │
│                                                     │
│  Returns unified JSON result                        │
└────────────────────┬────────────────────────────────┘
                     │ JSON response
                     ▼
┌─────────────────────────────────────────────────────┐
│              popup.js + popup.html                   │
│                                                     │
│  Renders verdict banner (red/orange/green)          │
│  Displays ML scores, IOCs, triggered rules          │
│  Shows URL scan results and header auth status      │
│  Provides PDF report download button                │
└─────────────────────────────────────────────────────┘
```

---
## 4. Project Structure
```
phishing-detector/
│
├── icons/                      # Extension icons
│   ├── icon16.png
│   ├── icon48.png
│   └── icon128.png
│
├── reports/                    # Auto-generated PDF reports
│
├── Model files (from Kaggle notebook)
│   ├── email_model.pkl         # Trained LightGBM email classifier
│   ├── url_model.pkl           # Trained LightGBM URL classifier
│   ├── tfidf_vectorizer.pkl    # Fitted TF-IDF vectorizer
│   ├── scaler.pkl              # Fitted StandardScaler
│   ├── url_feature_names.pkl   # URL feature column names
│   └── model_metadata.json     # Model performance metrics
│
├── Config / Support
│   ├── config.py               # API keys, paths, thresholds
│   └── requirements.txt        # Python dependencies
│
├── Python Backend
│   ├── app.py                  # Flask server, main entry point
│   ├── email_parser.py         # Email parsing and feature extraction
│   ├── threat_intel.py         # VirusTotal and AbuseIPDB API calls
│   ├── rules_engine.py         # Rule-based triage and scoring
│   ├── ml_classifier.py        # ML model loading and inference
│   └── report_generator.py     # PDF incident report generation
│
├── Chrome Extension
│   ├── manifest.json           # Extension configuration (MV3)
│   ├── popup.html              # Extension popup UI structure
│   ├── popup.css               # Dark cybersecurity theme styles
│   ├── popup.js                # Popup UI logic and rendering
│   ├── content.js              # Gmail DOM extraction script
│   └── background.js           # Service worker, API bridge
│
└── ML Notebook (Kaggle)
    └── phishing_model.ipynb    # Full ML pipeline notebook
```

---
## 5. Tech Stack

### Python Backend

| Technology | Version | Purpose |
|------------|---------|---------|
| Python | 3.10+ | Core backend language |
| Flask | 3.0.3 | REST API server |
| Flask-CORS | 5.0.0 | Cross-origin requests from extension |
| LightGBM | 4.5.0 | Primary ML classifier (GPU accelerated) |
| XGBoost | Latest | Secondary ML classifier (GPU accelerated) |
| scikit-learn | 1.5.1 | TF-IDF vectorizer, StandardScaler |
| pandas | 2.2.2 | Data manipulation |
| numpy | 1.26.4 | Numerical operations |
| scipy | 1.13.1 | Sparse matrix operations |
| joblib | 1.4.2 | Model serialization |
| requests | 2.32.3 | External API calls |
| BeautifulSoup4 | 4.12.3 | HTML parsing in email bodies |
| ReportLab | 4.2.2 | PDF incident report generation |
| python-whois | 0.9.4 | Domain age lookup |
| dnspython | 2.6.1 | DNS resolution utilities |

### Chrome Extension

| Technology | Purpose |
|------------|---------|
| JavaScript (ES6+) | Extension logic |
| Chrome Extension Manifest V3 | Latest extension standard |
| Chrome Storage API | Persisting results and history |
| Chrome Notifications API | Phishing alert notifications |
| Chrome Tabs API | Gmail tab interaction |
| MutationObserver | Gmail DOM change detection |

### ML and Data

| Technology | Purpose |
|------------|---------|
| Kaggle Notebooks | Training environment |
| CUDA / GPU T4 x2 | GPU-accelerated model training |
| TF-IDF (5000 features) | Email text vectorization |
| LightGBM (GPU mode) | Both email and URL classifiers |
| scipy sparse matrices | Efficient TF-IDF + feature stacking |

---

## 6. Datasets Used

### Dataset 1 — Phishing Email Dataset
**Source:** [Kaggle — naserabdullahalam](https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset)

This is a composite email dataset combining 7 source
files covering a wide range of real-world phishing and
legitimate email samples:

| File | Rows | Label | Notes |
|------|------|-------|-------|
| CEAS_08.csv | 39,154 | Mixed | Full headers available |
| Enron.csv | 29,767 | Legitimate | Internal corporate emails |
| Ling.csv | 2,859 | Mixed | Subject and body only |
| Nazario.csv | 1,565 | All phishing | No legitimate samples |
| Nigerian_Fraud.csv | 3,332 | All phishing | 419 fraud emails |
| SpamAssasin.csv | 5,809 | Mixed | Full headers available |
| phishing_email.csv | 82,486 | Mixed | Pre-combined text field |
| **Total** | **164,972** | **52% phishing** | **Well balanced** |

**Why this dataset:** The diversity of sources means the
model is exposed to many different phishing styles —
Nigerian fraud, credential harvesting, spam, and
legitimate corporate email — making it generalize well
to real-world inbox conditions.

**Preprocessing challenge:** The files have inconsistent
schemas. Ling and Enron have only subject, body, and
label. CEAS and SpamAssasin have full headers. A
`standardize()` function was written to add missing
columns as NaN before merging all 7 files into one
unified dataframe of 155,108 rows after deduplication.

---
### Dataset 2 — Phishing URL Feature Dataset
**Source:** [Kaggle — shashwatwork](https://www.kaggle.com/datasets/shashwatwork/phishing-dataset-for-machine-learning)

| Property | Value |
|----------|-------|
| Total rows | 10,000 (9,581 after dedup) |
| Features | 49 pre-engineered URL features |
| Label balance | Perfectly 50/50 |
| Missing values | Zero |

This dataset contains pre-computed structural and
behavioral features extracted from 10,000 URLs. Unlike
dataset 1 which is raw text, this dataset is already
feature-engineered — each column represents a specific
measurable property of a URL.

**Why this dataset:** Email-based ML models learn from
the email text but cannot deeply analyze URLs embedded
in the email. This dataset trains a separate specialized
URL classifier that scores individual links extracted
from emails. The two model scores are then combined into
one unified probability, producing a richer signal than
either model alone.

**Feature categories include:**
- Structural: `NumDots`, `SubdomainLevel`, `PathLevel`,
  `UrlLength`, `NumDash`, `NumDashInHostname`
- Security: `NoHttps`, `RandomString`, `IpAddress`,
  `NumSensitiveWords`, `EmbeddedBrandName`
- Behavioral: `PctExtHyperlinks`, `InsecureForms`,
  `PopUpWindow`, `RightClickDisabled`, `IframeOrFrame`
- Ratios: `SubdomainLevelRT`, `UrlLengthRT`,
  `PctExtResourceUrlsRT`

---

## 7. Machine Learning Pipeline

The ML pipeline is implemented in `phishing_model.ipynb`
and trained on Kaggle using GPU T4 x2 acceleration.
The notebook is divided into 9 sections:

### Section 1 — Imports
All required libraries loaded including `lightgbm`,
`xgboost`, `sklearn`, `scipy`, and `joblib`.
Display settings configured for wide dataframes.

### Section 2 — Load Dataset
All 7 email CSV files loaded and standardized to a
common schema using a `standardize()` function that
fills missing columns with NaN. The URL dataset is
loaded separately. Both datasets get a consistent
`label` column (0 = legitimate, 1 = phishing).

### Section 3 — Exploratory Data Analysis (EDA)
10 EDA subsections covering label distributions,
source file breakdown, body and subject length
distributions, URL feature correlations, missing value
heatmaps, phishing keyword frequency analysis, and top
URL feature distributions by label. All charts saved
as PNG files.

## 7. Machine Learning Pipeline

The ML pipeline is implemented in `phishing_model.ipynb`
and trained on Kaggle using GPU T4 x2 acceleration.
The notebook is divided into 9 sections:

### Section 1 — Imports
All required libraries loaded including `lightgbm`,
`xgboost`, `sklearn`, `scipy`, and `joblib`.
Display settings configured for wide dataframes.

### Section 2 — Load Dataset
All 7 email CSV files loaded and standardized to a
common schema using a `standardize()` function that
fills missing columns with NaN. The URL dataset is
loaded separately. Both datasets get a consistent
`label` column (0 = legitimate, 1 = phishing).

### Section 3 — Exploratory Data Analysis (EDA)
10 EDA subsections covering label distributions,
source file breakdown, body and subject length
distributions, URL feature correlations, missing value
heatmaps, phishing keyword frequency analysis, and top
URL feature distributions by label. All charts saved
as PNG files.

### Section 5 — Feature Engineering
**Email model features:**

Two complementary feature sets are built and stacked:

1. **TF-IDF features (5,000):** The cleaned text field
   is vectorized using `TfidfVectorizer` with
   `ngram_range=(1,2)` for unigrams and bigrams,
   `sublinear_tf=True` to dampen frequent terms,
   `min_df=5` to remove rare tokens, and
   `max_df=0.95` to remove ubiquitous terms.
   This produces a sparse matrix of 155,108 × 5,000.

2. **Hand-crafted features (13):** These capture signal
   that pure text frequency cannot detect:

   | Feature | Purpose |
   |---------|---------|
   | url_count | Phishing emails often embed many links |
   | email_count | Reply-chain spoofing indicators |
   | num_count | Lottery/prize fraud uses many numbers |
   | body_length | Phishing emails tend to be shorter |
   | subject_length | Very short subjects are suspicious |
   | word_count | Density of message |
   | avg_word_length | Unusual word length = obfuscation |
   | exclamation_count | Urgency tactic detection |
   | question_count | Credential harvesting patterns |
   | capital_ratio | SHOUTING = urgency/pressure |
   | keyword_count | 20 known phishing keywords |
   | suspicious_subject | 8 subject-level trigger words |
   | has_html | HTML emails hide malicious links |

   Both feature sets are stacked horizontally into a
   single sparse matrix of 155,108 × 5,013 using
   `scipy.sparse.hstack`.

**URL model features:**
The 47 scaled features are extended with 3 interaction
terms that capture compound phishing signals:
- `url_x_subdomain`: UrlLength × SubdomainLevel
- `nohttps_x_sensitive`: NoHttps × NumSensitiveWords
- `ip_x_urllength`: IpAddress × UrlLength

Final URL feature matrix: 9,581 × 50.

### Section 6 — Train-Test Split
Both datasets split 80/20 using `train_test_split` with
`stratify` to preserve class balance in both train and
test sets. All 4 label ratios confirmed within 1% of
the overall distribution.

**URL model features:**
The 47 scaled features are extended with 3 interaction
terms that capture compound phishing signals:
- `url_x_subdomain`: UrlLength × SubdomainLevel
- `nohttps_x_sensitive`: NoHttps × NumSensitiveWords
- `ip_x_urllength`: IpAddress × UrlLength

Final URL feature matrix: 9,581 × 50.

### Section 6 — Train-Test Split
Both datasets split 80/20 using `train_test_split` with
`stratify` to preserve class balance in both train and
test sets. All 4 label ratios confirmed within 1% of
the overall distribution.

### Section 7 — Model Training (GPU Accelerated)
Three models trained per dataset:
- Logistic Regression (CPU baseline)
- Random Forest (CPU ensemble)
- XGBoost with `device='cuda'` (GPU)
- LightGBM with `device='gpu'` (GPU)

**Why LightGBM won:**
LightGBM with GPU acceleration outperformed all other
models on both datasets. It handles sparse matrices
natively, supports early stopping to prevent
overfitting, and trains an order of magnitude faster
than scikit-learn's GradientBoostingClassifier on
large datasets.

**Key hyperparameters:**
```python
lgb_params = {
    'device'           : 'gpu',
    'objective'        : 'binary',
    'num_leaves'       : 63,
    'learning_rate'    : 0.05,
    'subsample'        : 0.8,
    'colsample_bytree' : 0.7,
    'min_child_samples': 20,
    'reg_alpha'        : 0.1,
    'reg_lambda'       : 1.0
}
```

`reg_alpha` and `reg_lambda` are L1 and L2
regularization terms that prevent overfitting.
`min_child_samples=20` ensures each leaf has enough
samples. Early stopping with `stopping_rounds=20`
halts training when validation score stops improving.

### Section 8 — Model Evaluation
6 evaluation parameters:
1. **Core metrics** (Accuracy, Precision, Recall, F1,
   ROC-AUC, Average Precision) with train vs test
   comparison and explicit overfitting gap measurement
2. **Confusion matrix** with TN, FP, FN, TP annotated
3. **ROC curve** with AUC score
4. **Precision-Recall curve** with average precision
5. **Feature importance** by gain — top 25 features
6. **Prediction probability distribution** showing
   model confidence and class separation

**Final model performance:**

**Final model performance:**

| Model | Dataset | F1 Score | Accuracy |
|-------|---------|----------|----------|
| LightGBM | Email | 0.9893 | 0.9890 |
| LightGBM | URL | 0.9886 | 0.9890 |
| XGBoost | Email | 0.9671 | 0.9658 |
| XGBoost | URL | 0.9875 | 0.9880 |

### Section 9 — Save Model
6 files saved to `/kaggle/working/phishing_models/`:
- `email_model.pkl` — LightGBM email classifier
- `url_model.pkl` — LightGBM URL classifier
- `tfidf_vectorizer.pkl` — Fitted TF-IDF vectorizer
- `scaler.pkl` — Fitted StandardScaler
- `url_feature_names.pkl` — URL feature column order
- `model_metadata.json` — Performance metrics and config

A verification step reloads all files from disk and
runs 5 sample predictions to confirm integrity before
download. All files are zipped as `phishing_models.zip`
for easy download from the Kaggle output panel.

---
## 8. Backend Modules — Deep Dive

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
### `report_generator.py`
Generates a multi-page professional PDF incident report
using ReportLab's Platypus layout engine.

**Why ReportLab:** ReportLab is the industry-standard
Python PDF library. It produces true vector PDFs that
are printable, searchable, and professional-grade —
unlike HTML-to-PDF conversion libraries which often
produce inconsistent output.

**Report structure (10 sections):**
1. Title banner with timestamp and classification level
2. Verdict banner (color-coded red/orange/green)
3. Executive summary with 5-column stats table
4. Email metadata
5. Threat score breakdown by category
6. ML model analysis table
7. Triggered rules with severity and weight
8. URL scan results from VirusTotal
9. IP reputation analysis from both APIs
10. IOC list, header authentication, and recommended
    actions

**Design rationale:** The report is intentionally
formatted to match the structure of real security
incident reports used in SOC environments. A security
professional reading this report should immediately
recognize the format and be able to act on it without
additional training.

Reports are only generated for malicious and suspicious
verdicts to avoid unnecessary file creation for clean
emails.

---

### `app.py`
The Flask application entry point and orchestration
layer.

**CORS configuration:** The extension origin
`chrome-extension://*` is explicitly allowed. Without
this the browser would block the extension's fetch
requests to the local server due to the Same-Origin
Policy.

**Pipeline orchestration:**
The `/analyze` endpoint calls all 4 modules in strict
sequence:
1. `email_parser.parse_email()`
2. `ml_classifier.run_ml_classifier()`
3. `threat_intel.run_threat_intelligence()`
4. `rules_engine.run_rules_engine()`
5. `report_generator.generate_report()` (conditional)

**Why ML before threat intel:** ML inference is fast
(milliseconds) while VirusTotal scanning is slow
(15-60+ seconds per URL). Running ML first means the
rules engine already has ML scores available when it
receives the threat intel results. More importantly,
if the threat intel APIs are unavailable the ML scores
alone still produce a meaningful verdict.

**Error handling:** Every step is wrapped in
try-except. A failure in any single module returns a
clean JSON error response rather than crashing the
server. The extension popup displays the error
message to the user.

---

## 9. Browser Extension — Deep Dive

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

### `popup.html` and `popup.css`
The extension popup is a 420px wide constrained UI
that renders inside Chrome's extension popup window.

**Dark cybersecurity theme:**
The UI uses a dark color scheme (`#0D1117` background)
modeled on GitHub's dark theme and common security
tool interfaces. This was chosen deliberately —
security professionals typically work in dark-themed
environments and the visual language of the tool
should match its domain.

**CSS variables:**
All colors, spacing, and border radii are defined as
CSS custom properties (variables). This means the
entire theme can be changed by editing the `:root`
block in popup.css — no searching for hardcoded hex
values throughout the file.

**Collapsible cards:**
Each section of the results is rendered as a
collapsible card. This is necessary because the full
result set — verdict, email metadata, auth headers,
ML scores, flags, IOCs, URL results, triggered rules,
actions, and report — would be far too long to display
at once in a 650px max-height popup. Cards let the
user expand exactly the sections they care about.

---

### `popup.js`
All dynamic rendering logic for the popup UI.

**XSS prevention:**
Every string from the API response is passed through
`escapeHtml()` before being inserted into the DOM.
This prevents a malicious email from injecting
JavaScript into the extension popup by crafting a
subject line or sender name containing script tags.

**Result persistence:**
The last scan result is saved to
`chrome.storage.local` by the background service
worker and loaded by popup.js on every popup open.
This means the results survive popup close/reopen
cycles — the user does not lose their scan results
just by clicking elsewhere.

**Animated score bars:**
ML probability bars animate to their final width with
a CSS transition. The animation is delayed 150ms to
ensure the DOM has fully rendered before the width
change triggers. Without the delay the transition
does not play because the element goes from 0 to the
final width before the browser has a chance to paint.

---

### `popup.js`
All dynamic rendering logic for the popup UI.

**XSS prevention:**
Every string from the API response is passed through
`escapeHtml()` before being inserted into the DOM.
This prevents a malicious email from injecting
JavaScript into the extension popup by crafting a
subject line or sender name containing script tags.

**Result persistence:**
The last scan result is saved to
`chrome.storage.local` by the background service
worker and loaded by popup.js on every popup open.
This means the results survive popup close/reopen
cycles — the user does not lose their scan results
just by clicking elsewhere.

**Animated score bars:**
ML probability bars animate to their final width with
a CSS transition. The animation is delayed 150ms to
ensure the DOM has fully rendered before the width
change triggers. Without the delay the transition
does not play because the element goes from 0 to the
final width before the browser has a chance to paint.

---

## 10. API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/ping` | Health check — confirms server is running |
| POST | `/analyze` | Main analysis endpoint |
| GET | `/report/<filename>` | Download PDF report |
| GET | `/reports` | List all generated reports |
| GET | `/status` | Detailed server status and config |

### POST `/analyze` — Request Body
```json
{
    "subject"   : "URGENT: Verify your account",
    "body"      : "Click here to verify...",
    "sender"    : "security@paypa1.com",
    "receiver"  : "user@gmail.com",
    "headers"   : {
        "received-spf"           : "fail",
        "dkim-signature"         : "fail",
        "authentication-results" : "dmarc=fail"
    },
    "urls"      : ["http://paypa1.com/verify"],
    "timestamp" : "2025-01-01T12:00:00.000Z",
    "source"    : "gmail"
}
```

### POST `/analyze` — Response Body
```json
{
    "verdict"       : "malicious",
    "threat_score"  : 85,
    "summary"       : "MALICIOUS — This email is a phishing attempt...",
    "email"         : { "sender": "...", "url_count": 2, "flags": [] },
    "ml"            : {
        "email_probability"   : 0.9823,
        "url_probability"     : 0.9741,
        "combined_probability": 0.9798
    },
    "threat_intel"  : {
        "malicious_url_count" : 1,
        "malicious_ip_count"  : 1,
        "url_results"         : [],
        "ip_results"          : []
    },
    "rules"         : {
        "triggered" : [],
        "score_breakdown": {},
        "actions"   : []
    },
    "iocs"          : [],
    "headers"       : { "spf": "fail", "dkim": "fail", "dmarc": "fail" },
    "report"        : {
        "generated"    : true,
        "download_url" : "http://127.0.0.1:5000/report/phishing_report_20250101_120000.pdf",
        "filename"     : "phishing_report_20250101_120000.pdf"
    }
}
```

---

## 11. Threat Scoring System

The threat score is a number from 0 to 100 calculated
by summing the weights of all triggered rules and
capping at 100.

### Rule Weights

| Category | Rule | Weight | Severity |
|----------|------|--------|----------|
| Headers | SPF fail | 10 | Medium |
| Headers | DKIM fail | 10 | Medium |
| Headers | DMARC fail | 10 | Medium |
| Headers | All three fail | +15 bonus | High |
| Headers | Reply-To mismatch | 8 | Medium |
| URLs | Malicious URL (VT) | 30 each | Critical |
| URLs | Suspicious URL (VT) | 10 each | Medium |
| URLs | IP as domain | 12 | High |
| URLs | No HTTPS | 5 | Low |
| URLs | Suspicious TLD | 8 | Medium |
| IP | VT malicious IP | 25 | Critical |
| IP | AbuseIPDB ≥75% | 20 | High |
| IP | AbuseIPDB ≥50% | 10 | Medium |
| IP | Tor exit node | 15 | High |
| Text | ≥5 phishing keywords | 10 | Medium |
| Text | 2-4 phishing keywords | 5 | Low |
| Text | Suspicious subject | 5 | Low |
| Text | ≥5 exclamation marks | 3 | Low |
| Text | Capital ratio >30% | 3 | Low |
| Text | HTML content | 2 | Low |
| ML | Email model ≥85% | 30 | High |
| ML | Email model ≥50% | 15 | Medium |
| ML | URL model ≥85% | 30 | High |
| ML | URL model ≥50% | 15 | Medium |

### Verdict Thresholds

| Score Range | Verdict | Action |
|-------------|---------|--------|
| 70 — 100 | Malicious | Block sender, quarantine, generate report |
| 40 — 69 | Suspicious | Warn user, do not click links |
| 0 — 39 | Benign | Allow, log result |

---

## 12. Installation and Setup

### Prerequisites

- Python 3.10 or higher
- Google Chrome browser
- VirusTotal API key (free at virustotal.com)
- AbuseIPDB API key (free at abuseipdb.com)
- Trained model files from the Kaggle notebook

### Step 1 — Clone the Repository
```bash
git clone https://github.com/yourusername/phishing-detector.git
cd phishing-detector
```

### Step 2 — Install Python Dependencies
```bash
pip install -r requirements.txt
```

### Step 3 — Add API Keys

Open `config.py` and replace the placeholder values:
```python
VIRUSTOTAL_API_KEY  = "your_actual_virustotal_key"
ABUSEIPDB_API_KEY   = "your_actual_abuseipdb_key"
```

### Step 4 — Add Model Files

Place all 6 model files in the root
`phishing-detector/` folder:
```
email_model.pkl
url_model.pkl
tfidf_vectorizer.pkl
scaler.pkl
url_feature_names.pkl
model_metadata.json
```

These are generated by running `phishing_model.ipynb`
on Kaggle and downloading `phishing_models.zip` from
the Kaggle output panel.

### Step 5 — Create Icons
```bash
python -c "
from PIL import Image, ImageDraw
import os
os.makedirs('icons', exist_ok=True)
for size in [16, 48, 128]:
    img = Image.new('RGB', (size, size), color='#1A252F')
    draw = ImageDraw.Draw(img)
    draw.ellipse([size//8, size//8, size*7//8, size*7//8],
                 fill='#E74C3C')
    img.save(f'icons/icon{size}.png')
print('Icons created')
"
```

---

## 13. Running the Project

Start the Flask backend server:
```bash
python app.py
```

Expected output:
```
=====================================================
Phishing Detector — Backend Server
=====================================================
[ml_classifier] Loading models...
  Email model loaded     : email_model.pkl
  URL model loaded       : url_model.pkl
  TF-IDF loaded          : tfidf_vectorizer.pkl
  Scaler loaded          : scaler.pkl
  URL feature names loaded : url_feature_names.pkl
  Metadata loaded        : model_metadata.json
[ml_classifier] All models loaded successfully
[app] Models loaded successfully
[app] Reports directory ready : reports
[app] Server starting on      : http://127.0.0.1:5000
=====================================================
 * Running on http://127.0.0.1:5000
```

Verify the server is running:
```bash
curl http://127.0.0.1:5000/ping
```

Expected response:
```json
{
    "status": "ok",
    "message": "Phishing Detector backend is running",
    "timestamp": "2025-01-01T12:00:00.000000"
}
```

---
## 15. How to Use

1. **Start the backend:** Run `python app.py` in your
   terminal and keep it running
2. **Open Gmail:** Navigate to `mail.google.com`
3. **Open an email:** Click on any email to open it
4. **Click the extension icon** in the Chrome toolbar
5. **Click Scan Email** in the popup
6. **Wait for results** — the analysis takes 15-90
   seconds depending on how many URLs are in the email
   and VirusTotal API response time
7. **Review the verdict** — the popup shows the verdict
   banner, ML scores, header authentication results,
   flagged IOCs, triggered rules, and recommended actions
8. **Download the report** — for malicious and suspicious
   emails a PDF report download button appears in the
   popup

---

## 16. Free Deployment Alternatives

Since this project is intentionally built without any
paid services, here are the deployment options:

### Local Development (Recommended)
Load the extension via Developer Mode and run
`python app.py` locally. This is the standard
development workflow and requires no configuration
beyond setup. The server runs on `localhost:5000`.

### Free Cloud Backend
Deploy the Python backend for free on:

| Platform | Free Tier | Notes |
|----------|-----------|-------|
| Render.com | 750 hours/month | Sleeps after 15min idle |
| Railway.app | $5 credit/month | Fast cold start |
| Fly.io | 3 shared VMs free | Always-on possible |

If deploying to cloud, update `SERVER_URL` in both
`background.js` and `popup.js` from
`http://127.0.0.1:5000` to your deployed URL, and
update `host_permissions` in `manifest.json`
accordingly.

### Extension Distribution Without Web Store
Share the extension folder as a ZIP file. Recipients
load it via Load Unpacked. For a portfolio or resume
demonstration this is completely sufficient and is
what hiring managers and interviewers will do when
evaluating the project.

---

## 17. Resume Highlights

This project demonstrates the following skills and
technologies that are directly relevant to
cybersecurity and ML engineering roles:

**Machine Learning and Data Science:**
- End-to-end ML pipeline from raw data to deployed model
- Multi-dataset training with schema normalization
- Feature engineering: TF-IDF, hand-crafted NLP features,
  URL structural features, interaction terms
- GPU-accelerated training with LightGBM on Kaggle T4 x2
- Model evaluation: F1, AUC-ROC, Precision-Recall,
  confusion matrix, feature importance
- >98% F1 score on both email and URL classification

**Cybersecurity:**
- Phishing detection methodology
- Email authentication protocols: SPF, DKIM, DMARC
- Indicators of Compromise (IOC) identification
- Threat intelligence API integration (VirusTotal,
  AbuseIPDB)
- Incident report generation in SOC format
- Browser-based security tooling

**Software Engineering:**
- Full-stack Python + JavaScript application
- REST API design with Flask
- Chrome Extension development (Manifest V3)
- Service worker architecture
- Cross-origin resource sharing (CORS)
- Asynchronous programming in both Python and JavaScript
- Modular, maintainable codebase with clear separation
  of concerns

**Tools and Infrastructure:**
- Kaggle Notebooks with GPU acceleration
- Chrome DevTools for extension debugging
- ReportLab for professional PDF generation
- Version control with Git

---

## 18. Known Limitations

**VirusTotal Free Tier Rate Limits:**
The free VirusTotal API allows only 4 requests per
minute. Emails with many URLs will take several minutes
to fully scan as the system sleeps between requests.
This is a business constraint of the free tier and
not a technical limitation of the platform.

**Gmail DOM Dependency:**
The content script relies on Gmail's DOM structure
which can change when Google updates the Gmail
interface. If extraction stops working after a Gmail
update the CSS selectors in `content.js` will need
to be updated to match the new structure.

**Local Server Requirement:**
The Flask backend must be running on the user's machine
for the extension to work. If `python app.py` is not
running the extension will show an offline status and
scans cannot be performed.

**Header Extraction Limitations:**
Gmail does not expose raw email headers in the standard
view. The content script can only extract header
information that Gmail chooses to render visibly in the
UI such as phishing warning banners, via-domain labels,
and authentication indicators. Full header access would
require the Gmail API with OAuth2 authentication.

**Page-Level URL Features:**
Several URL feature columns from Dataset 2 such as
`PctExtHyperlinks`, `ExtFavicon`, and `InsecureForms`
require loading and inspecting the actual web page the
URL points to. Since the extension reads emails and not
web pages, these features are set to 0 during inference.
The URL model was still trained with these features
present so their absence during inference reduces URL
model accuracy slightly compared to training conditions.

---

## 19. Future Improvements

- **Gmail API Integration:** Replace DOM scraping with
  the official Gmail API for reliable header access
  including full raw header strings for accurate SPF,
  DKIM, and DMARC parsing
- **VirusTotal Premium:** With a paid API key the rate
  limit increases to 1000 requests per minute,
  eliminating the scanning delay
- **BERT/Transformer Model:** Replace TF-IDF + LightGBM
  with a fine-tuned BERT model for email classification.
  Transformer models capture semantic meaning and long-
  range dependencies that TF-IDF bigrams miss
- **Automated Sender Blocking:** Integrate the Gmail API
  to automatically add malicious senders to the Gmail
  block list without manual user action
- **SIEM Integration:** Export IOCs and incident reports
  to Splunk, Elastic SIEM, or a custom threat intel feed
  via webhook
- **Multi-Browser Support:** Port the extension to
  Firefox using the WebExtensions API which shares most
  of the Chrome MV3 API surface
- **Attachment Analysis:** Integrate sandboxed attachment
  scanning using Any.run or Cuckoo Sandbox API for emails
  with file attachments
- **Phishing Campaign Detection:** Aggregate IOCs across
  multiple scanned emails to detect coordinated phishing
  campaigns targeting the same organization

---

## 20. License

This project is licensed under the MIT License.
```
MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any
person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the
Software without restriction, including without
limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software
is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice
shall be included in all copies or substantial portions
of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
```

---

*Built as a cybersecurity portfolio project
demonstrating end-to-end AI-powered threat detection,
ML engineering, and browser extension development.*




