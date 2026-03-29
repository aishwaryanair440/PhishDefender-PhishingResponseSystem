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

