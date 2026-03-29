## Machine Learning Pipeline

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

### Section 4 — Preprocessing
**Email dataset:**
- Dropped high-null columns (sender, receiver, date,
  urls — all 70%+ null)
- Filled remaining nulls with empty strings
- Combined subject (repeated twice for weight) + body
  into a single `text` field
- Applied text cleaning pipeline: lowercase, URL tokens,
  email tokens, number tokens, special character removal
- Removed 9,863 duplicate rows
- Final: 155,108 rows

**URL dataset:**
- Dropped `HttpsInHostname` (constant column,
  zero variance)
- No high-correlation pairs found above 0.95 threshold
- Applied `StandardScaler` to all 47 features
- Removed 419 duplicate rows
- Final: 9,581 rows, 47 features

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

