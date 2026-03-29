# ============================================================
# SECTION 5 — FEATURE ENGINEERING
# ============================================================

from sklearn.feature_extraction.text import TfidfVectorizer
import scipy.sparse as sp

# ──────────────────────────────────────────────────────────
# 5.1 DATASET 1 — EMAIL FEATURE ENGINEERING
# ──────────────────────────────────────────────────────────

print("=" * 55)
print("5.1 — Email Feature Engineering")
print("=" * 55)

# ── Step 1: Hand-crafted features from text ───────────────
# These capture signal that TF-IDF alone misses

def extract_email_features(df):
    features = pd.DataFrame()

    # URL count in body
    features['url_count'] = df['body'].apply(
        lambda x: len(re.findall(r'http\S+|www\S+', str(x)))
    )

    # Email address count in body
    features['email_count'] = df['body'].apply(
        lambda x: len(re.findall(r'[\w\.-]+@[\w\.-]+', str(x)))
    )

    # Number count in body
    features['num_count'] = df['body'].apply(
        lambda x: len(re.findall(r'\d+', str(x)))
    )

    # Body length in characters
    features['body_length'] = df['body'].apply(lambda x: len(str(x)))

    # Subject length in characters
    features['subject_length'] = df['subject'].apply(lambda x: len(str(x)))

    # Number of words in body
    features['word_count'] = df['body'].apply(
        lambda x: len(str(x).split())
    )

    # Average word length in body
    features['avg_word_length'] = df['body'].apply(
        lambda x: np.mean([len(w) for w in str(x).split()])
        if len(str(x).split()) > 0 else 0
    )

    # Exclamation mark count
    features['exclamation_count'] = df['body'].apply(
        lambda x: str(x).count('!')
    )

    # Question mark count
    features['question_count'] = df['body'].apply(
        lambda x: str(x).count('?')
    )

    # Capital letter ratio
    features['capital_ratio'] = df['body'].apply(
        lambda x: sum(1 for c in str(x) if c.isupper()) / max(len(str(x)), 1)
    )

    # Phishing keyword count
    KEYWORDS = [
        'click', 'verify', 'account', 'password', 'urgent',
        'bank', 'login', 'update', 'confirm', 'secure',
        'winner', 'prize', 'free', 'offer', 'limited',
        'suspend', 'validate', 'expire', 'immediate', 'alert'
    ]
    features['keyword_count'] = df['body'].apply(
        lambda x: sum(1 for kw in KEYWORDS if kw in str(x).lower())
    )

    # Has suspicious subject flag
    SUBJECT_KEYWORDS = [
        'urgent', 'verify', 'suspended', 'winner',
        'congratulations', 'alert', 'confirm', 'free'
    ]
    features['suspicious_subject'] = df['subject'].apply(
        lambda x: int(any(kw in str(x).lower() for kw in SUBJECT_KEYWORDS))
    )

    # Contains HTML tags in body
    features['has_html'] = df['body'].apply(
        lambda x: int(bool(re.search(r'<[^>]+>', str(x))))
    )

    return features

email_hand_features = extract_email_features(email_clean)

print(f"Hand-crafted features shape : {email_hand_features.shape}")
print(f"Feature columns             : {list(email_hand_features.columns)}")
print(f"\nSample stats:")
print(email_hand_features.describe().round(2))

# ── Step 2: TF-IDF on cleaned text ───────────────────────
# max_features = 5000 keeps memory manageable on Kaggle
# ngram_range (1,2) captures both single words and pairs
# sublinear_tf dampens effect of very frequent terms
print(f"\nFitting TF-IDF vectorizer...")

tfidf = TfidfVectorizer(
    max_features  = 5000,
    ngram_range   = (1, 2),
    sublinear_tf  = True,
    min_df        = 5,
    max_df        = 0.95,
    strip_accents = 'unicode',
    analyzer      = 'word'
)

X_tfidf = tfidf.fit_transform(email_clean['text'])
print(f"TF-IDF matrix shape         : {X_tfidf.shape}")
print(f"Top 20 TF-IDF tokens        : {tfidf.get_feature_names_out()[:20].tolist()}")

# ── Step 3: Combine TF-IDF + hand-crafted features ───────
# Convert hand-crafted features to sparse matrix for
# efficient horizontal stacking with TF-IDF sparse matrix
X_hand_sparse = sp.csr_matrix(email_hand_features.values)
X_email       = sp.hstack([X_tfidf, X_hand_sparse])
y_email       = email_clean['label'].values

print(f"\nCombined feature matrix shape : {X_email.shape}")
print(f"  TF-IDF features             : {X_tfidf.shape[1]}")
print(f"  Hand-crafted features       : {email_hand_features.shape[1]}")
print(f"  Total features              : {X_email.shape[1]}")

# ──────────────────────────────────────────────────────────
# 5.2 DATASET 2 — URL FEATURE ENGINEERING
# ──────────────────────────────────────────────────────────

print("\n")
print("=" * 55)
print("5.2 — URL Feature Engineering")
print("=" * 55)

# URL dataset is already fully feature-engineered
# We add 3 interaction features that improve ML signal

url_fe = X_url_scaled.copy()

# Interaction: URL length × subdomain level
url_fe['url_x_subdomain'] = (
    url_fe['UrlLength'] * url_fe['SubdomainLevel']
)

# Interaction: No HTTPS × number of sensitive words
url_fe['nohttps_x_sensitive'] = (
    url_fe['NoHttps'] * url_fe['NumSensitiveWords']
)

# Interaction: IP address flag × URL length
url_fe['ip_x_urllength'] = (
    url_fe['IpAddress'] * url_fe['UrlLength']
)

print(f"URL features before : {X_url_scaled.shape[1]}")
print(f"URL features after  : {url_fe.shape[1]}")
print(f"New interaction features added:")
print(f"  url_x_subdomain      — UrlLength × SubdomainLevel")
print(f"  nohttps_x_sensitive  — NoHttps × NumSensitiveWords")
print(f"  ip_x_urllength       — IpAddress × UrlLength")

# ──────────────────────────────────────────────────────────
# 5.3 FEATURE ENGINEERING SUMMARY
# ──────────────────────────────────────────────────────────

print("\n")
print("=" * 55)
print("5.3 — Feature Engineering Summary")
print("=" * 55)
print(f"Email model input")
print(f"  X_email shape    : {X_email.shape}")
print(f"  y_email shape    : {y_email.shape}")
print(f"  Feature type     : Sparse matrix (TF-IDF + hand-crafted)")
print(f"\nURL model input")
print(f"  url_fe shape     : {url_fe.shape}")
print(f"  y_url shape      : {y_url.shape}")
print(f"  Feature type     : Dense DataFrame (scaled + interaction)")
print(f"\nOutputs ready for Section 6:")
print(f"  X_email  — email feature matrix (sparse)")
print(f"  y_email  — email labels")
print(f"  url_fe   — URL feature dataframe (dense)")
print(f"  y_url    — URL labels")
print(f"  tfidf    — fitted TF-IDF vectorizer (save in Section 9)")
