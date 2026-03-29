# ============================================================
# SECTION 4 — DATA PREPROCESSING AND CLEANING
# ============================================================

import re
from sklearn.preprocessing import StandardScaler

# ──────────────────────────────────────────────────────────
# 4.1 DATASET 1 — EMAIL PREPROCESSING
# ──────────────────────────────────────────────────────────

print("=" * 55)
print("4.1 — Email Dataset Preprocessing")
print("=" * 55)

# ── Step 1: Drop columns with excessive nulls ──────────────
# sender, receiver, date, urls have 115k+ nulls
# not useful for text-based ML — drop them
DROP_COLS = ['sender', 'receiver', 'date', 'urls', 'source']
email_clean = email_df.drop(columns=DROP_COLS)
print(f"Dropped columns  : {DROP_COLS}")

# ── Step 2: Fill remaining nulls ──────────────────────────
# subject has 347 nulls, body has 1 null
# fill with empty string so TF-IDF doesn't break
email_clean['subject'] = email_clean['subject'].fillna('')
email_clean['body']    = email_clean['body'].fillna('')
print(f"Nulls after fill : {email_clean.isnull().sum().to_dict()}")

# ── Step 3: Combine subject + body into one text column ───
# TF-IDF works better on one unified text field
# subject gets repeated to give it more weight
email_clean['text'] = (
    email_clean['subject'] + ' ' +
    email_clean['subject'] + ' ' +
    email_clean['body']
)

# ── Step 4: Clean text ────────────────────────────────────
def clean_text(text):
    text = str(text).lower()
    text = re.sub(r'http\S+|www\S+', ' urltoken ', text)
    text = re.sub(r'[\w\.-]+@[\w\.-]+', ' emailtoken ', text)
    text = re.sub(r'\d+', ' numtoken ', text)
    text = re.sub(r'[^a-z\s]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

email_clean['text'] = email_clean['text'].apply(clean_text)

print(f"\nSample cleaned text (row 0):")
print(email_clean['text'].iloc[0][:300])

# ── Step 5: Remove duplicates ─────────────────────────────
before = email_clean.shape[0]
email_clean = email_clean.drop_duplicates(subset=['text'])
after  = email_clean.shape[0]
print(f"\nDuplicates removed : {before - after:,}")
print(f"Rows after dedup   : {after:,}")

# ── Step 6: Remove empty text rows ────────────────────────
email_clean = email_clean[email_clean['text'].str.strip() != '']
print(f"Rows after empty   : {email_clean.shape[0]:,}")

# ── Step 7: Reset index ───────────────────────────────────
email_clean = email_clean.reset_index(drop=True)

# ── Step 8: Final label distribution after cleaning ───────
print(f"\nFinal label distribution (email):")
print(email_clean['label'].value_counts())
print(f"\nFinal label % split:")
print(email_clean['label'].value_counts(normalize=True).mul(100).round(2))

print(f"\nEmail dataset cleaned shape : {email_clean.shape}")
print(f"Columns remaining           : {list(email_clean.columns)}")

# ──────────────────────────────────────────────────────────
# 4.2 DATASET 2 — URL FEATURE PREPROCESSING
# ──────────────────────────────────────────────────────────

print("\n")
print("=" * 55)
print("4.2 — URL Feature Dataset Preprocessing")
print("=" * 55)

url_clean = url_df.copy()

# ── Step 1: Confirm no nulls ──────────────────────────────
print(f"Null values      : {url_clean.isnull().sum().sum()}")

# ── Step 2: Separate features and label ───────────────────
X_url = url_clean.drop(columns=['label'])
y_url = url_clean['label']
print(f"Features shape   : {X_url.shape}")
print(f"Label shape      : {y_url.shape}")

# ── Step 3: Check for constant columns ────────────────────
# Constant columns carry zero information — drop them
constant_cols = [col for col in X_url.columns if X_url[col].nunique() == 1]
if constant_cols:
    X_url = X_url.drop(columns=constant_cols)
    print(f"Constant cols dropped : {constant_cols}")
else:
    print(f"No constant columns found")

# ── Step 4: Check for highly correlated features ──────────
# Drop one of any pair with correlation > 0.95
corr_matrix = X_url.corr().abs()
upper_tri   = corr_matrix.where(
    np.triu(np.ones(corr_matrix.shape), k=1).astype(bool)
)
high_corr_cols = [
    col for col in upper_tri.columns
    if any(upper_tri[col] > 0.95)
]
X_url = X_url.drop(columns=high_corr_cols)
print(f"High corr cols dropped : {high_corr_cols}")
print(f"Features after corr drop : {X_url.shape[1]}")

# ── Step 5: Scale features ────────────────────────────────
scaler   = StandardScaler()
X_url_scaled = scaler.fit_transform(X_url)
X_url_scaled = pd.DataFrame(X_url_scaled, columns=X_url.columns)
print(f"\nFeatures scaled with StandardScaler")
print(f"Mean after scaling (sample): {X_url_scaled.mean().head(3).round(4).to_dict()}")
print(f"Std after scaling  (sample): {X_url_scaled.std().head(3).round(4).to_dict()}")

# ── Step 6: Remove duplicates ─────────────────────────────
url_combined        = X_url_scaled.copy()
url_combined['label'] = y_url.values
before              = url_combined.shape[0]
url_combined        = url_combined.drop_duplicates()
after               = url_combined.shape[0]
print(f"\nDuplicates removed : {before - after:,}")
print(f"Rows after dedup   : {after:,}")

X_url_scaled = url_combined.drop(columns=['label']).reset_index(drop=True)
y_url        = url_combined['label'].reset_index(drop=True)

print(f"\nURL dataset cleaned shape  : {X_url_scaled.shape}")
print(f"Label distribution (URL):")
print(y_url.value_counts())

# ──────────────────────────────────────────────────────────
# 4.3 PREPROCESSING SUMMARY
# ──────────────────────────────────────────────────────────

print("\n")
print("=" * 55)
print("4.3 — Preprocessing Summary")
print("=" * 55)
print(f"Email dataset")
print(f"  Before cleaning : {email_df.shape[0]:,} rows")
print(f"  After cleaning  : {email_clean.shape[0]:,} rows")
print(f"  Columns kept    : {list(email_clean.columns)}")
print(f"\nURL dataset")
print(f"  Before cleaning : {url_df.shape[0]:,} rows")
print(f"  After cleaning  : {url_combined.shape[0]:,} rows")
print(f"  Features kept   : {X_url_scaled.shape[1]}")
print(f"\nOutputs ready for Section 5:")
print(f"  email_clean     — cleaned email dataframe")
print(f"  X_url_scaled    — scaled URL features")
print(f"  y_url           — URL labels")
print(f"  scaler          — fitted StandardScaler (needed for Section 9 save)")
