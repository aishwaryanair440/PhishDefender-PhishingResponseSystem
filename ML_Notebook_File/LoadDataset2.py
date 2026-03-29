# ============================================================
# SECTION 2 — LOAD DATASET
# ============================================================

import os
import numpy as np
import pandas as pd

# ── Dataset 1: individual email files ─────────────────────
BASE = '/kaggle/input/datasets/naserabdullahalam/phishing-email-dataset'

ceas           = pd.read_csv(f'{BASE}/CEAS_08.csv')
enron          = pd.read_csv(f'{BASE}/Enron.csv')
ling           = pd.read_csv(f'{BASE}/Ling.csv')
nazario        = pd.read_csv(f'{BASE}/Nazario.csv')
nigerian       = pd.read_csv(f'{BASE}/Nigerian_Fraud.csv')
spam           = pd.read_csv(f'{BASE}/SpamAssasin.csv')
phishing_email = pd.read_csv(f'{BASE}/phishing_email.csv')

# ── Dataset 2: URL feature-based ──────────────────────────
url_df = pd.read_csv('/kaggle/input/datasets/shashwatwork/phishing-dataset-for-machine-learning/Phishing_Legitimate_full.csv')

# ──────────────────────────────────────────────────────────
# phishing_email.csv has only text_combined + label
# Split text_combined into subject + body
# ──────────────────────────────────────────────────────────
phishing_email['subject'] = phishing_email['text_combined'].apply(
    lambda x: str(x).split('.')[0] if pd.notnull(x) else ''
)
phishing_email['body'] = phishing_email['text_combined'].apply(
    lambda x: '.'.join(str(x).split('.')[1:]) if pd.notnull(x) else ''
)
phishing_email = phishing_email.drop(columns=['text_combined'])

# ──────────────────────────────────────────────────────────
# Standardize all files to common columns before merging
# Files missing columns get NaN filled automatically
# ──────────────────────────────────────────────────────────

COMMON_COLS = ['sender', 'receiver', 'date', 'subject', 'body', 'urls', 'label']

def standardize(df, source_name):
    for col in COMMON_COLS:
        if col not in df.columns:
            df[col] = np.nan
    df = df[COMMON_COLS].copy()
    df['source'] = source_name
    return df

ceas           = standardize(ceas,           'CEAS_08')
enron          = standardize(enron,          'Enron')
ling           = standardize(ling,           'Ling')
nazario        = standardize(nazario,        'Nazario')
nigerian       = standardize(nigerian,       'Nigerian_Fraud')
spam           = standardize(spam,           'SpamAssasin')
phishing_email = standardize(phishing_email, 'phishing_email')

# ── Merge all 7 into one email dataframe ──────────────────
email_df = pd.concat(
    [ceas, enron, ling, nazario, nigerian, spam, phishing_email],
    ignore_index=True
)

# ── Rename URL dataset label column to match email_df ─────
url_df = url_df.rename(columns={'CLASS_LABEL': 'label'})
url_df = url_df.drop(columns=['id'])

# ──────────────────────────────────────────────────────────
# Sanity checks
# ──────────────────────────────────────────────────────────

print("=" * 55)
print("INDIVIDUAL FILE SIZES")
print("=" * 55)
print(f"CEAS_08         : {ceas.shape[0]:>7,} rows")
print(f"Enron           : {enron.shape[0]:>7,} rows")
print(f"Ling            : {ling.shape[0]:>7,} rows")
print(f"Nazario         : {nazario.shape[0]:>7,} rows")
print(f"Nigerian Fraud  : {nigerian.shape[0]:>7,} rows")
print(f"SpamAssasin     : {spam.shape[0]:>7,} rows")
print(f"Phishing Email  : {phishing_email.shape[0]:>7,} rows")

print("\n")
print("=" * 55)
print("DATASET 1 — Email dataset (merged)")
print("=" * 55)
print(f"Shape           : {email_df.shape}")
print(f"Columns         : {list(email_df.columns)}")
print(f"\nLabel distribution:")
print(email_df['label'].value_counts())
print(f"\nLabel % split:")
print(email_df['label'].value_counts(normalize=True).mul(100).round(2))
print(f"\nNull values per column:")
print(email_df.isnull().sum())
print(f"\nRows per source:")
print(email_df['source'].value_counts())

print("\n")
print("=" * 55)
print("DATASET 2 — URL feature dataset")
print("=" * 55)
print(f"Shape           : {url_df.shape}")
print(f"\nLabel distribution:")
print(url_df['label'].value_counts())
print(f"\nNull values: {url_df.isnull().sum().sum()}")
