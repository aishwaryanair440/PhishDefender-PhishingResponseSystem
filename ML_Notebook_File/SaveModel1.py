# ============================================================
# SECTION 9 — SAVE MODEL
# ============================================================

import joblib
import os
import json

# ──────────────────────────────────────────────────────────
# 9.1 CREATE OUTPUT DIRECTORY
# ──────────────────────────────────────────────────────────

print("=" * 55)
print("9.1 — Creating Output Directory")
print("=" * 55)

SAVE_DIR = '/kaggle/working/phishing_models'
os.makedirs(SAVE_DIR, exist_ok=True)
print(f"Save directory : {SAVE_DIR}")

# ──────────────────────────────────────────────────────────
# 9.2 SAVE EMAIL MODEL (LightGBM)
# ──────────────────────────────────────────────────────────

print("\n")
print("=" * 55)
print("9.2 — Saving Email Model")
print("=" * 55)

# Save LightGBM email model in native format
email_model_path = os.path.join(SAVE_DIR, 'email_model.pkl')
best_email_model.save_model(
    os.path.join(SAVE_DIR, 'email_model.txt')
)

# Also save with joblib for easy loading in Flask
joblib.dump(best_email_model, email_model_path)

print(f"Email model saved  : {email_model_path}")
print(f"Email model (txt)  : {SAVE_DIR}/email_model.txt")

# ──────────────────────────────────────────────────────────
# 9.3 SAVE URL MODEL (LightGBM)
# ──────────────────────────────────────────────────────────

print("\n")
print("=" * 55)
print("9.3 — Saving URL Model")
print("=" * 55)

url_model_path = os.path.join(SAVE_DIR, 'url_model.pkl')
best_url_model.save_model(
    os.path.join(SAVE_DIR, 'url_model.txt')
)

joblib.dump(best_url_model, url_model_path)

print(f"URL model saved    : {url_model_path}")
print(f"URL model (txt)    : {SAVE_DIR}/url_model.txt")

# ──────────────────────────────────────────────────────────
# 9.4 SAVE TFIDF VECTORIZER
# ──────────────────────────────────────────────────────────

print("\n")
print("=" * 55)
print("9.4 — Saving TF-IDF Vectorizer")
print("=" * 55)

tfidf_path = os.path.join(SAVE_DIR, 'tfidf_vectorizer.pkl')
joblib.dump(tfidf, tfidf_path)
print(f"TF-IDF saved       : {tfidf_path}")
print(f"Vocabulary size    : {len(tfidf.vocabulary_):,}")

# ──────────────────────────────────────────────────────────
# 9.5 SAVE SCALER
# ──────────────────────────────────────────────────────────

print("\n")
print("=" * 55)
print("9.5 — Saving StandardScaler")
print("=" * 55)

scaler_path = os.path.join(SAVE_DIR, 'scaler.pkl')
joblib.dump(scaler, scaler_path)
print(f"Scaler saved       : {scaler_path}")

# ──────────────────────────────────────────────────────────
# 9.6 SAVE URL FEATURE NAMES
# ──────────────────────────────────────────────────────────

print("\n")
print("=" * 55)
print("9.6 — Saving URL Feature Names")
print("=" * 55)

url_feature_names      = list(url_fe.columns)
url_feat_names_path    = os.path.join(SAVE_DIR, 'url_feature_names.pkl')
joblib.dump(url_feature_names, url_feat_names_path)
print(f"URL feature names saved : {url_feat_names_path}")
print(f"Total URL features      : {len(url_feature_names)}")

# ──────────────────────────────────────────────────────────
# 9.7 SAVE MODEL METADATA AS JSON
# ──────────────────────────────────────────────────────────

print("\n")
print("=" * 55)
print("9.7 — Saving Model Metadata")
print("=" * 55)

metadata = {
    'email_model': {
        'type'              : best_email_name,
        'f1_score'          : round(float(best_email_f1), 4),
        'accuracy'          : round(float(email_test_metrics['Accuracy']), 4),
        'precision'         : round(float(email_test_metrics['Precision']), 4),
        'recall'            : round(float(email_test_metrics['Recall']), 4),
        'roc_auc'           : round(float(email_test_metrics['ROC-AUC']), 4),
        'train_samples'     : int(X_email_train.shape[0]),
        'test_samples'      : int(X_email_test.shape[0]),
        'total_features'    : int(X_email.shape[1]),
        'tfidf_features'    : int(X_tfidf.shape[1]),
        'hand_features'     : int(email_hand_features.shape[1]),
        'model_file'        : 'email_model.pkl',
        'tfidf_file'        : 'tfidf_vectorizer.pkl'
    },
    'url_model': {
        'type'              : best_url_name,
        'f1_score'          : round(float(best_url_f1), 4),
        'accuracy'          : round(float(url_test_metrics['Accuracy']), 4),
        'precision'         : round(float(url_test_metrics['Precision']), 4),
        'recall'            : round(float(url_test_metrics['Recall']), 4),
        'roc_auc'           : round(float(url_test_metrics['ROC-AUC']), 4),
        'train_samples'     : int(X_url_train.shape[0]),
        'test_samples'      : int(X_url_test.shape[0]),
        'total_features'    : int(url_fe.shape[1]),
        'model_file'        : 'url_model.pkl',
        'scaler_file'       : 'scaler.pkl',
        'feature_names_file': 'url_feature_names.pkl'
    },
    'phishing_keywords' : [
        'click', 'verify', 'account', 'password', 'urgent',
        'bank', 'login', 'update', 'confirm', 'secure',
        'winner', 'prize', 'free', 'offer', 'limited',
        'suspend', 'validate', 'expire', 'immediate', 'alert'
    ],
    'subject_keywords'  : [
        'urgent', 'verify', 'suspended', 'winner',
        'congratulations', 'alert', 'confirm', 'free'
    ],
    'threshold'         : 0.5
}

metadata_path = os.path.join(SAVE_DIR, 'model_metadata.json')
with open(metadata_path, 'w') as f:
    json.dump(metadata, f, indent=4)

print(f"Metadata saved     : {metadata_path}")
print(json.dumps(metadata, indent=4))

# ──────────────────────────────────────────────────────────
# 9.8 VERIFY ALL SAVED FILES
# ──────────────────────────────────────────────────────────

print("\n")
print("=" * 55)
print("9.8 — Verifying Saved Files")
print("=" * 55)

saved_files = os.listdir(SAVE_DIR)
total_size  = 0

for fname in sorted(saved_files):
    fpath = os.path.join(SAVE_DIR, fname)
    fsize = os.path.getsize(fpath)
    total_size += fsize
    print(f"  {fname:<35} {fsize/1024/1024:.2f} MB")

print(f"\n  Total size         : {total_size/1024/1024:.2f} MB")
print(f"  Total files        : {len(saved_files)}")

# ──────────────────────────────────────────────────────────
# 9.9 QUICK LOAD AND PREDICT TEST
# ──────────────────────────────────────────────────────────

print("\n")
print("=" * 55)
print("9.9 — Load and Predict Verification Test")
print("=" * 55)

# Reload everything from disk
loaded_email_model = joblib.load(email_model_path)
loaded_url_model   = joblib.load(url_model_path)
loaded_tfidf       = joblib.load(tfidf_path)
loaded_scaler      = joblib.load(scaler_path)
loaded_feat_names  = joblib.load(url_feat_names_path)

print("All files loaded successfully")

# Test email model on 5 samples
sample_email_text  = email_clean['text'].iloc[:5].tolist()
sample_email_tfidf = loaded_tfidf.transform(sample_email_text).astype('float32')
sample_email_hand  = extract_email_features(
    email_clean.iloc[:5]
).values.astype('float32')
sample_email_feat  = sp.hstack([
    sp.csr_matrix(sample_email_tfidf),
    sp.csr_matrix(sample_email_hand)
]).astype('float32')

sample_email_probs = loaded_email_model.predict(sample_email_feat)
sample_email_preds = (sample_email_probs > 0.5).astype(int)

print(f"\nEmail model — 5 sample predictions:")
for i, (prob, pred, true) in enumerate(
    zip(sample_email_probs,
        sample_email_preds,
        y_email[:5])
):
    status = 'CORRECT' if pred == true else 'WRONG'
    print(f"  Sample {i+1}: prob={prob:.4f} "
          f"pred={'Phishing' if pred==1 else 'Legit':<10} "
          f"true={'Phishing' if true==1 else 'Legit':<10} "
          f"{status}")

# Test URL model on 5 samples
sample_url_raw   = url_fe.iloc[:5].values.astype('float32')
sample_url_probs = loaded_url_model.predict(sample_url_raw)
sample_url_preds = (sample_url_probs > 0.5).astype(int)

print(f"\nURL model — 5 sample predictions:")
for i, (prob, pred, true) in enumerate(
    zip(sample_url_probs,
        sample_url_preds,
        y_url.values[:5])
):
    status = 'CORRECT' if pred == true else 'WRONG'
    print(f"  Sample {i+1}: prob={prob:.4f} "
          f"pred={'Phishing' if pred==1 else 'Legit':<10} "
          f"true={'Phishing' if true==1 else 'Legit':<10} "
          f"{status}")

# ──────────────────────────────────────────────────────────
# 9.10 FINAL SUMMARY
# ──────────────────────────────────────────────────────────

print("\n")
print("=" * 55)
print("9.10 — Final Save Summary")
print("=" * 55)
print(f"All models saved to  : {SAVE_DIR}")
print(f"\nFiles to copy into phishing-detector/ folder:")
print(f"  email_model.pkl          — email classifier")
print(f"  url_model.pkl            — URL classifier")
print(f"  tfidf_vectorizer.pkl     — TF-IDF vectorizer")
print(f"  scaler.pkl               — StandardScaler")
print(f"  url_feature_names.pkl    — URL feature column names")
print(f"  model_metadata.json      — model info and thresholds")
print(f"\nNotebook complete — all 9 sections done")
print(f"Download files from Kaggle output panel")
print(f"and place them in your phishing-detector/ folder")
