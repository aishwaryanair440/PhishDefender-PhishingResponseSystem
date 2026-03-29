# ============================================================
# SECTION 8 — MODEL EVALUATION
# ============================================================

from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report,
    roc_auc_score, roc_curve, precision_recall_curve,
    average_precision_score
)
import matplotlib.gridspec as gridspec

# ──────────────────────────────────────────────────────────
# 8.0 GENERATE PREDICTIONS
# ──────────────────────────────────────────────────────────

print("=" * 55)
print("8.0 — Generating Predictions")
print("=" * 55)

# Email model predictions
lgb_email_probs_test  = best_email_model.predict(X_email_test_gpu)
lgb_email_preds_test  = (lgb_email_probs_test > 0.5).astype(int)
lgb_email_probs_train = best_email_model.predict(X_email_train_gpu)
lgb_email_preds_train = (lgb_email_probs_train > 0.5).astype(int)

# URL model predictions
lgb_url_probs_test    = best_url_model.predict(X_url_test_gpu)
lgb_url_preds_test    = (lgb_url_probs_test > 0.5).astype(int)
lgb_url_probs_train   = best_url_model.predict(X_url_train_gpu)
lgb_url_preds_train   = (lgb_url_probs_train > 0.5).astype(int)

print(f"Email predictions generated : {len(lgb_email_preds_test):,}")
print(f"URL predictions generated   : {len(lgb_url_preds_test):,}")

# ──────────────────────────────────────────────────────────
# 8.1 EVALUATION PARAMETER 1 — CORE METRICS TABLE
# ──────────────────────────────────────────────────────────

print("\n")
print("=" * 55)
print("8.1 — Core Metrics (Accuracy, Precision, Recall, F1)")
print("=" * 55)

def compute_metrics(y_true, y_pred, y_prob, name):
    return {
        'Model'     : name,
        'Accuracy'  : accuracy_score(y_true, y_pred),
        'Precision' : precision_score(y_true, y_pred),
        'Recall'    : recall_score(y_true, y_pred),
        'F1 Score'  : f1_score(y_true, y_pred),
        'ROC-AUC'   : roc_auc_score(y_true, y_prob),
        'Avg Prec'  : average_precision_score(y_true, y_prob)
    }

email_train_metrics = compute_metrics(
    y_email_train_gpu, lgb_email_preds_train,
    lgb_email_probs_train, 'Email — Train'
)
email_test_metrics  = compute_metrics(
    y_email_test_gpu, lgb_email_preds_test,
    lgb_email_probs_test, 'Email — Test'
)
url_train_metrics   = compute_metrics(
    y_url_train_gpu, lgb_url_preds_train,
    lgb_url_probs_train, 'URL — Train'
)
url_test_metrics    = compute_metrics(
    y_url_test_gpu, lgb_url_preds_test,
    lgb_url_probs_test, 'URL — Test'
)

metrics_df = pd.DataFrame([
    email_train_metrics,
    email_test_metrics,
    url_train_metrics,
    url_test_metrics
]).set_index('Model')

print(metrics_df.round(4).to_string())

# ── Overfitting gap ────────────────────────────────────────
email_gap = abs(email_train_metrics['F1 Score'] - email_test_metrics['F1 Score'])
url_gap   = abs(url_train_metrics['F1 Score']   - url_test_metrics['F1 Score'])

print(f"\nOverfitting Gap (Train F1 - Test F1):")
print(f"  Email model : {email_gap:.4f} {'GOOD' if email_gap < 0.03 else 'WARNING'}")
print(f"  URL model   : {url_gap:.4f}   {'GOOD' if url_gap   < 0.03 else 'WARNING'}")

# ── Plot core metrics ──────────────────────────────────────
fig, ax = plt.subplots(figsize=(14, 5))
metrics_plot = metrics_df[['Accuracy', 'Precision', 'Recall', 'F1 Score', 'ROC-AUC']]
x     = np.arange(len(metrics_plot.columns))
width = 0.2
colors = ['#3498db', '#2ecc71', '#e74c3c', '#9b59b6']
labels = metrics_plot.index.tolist()

for i, (label, color) in enumerate(zip(labels, colors)):
    ax.bar(x + i * width, metrics_plot.loc[label], width,
           label=label, color=color, edgecolor='black')

ax.set_title('Core Evaluation Metrics — All Models', fontsize=13)
ax.set_xticks(x + width * 1.5)
ax.set_xticklabels(metrics_plot.columns)
ax.set_ylim(0.90, 1.01)
ax.legend(loc='lower right')
ax.set_ylabel('Score')
plt.tight_layout()
plt.savefig('core_metrics.png', dpi=150, bbox_inches='tight')
plt.show()
print("8.1 — Core metrics plotted")

# ──────────────────────────────────────────────────────────
# 8.2 EVALUATION PARAMETER 2 — CONFUSION MATRIX
# ──────────────────────────────────────────────────────────

print("\n")
print("=" * 55)
print("8.2 — Confusion Matrix")
print("=" * 55)

fig, axes = plt.subplots(1, 2, figsize=(14, 6))

for ax, y_true, y_pred, title in [
    (axes[0], y_email_test_gpu, lgb_email_preds_test, 'Email Model — Confusion Matrix'),
    (axes[1], y_url_test_gpu,   lgb_url_preds_test,   'URL Model — Confusion Matrix')
]:
    cm = confusion_matrix(y_true, y_pred)
    sns.heatmap(
        cm,
        annot      = True,
        fmt        = 'd',
        cmap       = 'Blues',
        ax         = ax,
        linewidths = 0.5,
        cbar       = True,
        xticklabels= ['Legitimate (0)', 'Phishing (1)'],
        yticklabels= ['Legitimate (0)', 'Phishing (1)']
    )
    ax.set_title(title, fontsize=13)
    ax.set_xlabel('Predicted Label')
    ax.set_ylabel('True Label')

    # Annotate TN, FP, FN, TP
    tn, fp, fn, tp = cm.ravel()
    ax.text(0.5, -0.12,
            f'TN={tn:,}  FP={fp:,}  FN={fn:,}  TP={tp:,}',
            ha='center', transform=ax.transAxes, fontsize=10)

plt.tight_layout()
plt.savefig('confusion_matrix.png', dpi=150, bbox_inches='tight')
plt.show()

# Print raw values
for y_true, y_pred, name in [
    (y_email_test_gpu, lgb_email_preds_test, 'Email'),
    (y_url_test_gpu,   lgb_url_preds_test,   'URL')
]:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    print(f"\n{name} model:")
    print(f"  True Negatives  (correctly caught legitimate) : {tn:,}")
    print(f"  False Positives (legitimate flagged as phish) : {fp:,}")
    print(f"  False Negatives (phishing missed)             : {fn:,}")
    print(f"  True Positives  (correctly caught phishing)   : {tp:,}")
print("8.2 — Confusion matrices plotted")

# ──────────────────────────────────────────────────────────
# 8.3 EVALUATION PARAMETER 3 — ROC CURVE
# ──────────────────────────────────────────────────────────

print("\n")
print("=" * 55)
print("8.3 — ROC Curve (AUC)")
print("=" * 55)

fig, axes = plt.subplots(1, 2, figsize=(14, 6))

for ax, y_true, y_prob, name in [
    (axes[0], y_email_test_gpu, lgb_email_probs_test, 'Email Model'),
    (axes[1], y_url_test_gpu,   lgb_url_probs_test,   'URL Model')
]:
    fpr, tpr, thresholds = roc_curve(y_true, y_prob)
    auc_score = roc_auc_score(y_true, y_prob)

    ax.plot(fpr, tpr, color='#e74c3c', lw=2,
            label=f'ROC Curve (AUC = {auc_score:.4f})')
    ax.plot([0, 1], [0, 1], color='gray', lw=1,
            linestyle='--', label='Random Classifier')
    ax.fill_between(fpr, tpr, alpha=0.1, color='#e74c3c')
    ax.set_title(f'{name} — ROC Curve', fontsize=13)
    ax.set_xlabel('False Positive Rate')
    ax.set_ylabel('True Positive Rate')
    ax.legend(loc='lower right')
    ax.set_xlim([0, 1])
    ax.set_ylim([0, 1.02])

    print(f"\n{name}:")
    print(f"  AUC Score       : {auc_score:.4f}")

plt.tight_layout()
plt.savefig('roc_curve.png', dpi=150, bbox_inches='tight')
plt.show()
print("8.3 — ROC curves plotted")

# ──────────────────────────────────────────────────────────
# 8.4 EVALUATION PARAMETER 4 — PRECISION-RECALL CURVE
# ──────────────────────────────────────────────────────────

print("\n")
print("=" * 55)
print("8.4 — Precision-Recall Curve")
print("=" * 55)

fig, axes = plt.subplots(1, 2, figsize=(14, 6))

for ax, y_true, y_prob, name in [
    (axes[0], y_email_test_gpu, lgb_email_probs_test, 'Email Model'),
    (axes[1], y_url_test_gpu,   lgb_url_probs_test,   'URL Model')
]:
    precision, recall, thresholds = precision_recall_curve(y_true, y_prob)
    avg_precision = average_precision_score(y_true, y_prob)

    ax.plot(recall, precision, color='#3498db', lw=2,
            label=f'PR Curve (AP = {avg_precision:.4f})')
    ax.fill_between(recall, precision, alpha=0.1, color='#3498db')
    ax.axhline(
        y    = y_true.mean(),
        color= 'gray', lw=1,
        linestyle='--',
        label= f'Baseline (prevalence={y_true.mean():.2f})'
    )
    ax.set_title(f'{name} — Precision-Recall Curve', fontsize=13)
    ax.set_xlabel('Recall')
    ax.set_ylabel('Precision')
    ax.legend(loc='lower left')
    ax.set_xlim([0, 1])
    ax.set_ylim([0, 1.02])

    print(f"\n{name}:")
    print(f"  Average Precision : {avg_precision:.4f}")

plt.tight_layout()
plt.savefig('precision_recall_curve.png', dpi=150, bbox_inches='tight')
plt.show()
print("8.4 — Precision-Recall curves plotted")

# ──────────────────────────────────────────────────────────
# 8.5 EVALUATION PARAMETER 5 — FEATURE IMPORTANCE
# ──────────────────────────────────────────────────────────

print("\n")
print("=" * 55)
print("8.5 — Feature Importance")
print("=" * 55)

fig, axes = plt.subplots(1, 2, figsize=(16, 7))

# Email model — top 25 features
email_importance = best_email_model.feature_importance(importance_type='gain')

# Feature names — TF-IDF tokens + hand-crafted
tfidf_names      = tfidf.get_feature_names_out().tolist()
hand_feat_names  = [
    'url_count', 'email_count', 'num_count', 'body_length',
    'subject_length', 'word_count', 'avg_word_length',
    'exclamation_count', 'question_count', 'capital_ratio',
    'keyword_count', 'suspicious_subject', 'has_html'
]
email_feat_names = tfidf_names + hand_feat_names

email_imp_df = pd.DataFrame({
    'feature'    : email_feat_names,
    'importance' : email_importance
}).sort_values('importance', ascending=False).head(25)

axes[0].barh(
    email_imp_df['feature'][::-1],
    email_imp_df['importance'][::-1],
    color='#9b59b6', edgecolor='black'
)
axes[0].set_title('Email Model — Top 25 Features (Gain)', fontsize=13)
axes[0].set_xlabel('Feature Importance (Gain)')
axes[0].tick_params(axis='y', labelsize=8)

# URL model — top 25 features
url_importance   = best_url_model.feature_importance(importance_type='gain')
url_feat_names   = list(url_fe.columns)

url_imp_df = pd.DataFrame({
    'feature'    : url_feat_names,
    'importance' : url_importance
}).sort_values('importance', ascending=False).head(25)

axes[1].barh(
    url_imp_df['feature'][::-1],
    url_imp_df['importance'][::-1],
    color='#e67e22', edgecolor='black'
)
axes[1].set_title('URL Model — Top 25 Features (Gain)', fontsize=13)
axes[1].set_xlabel('Feature Importance (Gain)')
axes[1].tick_params(axis='y', labelsize=9)

plt.tight_layout()
plt.savefig('feature_importance.png', dpi=150, bbox_inches='tight')
plt.show()

print(f"\nEmail model — Top 10 features:")
print(email_imp_df[['feature', 'importance']].head(10).to_string(index=False))
print(f"\nURL model — Top 10 features:")
print(url_imp_df[['feature', 'importance']].head(10).to_string(index=False))
print("8.5 — Feature importance plotted")

# ──────────────────────────────────────────────────────────
# 8.6 EVALUATION PARAMETER 6 — PREDICTION PROBABILITY
#     DISTRIBUTION
# ──────────────────────────────────────────────────────────

print("\n")
print("=" * 55)
print("8.6 — Prediction Probability Distribution")
print("=" * 55)

fig, axes = plt.subplots(1, 2, figsize=(14, 6))

for ax, y_true, y_prob, name in [
    (axes[0], y_email_test_gpu, lgb_email_probs_test, 'Email Model'),
    (axes[1], y_url_test_gpu,   lgb_url_probs_test,   'URL Model')
]:
    for label, color, lname in [
        (0, '#2ecc71', 'Legitimate'),
        (1, '#e74c3c', 'Phishing')
    ]:
        mask = y_true == label
        ax.hist(
            y_prob[mask],
            bins      = 50,
            alpha     = 0.6,
            color     = color,
            label     = lname,
            edgecolor = 'black',
            density   = True
        )

    ax.axvline(x=0.5, color='black', lw=1.5,
               linestyle='--', label='Threshold = 0.5')
    ax.set_title(f'{name} — Probability Distribution', fontsize=13)
    ax.set_xlabel('Predicted Probability (Phishing)')
    ax.set_ylabel('Density')
    ax.legend()

plt.tight_layout()
plt.savefig('probability_distribution.png', dpi=150, bbox_inches='tight')
plt.show()

# Confidence analysis
for y_true, y_prob, name in [
    (y_email_test_gpu, lgb_email_probs_test, 'Email'),
    (y_url_test_gpu,   lgb_url_probs_test,   'URL')
]:
    high_conf = ((y_prob > 0.9) | (y_prob < 0.1)).mean() * 100
    uncertain = ((y_prob >= 0.4) & (y_prob <= 0.6)).mean() * 100
    print(f"\n{name} model confidence:")
    print(f"  High confidence (>0.9 or <0.1) : {high_conf:.1f}% of predictions")
    print(f"  Uncertain (0.4 - 0.6)          : {uncertain:.1f}% of predictions")

print("8.6 — Probability distributions plotted")

# ──────────────────────────────────────────────────────────
# 8.7 CLASSIFICATION REPORT
# ──────────────────────────────────────────────────────────

print("\n")
print("=" * 55)
print("8.7 — Full Classification Report")
print("=" * 55)

for y_true, y_pred, name in [
    (y_email_test_gpu, lgb_email_preds_test, 'Email Model'),
    (y_url_test_gpu,   lgb_url_preds_test,   'URL Model')
]:
    print(f"\n{name}:")
    print(classification_report(
        y_true, y_pred,
        target_names=['Legitimate', 'Phishing'],
        digits=4
    ))

# ──────────────────────────────────────────────────────────
# 8.8 EVALUATION SUMMARY
# ──────────────────────────────────────────────────────────

print("\n")
print("=" * 55)
print("8.8 — Evaluation Summary")
print("=" * 55)
print(metrics_df.round(4).to_string())
print(f"\nGraphs saved:")
print(f"  core_metrics.png")
print(f"  confusion_matrix.png")
print(f"  roc_curve.png")
print(f"  precision_recall_curve.png")
print(f"  feature_importance.png")
print(f"  probability_distribution.png")
print(f"\nOutputs ready for Section 9:")
print(f"  best_email_model — LightGBM email classifier")
print(f"  best_url_model   — LightGBM URL classifier")
print(f"  tfidf            — fitted TF-IDF vectorizer")
print(f"  scaler           — fitted StandardScaler")
print(f"  url_feat_names   — URL feature column names")
