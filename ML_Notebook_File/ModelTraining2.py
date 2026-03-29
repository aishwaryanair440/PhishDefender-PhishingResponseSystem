# ============================================================
# SECTION 7 — MODEL TRAINING (GPU ACCELERATED)
# ============================================================

import xgboost as xgb
import lightgbm as lgb
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import f1_score
import scipy.sparse as sp
import time

# ──────────────────────────────────────────────────────────
# 7.0 CONVERT SPARSE MATRIX FOR GPU COMPATIBILITY
# ──────────────────────────────────────────────────────────

print("=" * 55)
print("7.0 — Data Preparation for GPU")
print("=" * 55)

# Email — sparse matrix, convert to float32
X_email_train_gpu = X_email_train.astype('float32')
X_email_test_gpu  = X_email_test.astype('float32')

# URL — DataFrame, convert values to float32
X_url_train_gpu   = X_url_train.values.astype('float32')
X_url_test_gpu    = X_url_test.values.astype('float32')

# Labels — convert to int32
y_email_train_gpu = y_email_train.astype('int32')
y_email_test_gpu  = y_email_test.astype('int32')
y_url_train_gpu   = y_url_train.astype('int32').values
y_url_test_gpu    = y_url_test.astype('int32').values

print(f"Email train type      : {type(X_email_train_gpu)}")
print(f"Email train dtype     : {X_email_train_gpu.dtype}")
print(f"URL train type        : {type(X_url_train_gpu)}")
print(f"URL train dtype       : {X_url_train_gpu.dtype}")
print(f"y_email_train dtype   : {y_email_train_gpu.dtype}")
print(f"y_url_train dtype     : {y_url_train_gpu.dtype}")
print(f"GPU data ready")
# ──────────────────────────────────────────────────────────
# 7.1 EMAIL MODEL TRAINING
# ──────────────────────────────────────────────────────────

print("\n")
print("=" * 55)
print("7.1 — Email Model Training")
print("=" * 55)

# ── Model 1: XGBoost with DMatrix (best sparse GPU support)
print("\nTraining XGBoost (GPU)...")
start = time.time()

# Convert to DMatrix — XGBoost's native format
# handles sparse matrices most efficiently on GPU
dtrain_email = xgb.DMatrix(X_email_train_gpu, label=y_email_train_gpu)
dtest_email  = xgb.DMatrix(X_email_test_gpu,  label=y_email_test_gpu)

xgb_email_params = {
    'device'          : 'cuda',
    'objective'       : 'binary:logistic',
    'eval_metric'     : ['logloss', 'auc'],
    'max_depth'       : 6,
    'learning_rate'   : 0.05,
    'n_estimators'    : 300,
    'subsample'       : 0.8,
    'colsample_bytree': 0.7,
    'min_child_weight': 5,
    'gamma'           : 0.1,
    'reg_alpha'       : 0.1,
    'reg_lambda'      : 1.0,
    'scale_pos_weight': 1,
    'seed'            : 42
}

# Early stopping prevents overfitting automatically
xgb_email_model = xgb.train(
    xgb_email_params,
    dtrain_email,
    num_boost_round    = 300,
    evals              = [(dtrain_email, 'train'), (dtest_email, 'eval')],
    early_stopping_rounds = 20,
    verbose_eval       = 50
)

elapsed = time.time() - start
print(f"\n  XGBoost training time : {elapsed:.1f}s")

# ── Model 2: LightGBM (native sparse + GPU support) ───────
print("\nTraining LightGBM (GPU)...")
start = time.time()

lgb_email_params = {
    'device'          : 'gpu',
    'objective'       : 'binary',
    'metric'          : ['binary_logloss', 'auc'],
    'boosting_type'   : 'gbdt',
    'num_leaves'      : 63,
    'max_depth'       : -1,
    'learning_rate'   : 0.05,
    'n_estimators'    : 300,
    'subsample'       : 0.8,
    'colsample_bytree': 0.7,
    'min_child_samples': 20,
    'reg_alpha'       : 0.1,
    'reg_lambda'      : 1.0,
    'verbose'         : -1,
    'random_state'    : 42
}

lgb_email_train = lgb.Dataset(X_email_train_gpu, label=y_email_train_gpu)
lgb_email_val   = lgb.Dataset(X_email_test_gpu,  label=y_email_test_gpu,
                               reference=lgb_email_train)

callbacks = [
    lgb.early_stopping(stopping_rounds=20, verbose=True),
    lgb.log_evaluation(period=50)
]

lgb_email_model = lgb.train(
    lgb_email_params,
    lgb_email_train,
    num_boost_round   = 300,
    valid_sets        = [lgb_email_train, lgb_email_val],
    valid_names       = ['train', 'eval'],
    callbacks         = callbacks
)

elapsed = time.time() - start
print(f"\n  LightGBM training time : {elapsed:.1f}s")

# ── Compare both models on test set ───────────────────────
print("\n--- Email Model Comparison on Test Set ---")

# XGBoost predictions
xgb_email_probs = xgb_email_model.predict(dtest_email)
xgb_email_preds = (xgb_email_probs > 0.5).astype(int)
xgb_email_f1    = f1_score(y_email_test_gpu, xgb_email_preds)
xgb_email_acc   = (xgb_email_preds == y_email_test_gpu).mean()

# LightGBM predictions
lgb_email_probs = lgb_email_model.predict(X_email_test_gpu)
lgb_email_preds = (lgb_email_probs > 0.5).astype(int)
lgb_email_f1    = f1_score(y_email_test_gpu, lgb_email_preds)
lgb_email_acc   = (lgb_email_preds == y_email_test_gpu).mean()

print(f"\n  XGBoost  — Accuracy: {xgb_email_acc:.4f} | F1: {xgb_email_f1:.4f}")
print(f"  LightGBM — Accuracy: {lgb_email_acc:.4f} | F1: {lgb_email_f1:.4f}")

# Select best email model
if xgb_email_f1 >= lgb_email_f1:
    best_email_model      = xgb_email_model
    best_email_name       = 'XGBoost'
    best_email_type       = 'xgboost'
    best_email_f1         = xgb_email_f1
else:
    best_email_model      = lgb_email_model
    best_email_name       = 'LightGBM'
    best_email_type       = 'lightgbm'
    best_email_f1         = lgb_email_f1

print(f"\nBest email model      : {best_email_name}")
print(f"Best email F1         : {best_email_f1:.4f}")

# ── Overfitting check ──────────────────────────────────────
if best_email_type == 'xgboost':
    train_preds = (xgb_email_model.predict(dtrain_email) > 0.5).astype(int)
else:
    train_preds = (lgb_email_model.predict(X_email_train_gpu) > 0.5).astype(int)

train_f1 = f1_score(y_email_train_gpu, train_preds)
print(f"\nOverfitting check (email):")
print(f"  Train F1            : {train_f1:.4f}")
print(f"  Test  F1            : {best_email_f1:.4f}")
print(f"  Difference          : {abs(train_f1 - best_email_f1):.4f}")
if abs(train_f1 - best_email_f1) < 0.03:
    print(f"  Status              : GOOD — no overfitting detected")
elif abs(train_f1 - best_email_f1) < 0.06:
    print(f"  Status              : ACCEPTABLE — minor gap")
else:
    print(f"  Status              : WARNING — possible overfitting")

# ──────────────────────────────────────────────────────────
# 7.2 URL MODEL TRAINING
# ──────────────────────────────────────────────────────────

print("\n")
print("=" * 55)
print("7.2 — URL Model Training")
print("=" * 55)

# ── Model 1: XGBoost ──────────────────────────────────────
print("\nTraining XGBoost (GPU)...")
start = time.time()

dtrain_url = xgb.DMatrix(X_url_train_gpu, label=y_url_train_gpu)
dtest_url  = xgb.DMatrix(X_url_test_gpu,  label=y_url_test_gpu)

xgb_url_params = {
    'device'          : 'cuda',
    'objective'       : 'binary:logistic',
    'eval_metric'     : ['logloss', 'auc'],
    'max_depth'       : 6,
    'learning_rate'   : 0.05,
    'subsample'       : 0.8,
    'colsample_bytree': 0.7,
    'min_child_weight': 5,
    'gamma'           : 0.1,
    'reg_alpha'       : 0.1,
    'reg_lambda'      : 1.0,
    'seed'            : 42
}

xgb_url_model = xgb.train(
    xgb_url_params,
    dtrain_url,
    num_boost_round       = 300,
    evals                 = [(dtrain_url, 'train'), (dtest_url, 'eval')],
    early_stopping_rounds = 20,
    verbose_eval          = 50
)

elapsed = time.time() - start
print(f"\n  XGBoost training time : {elapsed:.1f}s")

# ── Model 2: LightGBM ─────────────────────────────────────
print("\nTraining LightGBM (GPU)...")
start = time.time()

lgb_url_params = {
    'device'           : 'gpu',
    'objective'        : 'binary',
    'metric'           : ['binary_logloss', 'auc'],
    'boosting_type'    : 'gbdt',
    'num_leaves'       : 63,
    'max_depth'        : -1,
    'learning_rate'    : 0.05,
    'subsample'        : 0.8,
    'colsample_bytree' : 0.7,
    'min_child_samples': 20,
    'reg_alpha'        : 0.1,
    'reg_lambda'       : 1.0,
    'verbose'          : -1,
    'random_state'     : 42
}

lgb_url_train = lgb.Dataset(X_url_train_gpu, label=y_url_train_gpu)
lgb_url_val   = lgb.Dataset(X_url_test_gpu,  label=y_url_test_gpu,
                              reference=lgb_url_train)

lgb_url_model = lgb.train(
    lgb_url_params,
    lgb_url_train,
    num_boost_round   = 300,
    valid_sets        = [lgb_url_train, lgb_url_val],
    valid_names       = ['train', 'eval'],
    callbacks         = callbacks
)

elapsed = time.time() - start
print(f"\n  LightGBM training time : {elapsed:.1f}s")

# ── Compare both models on test set ───────────────────────
print("\n--- URL Model Comparison on Test Set ---")

xgb_url_probs = xgb_url_model.predict(dtest_url)
xgb_url_preds = (xgb_url_probs > 0.5).astype(int)
xgb_url_f1    = f1_score(y_url_test_gpu, xgb_url_preds)
xgb_url_acc   = (xgb_url_preds == y_url_test_gpu).mean()

lgb_url_probs = lgb_url_model.predict(X_url_test_gpu)
lgb_url_preds = (lgb_url_probs > 0.5).astype(int)
lgb_url_f1    = f1_score(y_url_test_gpu, lgb_url_preds)
lgb_url_acc   = (lgb_url_preds == y_url_test_gpu).mean()

print(f"\n  XGBoost  — Accuracy: {xgb_url_acc:.4f} | F1: {xgb_url_f1:.4f}")
print(f"  LightGBM — Accuracy: {lgb_url_acc:.4f} | F1: {lgb_url_f1:.4f}")

if xgb_url_f1 >= lgb_url_f1:
    best_url_model  = xgb_url_model
    best_url_name   = 'XGBoost'
    best_url_type   = 'xgboost'
    best_url_f1     = xgb_url_f1
else:
    best_url_model  = lgb_url_model
    best_url_name   = 'LightGBM'
    best_url_type   = 'lightgbm'
    best_url_f1     = lgb_url_f1

print(f"\nBest URL model        : {best_url_name}")
print(f"Best URL F1           : {best_url_f1:.4f}")

# ── Overfitting check ──────────────────────────────────────
if best_url_type == 'xgboost':
    train_preds_url = (xgb_url_model.predict(dtrain_url) > 0.5).astype(int)
else:
    train_preds_url = (lgb_url_model.predict(X_url_train_gpu) > 0.5).astype(int)

train_f1_url = f1_score(y_url_train_gpu, train_preds_url)
print(f"\nOverfitting check (URL):")
print(f"  Train F1            : {train_f1_url:.4f}")
print(f"  Test  F1            : {best_url_f1:.4f}")
print(f"  Difference          : {abs(train_f1_url - best_url_f1):.4f}")
if abs(train_f1_url - best_url_f1) < 0.03:
    print(f"  Status              : GOOD — no overfitting detected")
elif abs(train_f1_url - best_url_f1) < 0.06:
    print(f"  Status              : ACCEPTABLE — minor gap")
else:
    print(f"  Status              : WARNING — possible overfitting")

# ──────────────────────────────────────────────────────────
# 7.3 CV SCORE COMPARISON PLOT
# ──────────────────────────────────────────────────────────

fig, axes = plt.subplots(1, 2, figsize=(14, 5))

# Email model comparison
email_names = ['XGBoost', 'LightGBM']
email_f1s   = [xgb_email_f1, lgb_email_f1]
email_accs  = [xgb_email_acc, lgb_email_acc]

x = np.arange(len(email_names))
w = 0.35
axes[0].bar(x - w/2, email_f1s,  w, label='F1 Score',  color='#3498db', edgecolor='black')
axes[0].bar(x + w/2, email_accs, w, label='Accuracy',  color='#2ecc71', edgecolor='black')
axes[0].set_title('Email Models — F1 & Accuracy', fontsize=13)
axes[0].set_xticks(x)
axes[0].set_xticklabels(email_names)
axes[0].set_ylim(0.8, 1.0)
axes[0].legend()
for i, (f1, acc) in enumerate(zip(email_f1s, email_accs)):
    axes[0].text(i - w/2, f1  + 0.002, f'{f1:.4f}',  ha='center', fontsize=9)
    axes[0].text(i + w/2, acc + 0.002, f'{acc:.4f}', ha='center', fontsize=9)

# URL model comparison
url_names = ['XGBoost', 'LightGBM']
url_f1s   = [xgb_url_f1, lgb_url_f1]
url_accs  = [xgb_url_acc, lgb_url_acc]

x = np.arange(len(url_names))
axes[1].bar(x - w/2, url_f1s,  w, label='F1 Score', color='#3498db', edgecolor='black')
axes[1].bar(x + w/2, url_accs, w, label='Accuracy', color='#2ecc71', edgecolor='black')
axes[1].set_title('URL Models — F1 & Accuracy', fontsize=13)
axes[1].set_xticks(x)
axes[1].set_xticklabels(url_names)
axes[1].set_ylim(0.8, 1.0)
axes[1].legend()
for i, (f1, acc) in enumerate(zip(url_f1s, url_accs)):
    axes[1].text(i - w/2, f1  + 0.002, f'{f1:.4f}',  ha='center', fontsize=9)
    axes[1].text(i + w/2, acc + 0.002, f'{acc:.4f}', ha='center', fontsize=9)

plt.tight_layout()
plt.savefig('model_comparison.png', dpi=150, bbox_inches='tight')
plt.show()
print("7.3 — Model comparison plotted")

# ──────────────────────────────────────────────────────────
# 7.4 TRAINING SUMMARY
# ──────────────────────────────────────────────────────────

print("\n")
print("=" * 55)
print("7.4 — Training Summary")
print("=" * 55)
print(f"Email model results:")
print(f"  XGBoost  — F1: {xgb_email_f1:.4f} | Accuracy: {xgb_email_acc:.4f}")
print(f"  LightGBM — F1: {lgb_email_f1:.4f} | Accuracy: {lgb_email_acc:.4f}")
print(f"\nURL model results:")
print(f"  XGBoost  — F1: {xgb_url_f1:.4f} | Accuracy: {xgb_url_acc:.4f}")
print(f"  LightGBM — F1: {lgb_url_f1:.4f} | Accuracy: {lgb_url_acc:.4f}")
print(f"\nSelected for evaluation:")
print(f"  Email model : {best_email_name} (F1={best_email_f1:.4f})")
print(f"  URL model   : {best_url_name}   (F1={best_url_f1:.4f})")
print(f"\nOutputs ready for Section 8:")
print(f"  best_email_model, best_email_name, best_email_type")
print(f"  best_url_model,   best_url_name,   best_url_type")
print(f"  dtrain_email, dtest_email")
print(f"  dtrain_url,   dtest_url")
