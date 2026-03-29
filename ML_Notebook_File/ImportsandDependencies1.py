# ============================================================
# SECTION 1 — IMPORTS AND DEPENDENCIES
# ============================================================

# ── Standard library ──────────────────────────────────────
import re
import warnings
warnings.filterwarnings('ignore')

# ── Data handling ──────────────────────────────────────────
import numpy as np
import pandas as pd

# ── Visualization ──────────────────────────────────────────
import matplotlib.pyplot as plt
import seaborn as sns

# ── Text processing (for Dataset 1 — email body/subject) ──
from sklearn.feature_extraction.text import TfidfVectorizer

# ── Preprocessing ─────────────────────────────────────────
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.pipeline import Pipeline

# ── Train-test split ──────────────────────────────────────
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold

# ── Models ────────────────────────────────────────────────
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC

# ── Evaluation metrics ────────────────────────────────────
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_auc_score,
    roc_curve
)

# ── Model saving ──────────────────────────────────────────
import joblib

# ── Display settings ──────────────────────────────────────
pd.set_option('display.max_columns', 50)
pd.set_option('display.max_colwidth', 100)
sns.set_theme(style='whitegrid')

print("All imports successful")
print(f"Pandas version   : {pd.__version__}")
print(f"NumPy version    : {np.__version__}")
print(f"Joblib version   : {joblib.__version__}")
