# ============================================================
# SECTION 2 — LOAD DATASET
# ============================================================

import os

# ── Confirm exact Kaggle paths ─────────────────────────────
for root, dirs, files in os.walk('/kaggle/input'):
    for file in files:
        print(os.path.join(root, file))
