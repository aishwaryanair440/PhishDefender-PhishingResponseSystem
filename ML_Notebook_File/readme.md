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



