"""
CVSS Score Regression Model Training
=====================================
Trains a Gradient Boosting Regressor to predict actual CVSS scores (0.0–10.0)
from CVE description text using the pre-trained TF-IDF vectorizer.

Prerequisites:
    - cve_data.csv must exist
    - tfidf_vectorizer.pkl must exist (run train_model.py first)

Output:
    - cvss_regressor.pkl (~1–3 MB)
"""

import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import GradientBoostingRegressor
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
from sklearn.model_selection import train_test_split

# -------------------------------------------------------------------
# 1. Load dataset
# -------------------------------------------------------------------
print("Loading data...")
df = pd.read_csv("cve_data.csv", engine="python", on_bad_lines="skip")

TEXT_COL = "Description"
SCORE_COL = "CVSS Score"

# Drop missing / non-numeric
df = df[df[TEXT_COL].notnull() & df[SCORE_COL].notnull()]
df[SCORE_COL] = pd.to_numeric(df[SCORE_COL], errors="coerce")
df = df.dropna(subset=[SCORE_COL])

print(f"Dataset size : {len(df)} samples")
print(f"CVSS range   : {df[SCORE_COL].min():.1f} – {df[SCORE_COL].max():.1f}")
print(f"CVSS mean    : {df[SCORE_COL].mean():.2f}")

# -------------------------------------------------------------------
# 2. Load pre-trained TF-IDF vectorizer (same one used by classifier)
# -------------------------------------------------------------------
print("\nLoading TF-IDF vectorizer...")
try:
    tfidf = joblib.load("tfidf_vectorizer.pkl")
except FileNotFoundError:
    print("Error: tfidf_vectorizer.pkl not found. Run train_model.py first.")
    exit(1)

# -------------------------------------------------------------------
# 3. Transform descriptions (NO retraining of vectorizer)
# -------------------------------------------------------------------
print("Transforming descriptions...")
X = tfidf.transform(df[TEXT_COL])
y = df[SCORE_COL].values

# -------------------------------------------------------------------
# 4. Train/test split
# -------------------------------------------------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)
print(f"Train: {X_train.shape[0]}  |  Test: {X_test.shape[0]}")

# -------------------------------------------------------------------
# 5. Train Gradient Boosting Regressor
# -------------------------------------------------------------------
print("\nTraining Gradient Boosting Regressor...")
gbr = GradientBoostingRegressor(
    n_estimators=200,
    max_depth=5,
    learning_rate=0.1,
    min_samples_split=10,
    min_samples_leaf=5,
    subsample=0.8,
    random_state=42,
)
gbr.fit(X_train, y_train)

# -------------------------------------------------------------------
# 6. Evaluate
# -------------------------------------------------------------------
y_pred = gbr.predict(X_test)
y_pred = np.clip(y_pred, 0.0, 10.0)  # Clamp to valid CVSS range

mae  = mean_absolute_error(y_test, y_pred)
rmse = np.sqrt(mean_squared_error(y_test, y_pred))
r2   = r2_score(y_test, y_pred)

print(f"\n{'Regression Metrics':^30}")
print("-" * 30)
print(f"  MAE  : {mae:.3f}  (avg error in CVSS points)")
print(f"  RMSE : {rmse:.3f}")
print(f"  R2   : {r2:.3f}")

# -------------------------------------------------------------------
# 7. Save model
# -------------------------------------------------------------------
joblib.dump(gbr, "cvss_regressor.pkl")
print(f"\nModel saved as cvss_regressor.pkl")
print("CVSS regression training completed successfully")
