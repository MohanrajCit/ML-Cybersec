import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest

# 1. Load data
print("Loading data...")
try:
    df = pd.read_csv("cve_data.csv", engine="python", on_bad_lines="skip")
except FileNotFoundError:
    print("Error: cve_data.csv not found.")
    exit(1)

TEXT_COL = "Description"
df = df[df[TEXT_COL].notnull()]

# 2. Load existing Vectorizer
print("Loading vectorizer...")
try:
    tfidf = joblib.load("tfidf_vectorizer.pkl")
except FileNotFoundError:
    print("Error: tfidf_vectorizer.pkl not found. Run train_model.py first.")
    exit(1)

# 3. Transform data
print("Transforming data...")
X = tfidf.transform(df[TEXT_COL])
# Convert to dense array to avoid scipy sparse format compatibility issues
# between scikit-learn 1.3.2 and newer scipy versions
X = X.toarray()

# 4. Train Isolation Forest
print("Training Isolation Forest...")
# contamination=0.05 means ~5% of data is expected to be anomalous
# This provides a good balance between sensitivity and false positives
clf_iso = IsolationForest(n_estimators=100, contamination=0.05, random_state=42, n_jobs=-1)
clf_iso.fit(X)

# 5. Save model
print("Saving anomaly model...")
joblib.dump(clf_iso, "anomaly_model.pkl")
print("Done. Model saved as anomaly_model.pkl")
