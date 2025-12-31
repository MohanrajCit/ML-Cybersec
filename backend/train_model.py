import pandas as pd
import numpy as np
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

# -----------------------------
# 1. Load dataset
# -----------------------------
df = pd.read_csv("cve_data.csv", engine="python", on_bad_lines="skip")

print("\n📌 Available columns:")
print(df.columns)

# -----------------------------
# 2. Use correct columns
# -----------------------------
TEXT_COL = "Description"
SCORE_COL = "CVSS Score"

# Drop missing values
df = df[df[TEXT_COL].notnull() & df[SCORE_COL].notnull()]

# -----------------------------
# 3. Create labels using CVSS
# -----------------------------
df["label"] = df[SCORE_COL].apply(lambda x: 1 if float(x) >= 7.0 else 0)

# -----------------------------
# 4. TF-IDF Vectorization
# -----------------------------
tfidf = TfidfVectorizer(
    max_features=1000,
    stop_words="english"
)

X = tfidf.fit_transform(df[TEXT_COL])
y = df["label"]

# -----------------------------
# 5. Train-test split
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# -----------------------------
# 6. Train model
# -----------------------------
clf = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)
clf.fit(X_train, y_train)

# -----------------------------
# 7. Evaluation
# -----------------------------
y_pred = clf.predict(X_test)
print("\n📊 Classification Report:\n")
print(classification_report(y_test, y_pred))

# -----------------------------
# 8. Save model & vectorizer
# -----------------------------
joblib.dump(clf, "rf_model.pkl")
joblib.dump(tfidf, "tfidf_vectorizer.pkl")

print("\n✅ Model saved as rf_model.pkl")
print("✅ TF-IDF vectorizer saved as tfidf_vectorizer.pkl")
print("🚀 Training completed successfully")

