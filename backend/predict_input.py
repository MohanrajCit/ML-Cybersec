import joblib

# Load model and vectorizer
clf = joblib.load("rf_model.pkl")
vectorizer = joblib.load("tfidf_vectorizer.pkl")

print("\n🔐 Naan ungal CVE Risk Prediction System\n")

# Get input
description = input("📝 Enter CVE Description:\n")

# Vectorize input
X_new = vectorizer.transform([description])

# Predict class & probability
prediction = clf.predict(X_new)[0]
probability = clf.predict_proba(X_new)[0][prediction]

# Output
if prediction == 1:
    print(f"\n🚨 Prediction: HIGH / CRITICAL RISK")
else:
    print(f"\n✅ Prediction: LOW RISK")

print(f"📊 Confidence: {probability * 100:.2f}%")

