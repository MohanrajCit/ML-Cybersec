🔐 CVE Risk Prediction System

Early Risk Assessment for Newly Disclosed Vulnerabilities

📌 Overview

The CVE Risk Prediction System is a machine-learning–based decision support tool designed to estimate the risk level of newly published software vulnerabilities at an early stage, when official severity metrics such as CVSS scores, patches, or exploit details may not yet be available.

The system analyzes only the textual vulnerability description and predicts the likely risk level (LOW / MEDIUM / HIGH) along with a confidence score.
It also includes real-time CVE ingestion and anomaly detection to flag unusual or previously unseen vulnerability patterns.

This project is intended to assist security teams, not replace official scoring systems or human experts.

🚨 Problem Statement

When a new vulnerability (CVE) is disclosed:

CVSS scores are often delayed

Patches may not exist yet

Impact details can be unclear or incomplete

Security teams must still decide:

Should this vulnerability be prioritized immediately?

Is emergency mitigation required?

This time gap between disclosure and full analysis creates risk.

💡 Solution

This system provides an early-stage risk estimation by:

Analyzing historical CVE descriptions

Learning textual patterns associated with severity

Predicting risk before official CVSS updates are published

It enables faster triage and prioritization of vulnerabilities during the critical early window.

✨ Key Features
🔹 1. Risk Prediction from Text

Input: Vulnerability description (manual or real-time)

Output:

Risk Level: LOW / MEDIUM / HIGH

Confidence Score (%)

Uses TF-IDF + Random Forest

🔹 2. Real-Time CVE Fetching

Fetches newly published CVEs using the official NVD REST API

Processes vulnerabilities immediately after disclosure

Does not rely on CVSS, exploit, or patch data

🔹 3. Anomaly Detection

Uses Isolation Forest

Flags descriptions that significantly deviate from known CVE patterns

Helps identify:

Unusual attack vectors

Novel vulnerability descriptions

⚠️ Does not claim zero-day detection

🔹 4. Manual Analysis Mode

Users can paste any vulnerability description

Useful for:

Security researchers

SOC analysts

Academic evaluation

Demo & testing

🔹 5. Confidence & Explainability

Every prediction includes a confidence score

Helps users understand model certainty

Encourages human validation

🧠 Machine Learning Approach
Component	Technique
Text Representation	TF-IDF
Risk Classification	Random Forest
Anomaly Detection	Isolation Forest
Training Data	Historical CVE descriptions
Accuracy	~83% (text-only prediction)

The model is trained once and never retrained during real-time processing.

🏗️ System Architecture
CVE Source (NVD API / Manual Input)
            ↓
   Text Preprocessing
            ↓
     TF-IDF Vectorizer
            ↓
  ┌───────────────┐
  │ Risk Classifier│ → LOW / MEDIUM / HIGH + Confidence
  └───────────────┘
            ↓
   Anomaly Detector
            ↓
     Final Analysis Output

🖥️ Modes of Operation
1️⃣ Manual Description Analysis

Paste vulnerability text

Get instant risk + anomaly result

2️⃣ Real-Time NVD Analysis

Fetches latest CVEs from NVD

Predicts risk before CVSS updates

3️⃣ Quick Demo Mode

Built-in test cases

Validates model loading and pipeline integrity

📊 Sample Output
{
  "cve_id": "CVE-2025-68939",
  "risk": "HIGH",
  "confidence": 0.68,
  "anomalous": false
}

⚠️ Limitations (Important)

Uses only textual descriptions

Does not replace CVSS

Does not detect exploits or zero-days

Predictions should be used as decision support, not final judgment

Honesty about limitations increases trust and credibility.

🎯 Use Cases

SOC teams prioritizing new vulnerabilities

Organizations without immediate CVSS access

Vulnerability research & analysis

Academic and learning purposes

Security dashboards and monitoring tools

🚀 Future Enhancements

Deep learning models (BERT / SBERT)

Explainable AI (keyword importance)

CVSS score range prediction

Integration with SIEM / SOAR tools

Web-based interactive dashboard

🛠️ Tech Stack

Python

scikit-learn

TF-IDF

Random Forest

Isolation Forest

NVD REST API

FastAPI (backend)

React + Tailwind CSS (frontend)
