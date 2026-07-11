"""
CVE Real-time Processing Module
================================
Extends existing CVE risk prediction system with:
1. Real-time NVD API ingestion
2. Anomaly detection layer

Constraints:
- Uses ONLY vectorizer.transform() (no retraining)
- Does NOT modify trained RF classifier
- Does NOT detect zero-day attacks
- Anomaly detection flags deviations from historical CVE patterns
"""

import os
import json
import logging
import joblib
import requests
import random
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple

# Load environment variables from .env file
try:
    from env_setup import load_env_file
    load_env_file()
except ImportError:
    # env_setup not available, continue without it
    pass
except Exception as e:
    logging.warning(f"Could not load .env file: {e}")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

import numpy as np

# --- Constants ---
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MODEL_PATH = "rf_model.pkl"
VECTORIZER_PATH = "tfidf_vectorizer.pkl"
ANOMALY_MODEL_PATH = "anomaly_model.pkl"
CVSS_MODEL_PATH = "cvss_regressor.pkl"
CSV_DATA_PATH = "cve_data.csv"  # Local fallback data

# --- Global Model Instances ---
# Loaded once at module import
try:
    clf = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)
    anomaly_clf = joblib.load(ANOMALY_MODEL_PATH)
    logger.info("✓ Core models loaded successfully")
except FileNotFoundError as e:
    logger.error(f"✗ Model file not found: {e}")
    clf, vectorizer, anomaly_clf = None, None, None
except Exception as e:
    logger.error(f"✗ Error loading models: {e}")
    clf, vectorizer, anomaly_clf = None, None, None

# CVSS regression model (optional — system works without it)
try:
    cvss_regressor = joblib.load(CVSS_MODEL_PATH)
    logger.info("✓ CVSS regression model loaded")
except FileNotFoundError:
    logger.warning("⚠ CVSS regressor not found — run train_cvss_model.py to enable score prediction")
    cvss_regressor = None
except Exception as e:
    logger.warning(f"⚠ Error loading CVSS regressor: {e}")
    cvss_regressor = None


def get_fallback_cves_from_csv(max_results: int = 20) -> List[Dict[str, str]]:
    """
    Get sample CVEs from local CSV file as fallback when NVD API is unavailable.
    
    This function is used when the NVD API is unreachable (network/DNS issues)
    to provide the application with data to process instead of returning errors.
    
    Args:
        max_results (int): Maximum number of CVEs to return
    
    Returns:
        list: Sample CVE data with cve_id and description
    """
    try:
        if not os.path.exists(CSV_DATA_PATH):
            logger.warning(f"Fallback CSV not found: {CSV_DATA_PATH}")
            return []
        
        df = pd.read_csv(CSV_DATA_PATH)
        
        # Ensure required columns exist
        if 'CVE ID' not in df.columns or 'Description' not in df.columns:
            logger.warning("CSV missing required columns (CVE ID, Description)")
            return []
        
        # Filter out rows with empty descriptions
        df = df[df['Description'].notna() & (df['Description'].str.len() > 20)]
        
        # Sample random CVEs (or take first N if not enough)
        sample_size = min(max_results, len(df))
        if sample_size == 0:
            return []
        
        sampled_df = df.sample(n=sample_size, random_state=None)
        
        fallback_cves = [
            {
                "cve_id": str(row["CVE ID"]),
                "description": str(row["Description"])
            }
            for _, row in sampled_df.iterrows()
        ]
        
        logger.info(f"✓ Using {len(fallback_cves)} CVEs from local fallback data")
        return fallback_cves
        
    except Exception as e:
        logger.error(f"✗ Error reading fallback CSV: {e}")
        return []

def predict_risk(description: str) -> Dict[str, any]:
    """
    Predict CVE risk from description text with three-level classification.
    
    Uses pre-trained binary TF-IDF vectorizer and Random Forest classifier.
    Applies keyword-based severity boosting to improve MEDIUM classification accuracy.
    
    Maps prediction probabilities to three risk levels:
    - HIGH:   probability >= 0.70 (high certainty of critical risk)
    - MEDIUM: probability 0.35-0.69 (moderate/uncertain risk level)
    - LOW:    probability < 0.35 (low risk/benign)
    
    DOES NOT retrain or modify models.
    
    Args:
        description (str): CVE vulnerability description text
    
    Returns:
        dict: {
            "risk": "HIGH" | "MEDIUM" | "LOW",
            "confidence": float (0.0 to 1.0),
            "prediction_class": int (1=HIGH, 0=LOW from original binary model),
            "boosted": bool (True if keyword boost was applied)
        }
    
    Raises:
        ValueError: If models are not loaded
    """
    if not clf or not vectorizer:
        raise ValueError("Models not loaded. Cannot perform prediction.")
    
    # Transform input using pre-trained vectorizer (NO retraining)
    X_transformed = vectorizer.transform([description])
    
    # Predict using trained binary classifier (NO modification)
    prediction_class = clf.predict(X_transformed)[0]
    probabilities = clf.predict_proba(X_transformed)[0]
    
    # Get probability of HIGH risk class (class 1)
    # For binary classifier: probabilities[0] = P(LOW), probabilities[1] = P(HIGH)
    high_risk_probability = float(probabilities[1])
    
    # --- Keyword-Based Severity Boosting ---
    # Boost probability for MEDIUM-severity patterns that the binary model underestimates
    # These keywords indicate vulnerabilities typically rated CVSS 4.0-6.9
    desc_lower = description.lower()
    
    # High-impact security keywords that warrant at least MEDIUM classification
    medium_severity_keywords = [
        # Access control issues (CVSS 4.0-6.9 typically)
        'insecure direct object reference', 'idor',
        'missing capability check', 'capability check',
        'insufficient permission', 'permission check',
        'authorization bypass', 'authentication bypass',
        'access control', 'broken access control',
        
        # Cross-site scripting (CVSS 4.0-6.9 for most XSS)
        'cross-site scripting', 'xss', 'stored xss', 'reflected xss',
        'script injection', 'inject scripts', 'html injection',
        'insufficient input sanitization', 'input sanitization',
        
        # Cross-site request forgery
        'cross-site request forgery', 'csrf', 'xsrf',
        
        # Data exposure issues
        'unauthorized access', 'unauthorized modification',
        'disclosure of sensitive', 'information disclosure',
        'api key', 'sensitive data', 'credential',
        
        # Privilege-related issues
        'privilege escalation', 'elevated privilege',
        'subscriber level', 'contributor level', 'author level',
        'authenticated attacker',
        
        # Path traversal / file issues
        'path traversal', 'directory traversal', 'local file inclusion',
        'file upload', 'arbitrary file', 'file read', 'file write',
        
        # Common WordPress/plugin vulnerability patterns
        'modify acf fields', 'modify posts', 'modify user',
        'edit_posts', 'edit_post', 'manage_options',
        'rest api', 'ajax action',
    ]
    
    # Higher severity keywords that warrant HIGH classification
    # These should ONLY boost to HIGH when combined with 'unauthenticated' context
    high_severity_keywords = [
        'remote code execution', 'rce', 'arbitrary code execution',
        'root access', 'full control', 'complete takeover',
        'zero-day', '0-day', 'critical vulnerability',
    ]
    
    # Keywords that are HIGH only when UNAUTHENTICATED
    conditional_high_keywords = [
        'sql injection', 'command injection', 'code injection',
        'arbitrary code', 'execute code', 'execute commands',
    ]
    
    # Check if vulnerability is unauthenticated (much more severe)
    is_unauthenticated = any(term in desc_lower for term in [
        'unauthenticated', 'without authentication', 'no authentication',
        'anonymous', 'pre-auth', 'before authentication'
    ])
    
    # Check if explicitly authenticated (less severe)
    is_authenticated = any(term in desc_lower for term in [
        'authenticated attacker', 'authenticated user',
        'subscriber level', 'contributor level', 'author level', 'editor level',
        'admin user', 'logged-in user', 'with subscriber', 'with contributor',
        'requires authentication', 'must be authenticated'
    ])
    
    boost_applied = False
    boost_amount = 0.0
    
    # HIGH severity: unauthenticated + dangerous keywords = definitely HIGH
    if is_unauthenticated and not is_authenticated:
        # Check for high-severity keywords
        for keyword in high_severity_keywords:
            if keyword in desc_lower:
                boost_amount = 0.40  # Strong boost to HIGH
                boost_applied = True
                break
        
        # Check for conditional high keywords (only HIGH when unauthenticated)
        if not boost_applied:
            for keyword in conditional_high_keywords:
                if keyword in desc_lower:
                    boost_amount = 0.35  # Boost to HIGH
                    boost_applied = True
                    break
    
    # Check for unconditional HIGH keywords (always HIGH regardless of auth)
    if not boost_applied:
        for keyword in ['remote code execution', 'rce', 'root access', 'full control', 'zero-day', '0-day']:
            if keyword in desc_lower and is_unauthenticated:
                boost_amount = 0.40
                boost_applied = True
                break
    
    # MEDIUM severity: authenticated vulnerabilities with dangerous patterns
    if not boost_applied:
        keyword_matches = sum(1 for kw in medium_severity_keywords if kw in desc_lower)
        
        # Also count conditional high keywords as MEDIUM evidence when authenticated
        if is_authenticated:
            for kw in conditional_high_keywords:
                if kw in desc_lower:
                    keyword_matches += 1
        
        if keyword_matches >= 4:
            boost_amount = 0.25  # Strong evidence of MEDIUM
            boost_applied = True
        elif keyword_matches >= 2:
            boost_amount = 0.18  # Moderate evidence of MEDIUM
            boost_applied = True
        elif keyword_matches >= 1:
            boost_amount = 0.10  # Some evidence of MEDIUM
            boost_applied = True
    
    # --- LOW Severity Detection ---
    # Keywords that indicate minimal impact (CVSS 0.1-3.9)
    # Apply negative boost to keep these as LOW
    low_severity_keywords = [
        'minor', 'non-sensitive', 'debug information', 'debug mode',
        'version number', 'version disclosure', 'http headers',
        'verbose error', 'error message', 'warning message',
        'edge case', 'specific conditions', 'certain conditions',
        'configuration issue', 'config issue', 'typo',
        'low impact', 'minimal impact', 'limited impact',
        'informational', 'cosmetic', 'display issue',
    ]
    
    # Check for LOW severity indicators (only if no MEDIUM/HIGH keywords found)
    if not boost_applied:
        low_matches = sum(1 for kw in low_severity_keywords if kw in desc_lower)
        if low_matches >= 2:
            boost_amount = -0.15  # Strong evidence of LOW - reduce probability
        elif low_matches >= 1:
            boost_amount = -0.08  # Some evidence of LOW
    
    # Apply boost (capped at 0.85 to avoid overconfidence, min 0 to avoid negative)
    boosted_probability = max(0, min(high_risk_probability + boost_amount, 0.85))
    
    # --- Three-Level Risk Mapping ---
    # Industry standard CVSS v3.0 Ratings:
    # LOW: 0.0 - 3.9
    # MEDIUM: 4.0 - 6.9
    # HIGH: 7.0 - 10.0 (combines High and Critical)
    
    cvss_score = predict_cvss_score(description)
    
    if cvss_score is not None:
        if cvss_score >= 7.0:
            risk_level = "HIGH"
            confidence = boosted_probability
        elif cvss_score >= 4.0:
            risk_level = "MEDIUM"
            confidence = boosted_probability
        else:
            risk_level = "LOW"
            # Invert confidence for LOW risk as before
            confidence = 1.0 - boosted_probability
    else:
        # Fallback to model probability if CVSS regressor is not loaded
        if boosted_probability >= 0.70:
            risk_level = "HIGH"
            confidence = boosted_probability
        elif boosted_probability >= 0.35:
            risk_level = "MEDIUM"
            confidence = boosted_probability
        else:
            risk_level = "LOW"
            confidence = 1.0 - boosted_probability
    
    return {
        "risk": risk_level,
        "confidence": confidence,
        "prediction_class": int(prediction_class),
        "boosted": boost_applied

    }


def detect_anomaly(description: str) -> Dict[str, any]:
    """
    Detect anomalous vulnerability patterns using Isolation Forest.
    
    Uses the same TF-IDF vectorizer as risk prediction.
    Flags deviations from historical CVE patterns.
    
    DOES NOT:
    - Detect zero-day attacks
    - Mix anomaly score with risk probability
    - Retrain the vectorizer
    
    Args:
        description (str): CVE vulnerability description text
    
    Returns:
        dict: {
            "anomalous": bool (True if anomalous),
            "anomaly_score": float (lower = more anomalous),
            "threshold_info": str
        }
    
    Raises:
        ValueError: If anomaly model is not loaded
    """
    if not anomaly_clf or not vectorizer:
        raise ValueError("Anomaly model or vectorizer not loaded.")
    
    # Transform using same vectorizer (NO retraining)
    X_transformed = vectorizer.transform([description])
    
    # Predict anomaly: -1 = anomalous, 1 = normal
    anomaly_prediction = anomaly_clf.predict(X_transformed)[0]
    anomaly_score = float(anomaly_clf.decision_function(X_transformed)[0])
    
    # Convert NumPy bool to Python bool for JSON serialization
    # scikit-learn returns np.bool_ which is not JSON serializable
    is_anomalous = bool(anomaly_prediction == -1)
    
    # Provide context
    threshold_info = "outside historical CVE patterns" if is_anomalous else "within normal patterns"
    
    return {
        "anomalous": is_anomalous,  # Now a native Python bool (JSON-safe)
        "anomaly_score": anomaly_score,  # Already converted to float above
        "threshold_info": threshold_info
    }

def predict_cvss_score(description: str) -> Optional[float]:
    """
    Predict the actual CVSS score (0.0–10.0) for a CVE description.

    Uses a Gradient Boosting Regressor trained on historical CVSS data.
    Returns None if the CVSS model is not loaded.

    Args:
        description: CVE vulnerability description text

    Returns:
        Predicted CVSS score clamped to [0.0, 10.0], or None
    """
    if cvss_regressor is None or vectorizer is None:
        return None

    X = vectorizer.transform([description])
    score = float(cvss_regressor.predict(X)[0])
    return round(max(0.0, min(10.0, score)), 1)


def explain_prediction(description: str) -> Dict:
    """
    Generate an explainability report for a prediction.

    Extracts:
      - Top TF-IDF features that contributed to the prediction
      - Keyword severity boosts that were applied
      - Authentication context detected
      - Model probability breakdown

    Args:
        description: CVE vulnerability description text

    Returns:
        dict with explainability data
    """
    if not clf or not vectorizer:
        raise ValueError("Models not loaded.")

    # --- TF-IDF Feature Analysis ---
    X = vectorizer.transform([description])
    feature_names = vectorizer.get_feature_names_out()
    rf_importances = clf.feature_importances_

    nonzero_indices = X[0].nonzero()[1]
    term_contributions = []
    for idx in nonzero_indices:
        tfidf_w = float(X[0, idx])
        rf_imp = float(rf_importances[idx])
        contribution = tfidf_w * rf_imp
        term_contributions.append({
            "term": str(feature_names[idx]),
            "tfidf_weight": round(tfidf_w, 4),
            "model_importance": round(rf_imp, 6),
            "contribution": round(contribution, 6),
        })

    term_contributions.sort(key=lambda x: x["contribution"], reverse=True)
    top_features = term_contributions[:10]

    # --- Model Probability ---
    probabilities = clf.predict_proba(X)[0]
    base_probability = float(probabilities[1])

    # --- Keyword Boost Analysis ---
    desc_lower = description.lower()

    matched_keywords = []
    critical_kws = [
        'remote code execution', 'rce', 'arbitrary code execution',
        'root access', 'full control', 'complete takeover', 'zero-day', '0-day',
    ]
    dangerous_kws = [
        'sql injection', 'command injection', 'code injection',
        'arbitrary code', 'execute code', 'execute commands',
    ]
    medium_kws = [
        'cross-site scripting', 'xss', 'csrf', 'cross-site request forgery',
        'path traversal', 'directory traversal', 'privilege escalation',
        'information disclosure', 'unauthorized access', 'file upload',
        'authentication bypass', 'authorization bypass',
    ]

    for kw in critical_kws:
        if kw in desc_lower:
            matched_keywords.append({"keyword": kw, "category": "critical", "boost": "+0.40"})
    for kw in dangerous_kws:
        if kw in desc_lower:
            matched_keywords.append({"keyword": kw, "category": "dangerous", "boost": "+0.35"})
    for kw in medium_kws:
        if kw in desc_lower:
            matched_keywords.append({"keyword": kw, "category": "medium", "boost": "+0.10 to +0.25"})

    # --- Auth Context ---
    is_unauth = any(t in desc_lower for t in [
        'unauthenticated', 'without authentication', 'no authentication',
        'anonymous', 'pre-auth',
    ])
    is_auth = any(t in desc_lower for t in [
        'authenticated attacker', 'authenticated user',
        'subscriber level', 'contributor level', 'requires authentication',
    ])
    auth_context = "unauthenticated" if is_unauth else ("authenticated" if is_auth else "not specified")

    # --- Run the actual prediction for final values ---
    risk_result = predict_risk(description)

    return {
        "top_features": top_features,
        "keyword_matches": matched_keywords,
        "auth_context": auth_context,
        "base_probability": round(base_probability, 4),
        "boost_applied": risk_result["boosted"],
        "final_risk": risk_result["risk"],
        "final_confidence": round(risk_result["confidence"], 4),
    }


def fetch_cves_from_nvd(
    days_back: int = 7,
    max_results: int = 20,
    api_key: Optional[str] = None
) -> List[Dict[str, str]]:
    """
    Fetch recently published CVEs from NVD REST API (JSON v2.0).
    
    Args:
        days_back (int): Number of days to look back (default: 7)
        max_results (int): Maximum CVEs to fetch (default: 20)
        api_key (str, optional): NVD API key from environment or parameter
    
    Returns:
        list: [
            {
                "cve_id": "CVE-XXXX-YYYY",
                "description": "English description text"
            },
            ...
        ]
    
    Raises:
        requests.RequestException: If API request fails
    """
    # Get API key from environment if not provided
    if api_key is None:
        api_key = os.getenv("NVD_API_KEY")
        if not api_key:
            logger.warning("NVD_API_KEY not found in environment. Proceeding without API key (rate limited).")
    
    # Calculate date range
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days_back)
    
    # NVD API expects ISO 8601 format with milliseconds
    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": max_results
    }
    
    # Add API key header if available (increases rate limit)
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    
    logger.info(f"Fetching CVEs from {start_date.date()} to {end_date.date()}...")
    
    try:
        response = requests.get(
            NVD_API_URL,
            params=params,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()
        data = response.json()
        
        # Extract CVE data
        cve_items = data.get("vulnerabilities", [])
        extracted_cves = []
        
        for item in cve_items:
            cve_obj = item.get("cve", {})
            cve_id = cve_obj.get("id", "Unknown")
            
            # Extract English description
            descriptions = cve_obj.get("descriptions", [])
            desc_text = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                None
            )
            
            if desc_text:
                extracted_cves.append({
                    "cve_id": cve_id,
                    "description": desc_text
                })
            else:
                logger.warning(f"No English description found for {cve_id}")
        
        logger.info(f"✓ Fetched {len(extracted_cves)} CVEs successfully")
        return extracted_cves
    
    except requests.RequestException as e:
        logger.error(f"✗ Error fetching from NVD API: {e}")
        logger.info("Attempting to use local fallback data...")
        
        # Use fallback data from local CSV instead of raising error
        fallback_cves = get_fallback_cves_from_csv(max_results)
        if fallback_cves:
            logger.warning("⚠ Using cached/sample CVEs due to API unavailability")
            return fallback_cves
        
        # Only raise if fallback also fails
        raise


def process_new_cves(
    days_back: int = 7,
    max_results: int = 20,
    api_key: Optional[str] = None
) -> List[Dict[str, any]]:
    """
    End-to-end pipeline: Fetch CVEs from NVD and predict risk + anomaly.
    
    For each CVE:
    1. Fetch from NVD API
    2. Extract description
    3. Predict risk using predict_risk()
    4. Detect anomaly using detect_anomaly()
    5. Return structured JSON
    
    Args:
        days_back (int): Number of days to look back
        max_results (int): Maximum CVEs to process
        api_key (str, optional): NVD API key
    
    Returns:
        list: [
            {
                "cve_id": "CVE-XXXX-YYYY",
                "risk": "HIGH" | "MEDIUM" | "LOW",
                "confidence": float,
                "anomalous": bool
            },
            ...
        ]
    
    Raises:
        Exception: If fetching or prediction fails
    """
    logger.info("=== Starting CVE Real-time Processing ===")
    
    # Step 1: Fetch CVEs from NVD
    try:
        cves = fetch_cves_from_nvd(
            days_back=days_back,
            max_results=max_results,
            api_key=api_key
        )
    except Exception as e:
        logger.error(f"Failed to fetch CVEs: {e}")
        raise
    
    if not cves:
        logger.warning("No CVEs fetched. Returning empty results.")
        return []
    
    # Step 2: Process each CVE
    results = []
    for idx, cve in enumerate(cves, 1):
        cve_id = cve["cve_id"]
        description = cve["description"]
        
        logger.info(f"[{idx}/{len(cves)}] Processing {cve_id}...")
        
        try:
            # Predict risk
            risk_result = predict_risk(description)
            
            # Detect anomaly
            anomaly_result = detect_anomaly(description)
            
            # Combine results with explicit type conversions for JSON safety
            # Ensures no NumPy types (np.bool_, np.float64, np.int64) leak through
            output = {
                "cve_id": str(cve_id),  # Ensure string (usually already is)
                "risk": str(risk_result["risk"]),  # Ensure string
                "confidence": float(risk_result["confidence"]),  # Ensure native Python float
                "anomalous": bool(anomaly_result["anomalous"])  # Ensure native Python bool
            }
            
            results.append(output)
            
            logger.info(
                f"  → Risk: {risk_result['risk']} "
                f"(confidence: {risk_result['confidence']:.2%}), "
                f"Anomalous: {anomaly_result['anomalous']}"
            )
        
        except Exception as e:
            logger.error(f"  ✗ Error processing {cve_id}: {e}")
            # Continue processing other CVEs
            continue
    
    logger.info(f"=== Completed: {len(results)}/{len(cves)} CVEs processed ===")
    return results


# --- Utility Functions ---

def save_results_to_json(results: List[Dict], filename: str = "cve_predictions.json"):
    """
    Save prediction results to JSON file.
    
    Args:
        results (list): List of prediction dictionaries
        filename (str): Output filename
    """
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        logger.info(f"✓ Results saved to {filename}")
    except Exception as e:
        logger.error(f"✗ Error saving results: {e}")


def print_results_summary(results: List[Dict]):
    """
    Print a formatted summary of prediction results.
    
    Args:
        results (list): List of prediction dictionaries
    """
    if not results:
        print("\n⚠️  No results to display.\n")
        return
    
    print("\n" + "="*80)
    print(f"CVE RISK PREDICTION SUMMARY ({len(results)} CVEs)")
    print("="*80)
    
    high_risk_count = sum(1 for r in results if r["risk"] == "HIGH")
    medium_risk_count = sum(1 for r in results if r["risk"] == "MEDIUM")
    low_risk_count = sum(1 for r in results if r["risk"] == "LOW")
    anomalous_count = sum(1 for r in results if r["anomalous"])
    
    print(f"\n📊 Statistics:")
    print(f"   HIGH Risk:    {high_risk_count}")
    print(f"   MEDIUM Risk:  {medium_risk_count}")
    print(f"   LOW Risk:     {low_risk_count}")
    print(f"   Anomalous:    {anomalous_count}")
    
    print(f"\n📋 Detailed Results:")
    print("-" * 80)
    
    for idx, result in enumerate(results, 1):
        # Risk level icons
        if result["risk"] == "HIGH":
            risk_icon = "🚨"
        elif result["risk"] == "MEDIUM":
            risk_icon = "⚠️ "
        else:
            risk_icon = "✅"
        
        anomaly_icon = "⚠️" if result["anomalous"] else "  "
        
        print(
            f"{idx:2}. {risk_icon} {result['cve_id']:20} | "
            f"Risk: {result['risk']:6} ({result['confidence']:.1%}) | "
            f"{anomaly_icon} {'ANOMALOUS' if result['anomalous'] else 'NORMAL'}"
        )
    
    print("="*80 + "\n")


# --- Main Execution ---

if __name__ == "__main__":
    """
    Example usage demonstrating the complete pipeline.
    """
    print("\n🔥 CVE Real-time Risk Prediction System")
    print("="*80 + "\n")
    
    # Read API key from environment
    api_key = os.getenv("NVD_API_KEY")
    if not api_key:
        print("⚠️  Warning: NVD_API_KEY not set. API requests will be rate-limited.")
        print("   Set it using: export NVD_API_KEY='your-key-here'\n")
    
    # Process recent CVEs
    try:
        results = process_new_cves(
            days_back=7,
            max_results=15,
            api_key=api_key
        )
        
        # Display results
        print_results_summary(results)
        
        # Save to JSON
        save_results_to_json(results)
        
    except Exception as e:
        logger.error(f"Pipeline failed: {e}")
        print(f"\n❌ Error: {e}\n")
