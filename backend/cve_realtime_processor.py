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

# --- Constants ---
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MODEL_PATH = "rf_model.pkl"
VECTORIZER_PATH = "tfidf_vectorizer.pkl"
ANOMALY_MODEL_PATH = "anomaly_model.pkl"

# --- Global Model Instances ---
# Loaded once at module import
try:
    clf = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)
    anomaly_clf = joblib.load(ANOMALY_MODEL_PATH)
    logger.info("✓ Models loaded successfully")
except FileNotFoundError as e:
    logger.error(f"✗ Model file not found: {e}")
    clf, vectorizer, anomaly_clf = None, None, None
except Exception as e:
    logger.error(f"✗ Error loading models: {e}")
    clf, vectorizer, anomaly_clf = None, None, None


def predict_risk(description: str) -> Dict[str, any]:
    """
    Predict CVE risk from description text with three-level classification.
    
    Uses pre-trained binary TF-IDF vectorizer and Random Forest classifier.
    Maps prediction probabilities to three risk levels:
    - HIGH:   probability >= 0.70 (high certainty of critical risk)
    - MEDIUM: probability 0.40-0.69 (moderate/uncertain risk level)
    - LOW:    probability < 0.40 (low risk/benign)
    
    DOES NOT retrain or modify models.
    
    Args:
        description (str): CVE vulnerability description text
    
    Returns:
        dict: {
            "risk": "HIGH" | "MEDIUM" | "LOW",
            "confidence": float (0.0 to 1.0),
            "prediction_class": int (1=HIGH, 0=LOW from original binary model)
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
    
    # --- Three-Level Risk Mapping ---
    # MEDIUM risk represents cases where the model is uncertain or detects moderate threat.
    # This provides a buffer zone between clearly HIGH and clearly LOW risk CVEs.
    if high_risk_probability >= 0.70:
        risk_level = "HIGH"
        confidence = high_risk_probability  # Confidence in HIGH classification
    elif high_risk_probability >= 0.40:
        risk_level = "MEDIUM"
        confidence = high_risk_probability  # Reflects moderate risk probability
    else:
        risk_level = "LOW"
        confidence = 1.0 - high_risk_probability  # Confidence in LOW classification
    
    return {
        "risk": risk_level,
        "confidence": confidence,
        "prediction_class": int(prediction_class)
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
