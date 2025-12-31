"""
JSON Serialization Fix - Code Snippet Summary
==============================================

Problem: "Object of type bool is not JSON serializable"
Root Cause: scikit-learn and NumPy return np.bool_, np.float64, etc.
Solution: Explicit type conversions to Python native types
"""

# ============================================================================
# FIX #1: In detect_anomaly() function
# ============================================================================

# BEFORE (Broken):
is_anomalous = (anomaly_prediction == -1)  # Returns np.bool_

# AFTER (Fixed):
# Convert NumPy bool to Python bool for JSON serialization
# scikit-learn returns np.bool_ which is not JSON serializable
is_anomalous = bool(anomaly_prediction == -1)  # Returns Python bool


# ============================================================================
# FIX #2: In process_new_cves() function
# ============================================================================

# BEFORE (Broken):
output = {
    "cve_id": cve_id,
    "risk": risk_result["risk"],
    "confidence": risk_result["confidence"],  # Might be np.float64
    "anomalous": anomaly_result["anomalous"]  # Might be np.bool_
}

# AFTER (Fixed):
# Combine results with explicit type conversions for JSON safety
# Ensures no NumPy types (np.bool_, np.float64, np.int64) leak through
output = {
    "cve_id": str(cve_id),                          # Ensure string
    "risk": str(risk_result["risk"]),               # Ensure string
    "confidence": float(risk_result["confidence"]), # Ensure Python float
    "anomalous": bool(anomaly_result["anomalous"])  # Ensure Python bool
}


# ============================================================================
# TYPE CONVERSION REFERENCE
# ============================================================================

"""
NumPy Type    →  Python Type  →  Conversion
─────────────────────────────────────────────
np.bool_      →  bool         →  bool(value)
np.float64    →  float        →  float(value)
np.int64      →  int          →  int(value)
np.str_       →  str          →  str(value)
"""


# ============================================================================
# VERIFICATION TEST
# ============================================================================

import json
from cve_realtime_processor import predict_risk, detect_anomaly

# Test data
description = "Buffer overflow allows remote code execution"

# Get predictions
risk = predict_risk(description)
anomaly = detect_anomaly(description)

# Create result (now JSON-safe)
result = {
    "cve_id": "CVE-TEST-001",
    "risk": risk["risk"],
    "confidence": risk["confidence"],    # Already converted to float
    "anomalous": anomaly["anomalous"]    # Already converted to bool
}

# Test JSON serialization
try:
    json_str = json.dumps(result, indent=2)
    print("✅ SUCCESS - JSON serialization works!")
    print(json_str)
except TypeError as e:
    print(f"❌ FAILED - {e}")


# ============================================================================
# EXPECTED OUTPUT
# ============================================================================

"""
✅ SUCCESS - JSON serialization works!
{
  "cve_id": "CVE-TEST-001",
  "risk": "HIGH",
  "confidence": 0.87,
  "anomalous": false
}
"""


# ============================================================================
# KEY TAKEAWAYS
# ============================================================================

"""
1. Always convert NumPy types to Python native types before JSON serialization
2. Use bool(), float(), int(), str() explicitly
3. Conversion is cheap (O(1)) and makes code more robust
4. No impact on model predictions or accuracy
5. Production-safe and future-proof
"""
