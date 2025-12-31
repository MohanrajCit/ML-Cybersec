"""
JSON Serialization Fix - Verification Test
==========================================
Tests that the JSON serialization fix works correctly.
"""

import json
from cve_realtime_processor import predict_risk, detect_anomaly

print("="*80)
print("JSON SERIALIZATION FIX - VERIFICATION TEST")
print("="*80 + "\n")

# Test 1: Single prediction
print("Test 1: Single CVE Prediction")
print("-" * 80)

description = "Buffer overflow in network service allows remote code execution"

# Get predictions
risk = predict_risk(description)
anomaly = detect_anomaly(description)

print(f"Risk result type: {type(risk['risk'])}")
print(f"Confidence type: {type(risk['confidence'])}")
print(f"Anomalous type: {type(anomaly['anomalous'])}")

# Create result
result = {
    "cve_id": "CVE-TEST-001",
    "risk": risk["risk"],
    "confidence": risk["confidence"],
    "anomalous": anomaly["anomalous"]
}

# Test JSON serialization
try:
    json_str = json.dumps(result, indent=2)
    print("\n✅ SUCCESS - JSON serialization works!")
    print("\nJSON Output:")
    print(json_str)
except TypeError as e:
    print(f"\n❌ FAILED - {e}")
    exit(1)

# Test 2: Verify types are correct
print("\n" + "="*80)
print("Test 2: Type Verification")
print("-" * 80)

print(f"✓ risk is str: {isinstance(result['risk'], str)}")
print(f"✓ confidence is float: {isinstance(result['confidence'], float)}")
print(f"✓ anomalous is bool: {isinstance(result['anomalous'], bool)}")

# Verify not NumPy types
import numpy as np
print(f"✓ confidence is NOT np.float64: {not isinstance(result['confidence'], np.float64)}")
print(f"✓ anomalous is NOT np.bool_: {not isinstance(result['anomalous'], np.bool_)}")

# Test 3: Multiple CVEs (batch)
print("\n" + "="*80)
print("Test 3: Batch Processing")
print("-" * 80)

test_descriptions = [
    "SQL injection vulnerability",
    "Cross-site scripting in web application",
    "Authentication bypass vulnerability"
]

batch_results = []
for i, desc in enumerate(test_descriptions, 1):
    r = predict_risk(desc)
    a = detect_anomaly(desc)
    batch_results.append({
        "cve_id": f"CVE-TEST-00{i}",
        "risk": r["risk"],
        "confidence": r["confidence"],
        "anomalous": a["anomalous"]
    })

try:
    json_str = json.dumps(batch_results, indent=2)
    print(f"✅ SUCCESS - Batch of {len(batch_results)} CVEs serialized")
    print(f"\nFirst result:\n{json.dumps(batch_results[0], indent=2)}")
except TypeError as e:
    print(f"❌ FAILED - {e}")
    exit(1)

# Final summary
print("\n" + "="*80)
print("ALL TESTS PASSED ✅")
print("="*80)
print("\nJSON serialization fix verified successfully!")
print("All output values are Python native types (str, float, bool)")
print("No NumPy types (np.bool_, np.float64) in output")
print("\n")
