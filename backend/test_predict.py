"""
Quick Prediction Test
=====================
Tests the /predict endpoint with a sample CVE description
"""

import requests
import json

BASE_URL = "http://127.0.0.1:8000"

# Sample CVE description for testing
test_description = """
A remote code execution vulnerability exists in the web application framework
that allows an attacker to execute arbitrary code by sending specially crafted
requests to the server endpoint. This vulnerability affects all versions prior
to 3.2.1 and can be exploited without authentication.
"""

def test_prediction():
    """Test the prediction endpoint"""
    print("=" * 80)
    print("TESTING POST /predict ENDPOINT")
    print("=" * 80)
    
    payload = {
        "description": test_description.strip()
    }
    
    print(f"\n📤 Sending request to: {BASE_URL}/predict")
    print(f"📝 Description length: {len(payload['description'])} characters\n")
    
    try:
        response = requests.post(
            f"{BASE_URL}/predict",
            json=payload,
            headers={"Content-Type": "application/json"}
        )
        
        print(f"📊 Status Code: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"\n✅ SUCCESS - Prediction Result:")
            print("=" * 80)
            print(f"Risk Level:      {result['risk']}")
            print(f"Confidence:      {result['confidence']:.2%}")
            print(f"Anomalous:       {result['anomalous']}")
            print(f"Anomaly Score:   {result['anomaly_score']:.4f}")
            print("=" * 80)
            
            # Interpretation
            print(f"\n📋 Interpretation:")
            if result['risk'] == 'HIGH':
                print("   🚨 This CVE is classified as HIGH RISK")
            elif result['risk'] == 'MEDIUM':
                print("   ⚠️  This CVE is classified as MEDIUM RISK")
            else:
                print("   ✅ This CVE is classified as LOW RISK")
            
            if result['anomalous']:
                print("   ⚠️  Pattern deviates from historical CVE descriptions")
            else:
                print("   ✓  Pattern is consistent with historical CVEs")
            
            return True
        else:
            print(f"\n❌ ERROR - Status {response.status_code}")
            print(f"Response: {response.text}")
            return False
    
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        return False

if __name__ == "__main__":
    test_prediction()
    print()
