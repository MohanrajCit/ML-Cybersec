"""
Quick Test Script for FastAPI Server
=====================================
Tests the two main endpoints:
1. POST /predict
2. GET /predict/latest-cves

Usage:
    1. Start server: uvicorn app:app --reload
    2. Run this script: python test_fastapi.py
"""

import requests
import json

BASE_URL = "http://127.0.0.1:8000"

def test_health_check():
    """Test the health endpoint"""
    print("\n" + "="*80)
    print("TEST 1: Health Check")
    print("="*80)
    
    try:
        response = requests.get(f"{BASE_URL}/health")
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def test_predict_endpoint():
    """Test the /predict endpoint"""
    print("\n" + "="*80)
    print("TEST 2: POST /predict")
    print("="*80)
    
    test_payload = {
        "description": "A remote code execution vulnerability exists in the web application framework that allows an attacker to execute arbitrary code by sending specially crafted requests to the server endpoint. This vulnerability affects all versions prior to 3.2.1 and can be exploited without authentication."
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/predict",
            json=test_payload
        )
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def test_latest_cves_endpoint():
    """Test the /predict/latest-cves endpoint"""
    print("\n" + "="*80)
    print("TEST 3: GET /predict/latest-cves")
    print("="*80)
    print("⚠️  Note: This requires internet connection and may take a few seconds...")
    
    try:
        response = requests.get(
            f"{BASE_URL}/predict/latest-cves",
            params={
                "days_back": 3,
                "max_results": 5
            }
        )
        print(f"Status Code: {response.status_code}")
        result = response.json()
        
        if isinstance(result, list):
            print(f"Number of CVEs fetched: {len(result)}")
            if result:
                print(f"\nFirst CVE result:")
                print(json.dumps(result[0], indent=2))
        else:
            print(f"Response: {json.dumps(result, indent=2)}")
        
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def main():
    """Run all tests"""
    print("\n" + "🔥"*40)
    print("FASTAPI SERVER TEST SUITE")
    print("🔥"*40)
    
    print(f"\n📡 Testing API at: {BASE_URL}")
    print("⚠️  Make sure the server is running with: uvicorn app:app --reload\n")
    
    results = []
    
    # Test 1: Health Check
    results.append(("Health Check", test_health_check()))
    
    # Test 2: Predict Endpoint
    results.append(("POST /predict", test_predict_endpoint()))
    
    # Test 3: Latest CVEs
    user_input = input("\n⚠️  Test 3 requires internet. Continue? [y/N]: ").strip().lower()
    if user_input == 'y':
        results.append(("GET /predict/latest-cves", test_latest_cves_endpoint()))
    else:
        print("⏭️  Skipping Test 3")
    
    # Summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    
    for test_name, passed in results:
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"{status} - {test_name}")
    
    total_passed = sum(1 for _, passed in results if passed)
    print(f"\n{total_passed}/{len(results)} tests passed")
    print("="*80 + "\n")


if __name__ == "__main__":
    main()
