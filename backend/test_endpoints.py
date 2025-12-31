import requests
import json
import time

BASE_URL = "http://127.0.0.1:5000"

def test_predict():
    print("\n--- Testing /predict ---")
    payload = {
        "description": "An attacker could execute arbitrary code remotely by sending a specially crafted packet."
    }
    try:
        res = requests.post(f"{BASE_URL}/predict", json=payload)
        print(f"Status: {res.status_code}")
        print(json.dumps(res.json(), indent=2))
    except Exception as e:
        print(f"Error: {e}")

def test_latest_cves():
    print("\n--- Testing /predict/latest-cves (This might take a moment) ---")
    try:
        res = requests.get(f"{BASE_URL}/predict/latest-cves")
        print(f"Status: {res.status_code}")
        data = res.json()
        if "predictions" in data:
            print(f"Fetched {data.get('count', 0)} CVEs")
            if data["predictions"]:
                print("First prediction sample:")
                print(json.dumps(data["predictions"][0], indent=2))
        else:
            print("Response:", data)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    time.sleep(2) # Ensure server is ready
    test_predict()
    test_latest_cves()
