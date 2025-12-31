"""
Quick Server Check
==================
Checks if the FastAPI server is running on port 8000
"""

import requests
import time

BASE_URL = "http://127.0.0.1:8000"

def check_server():
    """Check if server is accessible"""
    print("🔍 Checking if FastAPI server is running...")
    
    max_attempts = 5
    for attempt in range(1, max_attempts + 1):
        try:
            response = requests.get(f"{BASE_URL}/", timeout=2)
            if response.status_code == 200:
                print(f"✅ Server is running!")
                print(f"📡 API URL: {BASE_URL}")
                print(f"📚 Interactive docs: {BASE_URL}/docs")
                print(f"\nResponse from root endpoint:")
                print(response.json())
                return True
        except requests.RequestException as e:
            print(f"Attempt {attempt}/{max_attempts}: Server not ready... ({e.__class__.__name__})")
            if attempt < max_attempts:
                time.sleep(2)
    
    print("\n❌ Server is not running or not accessible")
    print("💡 Start the server with: uvicorn app:app --reload")
    return False

if __name__ == "__main__":
    check_server()
