"""
Complete API Usage Examples
============================
Demonstrates how to use the CVE Risk Prediction API from Python

Run this after starting the server with: uvicorn app:app --reload
"""

import requests
import json


BASE_URL = "http://127.0.0.1:8000"


def example_1_single_prediction():
    """
    Example 1: Predict risk for a single CVE description
    """
    print("\n" + "="*80)
    print("EXAMPLE 1: Single CVE Risk Prediction")
    print("="*80)
    
    # Sample CVE description
    cve_description = """
    A SQL injection vulnerability exists in the user authentication module
    that allows remote attackers to execute arbitrary SQL commands via
    crafted input in the login form. This affects versions 2.0 through 2.5.
    Exploitation requires no authentication.
    """
    
    # Prepare request
    payload = {
        "description": cve_description.strip()
    }
    
    # Send POST request
    print(f"\n📤 Sending request to: {BASE_URL}/predict")
    response = requests.post(
        f"{BASE_URL}/predict",
        json=payload,
        headers={"Content-Type": "application/json"}
    )
    
    # Process response
    if response.status_code == 200:
        result = response.json()
        print(f"\n✅ Success! Prediction result:")
        print(json.dumps(result, indent=2))
        
        # Interpret results
        print(f"\n📊 Interpretation:")
        print(f"   Risk Level: {result['risk']}")
        print(f"   Confidence: {result['confidence']:.1%}")
        print(f"   Anomalous: {'Yes' if result['anomalous'] else 'No'}")
    else:
        print(f"\n❌ Error: {response.status_code}")
        print(response.text)


def example_2_latest_cves():
    """
    Example 2: Fetch and analyze latest CVEs from NVD
    """
    print("\n" + "="*80)
    print("EXAMPLE 2: Fetch Latest CVEs from NVD")
    print("="*80)
    
    # Query parameters
    params = {
        "days_back": 3,
        "max_results": 5
    }
    
    print(f"\n📤 Fetching CVEs from last {params['days_back']} days (max {params['max_results']} results)")
    print(f"URL: {BASE_URL}/predict/latest-cves")
    print("⚠️  Note: This requires internet connection and may take a few seconds...")
    
    # Send GET request
    response = requests.get(
        f"{BASE_URL}/predict/latest-cves",
        params=params
    )
    
    # Process response
    if response.status_code == 200:
        results = response.json()
        print(f"\n✅ Success! Retrieved {len(results)} CVEs")
        
        if results:
            print(f"\n📋 Results Summary:")
            print("-" * 80)
            
            # Count by risk level
            high_count = sum(1 for r in results if r['risk'] == 'HIGH')
            medium_count = sum(1 for r in results if r['risk'] == 'MEDIUM')
            low_count = sum(1 for r in results if r['risk'] == 'LOW')
            anomalous_count = sum(1 for r in results if r['anomalous'])
            
            print(f"HIGH Risk:    {high_count}")
            print(f"MEDIUM Risk:  {medium_count}")
            print(f"LOW Risk:     {low_count}")
            print(f"Anomalous:    {anomalous_count}")
            
            print(f"\n📝 Detailed Results:")
            print("-" * 80)
            for idx, cve in enumerate(results, 1):
                risk_icon = "🚨" if cve['risk'] == 'HIGH' else ("⚠️" if cve['risk'] == 'MEDIUM' else "✅")
                anomaly_flag = "⚠️ ANOMALOUS" if cve['anomalous'] else ""
                print(f"{idx}. {risk_icon} {cve['cve_id']:20} | {cve['risk']:6} ({cve['confidence']:.1%}) {anomaly_flag}")
        else:
            print("\n⚠️  No CVEs found in the specified time range")
    else:
        print(f"\n❌ Error: {response.status_code}")
        print(response.text)


def example_3_batch_predictions():
    """
    Example 3: Batch process multiple CVE descriptions
    """
    print("\n" + "="*80)
    print("EXAMPLE 3: Batch Process Multiple Descriptions")
    print("="*80)
    
    # Multiple CVE descriptions
    descriptions = [
        "Buffer overflow in network service allows remote code execution",
        "Cross-site scripting vulnerability in web application input validation",
        "Privilege escalation through improper access control in admin panel",
        "Denial of service via malformed packet processing",
    ]
    
    results = []
    
    print(f"\n📤 Processing {len(descriptions)} descriptions...")
    
    for idx, desc in enumerate(descriptions, 1):
        print(f"   {idx}. Processing...")
        
        response = requests.post(
            f"{BASE_URL}/predict",
            json={"description": desc}
        )
        
        if response.status_code == 200:
            result = response.json()
            result['description_preview'] = desc[:50] + "..."
            results.append(result)
    
    print(f"\n✅ Successfully processed {len(results)}/{len(descriptions)} descriptions")
    print("\n📋 Results:")
    print("-" * 80)
    
    for idx, result in enumerate(results, 1):
        print(f"\n{idx}. {result['description_preview']}")
        print(f"   Risk: {result['risk']} (confidence: {result['confidence']:.1%})")
        print(f"   Anomalous: {result['anomalous']}")


def example_4_error_handling():
    """
    Example 4: Demonstrate error handling
    """
    print("\n" + "="*80)
    print("EXAMPLE 4: Error Handling")
    print("="*80)
    
    # Test with invalid input (too short)
    print("\n📤 Test 1: Description too short")
    
    response = requests.post(
        f"{BASE_URL}/predict",
        json={"description": "Short text"}
    )
    
    print(f"Status: {response.status_code}")
    if response.status_code != 200:
        print(f"Expected error: {response.json()}")
    
    # Test with missing field
    print("\n📤 Test 2: Missing description field")
    
    response = requests.post(
        f"{BASE_URL}/predict",
        json={"wrong_field": "value"}
    )
    
    print(f"Status: {response.status_code}")
    if response.status_code != 200:
        print(f"Expected error: {response.json()}")


def example_5_health_check():
    """
    Example 5: Health check endpoint
    """
    print("\n" + "="*80)
    print("EXAMPLE 5: Health Check")
    print("="*80)
    
    response = requests.get(f"{BASE_URL}/health")
    
    if response.status_code == 200:
        result = response.json()
        print(f"\n✅ API Health Status:")
        print(json.dumps(result, indent=2))
    else:
        print(f"\n❌ Health check failed: {response.status_code}")


def main():
    """
    Run all examples
    """
    print("\n" + "🔥"*40)
    print("CVE RISK PREDICTION API - USAGE EXAMPLES")
    print("🔥"*40)
    
    print(f"\n📡 API Base URL: {BASE_URL}")
    print("⚠️  Make sure the server is running: uvicorn app:app --reload")
    
    input("\nPress Enter to continue...")
    
    # Run examples
    example_1_single_prediction()
    
    input("\nPress Enter for next example...")
    example_5_health_check()
    
    input("\nPress Enter for next example...")
    example_3_batch_predictions()
    
    # Ask before running network-dependent example
    print("\n" + "-"*80)
    choice = input("\nRun Example 2 (Fetch Latest CVEs - requires internet)? [y/N]: ")
    if choice.lower() == 'y':
        example_2_latest_cves()
    
    # Ask before error handling demo
    choice = input("\nRun Example 4 (Error Handling Demo)? [y/N]: ")
    if choice.lower() == 'y':
        example_4_error_handling()
    
    print("\n" + "="*80)
    print("✅ ALL EXAMPLES COMPLETED")
    print("="*80)
    print("\n📚 Next Steps:")
    print("   1. Visit http://127.0.0.1:8000/docs for interactive API docs")
    print("   2. Integrate these examples into your frontend application")
    print("   3. See API_README.md for more details")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
