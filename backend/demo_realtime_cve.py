"""
Demo Script: CVE Real-time Processing
======================================
Demonstrates various usage patterns of the CVE real-time processor.
"""

import os
from cve_realtime_processor import (
    predict_risk,
    detect_anomaly,
    fetch_cves_from_nvd,
    process_new_cves,
    print_results_summary,
    save_results_to_json
)


def demo_single_prediction():
    """
    Demo 1: Single CVE risk prediction
    """
    print("\n" + "="*80)
    print("DEMO 1: Single CVE Prediction")
    print("="*80 + "\n")
    
    sample_description = """
    A buffer overflow vulnerability in the network service allows remote 
    attackers to execute arbitrary code by sending a specially crafted 
    packet to port 445. This affects all versions prior to 2.5.0.
    """
    
    print("📝 Sample CVE Description:")
    print(f"   {sample_description.strip()}\n")
    
    # Predict risk
    risk_result = predict_risk(sample_description)
    print(f"🎯 Risk Prediction:")
    print(f"   Risk Level:  {risk_result['risk']}")
    print(f"   Confidence:  {risk_result['confidence']:.2%}")
    
    # Detect anomaly
    anomaly_result = detect_anomaly(sample_description)
    print(f"\n🔍 Anomaly Detection:")
    print(f"   Anomalous:   {anomaly_result['anomalous']}")
    print(f"   Score:       {anomaly_result['anomaly_score']:.4f}")
    print(f"   Status:      {anomaly_result['threshold_info']}")


def demo_batch_prediction():
    """
    Demo 2: Batch prediction on multiple CVE descriptions
    """
    print("\n" + "="*80)
    print("DEMO 2: Batch Prediction on Sample CVEs")
    print("="*80 + "\n")
    
    sample_cves = [
        {
            "cve_id": "CVE-2024-SAMPLE-1",
            "description": "SQL injection vulnerability allows remote attackers to execute arbitrary SQL commands."
        },
        {
            "cve_id": "CVE-2024-SAMPLE-2",
            "description": "Information disclosure in log files may expose sensitive configuration data."
        },
        {
            "cve_id": "CVE-2024-SAMPLE-3",
            "description": "Remote code execution via deserialization of untrusted data in the API endpoint."
        }
    ]
    
    results = []
    for cve in sample_cves:
        risk = predict_risk(cve["description"])
        anomaly = detect_anomaly(cve["description"])
        
        results.append({
            "cve_id": cve["cve_id"],
            "risk": risk["risk"],
            "confidence": risk["confidence"],
            "anomalous": anomaly["anomalous"]
        })
    
    print_results_summary(results)


def demo_nvd_api_fetch():
    """
    Demo 3: Fetch recent CVEs from NVD API
    """
    print("\n" + "="*80)
    print("DEMO 3: Fetching Recent CVEs from NVD")
    print("="*80 + "\n")
    
    api_key = os.getenv("NVD_API_KEY")
    
    try:
        cves = fetch_cves_from_nvd(
            days_back=3,
            max_results=5,
            api_key=api_key
        )
        
        print(f"✓ Fetched {len(cves)} CVEs\n")
        
        for idx, cve in enumerate(cves[:3], 1):
            print(f"{idx}. {cve['cve_id']}")
            print(f"   Description: {cve['description'][:100]}...")
            print()
    
    except Exception as e:
        print(f"❌ Error: {e}")
        print("   Make sure you have internet connection and valid API key (optional).\n")


def demo_full_pipeline():
    """
    Demo 4: Full end-to-end pipeline
    """
    print("\n" + "="*80)
    print("DEMO 4: Full Pipeline - Fetch + Predict + Anomaly Detection")
    print("="*80 + "\n")
    
    api_key = os.getenv("NVD_API_KEY")
    
    try:
        results = process_new_cves(
            days_back=5,
            max_results=10,
            api_key=api_key
        )
        
        # Display results
        print_results_summary(results)
        
        # Save to file
        output_file = "demo_cve_results.json"
        save_results_to_json(results, output_file)
        print(f"💾 Results saved to: {output_file}\n")
    
    except Exception as e:
        print(f"❌ Pipeline Error: {e}\n")


def main():
    """
    Main demo runner
    """
    print("\n" + "🔥"*40)
    print("CVE REAL-TIME PROCESSING - DEMO SUITE")
    print("🔥"*40)
    
    # Check if NVD API key is set
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        print(f"\n✅ NVD API Key detected (length: {len(api_key)})")
    else:
        print("\n⚠️  NVD API Key not found in environment")
        print("   Set using: export NVD_API_KEY='your-api-key'")
        print("   (API will work without key but with rate limits)\n")
    
    # Run demos
    try:
        # Demo 1: Single prediction
        demo_single_prediction()
        
        # Demo 2: Batch prediction
        demo_batch_prediction()
        
        # Demo 3: NVD API fetch (requires internet)
        response = input("\n➡️  Run NVD API fetch demo? (requires internet) [y/N]: ")
        if response.lower() == 'y':
            demo_nvd_api_fetch()
        
        # Demo 4: Full pipeline (requires internet)
        response = input("\n➡️  Run full pipeline demo? (requires internet + may take time) [y/N]: ")
        if response.lower() == 'y':
            demo_full_pipeline()
    
    except KeyboardInterrupt:
        print("\n\n⚠️  Demo interrupted by user.\n")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}\n")
    
    print("\n" + "="*80)
    print("DEMO COMPLETE")
    print("="*80 + "\n")


if __name__ == "__main__":
    main()
