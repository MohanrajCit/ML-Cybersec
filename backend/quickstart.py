"""
Quick Start Script
==================
Simple script to test the CVE real-time processing system.
"""

import sys
import os

# Ensure environment is set up
try:
    from env_setup import setup_environment
    print("🔧 Initializing environment...")
    config = setup_environment()
    print()
except Exception as e:
    print(f"⚠️  Warning: Could not load environment: {e}\n")

# Import main processor
from cve_realtime_processor import (
    predict_risk,
    detect_anomaly,
    process_new_cves,
    print_results_summary,
    save_results_to_json
)


def manual_description_mode():
    """
    Manual vulnerability description input mode
    Allows user to input custom text for risk analysis
    """
    print("="*80)
    print("MANUAL VULNERABILITY ANALYSIS")
    print("="*80 + "\n")
    
    print("Enter or paste a vulnerability description below.")
    print("Press Enter twice (blank line) when finished:\n")
    print("-" * 80)
    
    # Collect multi-line input
    lines = []
    empty_line_count = 0
    
    while True:
        try:
            line = input()
            if line.strip() == "":
                empty_line_count += 1
                # Two consecutive empty lines = end of input
                if empty_line_count >= 2:
                    break
            else:
                empty_line_count = 0
                lines.append(line)
        except EOFError:
            break
    
    description = "\n".join(lines).strip()
    
    # Validate input
    MIN_LENGTH = 20  # Minimum character count for meaningful analysis
    
    if not description:
        print("\n❌ Error: No input provided.\n")
        return False
    
    if len(description) < MIN_LENGTH:
        print(f"\n❌ Error: Description too short (minimum {MIN_LENGTH} characters).\n")
        return False
    
    print("-" * 80)
    print(f"\n📊 Analyzing description ({len(description)} characters)...\n")
    
    # Perform risk prediction (uses vectorizer.transform() internally)
    try:
        risk = predict_risk(description)
        anomaly = detect_anomaly(description)
        
        # Display results in formatted output
        print("-" * 50)
        print("Manual Vulnerability Analysis Result")
        print("-" * 50)
        print(f"Risk Level:      {risk['risk']}")
        print(f"Confidence:      {risk['confidence']:.2%}")
        print(f"Anomaly Status:  {'ANOMALOUS' if anomaly['anomalous'] else 'NORMAL'}")
        print(f"Anomaly Score:   {anomaly['anomaly_score']:.4f}")
        print("-" * 50)
        print()
        
        return True
        
    except Exception as e:
        print(f"❌ Error during analysis: {e}\n")
        return False


def quick_test():
    """
    Quick test of basic functionality
    """
    print("="*80)
    print("CVE REAL-TIME PROCESSING - QUICK TEST")
    print("="*80 + "\n")
    
    # Test 1: Single prediction
    print("📝 Test 1: Single CVE Prediction")
    print("-" * 80)
    
    test_description = """
    A remote code execution vulnerability exists in the web application framework
    that allows an attacker to execute arbitrary code by sending specially crafted
    requests to the server endpoint. This vulnerability affects all versions prior
    to 3.2.1 and can be exploited without authentication.
    """
    
    try:
        risk = predict_risk(test_description.strip())
        print(f"✅ Risk Prediction: {risk['risk']} (Confidence: {risk['confidence']:.2%})")
        
        anomaly = detect_anomaly(test_description.strip())
        print(f"✅ Anomaly Detection: {'ANOMALOUS' if anomaly['anomalous'] else 'NORMAL'}")
        print(f"   Anomaly Score: {anomaly['anomaly_score']:.4f}\n")
    except Exception as e:
        print(f"❌ Error during prediction: {e}\n")
        return False
    
    return True


def full_pipeline_test():
    """
    Test full pipeline with real NVD data
    """
    print("📡 Test 2: Full Pipeline (Real NVD Data)")
    print("-" * 80)
    print("This will fetch recent CVEs from NVD and analyze them.")
    print("Note: Requires internet connection.\n")
    
    response = input("Continue? [y/N]: ")
    if response.lower() != 'y':
        print("⏭️  Skipping pipeline test.\n")
        return True
    
    try:
        print("\n🔄 Fetching and processing CVEs...")
        results = process_new_cves(
            days_back=3,
            max_results=5
        )
        
        if results:
            print(f"\n✅ Successfully processed {len(results)} CVEs\n")
            print_results_summary(results)
            
            # Save results
            output_file = "quickstart_results.json"
            save_results_to_json(results, output_file)
            print(f"💾 Results saved to: {output_file}\n")
        else:
            print("⚠️  No CVEs fetched. This might be due to:")
            print("   - No CVEs published in the date range")
            print("   - Network connectivity issues")
            print("   - NVD API temporarily unavailable\n")
        
        return True
    
    except Exception as e:
        print(f"❌ Pipeline error: {e}")
        print("\nPossible causes:")
        print("   - No internet connection")
        print("   - NVD API rate limit exceeded")
        print("   - Server temporarily unavailable\n")
        return False


def main():
    """
    Main quick start flow with menu selection
    """
    print("\n" + "🔥"*40)
    print("CVE RISK PREDICTION - QUICK START")
    print("🔥"*40 + "\n")
    
    # Check if models exist
    required_files = [
        "rf_model.pkl",
        "tfidf_vectorizer.pkl",
        "anomaly_model.pkl"
    ]
    
    missing_files = [f for f in required_files if not os.path.exists(f)]
    
    if missing_files:
        print("❌ ERROR: Required model files not found:")
        for f in missing_files:
            print(f"   - {f}")
        print("\nPlease ensure you run this script from the correct directory.")
        print("Required files should be in the same directory as the script.\n")
        sys.exit(1)
    else:
        print("✅ All required model files found\n")
    
    # Display menu
    print("=" * 80)
    print("SELECT ANALYSIS MODE")
    print("=" * 80)
    print("\n[1] Manual Description Analysis")
    print("    → Enter your own vulnerability description for analysis")
    print("\n[2] Real-Time NVD CVE Analysis")
    print("    → Fetch and analyze recent CVEs from NVD database")
    print("\n[3] Run Quick Test (Demo)")
    print("    → Test system with built-in example")
    print("\n[0] Exit")
    print("\n" + "=" * 80)
    
    # Get user choice
    while True:
        try:
            choice = input("\nSelect an option [0-3]: ").strip()
            
            if choice == "0":
                print("\n👋 Exiting. Goodbye!\n")
                sys.exit(0)
            
            elif choice == "1":
                # Manual description mode
                print()
                try:
                    manual_description_mode()
                except KeyboardInterrupt:
                    print("\n\n⚠️  Interrupted by user.\n")
                except Exception as e:
                    print(f"\n❌ Unexpected error: {e}\n")
                
                # Ask if user wants to continue
                again = input("Analyze another description? [y/N]: ").strip().lower()
                if again != 'y':
                    break
            
            elif choice == "2":
                # Real-time NVD mode
                print()
                try:
                    if not quick_test():
                        print("⚠️  Basic test failed. Please check your setup.\n")
                        sys.exit(1)
                    
                    full_pipeline_test()
                except KeyboardInterrupt:
                    print("\n\n⚠️  Interrupted by user.\n")
                except Exception as e:
                    print(f"\n❌ Unexpected error: {e}\n")
                break
            
            elif choice == "3":
                # Quick test mode
                print()
                try:
                    quick_test()
                except KeyboardInterrupt:
                    print("\n\n⚠️  Interrupted by user.\n")
                except Exception as e:
                    print(f"\n❌ Unexpected error: {e}\n")
                break
            
            else:
                print("❌ Invalid choice. Please enter 0, 1, 2, or 3.")
                continue
        
        except KeyboardInterrupt:
            print("\n\n⚠️  Interrupted by user.\n")
            sys.exit(0)
        except Exception as e:
            print(f"\n❌ Error: {e}\n")
            break
    
    # Summary
    print("\n" + "="*80)
    print("✅ SESSION COMPLETE")
    print("="*80)
    print("\nNext steps:")
    print("   1. Run demo_realtime_cve.py for comprehensive examples")
    print("   2. Read REALTIME_FEATURES_README.md for full documentation")
    print("   3. Integrate into your application using the provided API\n")


if __name__ == "__main__":
    main()
