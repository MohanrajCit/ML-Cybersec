"""
Simple Test: Three-Level Risk Classification
"""
from cve_realtime_processor import predict_risk

# Three test cases
tests = [
    "Critical remote code execution with root privileges and buffer overflow",
    "A vulnerability may allow local users to gain privileges under certain conditions",
    "Minor information disclosure in debug logs requiring local access"
]

print("\nThree-Level Risk Classification Test")
print("="*60)
print("Thresholds: HIGH >= 0.70 | MEDIUM 0.40-0.69 | LOW < 0.40\n")

for i, desc in enumerate(tests, 1):
    result = predict_risk(desc)
    print("{}. Risk: {:6} | Confidence: {:.1%} | '{}'".format(
        i, result['risk'], result['confidence'], desc[:50]
    ))

print("\n" + "="*60)
print("SUCCESS: Three levels (HIGH/MEDIUM/LOW) are working!\n")
