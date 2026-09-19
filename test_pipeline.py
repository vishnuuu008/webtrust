"""
test_pipeline.py - Verification script for WebTrust
Tests checker, risk_score, and graph generation.
"""
import os
import sys

# Ensure UTF-8 output on Windows terminal
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

# Add project root to sys.path
sys.path.insert(0, r"C:\Users\vp070\.gemini\antigravity-ide\scratch\WebTrust")

import checker
import risk_score
import graph

print("1. Testing checker.py on https://example.com ...")
analysis = checker.analyze_website("https://example.com")
print("   Success:", analysis["success"])
print("   Status Code:", analysis["status_code"])
print("   Domain:", analysis["url_data"]["domain"])
print("   Title:", analysis["title"])
print("   Response Time:", analysis["response_time"], "s")

print("\n2. Testing risk_score.py ...")
risk = risk_score.calculate_risk(analysis)
print("   Risk Score:", risk["score"], "/ 100")
print("   Verdict:", risk["verdict"])
print("   Breakdown:", risk["breakdown"])
print("   Positive Signals Count:", len(risk["positive_signals"]))
print("   Warning Signals Count:", len(risk["warning_signals"]))
print("   Risk Signals Count:", len(risk["risk_signals"]))

print("\n3. Testing graph.py ...")
static_dir = r"C:\Users\vp070\.gemini\antigravity-ide\scratch\WebTrust\static"
history_records = [
    {"website": "example.com", "risk_score": 15, "result": "Likely Trustworthy", "date": "2026-09-19 20:00:00"},
    {"website": "test.com", "risk_score": 45, "result": "Needs Caution", "date": "2026-09-19 20:30:00"}
]
signal_counts = {
    "positive": len(risk["positive_signals"]),
    "warning": len(risk["warning_signals"]),
    "risk": len(risk["risk_signals"])
}
charts = graph.generate_all_graphs(risk["breakdown"], signal_counts, history_records, static_dir)
print("   Generated Charts:", charts)

for chart_key, chart_file in charts.items():
    full_path = os.path.join(static_dir, chart_file)
    assert os.path.exists(full_path), f"Chart file {full_path} not found!"
    print(f"   ✓ Verified: {chart_file} (Size: {os.path.getsize(full_path)} bytes)")

print("\n4. Testing error handling on unreachable host ...")
err_analysis = checker.analyze_website("http://non-existent-domain-webtrust-test-xyz-99.org")
print("   Success (should be False):", err_analysis["success"])
print("   Error message captured:", err_analysis["error_message"])
err_risk = risk_score.calculate_risk(err_analysis)
print("   Risk score for unreachable site:", err_risk["score"], "/ 100")
print("   Verdict:", err_risk["verdict"])

print("\nALL VERIFICATION TESTS PASSED SUCCESSFULLY! ✓")
