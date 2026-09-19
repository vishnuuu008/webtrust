"""
app.py - WebTrust Flask Web Application Controller
==================================================
This is the main entry point for the WebTrust application.
It connects the user interface (HTML templates) with the Python modules:
- checker.py: Safely scans the website
- risk_score.py: Computes the 0-100 risk score
- graph.py: Generates Matplotlib data visualizations

NO JavaScript is used in this project. All submissions are standard HTML forms.
"""

import json
import os
import re
import time
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash

import checker
import risk_score
import graph


# Initialize Flask application
app = Flask(__name__)
app.secret_key = "webtrust_educational_secret_key_2026"

# Directory paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
HISTORY_FILE = os.path.join(BASE_DIR, "scan_history.json")

# Ensure required directories exist
os.makedirs(os.path.join(STATIC_DIR, "graphs"), exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)


def load_scan_history() -> list:
    """Read past scans from scan_history.json safely."""
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"Warning: Could not read history file: {e}")
        return []


def save_scan_record(website: str, score: int, result: str, scan_time: str):
    """Append a new scan record to scan_history.json."""
    records = load_scan_history()
    new_record = {
        "website": website,
        "risk_score": score,
        "result": result,
        "date": scan_time
    }
    records.append(new_record)
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2)
    except Exception as e:
        print(f"Warning: Could not save scan history: {e}")


def generate_text_report(analysis: dict, risk: dict, filename: str):
    """
    Creates a clean, human-readable text report summarizing the scan.
    Stored in reports/ directory for download.
    """
    filepath = os.path.join(REPORTS_DIR, filename)
    url_data = analysis.get("url_data", {})
    headers = analysis.get("security_headers", {})
    trust_pages = analysis.get("trust_pages", {})

    report_content = f"""================================================================================
WEBTRUST - WEBSITE TRUST & RISK ASSESSMENT REPORT
================================================================================
Generated: {analysis.get('scan_time')}
Target Website: {url_data.get('url')}
Domain Name:    {url_data.get('domain')}

--------------------------------------------------------------------------------
1. EXECUTIVE SUMMARY
--------------------------------------------------------------------------------
Risk Score:     {risk.get('score')} / 100
Assessment:     {risk.get('verdict')}
Summary:        {risk.get('summary')}

DISCLAIMER:
This automated assessment evaluates publicly accessible signals and heuristics.
It is an educational risk evaluation and does NOT guarantee that a website is
definitely genuine or fraudulent.

--------------------------------------------------------------------------------
2. RISK SCORE BREAKDOWN
--------------------------------------------------------------------------------
HTTPS & SSL:        {risk.get('breakdown', {}).get('HTTPS', 0)} pts
Domain & Host:      {risk.get('breakdown', {}).get('Domain', 0)} pts
URL Structure:      {risk.get('breakdown', {}).get('URL Structure', 0)} pts
Redirects:          {risk.get('breakdown', {}).get('Redirects', 0)} pts
Website Content:    {risk.get('breakdown', {}).get('Website Content', 0)} pts
Security Headers:   {risk.get('breakdown', {}).get('Security Headers', 0)} pts
Total Risk Score:   {risk.get('score')} pts (Scale 0-100, lower is safer)

--------------------------------------------------------------------------------
3. DETAILED SIGNALS
--------------------------------------------------------------------------------
[POSITIVE SIGNALS]
"""
    for sig in risk.get("positive_signals", []):
        report_content += f"  [+] {sig}\n"

    report_content += "\n[WARNING SIGNALS]\n"
    for sig in risk.get("warning_signals", []):
        report_content += f"  [!] {sig}\n"

    report_content += "\n[HIGH RISK INDICATORS]\n"
    if risk.get("risk_signals"):
        for sig in risk.get("risk_signals", []):
            report_content += f"  [X] {sig}\n"
    else:
        report_content += "  None detected.\n"

    report_content += f"""
--------------------------------------------------------------------------------
4. TECHNICAL SPECIFICATIONS
--------------------------------------------------------------------------------
HTTP Status Code:   {analysis.get('status_code', 'N/A')}
Response Time:      {analysis.get('response_time', 0.0)} seconds
Number of Redirects:{analysis.get('redirect_count', 0)}
Webpage Title:      {analysis.get('title', 'N/A')}
Total Links Count:  {analysis.get('link_count', 0)}
Total Forms Count:  {analysis.get('form_count', 0)}
Server Software:    {analysis.get('server_info', 'N/A')}

--------------------------------------------------------------------------------
5. TRUST PAGES DETECTED
--------------------------------------------------------------------------------
About Page:         {'Found' if trust_pages.get('about') else 'Not Found'}
Contact Page:       {'Found' if trust_pages.get('contact') else 'Not Found'}
Privacy Policy:     {'Found' if trust_pages.get('privacy') else 'Not Found'}
Terms of Service:   {'Found' if trust_pages.get('terms') else 'Not Found'}
Refund Policy:      {'Found' if trust_pages.get('refund') else 'Not Found'}

--------------------------------------------------------------------------------
6. SECURITY HEADERS
--------------------------------------------------------------------------------
HSTS (Strict-Transport-Security):   {'Present' if headers.get('hsts') else 'Missing'}
CSP (Content-Security-Policy):      {'Present' if headers.get('csp') else 'Missing'}
X-Frame-Options (Clickjacking):     {'Present' if headers.get('x_frame_options') else 'Missing'}
X-Content-Type-Options:             {'Present' if headers.get('x_content_type_options') else 'Missing'}
Referrer-Policy:                    {'Present' if headers.get('referrer_policy') else 'Missing'}

================================================================================
END OF REPORT - Generated by WebTrust (Python, Flask, Matplotlib)
================================================================================
"""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(report_content)


@app.route("/", methods=["GET"])
def home():
    """Renders the clean homepage with URL input."""
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Main analysis route.
    1. Reads user URL input
    2. Runs passive checks via checker.py
    3. Calculates risk score via risk_score.py
    4. Generates 3 Matplotlib charts via graph.py
    5. Saves scan to scan_history.json
    6. Generates downloadable report
    7. Renders result.html
    """
    target_url = request.form.get("url", "").strip()

    # Input validation: check for empty input
    if not target_url:
        flash("Please enter a website URL to analyze.", "error")
        return redirect(url_for("home"))

    # Step 1: Perform passive check
    analysis = checker.analyze_website(target_url)

    # Step 2: Calculate transparent risk score
    risk = risk_score.calculate_risk(analysis)

    # Step 3: Load history and append new scan
    history = load_scan_history()
    domain_name = analysis.get("url_data", {}).get("domain", target_url)
    save_scan_record(
        website=domain_name,
        score=risk["score"],
        result=risk["verdict"],
        scan_time=analysis.get("scan_time")
    )
    # Refresh history records including the new one
    updated_history = load_scan_history()

    # Step 4: Generate Matplotlib charts
    signal_counts = {
        "positive": len(risk["positive_signals"]),
        "warning": len(risk["warning_signals"]),
        "risk": len(risk["risk_signals"])
    }
    charts = graph.generate_all_graphs(
        breakdown=risk["breakdown"],
        signal_counts=signal_counts,
        history_records=updated_history,
        static_dir=STATIC_DIR
    )

    # Step 5: Generate downloadable report
    safe_domain = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", domain_name)
    timestamp_str = time.strftime("%Y%m%d_%H%M%S")
    report_filename = f"webtrust_report_{safe_domain}_{timestamp_str}.txt"
    generate_text_report(analysis, risk, report_filename)

    return render_template(
        "result.html",
        analysis=analysis,
        risk=risk,
        charts=charts,
        report_filename=report_filename
    )


@app.route("/history", methods=["GET"])
def history_page():
    """Displays previous scans and historical line chart."""
    records = load_scan_history()
    
    # Generate standalone history chart
    chart_filename = f"history_trend_{int(time.time())}.png"
    chart_path = os.path.join(STATIC_DIR, "graphs", chart_filename)
    graph.generate_scan_history_chart(records, chart_path)
    
    return render_template(
        "history.html",
        records=reversed(records),  # Show newest first
        history_chart=f"graphs/{chart_filename}"
    )


@app.route("/how-it-works", methods=["GET"])
def how_it_works():
    """Explains the pipeline, scoring rules, and passive methodology."""
    return render_template("how_it_works.html")


@app.route("/download-report/<filename>", methods=["GET"])
def download_report(filename):
    """Safely serves the generated scan report from the reports/ directory."""
    # Basic path traversal protection
    safe_name = os.path.basename(filename)
    return send_from_directory(REPORTS_DIR, safe_name, as_attachment=True)


if __name__ == "__main__":
    print("=" * 60)
    print(" WebTrust - Website Trust & Risk Analyzer")
    print(" Running on: http://127.0.0.1:5000")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5000, debug=True)
