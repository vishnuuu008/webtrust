"""
risk_score.py - Transparent Risk Scoring Engine
===============================================
This module calculates an educational trust & risk score between 0 and 100.

SCORING PHILOSOPHY:
- 0 to 29:   "Likely Trustworthy"   (Low risk, good security habits)
- 30 to 65:  "Needs Caution"        (Moderate risk, some signals missing)
- 66 to 100: "High Risk Indicators" (Significant number of warning signs)

RULES EXPLANATION:
Every rule has an assigned weight. Points are added when suspicious patterns
or missing security standards are detected.
"""

def calculate_risk(analysis_data: dict) -> dict:
    """
    Calculates the risk score (0-100) and produces detailed signals and category breakdown.
    
    Category Breakdown:
    - HTTPS: 0 to 25 points
    - Domain: 0 to 25 points
    - URL Structure: 0 to 20 points
    - Redirects: 0 to 15 points
    - Website Content: 0 to 20 points
    - Security Headers: 0 to 20 points
    
    Returns a dictionary containing:
    - 'score': Final clamped score (0-100)
    - 'verdict': Text classification
    - 'verdict_color': CSS color code
    - 'breakdown': Points per category (for Graph 1)
    - 'positive_signals': List of good findings
    - 'warning_signals': List of caution findings
    - 'risk_signals': List of high-risk findings
    - 'summary': Short sentence summarizing the score
    """
    url_data = analysis_data.get("url_data", {})
    headers = analysis_data.get("security_headers", {})
    trust_pages = analysis_data.get("trust_pages", {})
    
    # Track points per category
    cat_https = 0
    cat_domain = 0
    cat_url = 0
    cat_redirects = 0
    cat_content = 0
    cat_headers = 0
    
    positive_signals = []
    warning_signals = []
    risk_signals = []
    
    # -------------------------------------------------------------------------
    # RULE 1: HTTPS & SSL ENCRYPTION
    # HTTPS encrypts data between the visitor and the server.
    # -------------------------------------------------------------------------
    if url_data.get("is_https"):
        positive_signals.append("HTTPS is enabled for encrypted communication.")
    else:
        cat_https += 25
        risk_signals.append("Unencrypted HTTP is used. Sensitive data can be intercepted.")

    # If an SSL error occurred during connection
    if analysis_data.get("error_message") and "SSL" in analysis_data["error_message"]:
        cat_https += 20
        risk_signals.append("SSL/TLS Certificate is invalid or untrusted.")

    # -------------------------------------------------------------------------
    # RULE 2: DOMAIN & IP ADDRESS CHECK
    # Legitimate websites use registered domains (e.g. google.com), not raw IPs.
    # -------------------------------------------------------------------------
    if url_data.get("is_ip_address"):
        cat_domain += 25
        risk_signals.append("Domain is a raw IP address, frequently seen in phishing/attacks.")
    else:
        positive_signals.append("Uses a standard registered domain name.")

    if url_data.get("excessive_subdomains"):
        cat_domain += 10
        warning_signals.append(f"Excessive subdomains detected ({url_data.get('subdomain_count')} subdomains).")
    else:
        positive_signals.append("Normal subdomain structure.")

    # -------------------------------------------------------------------------
    # RULE 3: URL STRUCTURE & PHISHING PATTERNS
    # Malicious links often use special tricks (like '@') or deceptive keywords.
    # -------------------------------------------------------------------------
    if url_data.get("has_at_symbol"):
        cat_url += 15
        risk_signals.append("The '@' symbol was detected in the URL, which can disguise destination hosts.")
    
    if url_data.get("is_long_url"):
        cat_url += 10
        warning_signals.append(f"URL is unusually long ({url_data.get('url_length')} characters).")
    else:
        positive_signals.append("URL length is normal and concise.")

    if url_data.get("excessive_hyphens"):
        cat_url += 10
        warning_signals.append("Multiple hyphens found in domain, often used in typosquatting.")

    found_kw = url_data.get("found_keywords", [])
    if found_kw:
        cat_url += 10
        warning_signals.append(f"Sensitive keywords in URL: {', '.join(found_kw)}.")

    # -------------------------------------------------------------------------
    # RULE 4: REDIRECTS
    # Multiple redirects can be used to hide the true final destination.
    # -------------------------------------------------------------------------
    redirect_count = analysis_data.get("redirect_count", 0)
    if redirect_count == 0:
        positive_signals.append("Direct response without redirect hops.")
    elif redirect_count <= 2:
        positive_signals.append(f"Normal redirect behavior ({redirect_count} redirect(s)).")
    else:
        cat_redirects += 15
        warning_signals.append(f"High number of redirects detected ({redirect_count} hops).")

    # -------------------------------------------------------------------------
    # RULE 5: WEBSITE CONTENT & TRUST PAGES
    # Legitimate commercial or organizational sites usually feature basic trust pages.
    # Missing these does NOT mean a site is fake, but provides a minor signal.
    # -------------------------------------------------------------------------
    if analysis_data.get("success"):
        # Status code check
        status = analysis_data.get("status_code", 0)
        if status == 200:
            positive_signals.append("Website responded with HTTP 200 OK.")
        elif status in [401, 403]:
            cat_content += 10
            warning_signals.append(f"Website returned restricted status code {status}.")
        elif status >= 400:
            cat_content += 15
            warning_signals.append(f"Website returned client/server error code {status}.")

        # Check trust pages
        found_trust_count = sum(1 for v in trust_pages.values() if v)
        if trust_pages.get("privacy"):
            positive_signals.append("Privacy Policy page link detected.")
        else:
            cat_content += 5
            warning_signals.append("Privacy Policy link not detected on the homepage.")

        if trust_pages.get("contact"):
            positive_signals.append("Contact page link detected.")
        else:
            cat_content += 5
            warning_signals.append("Contact information page not detected on the homepage.")

        if trust_pages.get("about"):
            positive_signals.append("About page link detected.")
        else:
            cat_content += 3
            warning_signals.append("About page not detected.")

        if trust_pages.get("terms"):
            positive_signals.append("Terms of Service link detected.")
        else:
            cat_content += 2
            warning_signals.append("Terms of Service link not detected.")

        # Forms and password fields
        if analysis_data.get("has_password_field") and not url_data.get("is_https"):
            cat_content += 20
            risk_signals.append("Login form / password field detected over insecure HTTP connection!")
    else:
        # Connection failed or error
        cat_content += 20
        risk_signals.append(f"Could not retrieve webpage content: {analysis_data.get('error_message')}")

    # -------------------------------------------------------------------------
    # RULE 6: SECURITY HEADERS
    # Headers protect against common web attacks.
    # -------------------------------------------------------------------------
    header_checks = [
        ("hsts", "Strict-Transport-Security (HSTS)", 5),
        ("csp", "Content-Security-Policy (CSP)", 5),
        ("x_frame_options", "X-Frame-Options (Clickjacking defense)", 5),
        ("x_content_type_options", "X-Content-Type-Options (MIME sniffing defense)", 3),
        ("referrer_policy", "Referrer-Policy", 2)
    ]
    
    missing_headers = []
    present_headers = []
    
    for key, name, weight in header_checks:
        if headers.get(key):
            present_headers.append(name)
        else:
            cat_headers += weight
            missing_headers.append(name)
            
    if present_headers:
        positive_signals.append(f"Security headers enabled: {len(present_headers)} of {len(header_checks)} recommended headers detected.")
    if missing_headers:
        warning_signals.append(f"Missing security headers: {', '.join([h.split()[0] for h in missing_headers])}.")

    # -------------------------------------------------------------------------
    # CALCULATE FINAL SCORE
    # -------------------------------------------------------------------------
    total_raw_score = (
        cat_https +
        cat_domain +
        cat_url +
        cat_redirects +
        cat_content +
        cat_headers
    )
    
    # Cap total score strictly between 0 and 100
    final_score = min(100, max(0, total_raw_score))
    
    # Determine classification
    if final_score < 30:
        verdict = "Likely Trustworthy"
        verdict_color = "#10b981"  # Emerald Green
        verdict_badge = "trustworthy"
        summary = "This website shows strong security indicators and standard trust signals."
    elif final_score <= 65:
        verdict = "Needs Caution"
        verdict_color = "#f59e0b"  # Amber / Yellow
        verdict_badge = "caution"
        summary = "Some safety signals or security configurations are missing. Review details carefully."
    else:
        verdict = "High Risk Indicators"
        verdict_color = "#ef4444"  # Red
        verdict_badge = "high-risk"
        summary = "Multiple high-risk indicators detected. Exercise extreme caution when visiting."

    return {
        "score": final_score,
        "verdict": verdict,
        "verdict_badge": verdict_badge,
        "verdict_color": verdict_color,
        "summary": summary,
        "breakdown": {
            "HTTPS": cat_https,
            "Domain": cat_domain,
            "URL Structure": cat_url,
            "Redirects": cat_redirects,
            "Website Content": cat_content,
            "Security Headers": cat_headers
        },
        "positive_signals": positive_signals,
        "warning_signals": warning_signals,
        "risk_signals": risk_signals
    }
