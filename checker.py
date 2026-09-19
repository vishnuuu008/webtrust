"""
checker.py - Website Safety & Trust Signal Checker
==================================================
This module performs SAFE, PASSIVE checks on a target website URL.
It uses standard HTTP/HTTPS GET requests and parses the HTML using BeautifulSoup.

SAFETY GUARANTEE:
- No attacks, no exploits, no SQL injection, no XSS.
- Passive inspection only (normal web browsing behavior).
- Uses request timeouts to prevent freezing.
"""

import re
import socket
import time
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup


# A standard browser User-Agent so target websites don't reject requests
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36 WebTrust-Scanner/1.0"
    )
}

# Suspicious keywords commonly used in phishing or scam URLs
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "banking", "secure", "account",
    "free", "bonus", "crypto", "signin", "wallet", "support",
    "password", "auth", "confirm", "claim"
]


def is_ip_address(domain: str) -> bool:
    """
    Check if a domain name is a raw IPv4 or IPv6 address instead of a domain name.
    Legitimate public websites rarely use direct IP addresses.
    """
    # Remove port if present (e.g. 192.168.1.1:8080)
    host = domain.split(":")[0]
    
    # Try IPv4
    try:
        socket.inet_aton(host)
        return True
    except socket.error:
        pass

    # Try IPv6
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except (socket.error, AttributeError):
        pass

    return False


def normalize_url(url: str) -> str:
    """
    Ensure the URL has a valid scheme (defaults to https:// if missing).
    Cleans leading/trailing whitespace.
    """
    url = url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    return url


def analyze_url_structure(url: str) -> dict:
    """
    Examines the URL string itself for structural anomalies and risk indicators.
    Does not require an internet connection.
    """
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    
    # Subdomain count: count dots in the hostname, ignoring trailing dot
    hostname = parsed.hostname or ""
    parts = hostname.split(".")
    # Example: "sub.example.com" has 3 parts -> 1 subdomain
    # "a.b.c.example.com" has 5 parts -> 3 subdomains
    subdomain_count = max(0, len(parts) - 2)
    
    # Check for IP address in host
    is_ip = is_ip_address(hostname)
    
    # Check URL length (URLs over 75 characters are statistically more common in phishing)
    url_length = len(url)
    is_long_url = url_length > 75
    
    # Check for suspicious characters
    has_at_symbol = "@" in url  # @ can be used to trick URL parsers (e.g., legitimate.com@evil.com)
    excessive_hyphens = domain.count("-") >= 3
    excessive_subdomains = subdomain_count >= 3
    
    # Check for suspicious keywords in domain or path
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in path or kw in domain]
    
    return {
        "url": url,
        "scheme": parsed.scheme,
        "domain": hostname,
        "is_https": parsed.scheme == "https",
        "url_length": url_length,
        "is_long_url": is_long_url,
        "is_ip_address": is_ip,
        "subdomain_count": subdomain_count,
        "excessive_subdomains": excessive_subdomains,
        "has_at_symbol": has_at_symbol,
        "excessive_hyphens": excessive_hyphens,
        "found_keywords": found_keywords,
    }


def check_trust_pages(soup: BeautifulSoup) -> dict:
    """
    Passively scans the page's <a> tags to see if common trust pages exist:
    - About Us
    - Contact Us
    - Privacy Policy
    - Terms of Service
    - Refund / Return Policy
    """
    # Keywords to look for in link text or href
    targets = {
        "about": ["about", "who-we-are", "our-story", "about-us"],
        "contact": ["contact", "reach-us", "support", "contact-us", "get-in-touch"],
        "privacy": ["privacy", "privacy-policy", "data-protection"],
        "terms": ["terms", "tos", "conditions", "terms-of-service", "terms-of-use"],
        "refund": ["refund", "return", "cancellation", "returns-policy"]
    }
    
    results = {
        "about": False,
        "contact": False,
        "privacy": False,
        "terms": False,
        "refund": False
    }

    if not soup:
        return results

    # Check all links on the page
    for a in soup.find_all("a", href=True):
        href = (a.get("href") or "").lower()
        text = a.get_text(strip=True).lower()
        
        for key, keywords in targets.items():
            if not results[key]:
                for kw in keywords:
                    if kw in href or kw in text:
                        results[key] = True
                        break

    return results


def check_security_headers(headers: dict) -> dict:
    """
    Checks for the presence of standard HTTP security headers that protect
    browsers from common web threats (like clickjacking, MIME sniffing, and MITM).
    """
    # Convert header keys to lowercase for case-insensitive lookup
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    return {
        "hsts": "strict-transport-security" in headers_lower,
        "csp": "content-security-policy" in headers_lower,
        "x_frame_options": "x-frame-options" in headers_lower,
        "x_content_type_options": "x-content-type-options" in headers_lower,
        "referrer_policy": "referrer-policy" in headers_lower,
    }


def analyze_website(target_url: str) -> dict:
    """
    Main passive analysis function.
    
    Steps:
    1. Clean and parse URL structure
    2. Perform a safe HTTP GET request with a 6-second timeout
    3. Measure response status and latency
    4. Parse HTML with BeautifulSoup for links, forms, title, and trust pages
    5. Check security headers
    
    Returns a comprehensive dictionary containing all collected signals.
    """
    cleaned_url = normalize_url(target_url)
    url_data = analyze_url_structure(cleaned_url)
    
    # Default structure in case of request error
    result = {
        "success": False,
        "error_message": None,
        "url_data": url_data,
        "status_code": None,
        "response_time": 0.0,
        "redirect_count": 0,
        "redirect_history": [],
        "title": "N/A",
        "link_count": 0,
        "form_count": 0,
        "has_password_field": False,
        "security_headers": {
            "hsts": False,
            "csp": False,
            "x_frame_options": False,
            "x_content_type_options": False,
            "referrer_policy": False
        },
        "trust_pages": {
            "about": False,
            "contact": False,
            "privacy": False,
            "terms": False,
            "refund": False
        },
        "server_info": "Unknown",
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    # Validate domain before sending network request
    if not url_data["domain"]:
        result["error_message"] = "Invalid URL format. Please enter a valid website address."
        return result

    # Perform safe HTTP request
    try:
        start_time = time.time()
        response = requests.get(
            cleaned_url,
            headers=DEFAULT_HEADERS,
            timeout=7,               # Safe timeout: stop if server does not respond within 7s
            allow_redirects=True,    # Follow redirects to see where it leads
            stream=False
        )
        elapsed = round(time.time() - start_time, 2)
        
        result["success"] = True
        result["status_code"] = response.status_code
        result["response_time"] = elapsed
        result["redirect_count"] = len(response.history)
        result["redirect_history"] = [r.url for r in response.history] + [response.url]
        result["server_info"] = response.headers.get("Server", "Hidden / Not Disclosed")
        
        # Check security headers on final response
        result["security_headers"] = check_security_headers(response.headers)
        
        # Parse HTML safely using BeautifulSoup (limiting to first 500KB to prevent memory overload)
        html_content = response.text[:500000]
        soup = BeautifulSoup(html_content, "html.parser")
        
        # Extract title
        title_tag = soup.find("title")
        if title_tag and title_tag.string:
            result["title"] = title_tag.string.strip()[:100]  # Truncate if excessively long
        else:
            result["title"] = "No Title Found"
            
        # Count links
        links = soup.find_all("a")
        result["link_count"] = len(links)
        
        # Count forms & check for password inputs
        forms = soup.find_all("form")
        result["form_count"] = len(forms)
        password_inputs = soup.find_all("input", {"type": "password"})
        result["has_password_field"] = len(password_inputs) > 0
        
        # Check for trust pages
        result["trust_pages"] = check_trust_pages(soup)
        
    except requests.exceptions.SSLError:
        result["error_message"] = "SSL/HTTPS Certificate Error. The website's security certificate is invalid, expired, or self-signed."
    except requests.exceptions.Timeout:
        result["error_message"] = "Connection Timed Out. The website took more than 7 seconds to respond."
    except requests.exceptions.ConnectionError:
        result["error_message"] = "Connection Failed. Could not reach the server. Domain may not exist or the server is down."
    except requests.exceptions.RequestException as e:
        result["error_message"] = f"Network Request Error: {str(e)}"
    except Exception as e:
        result["error_message"] = f"Unexpected Error: {str(e)}"

    return result
