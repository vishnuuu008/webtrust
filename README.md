# 🛡️ WebTrust – Website Trust & Risk Analyzer

> An educational, beginner-friendly Python web application designed for students and educators to safely analyze website trust signals, assess risk, and generate server-side data visualizations with **zero JavaScript**.

---

## 1. What WebTrust Does

WebTrust is a passive website trust and safety analyzer. When you enter any website address (e.g., `https://example.com`), WebTrust:
1. Safely inspects the website using standard HTTP/HTTPS requests (no hacking, no attacks).
2. Checks URL characteristics, domain properties, and security headers.
3. Passively scans the page's HTML for trust indicators (like Privacy Policy, About Us, and Contact pages).
4. Computes a clear, rule-based **Risk Score from 0 to 100**.
5. Classifies the website into one of three educational tiers:
   - **Likely Trustworthy** (0 – 29)
   - **Needs Caution** (30 – 65)
   - **High Risk Indicators** (66 – 100)
6. Generates **three Python Matplotlib charts** (Risk Breakdown, Trust Signals, Scan History).
7. Produces a **downloadable text report** (`.txt`) for documentation or coursework submission.
8. Stores scan history in a local JSON file (`scan_history.json`).

> **⚠️ Important Safety Notice:**  
> WebTrust performs only safe, passive HTTP GET requests with timeouts. It **never** performs SQL injection, XSS, brute force, password testing, or destructive actions. WebTrust provides an automated risk assessment based on available signals; it does not guarantee that a website is genuine or fraudulent.

---

## 2. Technologies Used

WebTrust uses a minimal, carefully selected Python technology stack:

| Technology | Purpose |
| :--- | :--- |
| **Python 3** | Core programming language for logic, scoring, and data handling |
| **Flask** | Lightweight web framework to handle routes and render HTML templates |
| **Requests** | Performs safe, passive HTTP/HTTPS network requests with timeouts |
| **BeautifulSoup 4** | Parses HTML to find page titles, links, forms, and trust policy pages |
| **Matplotlib** | Generates server-side statistical charts saved as PNG images |
| **HTML5 & CSS3** | Clean, dark-modern user interface with **zero JavaScript** |

---

## 3. What Each File Does

```
WebTrust/
│
├── app.py                  # Flask web controller (handles routes, form submission, and downloads)
├── checker.py              # Performs safe, passive checks on the website using Requests & BeautifulSoup
├── risk_score.py           # Calculates the 0-100 risk score and categorizes findings
├── graph.py                # Uses Matplotlib to generate the 3 charts saved as PNGs
├── scan_history.json       # Lightweight JSON file storing previous scan results
├── requirements.txt        # List of Python dependencies
├── README.md               # Beginner-friendly documentation and guide
│
├── templates/
│   ├── index.html          # Homepage with URL input form and trust notice
│   ├── result.html         # Comprehensive result dashboard with cards & graphs
│   ├── how_it_works.html   # Step-by-step pipeline diagram and explanation
│   └── history.html        # Scan history table and historical trend chart
│
├── static/
│   ├── style.css           # Modern dark theme styles (responsive, pure CSS)
│   └── graphs/             # Output folder where Matplotlib saves chart images
│
└── reports/                # Output folder where downloadable text reports are saved
```

---

## 4. How to Install Python

If Python is not already installed on your computer:
1. Visit the official Python website: [https://www.python.org/downloads/](https://www.python.org/downloads/)
2. Download the installer for your operating system (Windows, macOS, or Linux).
3. **Important on Windows:** During installation, make sure to check the box:  
   ☑ **"Add python.exe to PATH"**
4. Verify the installation by opening a terminal (Command Prompt or PowerShell) and typing:
   ```bash
   python --version
   pip --version
   ```

---

## 5. How to Install Requirements

Open your terminal, navigate to the `WebTrust` project folder, and run:

```bash
pip install -r requirements.txt
```

This will install:
- `Flask` (Web framework)
- `requests` (HTTP client)
- `beautifulsoup4` (HTML parser)
- `matplotlib` (Data visualization)

---

## 6. How to Run the Project

To start the WebTrust application, run:

```bash
python app.py
```

You will see output similar to:
```
============================================================
 WebTrust - Website Trust & Risk Analyzer
 Running on: http://127.0.0.1:5000
============================================================
 * Serving Flask app 'app'
 * Running on http://127.0.0.1:5000
```

Open your web browser and navigate to:  
👉 **`http://127.0.0.1:5000`**

---

## 7. How the Risk Score Works

The risk scoring logic is defined in `risk_score.py`. The score ranges from **0 to 100**:
- **0 points:** Very few risk indicators, strong security signals.
- **100 points:** Many risk indicators detected.

### Category Breakdown:
1. **HTTPS & Encryption (0 – 25 points):**
   - Uses HTTPS: `+0` points (Good)
   - Uses unencrypted HTTP: `+25` points (Risk)
   - SSL/TLS certificate error: `+20` points (Risk)
2. **Domain & Host Type (0 – 25 points):**
   - Standard domain name: `+0` points
   - Direct IP address used: `+25` points (Frequent in phishing)
   - Excessive subdomains (e.g. `a.b.c.example.com`): `+10` points
3. **URL Structure (0 – 20 points):**
   - `@` symbol in URL: `+15` points (Disguised destination)
   - Long URL (> 75 chars): `+10` points
   - Sensitive keywords (`login`, `banking`, `verify` in path): `+10` points
4. **Redirects (0 – 15 points):**
   - 0 – 2 redirects: `+0` points
   - More than 2 redirects: `+15` points (Hiding true destination)
5. **Website Content & Trust Pages (0 – 20 points):**
   - Missing Privacy Policy: `+5` points
   - Missing Contact page: `+5` points
   - Missing About page: `+3` points
   - Insecure login form over HTTP: `+20` points
6. **Security Headers (0 – 20 points):**
   - Missing HSTS: `+5` points
   - Missing CSP: `+5` points
   - Missing X-Frame-Options: `+5` points
   - Missing X-Content-Type-Options: `+3` points

All points are summed and clamped strictly between `0` and `100`.

---

## 8. How Matplotlib Graphs Are Generated

WebTrust does **not** use JavaScript or Chart.js. Instead, all charts are generated on the server using Python's **Matplotlib** library in `graph.py`:

1. **Headless Backend:** `matplotlib.use("Agg")` ensures Matplotlib runs in the background without needing a display window or GUI.
2. **Custom Dark Theme:** The figures use dark background colors (`#111827`, `#1f2937`) and vibrant accents (`#10b981`, `#f59e0b`, `#ef4444`, `#06b6d4`) matching `style.css`.
3. **Three Generated Charts:**
   - **Graph 1 (Horizontal Bar Chart):** Visualizes points contributed by each of the 6 categories.
   - **Graph 2 (Donut / Pie Chart):** Shows the ratio of Positive, Warning, and High Risk signals.
   - **Graph 3 (Line Chart):** Displays recent scan scores from `scan_history.json` with colored zones for Trustworthy, Caution, and High Risk.
4. **Export to PNG:** Each chart is saved as a PNG image in `static/graphs/` with a timestamp to prevent browser caching. Flask renders these images using standard HTML `<img>` tags.

---

## 9. How to Modify the Risk Rules

The risk rules in `risk_score.py` are designed to be easily modified:

1. Open `risk_score.py` in your code editor.
2. Locate the rule you want to change. For example, to increase the penalty for missing a Privacy Policy:
   ```python
   # Original:
   if not trust_pages.get("privacy"):
       cat_content += 5
       warning_signals.append("Privacy Policy link not detected on the homepage.")

   # Modified (e.g. increase penalty to 10 points):
   if not trust_pages.get("privacy"):
       cat_content += 10
       warning_signals.append("Privacy Policy link not detected on the homepage.")
   ```
3. Save the file. Because Flask runs with `debug=True`, changes take effect immediately on your next scan!

---

## 10. Future Improvements (Version 2.0 Ideas)

As an AI & Data Science student, you can expand this project in the future:
1. **WHOIS Domain Age:** Check domain creation date (newly registered domains < 30 days old carry higher risk).
2. **DNS & MX Records:** Inspect mail server records to verify whether the domain can receive legitimate emails.
3. **Machine Learning Model:** Train a Scikit-learn Classifier (Random Forest or Logistic Regression) on phishing URL datasets (e.g., from Kaggle or PhishTank) to predict risk probabilities alongside rule-based scoring.
4. **SSL Certificate Expiry Date:** Extract the exact number of days remaining before certificate expiration using Python's `ssl` socket module.
5. **Export to PDF:** Use `reportlab` or `weasyprint` to allow PDF report generation.

---

## 🎓 Academic Presentation Tips

When presenting WebTrust to your lecturer:
1. **Explain the Architecture:** Point out the modularity—how `checker.py` gathers data, `risk_score.py` applies heuristics, `graph.py` visualizes, and `app.py` routes.
2. **Highlight Ethics & Passive Analysis:** Emphasize that WebTrust respects ethical cybersecurity guidelines by only using standard HTTP GET requests and never performing invasive penetration tests.
3. **Demonstrate Data Visualization:** Show that data science visualizations can be cleanly generated using Matplotlib and seamlessly integrated into web dashboards without any client-side JavaScript.
