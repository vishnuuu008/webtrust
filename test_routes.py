import requests
import re
import sys

# Ensure UTF-8 output on Windows terminal
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

base = 'http://127.0.0.1:5000'

# Test Home
r = requests.get(base + '/')
assert r.status_code == 200
assert 'WebTrust' in r.text
assert 'Analyze Website' in r.text
print('✓ GET / : OK')

# Test How It Works
r = requests.get(base + '/how-it-works')
assert r.status_code == 200
assert 'How WebTrust Works' in r.text
print('✓ GET /how-it-works : OK')

# Test History
r = requests.get(base + '/history')
assert r.status_code == 200
assert 'Website Scan History' in r.text
print('✓ GET /history : OK')

# Test Analyze POST
r = requests.post(base + '/analyze', data={'url': 'https://example.com'})
assert r.status_code == 200
assert 'example.com' in r.text
assert 'Risk Score' in r.text
assert 'graph_breakdown' in r.text
assert 'graph_signals' in r.text
assert 'graph_history' in r.text
assert 'Security Check Cards' in r.text
print('✓ POST /analyze (https://example.com) : OK')

# Extract report filename and test download
match = re.search(r'download-report/([^\s"\'>]+)', r.text)
if match:
    rep_file = match.group(1)
    rep_res = requests.get(base + '/download-report/' + rep_file)
    assert rep_res.status_code == 200
    assert 'WEBTRUST - WEBSITE TRUST & RISK ASSESSMENT REPORT' in rep_res.text
    print(f'✓ GET /download-report/{rep_file} : OK')

print('\nALL HTTP ROUTE TESTS PASSED 100%! ✓')
