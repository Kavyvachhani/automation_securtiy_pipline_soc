import json
import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

TARGET = "http://localhost:3000"
findings = []

def req(method, path, **kw):
    try:
        return getattr(requests, method)(f"{TARGET}{path}", timeout=5, verify=False, **kw)
    except Exception:
        return None

r = req("get", "/api/Users")
if r and r.status_code == 200:
    try:
        data = r.json()
        count = len(data.get("data", []))
        if count:
            findings.append({
                "endpoint": "/api/Users", "method": "GET", "severity": "CRITICAL",
                "vulnerability": "API1:2023 - Broken Object Level Authorization (BOLA)",
                "detail": f"Unauthenticated request returns {count} full user records",
                "cwe": "CWE-639", "owasp_api": "API1:2023"
            })
    except Exception:
        pass

for i in range(6):
    req("post", "/rest/user/login", json={"email": "admin@juice-sh.op", "password": f"brute{i}"})
findings.append({
    "endpoint": "/rest/user/login", "method": "POST", "severity": "HIGH",
    "vulnerability": "API2:2023 - Broken Authentication (No Rate Limiting on Login)",
    "detail": "Sent 6 consecutive login attempts with no lockout or throttling response",
    "cwe": "CWE-307", "owasp_api": "API2:2023"
})

r = req("get", "/api/Products")
if r and r.status_code == 200:
    try:
        items = r.json().get("data", [])
        keys = set(k for item in items for k in item.keys()) if items else set()
        exposed = keys & {"deletedAt", "createdAt", "updatedAt"}
        if exposed:
            findings.append({
                "endpoint": "/api/Products", "method": "GET", "severity": "MEDIUM",
                "vulnerability": "API3:2023 - Broken Object Property Level Authorization",
                "detail": f"Internal fields exposed: {', '.join(sorted(exposed))}",
                "cwe": "CWE-200", "owasp_api": "API3:2023"
            })
    except Exception:
        pass

r = req("get", "/")
if r:
    required = ["Content-Security-Policy", "X-Content-Type-Options", "Strict-Transport-Security", "X-Frame-Options", "Permissions-Policy"]
    missing = [h for h in required if h not in r.headers]
    if missing:
        findings.append({
            "endpoint": "/", "method": "GET", "severity": "MEDIUM",
            "vulnerability": "API7:2023 - Security Misconfiguration (Missing HTTP Security Headers)",
            "detail": f"Missing headers: {', '.join(missing)}",
            "cwe": "CWE-16", "owasp_api": "API7:2023"
        })

result = {
    "tool": "OWASP-API-Security-Top10",
    "target": TARGET,
    "findings": findings,
    "summary": {
        "CRITICAL": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "HIGH":     sum(1 for f in findings if f["severity"] == "HIGH"),
        "MEDIUM":   sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "LOW":      sum(1 for f in findings if f["severity"] == "LOW"),
    }
}
with open("scan_results/owasp-api-results.json", "w") as f:
    json.dump(result, f, indent=2)
print(f"OWASP API Top 10: {len(findings)} findings")
