import json

def load(path, fn):
    try:
        return fn(json.load(open(path)))
    except Exception:
        return "ERR"

rows = [
    ("Gitleaks",         "scan_results/gitleaks-results.json",
     lambda d: f"{len(d) if isinstance(d, list) else 0} secrets"),
    ("TruffleHog",       "scan_results/trufflehog-results.json",
     lambda d: f"{len(d) if isinstance(d, list) else 0} secrets"),
    ("Semgrep",          "scan_results/semgrep-results.json",
     lambda d: f"{len(d.get('results', []))} findings"),
    ("SonarQube",        "scan_results/sonarqube-results.json",
     lambda d: f"{d.get('paging', {}).get('total', len(d.get('issues', [])))} issues"),
    ("Trivy (fs)",       "scan_results/trivy-fs-results.json",
     lambda d: f"{sum(len(r.get('Vulnerabilities', [])) for r in d.get('Results', []))} vulns"),
    ("npm audit",        "scan_results/npm-audit-results.json",
     lambda d: f"{d.get('metadata', {}).get('vulnerabilities', {}).get('total', '?')} vulns"),
    ("Grype",            "scan_results/grype-results.json",
     lambda d: f"{len(d.get('matches', []))} matches"),
    ("Checkov",          "scan_results/checkov-results.json",
     lambda d: f"{len(d.get('results', {}).get('failed_checks', []))} failed"),
    ("tfsec",            "scan_results/tfsec-results.json",
     lambda d: f"{len(d.get('results', []))} findings"),
    ("Trivy (image)",    "scan_results/trivy-image-results.json",
     lambda d: f"{sum(len(r.get('Vulnerabilities', [])) for r in d.get('Results', []))} vulns"),
    ("Docker Bench",     "scan_results/docker-bench-results.json",
     lambda d: f"WARN:{d.get('summary', {}).get('WARN', 0)} FAIL:{d.get('summary', {}).get('FAIL', 0)}"),
    ("ZAP",              "scan_results/zap-results.json",
     lambda d: f"{sum(len(s.get('alerts', [])) for s in d.get('site', []))} alert types"),
    ("Nuclei",           "scan_results/nuclei-results.json",
     lambda d: f"{len(d) if isinstance(d, list) else 0} findings"),
    ("Shannon AI",       "scan_results/shannon-results.json",
     lambda d: f"{len(d.get('findings', []))} findings"),
    ("OWASP API Top 10", "scan_results/owasp-api-results.json",
     lambda d: f"{len(d.get('findings', []))} findings"),
]
print()
print("+--------------------------+----------------------------------+")
print("|  ENTERPRISE DEVSECOPS PLATFORM - SCAN SUMMARY             |")
print("+--------------------------+----------------------------------+")
print("| Tool                     | Result                           |")
print("+--------------------------+----------------------------------+")
for tool, path, fn in rows:
    result = load(path, fn)
    ok = result != "ERR"
    icon = "+" if ok else "-"
    print(f"| [{icon}] {tool:<22}| {str(result):<33}|")
print("+--------------------------+----------------------------------+")
print()
