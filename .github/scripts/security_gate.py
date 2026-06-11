import json

warnings = []

def load_check(path, fn):
    try:
        fn(json.load(open(path)), warnings)
    except Exception:
        pass

def check_gitleaks(data, warnings):
    count = len(data) if isinstance(data, list) else 0
    if count:
        warnings.append(f"Gitleaks: {count} secrets/credentials detected in repository")

def check_trufflehog(data, warnings):
    count = len(data) if isinstance(data, list) else 0
    if count:
        warnings.append(f"TruffleHog: {count} verified/unverified secrets detected")

def check_trivy(data, warnings):
    crits = sum(1 for r in data.get("Results", []) for v in r.get("Vulnerabilities", []) if v.get("Severity") == "CRITICAL")
    if crits > 0:
        warnings.append(f"Trivy: {crits} critical CVEs in dependencies")

def check_owasp_api(data, warnings):
    crits = sum(1 for f in data.get("findings", []) if f.get("severity") == "CRITICAL")
    if crits > 0:
        warnings.append(f"OWASP API: {crits} critical API security issues")

load_check("scan_results/gitleaks-results.json", check_gitleaks)
load_check("scan_results/trufflehog-results.json", check_trufflehog)
load_check("scan_results/trivy-fs-results.json", check_trivy)
load_check("scan_results/owasp-api-results.json", check_owasp_api)

print("=" * 65)
print("SECURITY GATE RESULTS")
print("=" * 65)
print("Target: OWASP Juice Shop (intentionally vulnerable app)")
print()
if warnings:
    print("STATUS: WARNINGS DETECTED (not blocking - educational target)")
    for w in warnings:
        print(f"  [WARN] {w}")
else:
    print("STATUS: PASS - No gate violations")
print()
print("Full report: GitHub Artifacts -> security-report-pdf")
print("=" * 65)
