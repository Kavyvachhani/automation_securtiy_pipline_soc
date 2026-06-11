"""
Enterprise DevSecOps Report Generator - Lambda v2
Parses 15 scanner outputs, scores risk, maps to compliance frameworks,
and generates a multi-section SOC2-grade PDF report.
"""
import json
import os
import datetime
import boto3
from collections import defaultdict
from fpdf import FPDF
from fpdf.enums import XPos, YPos

s3 = boto3.client("s3")
BUCKET = os.environ.get("S3_BUCKET", "")

# --- SEVERITY CONSTANTS ---------------------------------------
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}
SEV_SCORE = {"CRITICAL": 40, "HIGH": 15, "MEDIUM": 5, "LOW": 1, "INFO": 0, "UNKNOWN": 0}

# --- COMPLIANCE MAPPINGS -------------------------------------
CWE_SOC2 = {
    "CWE-78": "CC6.1", "CWE-79": "CC6.1", "CWE-89": "CC6.1",
    "CWE-200": "CC6.7", "CWE-312": "CC6.7", "CWE-798": "CC6.2",
    "CWE-307": "CC6.6", "CWE-639": "CC6.3", "CWE-16": "CC6.8",
    "CWE-78": "CC6.1", "CWE-1321": "CC6.1",
}
CWE_OWASP = {
    "CWE-79": "A03", "CWE-89": "A03", "CWE-78": "A03",
    "CWE-200": "A02", "CWE-312": "A02", "CWE-798": "A07",
    "CWE-307": "A07", "CWE-639": "A01", "CWE-16": "A05",
}
CWE_NIST = {
    "CWE-79": "SI-10", "CWE-89": "SI-10", "CWE-200": "AC-3",
    "CWE-312": "SC-28", "CWE-798": "IA-5", "CWE-307": "AC-7",
    "CWE-639": "AC-3", "CWE-16": "CM-6",
}

# --- S3 HELPERS ----------------------------------------------
def get_s3_json(key):
    try:
        obj = s3.get_object(Bucket=BUCKET, Key=key)
        raw = obj["Body"].read().decode("utf-8")
        return json.loads(raw)
    except Exception as e:
        print(f"[S3] Skip {key}: {e}")
        return None

def safe_str(val, maxlen=90):
    if val is None:
        return ""
    s = str(val).replace("\n", " ").replace("\r", " ").strip()
    return s[:maxlen] + "..." if len(s) > maxlen else s

# --- NORMALISED FINDING --------------------------------------
def finding(tool, sev, title, rule_id="", file_path="", line=0,
            cwe="", owasp="", detail="", endpoint=""):
    sev = sev.upper() if sev else "UNKNOWN"
    if sev not in SEV_ORDER:
        sev = "UNKNOWN"
    return {
        "tool": tool, "severity": sev, "title": safe_str(title),
        "rule_id": safe_str(rule_id, 50), "file_path": safe_str(file_path, 70),
        "line": line or 0, "cwe": cwe or "",
        "owasp": owasp or CWE_OWASP.get(cwe, ""),
        "soc2": CWE_SOC2.get(cwe, ""),
        "nist": CWE_NIST.get(cwe, ""),
        "detail": safe_str(detail),
        "endpoint": safe_str(endpoint, 50),
    }

# --- PARSERS -------------------------------------------------

def parse_gitleaks(data):
    """Binary JSON: array of leak objects"""
    findings = []
    if not data or not isinstance(data, list):
        return findings
    for item in data:
        findings.append(finding(
            tool="Gitleaks",
            sev="CRITICAL",
            title=f"Secret exposed: {item.get('RuleID', 'unknown-rule')}",
            rule_id=item.get("RuleID", ""),
            file_path=item.get("File", ""),
            line=item.get("StartLine", 0),
            cwe="CWE-798",
            detail=f"Commit {str(item.get('Commit',''))[:7]} by {item.get('Author','')} - {item.get('Description','')}"
        ))
    return findings


def parse_trufflehog(data):
    """Array of JSON-lines objects from TruffleHog v3"""
    findings = []
    if not data or not isinstance(data, list):
        return findings
    for item in data:
        detector = item.get("DetectorName", item.get("DetectorType", "unknown"))
        verified = item.get("Verified", False)
        sev = "CRITICAL" if verified else "HIGH"
        src = item.get("SourceMetadata", {}).get("Data", {})
        file_info = next(iter(src.values()), {}) if src else {}
        fpath = file_info.get("file", file_info.get("filename", ""))
        line = file_info.get("line", file_info.get("startLine", 0))
        findings.append(finding(
            tool="TruffleHog",
            sev=sev,
            title=f"{'[VERIFIED] ' if verified else ''}Secret: {detector}",
            rule_id=str(detector),
            file_path=fpath,
            line=line,
            cwe="CWE-798",
            detail=f"Verified={verified} Raw={str(item.get('Raw',''))[:30]}..."
        ))
    return findings


def parse_semgrep(data):
    """Semgrep --json output: {'results': [...]}"""
    findings = []
    if not data or "results" not in data:
        return findings
    for r in data["results"]:
        extra = r.get("extra", {})
        raw_sev = extra.get("severity", "INFO").upper()
        # Semgrep uses ERROR/WARNING/INFO - map to standard
        sev_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
        sev = sev_map.get(raw_sev, raw_sev)
        # If semgrep returns HIGH/CRITICAL directly, keep it
        if raw_sev in ("HIGH", "CRITICAL", "MEDIUM", "LOW"):
            sev = raw_sev
        meta = extra.get("metadata", {})
        cwe_list = meta.get("cwe", [])
        cwe = cwe_list[0] if cwe_list else ""
        owasp_list = meta.get("owasp", [])
        owasp = owasp_list[0][:10] if owasp_list else ""
        findings.append(finding(
            tool="Semgrep",
            sev=sev,
            title=extra.get("message", r.get("check_id", "No message")),
            rule_id=r.get("check_id", ""),
            file_path=r.get("path", ""),
            line=r.get("start", {}).get("line", 0),
            cwe=cwe,
            owasp=owasp,
            detail=f"Lines {r.get('start',{}).get('line',0)}-{r.get('end',{}).get('line',0)}"
        ))
    return findings


def parse_sonarqube(data):
    """SonarQube /api/issues/search response: {'issues': [...]}"""
    findings = []
    if not data:
        return findings
    # Handle both the full API response and skipped placeholder
    if data.get("_skipped"):
        return findings
    issues = data.get("issues", [])
    sev_map = {"BLOCKER": "CRITICAL", "CRITICAL": "CRITICAL", "MAJOR": "HIGH", "MINOR": "MEDIUM", "INFO": "LOW"}
    for issue in issues:
        sev = sev_map.get(issue.get("severity", "INFO"), "LOW")
        component = issue.get("component", "")
        file_path = component.split(":")[-1] if ":" in component else component
        findings.append(finding(
            tool="SonarQube",
            sev=sev,
            title=issue.get("message", issue.get("rule", "No message")),
            rule_id=issue.get("rule", ""),
            file_path=file_path,
            line=issue.get("line", 0),
            cwe="",
            detail=f"Type={issue.get('type','')} Status={issue.get('status','')} Effort={issue.get('effort','')}"
        ))
    return findings


def parse_trivy(data, source_label="Trivy-FS"):
    """Trivy --format json: {'Results': [{'Vulnerabilities': [...]}]}"""
    findings = []
    if not data or "Results" not in data:
        return findings
    for result in data.get("Results", []):
        target = result.get("Target", "")
        for v in result.get("Vulnerabilities", []) or []:
            sev = v.get("Severity", "UNKNOWN").upper()
            cve_id = v.get("VulnerabilityID", "N/A")
            pkg = v.get("PkgName", "")
            ver = v.get("InstalledVersion", "")
            fixed = v.get("FixedVersion", "unpatched")
            cwe_list = v.get("CweIDs", [])
            cwe = cwe_list[0] if cwe_list else ""
            findings.append(finding(
                tool=source_label,
                sev=sev,
                title=f"{cve_id}: {v.get('Title', pkg + ' vulnerability')}",
                rule_id=cve_id,
                file_path=target,
                cwe=cwe,
                detail=f"pkg={pkg}@{ver} fixed={fixed}"
            ))
    return findings


def parse_grype(data):
    """Grype --output json: {'matches': [...]}"""
    findings = []
    if not data or "matches" not in data:
        return findings
    sev_map = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "negligible": "INFO"}
    for match in data.get("matches", []):
        vuln = match.get("vulnerability", {})
        art = match.get("artifact", {})
        sev = sev_map.get(vuln.get("severity", "").lower(), "UNKNOWN")
        findings.append(finding(
            tool="Grype",
            sev=sev,
            title=f"{vuln.get('id','N/A')}: {art.get('name','')}@{art.get('version','')}",
            rule_id=vuln.get("id", ""),
            file_path=art.get("type", "") + "/" + art.get("name", ""),
            detail=f"fix={vuln.get('fix',{}).get('state','unknown')} namespace={vuln.get('namespace','')}"
        ))
    return findings


def parse_npm_audit(data):
    """npm audit --json: {'vulnerabilities': {...}, 'metadata': {...}}"""
    findings = []
    if not data:
        return findings
    sev_map = {"critical": "CRITICAL", "high": "HIGH", "moderate": "MEDIUM", "low": "LOW", "info": "INFO"}
    vulns = data.get("vulnerabilities", {})
    for pkg_name, vuln in vulns.items():
        sev = sev_map.get(vuln.get("severity", "low").lower(), "LOW")
        via = vuln.get("via", [])
        via_str = ", ".join(v if isinstance(v, str) else v.get("title", "") for v in via[:3])
        findings.append(finding(
            tool="npm audit",
            sev=sev,
            title=f"{pkg_name}: {via_str or 'Vulnerable dependency'}",
            rule_id=pkg_name,
            file_path="package.json",
            detail=f"range={vuln.get('range','')} fixAvailable={vuln.get('fixAvailable',False)}"
        ))
    return findings


def parse_checkov(data):
    """Checkov --output json: {'results': {'failed_checks': [...]}}"""
    findings = []
    if not data:
        return findings
    if isinstance(data, list):
        data = data[0] if data else {}
    failed = data.get("results", {}).get("failed_checks", [])
    for check in failed:
        check_id = check.get("check_id", "N/A")
        check_name = check.get("check_name", "IaC misconfiguration")
        file_path = check.get("file_path", check.get("repo_file_path", ""))
        resource = check.get("resource", "")
        line_range = check.get("file_line_range", [0, 0])
        line = line_range[0] if isinstance(line_range, list) and line_range else 0
        findings.append(finding(
            tool="Checkov",
            sev="HIGH",
            title=check_name,
            rule_id=check_id,
            file_path=file_path,
            line=line,
            cwe="CWE-16",
            detail=f"resource={resource}"
        ))
    return findings


def parse_tfsec(data):
    """tfsec --format json: {'results': [...]}"""
    findings = []
    if not data or "results" not in data:
        return findings
    sev_map = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "WARNING": "MEDIUM"}
    for result in data.get("results", []):
        sev = sev_map.get(result.get("severity", "LOW").upper(), "LOW")
        loc = result.get("location", {})
        findings.append(finding(
            tool="tfsec",
            sev=sev,
            title=result.get("rule_description", result.get("description", "IaC issue")),
            rule_id=result.get("rule_id", result.get("long_id", "")),
            file_path=loc.get("filename", ""),
            line=loc.get("start_line", 0),
            cwe="CWE-16",
            detail=f"resource={result.get('resource','')} impact={result.get('impact','')}"
        ))
    return findings


def parse_zap(data):
    """ZAP report_json.json: {'site': [{'alerts': [...]}]}"""
    findings = []
    if not data or "site" not in data:
        return findings
    risk_map = {
        "3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO",
        "High": "HIGH", "Medium": "MEDIUM", "Low": "LOW", "Informational": "INFO"
    }
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            risk_code = str(alert.get("riskcode", "0"))
            risk_desc = alert.get("riskdesc", "")
            # Try riskcode first, then parse riskdesc
            sev = risk_map.get(risk_code, "INFO")
            if sev == "INFO" and risk_desc:
                for label in ("High", "Medium", "Low"):
                    if label in risk_desc:
                        sev = risk_map[label]
                        break
            cwe_id = alert.get("cweid", "")
            cwe = f"CWE-{cwe_id}" if cwe_id and cwe_id != "-1" else ""
            count = int(alert.get("count", 1))
            instances = alert.get("instances", [])
            first_url = instances[0].get("uri", "") if instances else site.get("@name", "")
            findings.append(finding(
                tool="OWASP ZAP",
                sev=sev,
                title=alert.get("alert", alert.get("name", "ZAP Alert")),
                rule_id=str(alert.get("pluginid", "")),
                endpoint=first_url,
                cwe=cwe,
                detail=f"count={count} confidence={alert.get('confidence','')} solution={safe_str(alert.get('solution',''),60)}"
            ))
    return findings


def parse_nuclei(data):
    """Nuclei JSON array: [{template-id, info: {severity}, host, ...}]"""
    findings = []
    if not data:
        return findings
    if not isinstance(data, list):
        data = [data]
    sev_map = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO", "unknown": "UNKNOWN"}
    for item in data:
        if not isinstance(item, dict):
            continue
        info = item.get("info", {})
        sev = sev_map.get(info.get("severity", "info").lower(), "INFO")
        findings.append(finding(
            tool="Nuclei",
            sev=sev,
            title=info.get("name", item.get("template-id", "Nuclei Finding")),
            rule_id=item.get("template-id", ""),
            endpoint=item.get("host", item.get("url", item.get("matched-at", ""))),
            detail=f"tags={','.join(info.get('tags',[])[:4])} type={item.get('type','')}"
        ))
    return findings


def parse_shannon(data):
    """Shannon AI custom output: {'findings': [...]}"""
    findings = []
    if not data or "findings" not in data:
        return findings
    for f in data["findings"]:
        sev = f.get("severity", "UNKNOWN").upper()
        findings.append(finding(
            tool="Shannon AI",
            sev=sev,
            title=f.get("vulnerability", "API Vulnerability"),
            rule_id=f.get("endpoint", ""),
            endpoint=f.get("endpoint", ""),
            detail=f.get("description", ""),
            cwe=f.get("cwe", "CWE-639") if "BOLA" in f.get("vulnerability", "") else ""
        ))
    return findings


def parse_owasp_api(data):
    """OWASP API Top 10 custom check: {'findings': [...]}"""
    findings = []
    if not data or "findings" not in data:
        return findings
    for f in data["findings"]:
        sev = f.get("severity", "MEDIUM").upper()
        findings.append(finding(
            tool="OWASP API Top 10",
            sev=sev,
            title=f.get("vulnerability", "API Security Issue"),
            rule_id=f.get("owasp_api", ""),
            endpoint=f.get("endpoint", ""),
            cwe=f.get("cwe", ""),
            detail=f.get("detail", "")
        ))
    return findings


def parse_docker_bench(data):
    """Docker Bench custom output: {'findings': [{'status': 'FAIL/WARN', 'description': '...'}]}"""
    findings = []
    if not data or "findings" not in data:
        return findings
    sev_map = {"FAIL": "HIGH", "WARN": "MEDIUM", "INFO": "LOW", "NOTE": "INFO", "PASS": None}
    for f in data["findings"]:
        status = f.get("status", "INFO")
        sev = sev_map.get(status)
        if sev is None:
            continue
        desc = f.get("description", "Docker configuration issue")
        findings.append(finding(
            tool="Docker Bench",
            sev=sev,
            title=desc[:80],
            rule_id=status,
            detail=desc
        ))
    return findings


# --- RISK SCORING --------------------------------------------

def calculate_risk_score(all_findings):
    if not all_findings:
        return 100, "A+"
    raw = sum(SEV_SCORE.get(f["severity"], 0) for f in all_findings)
    score = max(0, 100 - min(raw, 100))
    if score >= 90:   grade = "A+"
    elif score >= 80: grade = "A"
    elif score >= 70: grade = "B"
    elif score >= 60: grade = "C"
    elif score >= 50: grade = "D"
    else:             grade = "F"
    return score, grade


def severity_counts(findings):
    counts = defaultdict(int)
    for f in findings:
        counts[f["severity"]] += 1
    return dict(counts)


# --- PDF GENERATION ------------------------------------------

class SecurityPDF(FPDF):
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=20)
        self.set_margins(15, 15, 15)
        self._report_title = "SOC2 DevSecOps Master Security Report"

    def header(self):
        if self.page_no() == 1:
            return
        self.set_fill_color(15, 23, 42)
        self.rect(0, 0, 210, 10, "F")
        self.set_font("Helvetica", "B", 7)
        self.set_text_color(180, 180, 180)
        self.set_y(2)
        self.cell(0, 6, f"CONFIDENTIAL - DevSecOps Security Report  |  OWASP Juice Shop", align="C",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)
        self.set_y(12)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(120, 120, 120)
        self.cell(0, 5, f"Page {self.page_no()} | Generated {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} | CONFIDENTIAL",
                  align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)

    def sev_color(self, sev):
        return {
            "CRITICAL": (185, 28, 28),
            "HIGH":     (234, 88, 12),
            "MEDIUM":   (202, 138, 4),
            "LOW":      (37, 99, 235),
            "INFO":     (75, 85, 99),
        }.get(sev, (75, 85, 99))

    def cover_page(self, meta):
        self.add_page()
        # Dark header band
        self.set_fill_color(15, 23, 42)
        self.rect(0, 0, 210, 60, "F")
        self.set_font("Helvetica", "B", 22)
        self.set_text_color(255, 255, 255)
        self.set_y(18)
        self.cell(0, 12, "SOC2 ENTERPRISE SECURITY REPORT", align="C",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_font("Helvetica", "", 11)
        self.set_text_color(148, 163, 184)
        self.cell(0, 8, "DevSecOps Platform - OWASP Juice Shop", align="C",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)
        self.set_y(70)

        # Metadata table
        self.set_font("Helvetica", "B", 10)
        self.set_fill_color(241, 245, 249)
        rows = [
            ("Generated",   meta["timestamp"]),
            ("Commit SHA",  meta["commit_sha"]),
            ("Branch",      meta["branch"]),
            ("Run ID",      meta["run_id"]),
            ("Pipeline",    "Enterprise DevSecOps Platform v2"),
            ("Target",      "OWASP Juice Shop (Intentionally Vulnerable)"),
            ("Classification", "CONFIDENTIAL - SOC2 Audit Evidence"),
        ]
        for label, value in rows:
            self.set_font("Helvetica", "B", 9)
            self.set_fill_color(226, 232, 240)
            self.cell(45, 8, f"  {label}", fill=True, border=1)
            self.set_font("Helvetica", "", 9)
            self.set_fill_color(248, 250, 252)
            self.cell(0, 8, f"  {value}", fill=True, border=1,
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(8)

        # SOC2 badge
        self.set_fill_color(15, 23, 42)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 9)
        self.cell(0, 9, "  SOC2 TYPE II AUDIT EVIDENCE  |  ISO 27001  |  NIST 800-53  |  OWASP ASVS",
                  fill=True, align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)

    def executive_summary(self, all_findings, score, grade, meta):
        self.add_page()
        self.section_header("EXECUTIVE SUMMARY", (15, 23, 42))
        counts = severity_counts(all_findings)
        total = len(all_findings)

        # Risk score box
        self.set_font("Helvetica", "B", 11)
        self.set_fill_color(15, 23, 42)
        self.set_text_color(255, 255, 255)
        self.cell(0, 10, f"  SECURITY RISK SCORE: {score}/100  |  GRADE: {grade}  |  TOTAL FINDINGS: {total}",
                  fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)
        self.ln(4)

        # Release gate
        crits = counts.get("CRITICAL", 0)
        highs = counts.get("HIGH", 0)
        gate_color = (185, 28, 28) if crits > 0 else (234, 88, 12) if highs > 0 else (21, 128, 61)
        gate_text = "RELEASE BLOCKED" if crits > 0 else "REVIEW REQUIRED" if highs > 0 else "RELEASE APPROVED"
        self.set_fill_color(*gate_color)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 12)
        self.cell(0, 10, f"  RELEASE GATE STATUS: {gate_text}", fill=True,
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)
        self.ln(5)

        # Severity breakdown
        self.set_font("Helvetica", "B", 10)
        self.cell(0, 7, "FINDINGS BY SEVERITY", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(2)
        col_w = [35, 25, 110]
        self.set_font("Helvetica", "B", 9)
        self.set_fill_color(30, 41, 59)
        self.set_text_color(255, 255, 255)
        for txt, w in zip(["Severity", "Count", "Description"], col_w):
            self.cell(w, 7, f"  {txt}", fill=True, border=1)
        self.ln()
        self.set_text_color(0, 0, 0)
        rows = [
            ("CRITICAL", "Remote code execution, auth bypass, credential exposure requiring immediate action"),
            ("HIGH",     "Significant risk: SQL injection, XSS, insecure secrets, broken auth"),
            ("MEDIUM",   "Moderate risk: configuration issues, missing headers, deprecated protocols"),
            ("LOW",      "Minor risk: best practice violations, informational exposures"),
            ("INFO",     "Informational: no direct exploitability"),
        ]
        for sev, desc in rows:
            count = counts.get(sev, 0)
            r, g, b = self.sev_color(sev)
            self.set_fill_color(r, g, b)
            self.set_text_color(255, 255, 255)
            self.set_font("Helvetica", "B", 9)
            self.cell(col_w[0], 7, f"  {sev}", fill=True, border=1)
            self.set_fill_color(245, 245, 245) if count == 0 else self.set_fill_color(255, 245, 245)
            self.set_text_color(0, 0, 0)
            self.set_font("Helvetica", "B" if count > 0 else "", 9)
            self.cell(col_w[1], 7, f"  {count}", fill=True, border=1)
            self.set_font("Helvetica", "", 8)
            self.cell(col_w[2], 7, f"  {desc}", fill=True, border=1)
            self.ln()
        self.ln(5)

        # Tool coverage
        self.set_font("Helvetica", "B", 10)
        self.cell(0, 7, "SCANNER COVERAGE", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(2)
        tools_by_category = {
            "Secrets":    ["Gitleaks", "TruffleHog"],
            "SAST":       ["Semgrep", "SonarQube"],
            "SCA":        ["Trivy-FS", "Grype", "npm audit"],
            "IaC":        ["Checkov", "tfsec"],
            "Container":  ["Trivy-Image", "Docker Bench"],
            "DAST":       ["OWASP ZAP", "Nuclei"],
            "API":        ["Shannon AI", "OWASP API Top 10"],
        }
        tools_with_findings = set(f["tool"] for f in all_findings)
        col_w2 = [40, 135]
        self.set_fill_color(30, 41, 59)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 9)
        for txt, w in zip(["Category", "Scanners"], col_w2):
            self.cell(w, 7, f"  {txt}", fill=True, border=1)
        self.ln()
        self.set_text_color(0, 0, 0)
        for cat, tools in tools_by_category.items():
            tool_str = "  "
            for t in tools:
                has = any(t.lower() in tf.lower() for tf in tools_with_findings)
                tool_str += f"[{'[OK]' if has else '·'}] {t}  "
            self.set_fill_color(248, 250, 252)
            self.set_font("Helvetica", "B", 9)
            self.cell(col_w2[0], 7, f"  {cat}", fill=True, border=1)
            self.set_font("Helvetica", "", 8)
            self.cell(col_w2[1], 7, tool_str, fill=True, border=1)
            self.ln()
        self.ln(5)

        # Compliance Score
        soc2_mapped = sum(1 for f in all_findings if f.get("soc2"))
        compliance_pct = max(0, 100 - min(100, crits * 20 + highs * 5))
        self.set_font("Helvetica", "B", 10)
        self.cell(0, 7, "COMPLIANCE POSTURE", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(2)
        comp_rows = [
            ("SOC2 Type II",    f"{compliance_pct}% posture  ({soc2_mapped} findings mapped to Trust Service Criteria)"),
            ("ISO 27001",       f"Risk-based assessment required - {crits + highs} high-impact findings to address"),
            ("NIST 800-53",     f"AC/IA/SI controls affected - {len([f for f in all_findings if f.get('nist')])} mapped findings"),
            ("OWASP ASVS",      f"Verification Level 2 target - {len([f for f in all_findings if f.get('owasp')])} OWASP-mapped findings"),
            ("CIS Controls",    f"CIS v8 coverage: Secrets(CS1), Vuln Mgmt(CS7), AppSec(CS16)"),
        ]
        self.set_fill_color(30, 41, 59)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 9)
        self.cell(40, 7, "  Framework", fill=True, border=1)
        self.cell(0, 7, "  Status", fill=True, border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)
        for fw, status in comp_rows:
            self.set_fill_color(248, 250, 252)
            self.set_font("Helvetica", "B", 9)
            self.cell(40, 7, f"  {fw}", fill=True, border=1)
            self.set_font("Helvetica", "", 8)
            self.cell(0, 7, f"  {status}", fill=True, border=1,
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def section_header(self, title, color=(30, 41, 59)):
        self.set_fill_color(*color)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 13)
        self.cell(0, 11, f"  {title}", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)
        self.ln(3)

    def tool_section(self, tool_name, findings, description=""):
        self.add_page()
        counts = severity_counts(findings)
        summary = "  ".join(f"{s}: {c}" for s, c in sorted(counts.items(), key=lambda x: SEV_ORDER.get(x[0], 9)) if c > 0)
        self.section_header(tool_name.upper())
        if description:
            self.set_font("Helvetica", "I", 9)
            self.set_text_color(71, 85, 105)
            self.cell(0, 6, description, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.set_text_color(0, 0, 0)
        self.set_font("Helvetica", "B", 9)
        if not findings:
            self.set_fill_color(220, 252, 231)
            self.cell(0, 8, "  No findings detected - PASS", fill=True,
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.ln(3)
            return
        # Summary bar
        self.set_fill_color(241, 245, 249)
        self.cell(0, 8, f"  FINDINGS SUMMARY: {summary}  |  Total: {len(findings)}",
                  fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(3)
        # Table header
        col_w = [18, 55, 30, 22, 55]
        self.set_fill_color(30, 41, 59)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 8)
        for txt, w in zip(["SEV", "TITLE / VULNERABILITY", "RULE / ID", "FILE:LINE", "DETAIL / CWE / OWASP"], col_w):
            self.cell(w, 7, f" {txt}", fill=True, border=1)
        self.ln()
        self.set_text_color(0, 0, 0)

        shown = 0
        max_show = 50
        for f in sorted(findings, key=lambda x: SEV_ORDER.get(x["severity"], 9)):
            if shown >= max_show:
                break
            r, g, b = self.sev_color(f["severity"])
            self.set_fill_color(r, g, b)
            self.set_text_color(255, 255, 255)
            self.set_font("Helvetica", "B", 7)
            self.cell(col_w[0], 6, f" {f['severity'][:4]}", fill=True, border=1)
            self.set_fill_color(252, 252, 252)
            self.set_text_color(0, 0, 0)
            self.set_font("Helvetica", "", 7)
            title_str = f["title"][:52]
            ep = f.get("endpoint", "")
            if ep and ep not in title_str:
                title_str = f"{title_str} [{ep[:20]}]"
            self.cell(col_w[1], 6, f" {title_str[:53]}", fill=True, border=1)
            self.cell(col_w[2], 6, f" {f['rule_id'][:27]}", fill=True, border=1)
            loc = f["file_path"][:18] if f["file_path"] else ""
            if f["line"]:
                loc = f"{loc}:{f['line']}"
            self.cell(col_w[3], 6, f" {loc}", fill=True, border=1)
            detail = f["detail"][:30]
            if f.get("cwe"):
                detail = f"{f['cwe']} | {detail}"
            elif f.get("owasp"):
                detail = f"OWASP-{f['owasp']} | {detail}"
            self.cell(col_w[4], 6, f" {detail[:52]}", fill=True, border=1)
            self.ln()
            shown += 1

        if len(findings) > max_show:
            self.set_font("Helvetica", "I", 8)
            self.set_fill_color(241, 245, 249)
            self.cell(0, 6, f"  ... and {len(findings) - max_show} more findings (see JSON report for full list)",
                      fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(3)

    def compliance_section(self, all_findings):
        self.add_page()
        self.section_header("COMPLIANCE MAPPING - SOC2 / ISO27001 / NIST / OWASP")

        # Group by SOC2 criteria
        by_soc2 = defaultdict(list)
        for f in all_findings:
            by_soc2[f.get("soc2") or "Unmapped"].append(f)

        soc2_labels = {
            "CC6.1": "CC6.1 - Logical Access Controls",
            "CC6.2": "CC6.2 - Credentials and Authentication",
            "CC6.3": "CC6.3 - Access Privileges",
            "CC6.6": "CC6.6 - Protection Against Threats",
            "CC6.7": "CC6.7 - Data Transmission and Disposal",
            "CC6.8": "CC6.8 - Prevention of Unauthorized Software",
            "Unmapped": "Unmapped - General Security Findings",
        }
        col_w = [45, 20, 115]
        self.set_fill_color(30, 41, 59)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 9)
        for txt, w in zip(["SOC2 Criterion", "Count", "Sample Findings"], col_w):
            self.cell(w, 7, f"  {txt}", fill=True, border=1)
        self.ln()
        self.set_text_color(0, 0, 0)
        for crit in sorted(by_soc2.keys()):
            items = by_soc2[crit]
            label = soc2_labels.get(crit, crit)
            sample = items[0]["title"][:70] if items else ""
            self.set_font("Helvetica", "B", 8)
            self.set_fill_color(248, 250, 252)
            self.cell(col_w[0], 6, f"  {label[:43]}", fill=True, border=1)
            self.cell(col_w[1], 6, f"  {len(items)}", fill=True, border=1)
            self.set_font("Helvetica", "", 7)
            extra = f" +{len(items)-1} more" if len(items) > 1 else ""
            self.cell(col_w[2], 6, f"  {sample[:75]}{extra}", fill=True, border=1)
            self.ln()
        self.ln(6)

        # OWASP Top 10 mapping
        self.set_font("Helvetica", "B", 10)
        self.cell(0, 7, "OWASP TOP 10 MAPPING", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(2)
        by_owasp = defaultdict(list)
        for f in all_findings:
            by_owasp[f.get("owasp") or "N/A"].append(f)
        owasp_labels = {
            "A01": "A01 - Broken Access Control",
            "A02": "A02 - Cryptographic Failures",
            "A03": "A03 - Injection",
            "A04": "A04 - Insecure Design",
            "A05": "A05 - Security Misconfiguration",
            "A06": "A06 - Vulnerable and Outdated Components",
            "A07": "A07 - Identification and Authentication Failures",
            "A08": "A08 - Software and Data Integrity Failures",
            "A09": "A09 - Security Logging and Monitoring Failures",
            "A10": "A10 - Server-Side Request Forgery",
            "N/A": "Not mapped to OWASP Top 10",
        }
        col_w2 = [60, 20, 100]
        self.set_fill_color(30, 41, 59)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 9)
        for txt, w in zip(["OWASP Category", "Count", "Sample Finding"], col_w2):
            self.cell(w, 7, f"  {txt}", fill=True, border=1)
        self.ln()
        self.set_text_color(0, 0, 0)
        for cat in sorted(by_owasp.keys()):
            items = by_owasp[cat]
            label = owasp_labels.get(cat, cat)
            sample = items[0]["title"][:55] if items else ""
            self.set_font("Helvetica", "B", 8)
            self.set_fill_color(248, 250, 252)
            self.cell(col_w2[0], 6, f"  {label[:58]}", fill=True, border=1)
            self.cell(col_w2[1], 6, f"  {len(items)}", fill=True, border=1)
            self.set_font("Helvetica", "", 7)
            self.cell(col_w2[2], 6, f"  {sample[:55]}", fill=True, border=1)
            self.ln()

    def appendix(self, meta, scan_files):
        self.add_page()
        self.section_header("APPENDIX - EVIDENCE COLLECTION")
        self.set_font("Helvetica", "B", 10)
        self.cell(0, 7, "SCAN METADATA", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(2)
        for label, value in meta.items():
            self.set_font("Helvetica", "B", 9)
            self.set_fill_color(226, 232, 240)
            self.cell(45, 7, f"  {label}", fill=True, border=1)
            self.set_font("Helvetica", "", 9)
            self.set_fill_color(248, 250, 252)
            self.cell(0, 7, f"  {value}", fill=True, border=1,
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(5)
        self.set_font("Helvetica", "B", 10)
        self.cell(0, 7, "EVIDENCE FILES (S3 RAW SCANNER OUTPUTS)", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(2)
        self.set_fill_color(30, 41, 59)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 9)
        self.cell(80, 7, "  File", fill=True, border=1)
        self.cell(0, 7, "  SHA256 Checksum", fill=True, border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)
        self.set_font("Helvetica", "", 8)
        for sf in scan_files:
            if isinstance(sf, dict):
                fname = sf.get("file", str(sf))
                sha = sf.get("sha256", "N/A")[:36]
            else:
                fname = str(sf)
                sha = "N/A"
            self.set_fill_color(248, 250, 252)
            self.cell(80, 6, f"  {fname[:76]}", fill=True, border=1)
            self.cell(0, 6, f"  {sha}", fill=True, border=1,
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)


# --- ORCHESTRATOR --------------------------------------------

def handler(event, context):
    print(f"[Lambda] Event: {json.dumps(event)}")
    commit_sha = event.get("commit_sha", "latest")
    run_id     = event.get("run_id", "unknown")
    run_number = event.get("run_number", "0")
    branch     = event.get("branch", "main")
    actor      = event.get("actor", "unknown")
    repository = event.get("repository", "unknown")

    prefix = f"scans/{commit_sha}"
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    # -- Load all scan files --------------------------------
    loaders = {
        "gitleaks":    get_s3_json(f"{prefix}/gitleaks-results.json"),
        "trufflehog":  get_s3_json(f"{prefix}/trufflehog-results.json"),
        "semgrep":     get_s3_json(f"{prefix}/semgrep-results.json"),
        "sonarqube":   get_s3_json(f"{prefix}/sonarqube-results.json"),
        "trivy_fs":    get_s3_json(f"{prefix}/trivy-fs-results.json"),
        "trivy_img":   get_s3_json(f"{prefix}/trivy-image-results.json"),
        "grype":       get_s3_json(f"{prefix}/grype-results.json"),
        "npm_audit":   get_s3_json(f"{prefix}/npm-audit-results.json"),
        "checkov":     get_s3_json(f"{prefix}/checkov-results.json"),
        "tfsec":       get_s3_json(f"{prefix}/tfsec-results.json"),
        "zap":         get_s3_json(f"{prefix}/zap-results.json"),
        "nuclei":      get_s3_json(f"{prefix}/nuclei-results.json"),
        "shannon":     get_s3_json(f"{prefix}/shannon-results.json"),
        "owasp_api":   get_s3_json(f"{prefix}/owasp-api-results.json"),
        "docker_bench":get_s3_json(f"{prefix}/docker-bench-results.json"),
        "manifest":    get_s3_json(f"{prefix}/manifest.json"),
    }

    # -- Parse all scanner outputs --------------------------
    all_findings_by_tool = {
        "Secret Scanning - Gitleaks":        parse_gitleaks(loaders["gitleaks"]),
        "Secret Scanning - TruffleHog":      parse_trufflehog(loaders["trufflehog"]),
        "SAST - Semgrep":                    parse_semgrep(loaders["semgrep"]),
        "SAST - SonarQube":                  parse_sonarqube(loaders["sonarqube"]),
        "SCA - Trivy (Filesystem)":          parse_trivy(loaders["trivy_fs"], "Trivy-FS"),
        "SCA - Trivy (Container Image)":     parse_trivy(loaders["trivy_img"], "Trivy-Image"),
        "SCA - Grype":                       parse_grype(loaders["grype"]),
        "SCA - npm audit":                   parse_npm_audit(loaders["npm_audit"]),
        "IaC Security - Checkov":            parse_checkov(loaders["checkov"]),
        "IaC Security - tfsec":              parse_tfsec(loaders["tfsec"]),
        "Container - Docker Bench Security": parse_docker_bench(loaders["docker_bench"]),
        "DAST - OWASP ZAP":                  parse_zap(loaders["zap"]),
        "DAST - Nuclei":                     parse_nuclei(loaders["nuclei"]),
        "API Security - Shannon AI":         parse_shannon(loaders["shannon"]),
        "API Security - OWASP API Top 10":   parse_owasp_api(loaders["owasp_api"]),
    }

    all_findings = [f for findings in all_findings_by_tool.values() for f in findings]
    score, grade = calculate_risk_score(all_findings)

    print(f"[Lambda] Total findings: {len(all_findings)} | Score: {score}/100 | Grade: {grade}")
    for tool, findings in all_findings_by_tool.items():
        if findings:
            print(f"[Lambda]   {tool}: {len(findings)} findings")

    meta = {
        "Commit SHA":   commit_sha,
        "Branch":       branch,
        "Actor":        actor,
        "Repository":   repository,
        "Run ID":       run_id,
        "Run Number":   run_number,
        "Generated":    timestamp,
        "Risk Score":   f"{score}/100 (Grade: {grade})",
        "Total Findings": str(len(all_findings)),
        "S3 Prefix":    f"s3://{BUCKET}/{prefix}/",
    }

    scan_files = loaders["manifest"].get("scan_files", []) if loaders["manifest"] else []

    # -- Build PDF -----------------------------------------
    pdf = SecurityPDF()
    pdf.cover_page(meta)
    pdf.executive_summary(all_findings, score, grade, meta)

    tool_descriptions = {
        "Secret Scanning - Gitleaks":        "Detects credentials, API keys, tokens, and private keys committed to git history.",
        "Secret Scanning - TruffleHog":      "Deep entropy and regex scanning with secret verification against service APIs.",
        "SAST - Semgrep":                    "Pattern-based static analysis: SQL injection, XSS, eval injection, hardcoded secrets.",
        "SAST - SonarQube":                  "Enterprise SAST platform: bugs, code smells, security hotspots, coverage.",
        "SCA - Trivy (Filesystem)":          "Dependency CVE scanning across npm, pip, go, maven package manifests.",
        "SCA - Trivy (Container Image)":     "Container image layer-by-layer CVE scan including OS packages.",
        "SCA - Grype":                       "Anchore Grype: vulnerability matching against NVD, GitHub Advisory, OSV databases.",
        "SCA - npm audit":                   "npm official audit against the npm Advisory Database.",
        "IaC Security - Checkov":            "Terraform / CloudFormation / Kubernetes IaC policy-as-code checks.",
        "IaC Security - tfsec":              "Terraform-specific security scanner: AWS, GCP, Azure misconfiguration detection.",
        "Container - Docker Bench Security": "CIS Docker Benchmark: host, daemon, image, container runtime configuration.",
        "DAST - OWASP ZAP":                  "Active baseline web application scan: headers, XSS, injection, misconfigurations.",
        "DAST - Nuclei":                     "Template-based scanner: CVE exploitation, misconfiguration, OWASP checks.",
        "API Security - Shannon AI":         "AI-powered endpoint pentesting: BOLA, auth bypass, rate limiting.",
        "API Security - OWASP API Top 10":   "OWASP API Security Top 10:2023 automated checks against live endpoints.",
    }

    for tool_name, findings in all_findings_by_tool.items():
        pdf.tool_section(tool_name, findings, tool_descriptions.get(tool_name, ""))

    pdf.compliance_section(all_findings)
    pdf.appendix(meta, scan_files)

    # -- Save and Upload PDF --------------------------------
    output_pdf = "/tmp/SOC2_DevSecOps_Master_Report.pdf"
    pdf.output(output_pdf)

    pdf_size = os.path.getsize(output_pdf)
    print(f"[Lambda] PDF generated: {pdf_size} bytes, {pdf.page} pages")

    s3.upload_file(output_pdf, BUCKET, f"{prefix}/SOC2_DevSecOps_Master_Report.pdf",
                   ExtraArgs={"ContentType": "application/pdf",
                               "Metadata": {"commit": commit_sha, "run-id": run_id}})
    s3.upload_file(output_pdf, BUCKET, f"reports/{commit_sha}/SOC2_DevSecOps_Master_Report.pdf",
                   ExtraArgs={"ContentType": "application/pdf"})

    # -- Save JSON Summary ----------------------------------
    summary = {
        "schema_version": "2.0",
        "generated_at": timestamp,
        "commit_sha": commit_sha,
        "run_id": run_id,
        "branch": branch,
        "risk_score": score,
        "grade": grade,
        "total_findings": len(all_findings),
        "findings_by_severity": severity_counts(all_findings),
        "findings_by_tool": {tool: len(f) for tool, f in all_findings_by_tool.items()},
        "pdf_location": f"s3://{BUCKET}/{prefix}/SOC2_DevSecOps_Master_Report.pdf",
        "pdf_size_bytes": pdf_size,
        "pdf_pages": pdf.page,
    }
    summary_json = json.dumps(summary, indent=2).encode()
    s3.put_object(
        Bucket=BUCKET,
        Key=f"{prefix}/report-summary.json",
        Body=summary_json,
        ContentType="application/json"
    )

    return {
        "statusCode": 200,
        "risk_score": score,
        "grade": grade,
        "total_findings": len(all_findings),
        "pdf": f"s3://{BUCKET}/{prefix}/SOC2_DevSecOps_Master_Report.pdf",
        "body": f"Report generated: {len(all_findings)} findings, score={score}/100, grade={grade}, pages={pdf.page}"
    }
