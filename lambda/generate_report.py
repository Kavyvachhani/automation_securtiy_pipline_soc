import json
import os
import datetime
import boto3
from collections import defaultdict
from fpdf import FPDF
from fpdf.enums import XPos, YPos

s3 = boto3.client('s3')
BUCKET = os.environ.get("S3_BUCKET", "")

def get_s3_json(key):
    try:
        obj = s3.get_object(Bucket=BUCKET, Key=key)
        return json.loads(obj['Body'].read().decode('utf-8'))
    except Exception as e:
        print(f"Skipping {key}: {e}")
        return None

def parse_trivy(data):
    stats = defaultdict(int)
    vulns = []
    if not data or "Results" not in data: return stats, vulns
    for result in data["Results"]:
        for v in result.get("Vulnerabilities", []):
            sev = v.get("Severity", "UNKNOWN")
            stats[sev] += 1
            if sev in ["CRITICAL", "HIGH"]:
                vulns.append({"id": v.get("VulnerabilityID", "N/A"), "title": v.get("Title", "No Title")[:80], "severity": sev})
    return stats, vulns

def parse_semgrep(data):
    stats = defaultdict(int)
    vulns = []
    if not data or "results" not in data: return stats, vulns
    for r in data["results"]:
        sev = r.get("extra", {}).get("severity", "UNKNOWN").upper()
        if sev == "ERROR": sev = "HIGH"
        elif sev == "WARNING": sev = "MEDIUM"
        else: sev = "LOW"
        stats[sev] += 1
        if sev in ["CRITICAL", "HIGH", "ERROR"]:
            vulns.append({"id": r.get("check_id", "N/A")[:30], "title": r.get("extra", {}).get("message", "No Title")[:80], "severity": sev})
    return stats, vulns

def parse_zap(data):
    stats = defaultdict(int)
    vulns = []
    if not data or "site" not in data: return stats, vulns
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            risk = alert.get("riskdesc", "Unknown")
            if "High" in risk: sev = "HIGH"
            elif "Medium" in risk: sev = "MEDIUM"
            elif "Low" in risk: sev = "LOW"
            else: sev = "INFO"
            count = int(alert.get("count", 1))
            stats[sev] += count
            if sev in ["HIGH", "CRITICAL"]:
                vulns.append({"id": alert.get("pluginid", "N/A"), "title": alert.get("alert", "No Title")[:80], "severity": sev})
    return stats, vulns

def parse_nuclei(data_list):
    stats = defaultdict(int)
    vulns = []
    if not data_list: return stats, vulns
    # nuclei-results.json can be an array or json lines, but nuclei action with json output usually makes it an array
    if not isinstance(data_list, list): data_list = [data_list]
    for r in data_list:
        sev = r.get("info", {}).get("severity", "UNKNOWN").upper()
        stats[sev] += 1
        if sev in ["CRITICAL", "HIGH"]:
            vulns.append({"id": r.get("template-id", "N/A")[:30], "title": r.get("info", {}).get("name", "No Title")[:80], "severity": sev})
    return stats, vulns

def parse_shannon(data):
    stats = defaultdict(int)
    vulns = []
    if not data or "findings" not in data: return stats, vulns
    for f in data["findings"]:
        sev = f.get("severity", "UNKNOWN").upper()
        stats[sev] += 1
        if sev in ["CRITICAL", "HIGH"]:
            vulns.append({"id": f.get("endpoint", "N/A")[:30], "title": f.get("vulnerability", "No Title")[:80], "severity": sev})
    return stats, vulns

def parse_checkov(data):
    stats = defaultdict(int)
    vulns = []
    if not data or "results" not in data: return stats, vulns
    for f in data["results"].get("failed_checks", []):
        sev = "HIGH" # Checkov doesn't always have strict severity, assume HIGH for failed IaC
        stats[sev] += 1
        vulns.append({"id": f.get("check_id", "N/A")[:30], "title": f.get("check_name", "No Title")[:80], "severity": sev})
    return stats, vulns

def parse_gitleaks(data_list):
    stats = defaultdict(int)
    vulns = []
    if not data_list: return stats, vulns
    if not isinstance(data_list, list): data_list = [data_list]
    for f in data_list:
        sev = "CRITICAL"
        stats[sev] += 1
        vulns.append({"id": f.get("RuleID", "N/A")[:30], "title": f"Secret exposed in {f.get('File', 'Unknown')} at commit {f.get('Commit', 'N/A')[:7]}", "severity": sev})
    return stats, vulns

def create_pdf(t_stats, t_vulns, s_stats, s_vulns, z_stats, z_vulns, n_stats, n_vulns, sh_stats, sh_vulns, c_stats, c_vulns, g_stats, g_vulns, output_path):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_fill_color(15, 23, 42)
    pdf.set_text_color(255, 255, 255)
    pdf.rect(0, 0, 210, 30, "F")
    pdf.set_y(10)
    pdf.cell(0, 10, "DevSecOps Master Security Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(15)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, f"Generated: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 8, "Target: OWASP Juice Shop Pipeline", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(10)
    
    def print_section(title, stats, vulns):
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_fill_color(240, 240, 240)
        pdf.cell(0, 10, f" {title}", new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
        pdf.set_font("Helvetica", "B", 10)
        summary = " | ".join([f"{k}: {v}" for k, v in stats.items()])
        if not summary: summary = "No vulnerabilities detected or tool not run."
        pdf.cell(0, 8, f"Summary: {summary}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        if vulns:
            pdf.ln(2)
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(30, 6, "ID/Severity", border=1)
            pdf.cell(0, 6, "Description", border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("Helvetica", "", 8)
            for v in vulns[:20]:
                pdf.cell(30, 6, f"{v['severity'][:4]}-{v['id']}", border=1)
                pdf.cell(0, 6, v['title'].replace('\n', ' '), border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            if len(vulns) > 20:
                pdf.set_font("Helvetica", "I", 8)
                pdf.cell(0, 6, f"... and {len(vulns)-20} more critical/high issues hidden for brevity.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(10)
        
    print_section("1. Secret Scanning (Gitleaks)", g_stats, g_vulns)
    print_section("2. IaC Misconfigurations (Checkov)", c_stats, c_vulns)
    print_section("3. SCA & Container Scan (Trivy)", t_stats, t_vulns)
    print_section("4. SAST Code Scan (Semgrep)", s_stats, s_vulns)
    print_section("5. Endpoint AI Pentest (Shannon AI)", sh_stats, sh_vulns)
    print_section("6. DAST Pentest (OWASP ZAP)", z_stats, z_vulns)
    print_section("7. DAST Zero-Day Scan (Nuclei)", n_stats, n_vulns)
    
    pdf.output(output_path)

def handler(event, context):
    print(f"Event: {json.dumps(event)}")
    # Expected event: {"commit_sha": "abc1234"}
    commit_sha = event.get("commit_sha", "latest")
    
    prefix = f"scans/{commit_sha}"
    t_data = get_s3_json(f"{prefix}/trivy-results.json")
    s_data = get_s3_json(f"{prefix}/semgrep-results.json")
    z_data = get_s3_json(f"{prefix}/zap-results.json")
    n_data = get_s3_json(f"{prefix}/nuclei-results.json")
    sh_data = get_s3_json(f"{prefix}/shannon-results.json")
    c_data = get_s3_json(f"{prefix}/checkov-results.json")
    g_data = get_s3_json(f"{prefix}/gitleaks-results.json")
    
    t_stats, t_vulns = parse_trivy(t_data)
    s_stats, s_vulns = parse_semgrep(s_data)
    z_stats, z_vulns = parse_zap(z_data)
    n_stats, n_vulns = parse_nuclei(n_data)
    sh_stats, sh_vulns = parse_shannon(sh_data)
    c_stats, c_vulns = parse_checkov(c_data)
    g_stats, g_vulns = parse_gitleaks(g_data)
    
    output_pdf = "/tmp/SOC2_DevSecOps_Master_Report.pdf"
    create_pdf(t_stats, t_vulns, s_stats, s_vulns, z_stats, z_vulns, n_stats, n_vulns, sh_stats, sh_vulns, c_stats, c_vulns, g_stats, g_vulns, output_pdf)
    
    # Uploading to the scans folder so it's right alongside the raw json files for easy access!
    s3.upload_file(output_pdf, BUCKET, f"scans/{commit_sha}/SOC2_DevSecOps_Master_Report.pdf")
    s3.upload_file(output_pdf, BUCKET, f"reports/{commit_sha}/SOC2_DevSecOps_Master_Report.pdf")
    
    return {
        "statusCode": 200,
        "body": f"Report generated successfully at s3://{BUCKET}/scans/{commit_sha}/SOC2_DevSecOps_Master_Report.pdf"
    }
