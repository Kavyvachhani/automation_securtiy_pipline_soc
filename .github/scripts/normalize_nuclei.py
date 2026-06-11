import json
import os

findings = []
for path in ['scan_results/nuclei-raw.jsonl', 'scan_results/nuclei-results.json']:
    if not os.path.exists(path):
        continue
    with open(path) as f:
        content = f.read().strip()
    if not content:
        continue
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except Exception:
            pass
    if findings:
        break
with open('scan_results/nuclei-results.json', 'w') as f:
    json.dump(findings, f, indent=2)
print(f'Nuclei: {len(findings)} findings normalized')
