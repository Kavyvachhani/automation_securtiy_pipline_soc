import sys
import json

lines = []
for line in sys.stdin:
    line = line.strip()
    if line:
        try:
            lines.append(json.loads(line))
        except Exception:
            pass
json.dump(lines, open('scan_results/trufflehog-results.json', 'w'), indent=2)
print(f'TruffleHog: {len(lines)} secrets detected')
