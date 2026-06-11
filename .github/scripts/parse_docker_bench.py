import sys
import json

lines = sys.stdin.readlines()
buckets = {'PASS': [], 'WARN': [], 'FAIL': [], 'INFO': [], 'NOTE': []}
for line in lines:
    stripped = line.strip()
    for status in buckets:
        if f'[{status}]' in stripped:
            buckets[status].append(stripped)
            break
result = {
    'tool': 'docker-bench-security',
    'summary': {k: len(v) for k, v in buckets.items()},
    'findings': [{'status': s, 'description': d} for s, items in buckets.items() for d in items]
}
json.dump(result, open('scan_results/docker-bench-results.json', 'w'), indent=2)
total = sum(len(v) for v in buckets.values())
print(f'Docker Bench: WARN={len(buckets["WARN"])} FAIL={len(buckets["FAIL"])} total={total}')
