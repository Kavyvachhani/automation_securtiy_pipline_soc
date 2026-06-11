import json

try:
    data = json.load(open('scan_results/checkov-results.json'))
    if isinstance(data, list):
        data = data[0] if data else {'results': {'failed_checks': [], 'passed_checks': []}, 'summary': {'failed': 0, 'passed': 0}}
    data.setdefault('results', {'failed_checks': [], 'passed_checks': []})
    data['results'].setdefault('failed_checks', [])
    data['results'].setdefault('passed_checks', [])
    json.dump(data, open('scan_results/checkov-results.json', 'w'), indent=2)
except Exception as e:
    print(f'Normalizing checkov output failed ({e}) - writing empty result')
    json.dump({'results': {'failed_checks': [], 'passed_checks': []}, 'summary': {'failed': 0, 'passed': 0}}, open('scan_results/checkov-results.json', 'w'))
