import base64
import json
import os
import sys

if not os.path.exists("lambda_meta.json"):
    print("No lambda_meta.json found - skipping log decode")
    sys.exit(0)

with open("lambda_meta.json") as f:
    meta = json.load(f)
if "LogResult" in meta:
    logs = base64.b64decode(meta["LogResult"]).decode("utf-8", errors="replace")
    print("=== Lambda Execution Logs ===")
    print(logs)
if "FunctionError" in meta:
    print(f"Lambda FunctionError: {meta['FunctionError']}")
    sys.exit(1)
