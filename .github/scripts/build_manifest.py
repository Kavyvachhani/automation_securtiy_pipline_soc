import json
import os
import datetime
import hashlib

files = []
for fname in sorted(os.listdir("scan_results")):
    if not fname.endswith(".json"):
        continue
    fpath = f"scan_results/{fname}"
    size = os.path.getsize(fpath)
    with open(fpath, "rb") as f:
        sha256 = hashlib.sha256(f.read()).hexdigest()
    files.append({"file": fname, "size_bytes": size, "sha256": sha256})

manifest = {
    "schema_version": "2.0",
    "pipeline": "Enterprise DevSecOps Platform v2",
    "commit_sha": os.environ.get("GITHUB_SHA", "unknown"),
    "run_id": os.environ.get("GITHUB_RUN_ID", "unknown"),
    "run_number": os.environ.get("GITHUB_RUN_NUMBER", "unknown"),
    "branch": os.environ.get("GITHUB_REF_NAME", "unknown"),
    "actor": os.environ.get("GITHUB_ACTOR", "unknown"),
    "repository": os.environ.get("GITHUB_REPOSITORY", "unknown"),
    "timestamp_utc": datetime.datetime.utcnow().isoformat() + "Z",
    "scan_file_count": len(files),
    "scan_files": files
}
with open("scan_results/manifest.json", "w") as f:
    json.dump(manifest, f, indent=2)
print(f"Manifest: {len(files)} scan files with SHA256 checksums")
