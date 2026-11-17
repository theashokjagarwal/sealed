#!/usr/bin/env python3
"""Push SEALED directly to GitHub via the GitHub REST Git Data API.

Zero local `git` installation required (uses Python 3 standard library only).

Usage:
    GITHUB_TOKEN=ghp_xxx python3 scripts/push_to_github.py <owner> <repo> [--private]
"""

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

API = "https://api.github.com"
SKIP_DIRS = {".git", "target", "audit-artifacts", "__pycache__", ".venv", "venv"}
SKIP_FILES = {".DS_Store"}


def api_request(method: str, path: str, token: str, body=None):
    url = f"{API}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("User-Agent", "sealed-github-pusher")
    if data is not None:
        req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as err:
        raw = err.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = {"message": raw}
        return err.code, parsed


def main() -> int:
    token = os.environ.get("GITHUB_TOKEN", "")
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    is_private = "--private" in sys.argv[1:]

    if not token or len(args) < 2:
        print(
            "Usage:\n  GITHUB_TOKEN=<pat> python3 scripts/push_to_github.py <owner> <repo> [--private]",
            file=sys.stderr,
        )
        return 1

    owner, repo = args[0], args[1]
    root = Path(__file__).resolve().parent.parent

    code, info = api_request("GET", f"/repos/{owner}/{repo}", token)
    if code == 404:
        print(f"[1/5] Creating repository {owner}/{repo}...")
        c_code, c_res = api_request(
            "POST",
            "/user/repos",
            token,
            {
                "name": repo,
                "description": "Local-first, air-gapped AI compliance & safety auditor",
                "private": is_private,
                "auto_init": True,
            },
        )
        if c_code not in (200, 201):
            print(f"[ERROR] Failed to create repo (HTTP {c_code}): {c_res.get('message')}", file=sys.stderr)
            return 1
        time.sleep(2)
        default_branch = c_res.get("default_branch", "main")
    elif code == 200:
        print(f"[1/5] Found existing repository {owner}/{repo}.")
        default_branch = info.get("default_branch", "main")
    else:
        print(f"[ERROR] GitHub API check failed (HTTP {code}): {info.get('message')}", file=sys.stderr)
        return 1

    ref_code, ref_data = api_request("GET", f"/repos/{owner}/{repo}/git/ref/heads/{default_branch}", token)
    if ref_code != 200:
        print(f"[ERROR] Could not read branch ref (HTTP {ref_code}): {ref_data.get('message')}", file=sys.stderr)
        return 1
    parent_sha = ref_data["object"]["sha"]

    files = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        parts = rel.split("/")
        if any(p in SKIP_DIRS for p in parts):
            continue
        if path.name in SKIP_FILES or rel.endswith((".tmp", ".swp", ".pyc")):
            continue
        files.append((path, rel))

    print(f"[2/5] Uploading {len(files)} files as Git blobs...")
    tree_entries = []
    for idx, (path, rel) in enumerate(files, start=1):
        b64 = base64.b64encode(path.read_bytes()).decode("ascii")
        b_code, b_res = api_request(
            "POST",
            f"/repos/{owner}/{repo}/git/blobs",
            token,
            {"content": b64, "encoding": "base64"},
        )
        if b_code not in (200, 201):
            print(f"\n[ERROR] Blob upload failed for {rel}: {b_res.get('message')}", file=sys.stderr)
            return 1
        mode = "100755" if os.access(path, os.X_OK) else "100644"
        tree_entries.append({"path": rel, "mode": mode, "type": "blob", "sha": b_res["sha"]})
        print(f"\r      Uploaded {idx}/{len(files)} ({rel})          ", end="", flush=True)
    print("")

    print("[3/5] Creating Git tree...")
    t_code, t_res = api_request("POST", f"/repos/{owner}/{repo}/git/trees", token, {"tree": tree_entries})
    if t_code not in (200, 201):
        print(f"[ERROR] Tree creation failed: {t_res.get('message')}", file=sys.stderr)
        return 1

    print("[4/5] Creating commit...")
    commit_msg = os.environ.get(
        "COMMIT_MESSAGE",
        "feat: SEALED v2.0 (Python + C++17 + Java + HTML/CSS/JS Instrument Panel)",
    )
    cm_code, cm_res = api_request(
        "POST",
        f"/repos/{owner}/{repo}/git/commits",
        token,
        {"message": commit_msg, "tree": t_res["sha"], "parents": [parent_sha]},
    )
    if cm_code not in (200, 201):
        print(f"[ERROR] Commit creation failed: {cm_res.get('message')}", file=sys.stderr)
        return 1

    print(f"[5/5] Updating refs/heads/{default_branch}...")
    u_code, u_res = api_request(
        "PATCH",
        f"/repos/{owner}/{repo}/git/refs/heads/{default_branch}",
        token,
        {"sha": cm_res["sha"], "force": False},
    )
    if u_code != 200:
        print(f"[ERROR] Ref update failed: {u_res.get('message')}", file=sys.stderr)
        return 1

    print(f"[OK] Pushed {len(files)} files to https://github.com/{owner}/{repo}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
