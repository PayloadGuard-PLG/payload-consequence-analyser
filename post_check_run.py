#!/usr/bin/env python3
"""Post a GitHub Check Run using GitHub App credentials."""
import os
import sys
import time

import jwt
import requests


def main():
    app_id = os.environ.get("PAYLOADGUARD_APP_ID", "").strip()
    if not app_id:
        print("No App credentials configured — skipping Check Run")
        return
    app_id = app_id  # reassign for clarity below
    private_key = os.environ["PAYLOADGUARD_PRIVATE_KEY"]
    installation_id = os.environ["PAYLOADGUARD_INSTALLATION_ID"]
    head_sha = os.environ["PR_HEAD_SHA"]
    repo = os.environ["GITHUB_REPOSITORY"]
    exit_code = int(os.environ.get("PAYLOADGUARD_EXIT_CODE", "1"))
    report_path = os.environ.get("PAYLOADGUARD_REPORT_PATH", "")

    now = int(time.time())
    app_token = jwt.encode(
        {"iat": now - 60, "exp": now + 540, "iss": app_id},
        private_key,
        algorithm="RS256",
    )

    resp = requests.post(
        f"https://api.github.com/app/installations/{installation_id}/access_tokens",
        headers={
            "Authorization": f"Bearer {app_token}",
            "Accept": "application/vnd.github+json",
        },
        timeout=15,
    )
    resp.raise_for_status()
    install_token = resp.json()["token"]

    if exit_code == 0:
        conclusion = "success"
        title = "PayloadGuard — SAFE"
    elif exit_code == 2:
        conclusion = "failure"
        title = "PayloadGuard — DESTRUCTIVE: do not merge"
    else:
        conclusion = "action_required"
        title = "PayloadGuard — analysis error"

    summary = title
    if report_path and os.path.exists(report_path):
        with open(report_path, encoding="utf-8") as f:
            summary = f.read()[:65535]

    resp = requests.post(
        f"https://api.github.com/repos/{repo}/check-runs",
        headers={
            "Authorization": f"Bearer {install_token}",
            "Accept": "application/vnd.github+json",
        },
        json={
            "name": "PayloadGuard",
            "head_sha": head_sha,
            "status": "completed",
            "conclusion": conclusion,
            "output": {"title": title, "summary": summary},
        },
        timeout=15,
    )
    resp.raise_for_status()
    print(f"Check Run posted: {resp.json().get('html_url', 'ok')}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"::error::Check Run failed: {e}", file=sys.stderr)
        sys.exit(1)
