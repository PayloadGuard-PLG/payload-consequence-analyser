#!/usr/bin/env python3
"""Post a GitHub Check Run using GitHub App credentials."""
import os
import stat
import sys
import time

try:
    import cryptography  # noqa: F401 — required by PyJWT for RS256
except ImportError:
    print(
        "ERROR: The 'cryptography' package is required for RS256 JWT signing.\n"
        "Install it with: pip install cryptography",
        file=sys.stderr,
    )
    sys.exit(1)

import jwt
import requests
from requests.adapters import HTTPAdapter, Retry


_GITHUB_LIMIT = 65_000  # leave headroom for truncation notice and closure


def _safe_truncate(content: str, limit: int = _GITHUB_LIMIT) -> str:
    """Truncate markdown to GitHub's Check Run character limit without corrupting structure."""
    if len(content) <= limit:
        return content
    content = content[:limit]
    last_nl = content.rfind('\n')
    if last_nl > 0:
        content = content[:last_nl]
    if content.count('```') % 2 == 1:
        content += '\n```'
    return (
        content
        + '\n\n---\n*Report truncated. Full results available '
        'in the `payloadguard-results` artifact.*'
    )


def _require_env(name: str) -> str:
    val = os.environ.get(name, "").strip()
    if not val:
        raise EnvironmentError(f"Required environment variable {name!r} is not set")
    return val


def main():
    app_id = os.environ.get("PAYLOADGUARD_APP_ID", "").strip()
    if not app_id:
        print("No App credentials configured — skipping Check Run")
        return

    private_key     = _require_env("PAYLOADGUARD_PRIVATE_KEY")
    installation_id = _require_env("PAYLOADGUARD_INSTALLATION_ID")
    head_sha        = _require_env("PR_HEAD_SHA")
    repo            = _require_env("GITHUB_REPOSITORY")

    if "-----BEGIN" not in private_key or "PRIVATE KEY-----" not in private_key:
        raise EnvironmentError(
            "PAYLOADGUARD_PRIVATE_KEY does not look like a valid PEM private key. "
            "Expected a string containing '-----BEGIN RSA PRIVATE KEY-----' or "
            "'-----BEGIN PRIVATE KEY-----'."
        )

    try:
        exit_code = int(os.environ.get("PAYLOADGUARD_EXIT_CODE", "1"))
    except ValueError:
        exit_code = 1

    report_path = os.environ.get("PAYLOADGUARD_REPORT_PATH", "")

    now = int(time.time())
    app_token = jwt.encode(
        {"iat": now - 60, "exp": now + 540, "iss": app_id},
        private_key,
        algorithm="RS256",
    )

    session = requests.Session()
    retries = Retry(total=3, backoff_factor=2, status_forcelist=[429, 500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retries))

    resp = session.post(
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
    if report_path:
        try:
            st = os.stat(report_path)
            if stat.S_ISREG(st.st_mode):
                with open(report_path, encoding="utf-8") as f:
                    summary = _safe_truncate(f.read())
        except OSError:
            pass

    resp = session.post(
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
