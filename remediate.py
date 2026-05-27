"""
PayloadGuard Auto-Remediation — mutable action ref → immutable SHA pinning.

Scans GitHub Actions workflow files for mutable `uses:` references (version
tags like @v4, @main) and resolves them to verified commit SHAs via the
GitHub API. Opens a new PR with the pinned SHAs rather than committing
directly to the offending branch.

Security model: new PR only (requires pull-requests: write). Never commits
directly (that would require contents: write, exploitable via GITHUB_TOKEN).

SHA resolution sequence:
  1. GET /repos/{owner}/{repo}/git/ref/tags/{ref}
     - object.type == 'commit' → lightweight tag, done
     - object.type == 'tag'    → annotated; dereference via
       GET /repos/{owner}/{repo}/git/tags/{sha}
  2. If tag returns 404, try GET /repos/{owner}/{repo}/git/ref/heads/{ref}
     - Branch ref: warn loudly — branch SHAs are still mutable, do not pin
"""
from __future__ import annotations

import base64
import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional

_SHA_RE = re.compile(r'^[0-9a-f]{40}$', re.IGNORECASE)
_WORKFLOW_PATH_RE = re.compile(r'\.github/workflows/[^/]+\.ya?ml$')
_FIRST_PARTY_PREFIXES = ('actions/', 'github/')
_GITHUB_API = 'https://api.github.com'


@dataclass
class RemediationTarget:
    """One mutable `uses:` reference found in a workflow file."""
    file: str
    step_name: str
    action: str           # e.g. "actions/checkout"
    current_ref: str      # e.g. "v4" or "main"
    resolved_sha: str     # 40-char commit SHA (empty if unresolved)
    original_uses: str    # full value e.g. "actions/checkout@v4"
    is_first_party: bool = False
    ref_type: str = "unknown"   # "tag", "branch", or "unknown"
    error: str = ""

    def to_dict(self) -> dict:
        return {
            'file': self.file,
            'step_name': self.step_name,
            'action': self.action,
            'current_ref': self.current_ref,
            'resolved_sha': self.resolved_sha,
            'original_uses': self.original_uses,
            'is_first_party': self.is_first_party,
            'ref_type': self.ref_type,
            'error': self.error,
        }


class WorkflowRemediator:
    """Scans workflow diffs and resolves mutable action refs to pinned SHAs."""

    def __init__(self, token: str = '', cache_path: Optional[str] = None):
        self.token = token
        self._cache: dict = {}
        self._cache_path = cache_path or os.path.join(
            os.environ.get('RUNNER_TEMP', '/tmp'), 'pg-sha-cache.json'
        )
        self._load_cache()

    # ------------------------------------------------------------------
    # Cache
    # ------------------------------------------------------------------

    def _load_cache(self) -> None:
        try:
            with open(self._cache_path) as f:
                self._cache = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self._cache = {}

    def _save_cache(self) -> None:
        try:
            with open(self._cache_path, 'w') as f:
                json.dump(self._cache, f)
        except OSError:
            pass

    # ------------------------------------------------------------------
    # GitHub API helpers
    # ------------------------------------------------------------------

    def _headers(self) -> dict:
        h = {
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
            'User-Agent': 'PayloadGuard-AutoRemediate/1.0',
        }
        if self.token:
            h['Authorization'] = f'Bearer {self.token}'
        return h

    def _api_get(self, path: str) -> dict:
        req = urllib.request.Request(
            f'{_GITHUB_API}{path}', headers=self._headers()
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())

    def _api_post(self, path: str, payload: dict) -> dict:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            f'{_GITHUB_API}{path}',
            data=data,
            headers={**self._headers(), 'Content-Type': 'application/json'},
            method='POST',
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())

    def _api_put(self, path: str, payload: dict) -> dict:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            f'{_GITHUB_API}{path}',
            data=data,
            headers={**self._headers(), 'Content-Type': 'application/json'},
            method='PUT',
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())

    # ------------------------------------------------------------------
    # SHA resolution
    # ------------------------------------------------------------------

    def resolve_sha(self, action: str, ref: str) -> Optional[RemediationTarget]:
        """Resolve a mutable ref to a commit SHA. Returns None if already pinned."""
        if not action or '/' not in action:
            return None
        if _SHA_RE.match(ref):
            return None

        cache_key = f'{action}@{ref}'
        if cache_key in self._cache:
            c = self._cache[cache_key]
            return RemediationTarget(
                file='', step_name='',
                action=action, current_ref=ref,
                resolved_sha=c.get('sha', ''),
                original_uses=f'{action}@{ref}',
                is_first_party=action.startswith(_FIRST_PARTY_PREFIXES),
                ref_type=c.get('ref_type', 'unknown'),
                error=c.get('error', ''),
            )

        parts = action.split('/')
        owner, repo_name = parts[0], parts[1]
        result = RemediationTarget(
            file='', step_name='',
            action=action, current_ref=ref,
            resolved_sha='',
            original_uses=f'{action}@{ref}',
            is_first_party=action.startswith(_FIRST_PARTY_PREFIXES),
        )

        # Try as tag first
        try:
            data = self._api_get(f'/repos/{owner}/{repo_name}/git/ref/tags/{ref}')
            obj = data.get('object', {})
            sha = obj.get('sha', '')
            if obj.get('type') == 'tag':
                # Annotated tag — dereference to get the commit SHA
                tag_data = self._api_get(
                    f'/repos/{owner}/{repo_name}/git/tags/{sha}'
                )
                sha = tag_data.get('object', {}).get('sha', sha)
            result.resolved_sha = sha
            result.ref_type = 'tag'
            self._cache[cache_key] = {'sha': sha, 'ref_type': 'tag'}
            self._save_cache()
            return result
        except urllib.error.HTTPError as e:
            if e.code != 404:
                result.error = f'GitHub API error {e.code} resolving {action}@{ref}'
                return result

        # Tag 404 — try as branch
        try:
            data = self._api_get(
                f'/repos/{owner}/{repo_name}/git/ref/heads/{ref}'
            )
            sha = data.get('object', {}).get('sha', '')
            result.resolved_sha = sha
            result.ref_type = 'branch'
            result.error = (
                f'{action}@{ref} is a branch ref — branch SHAs are mutable '
                f'and cannot be safely pinned; use a version tag instead'
            )
            self._cache[cache_key] = {
                'sha': sha, 'ref_type': 'branch', 'error': result.error
            }
            self._save_cache()
            return result
        except urllib.error.HTTPError:
            result.error = (
                f'Ref {ref!r} not found for {action} (tried tag and branch)'
            )
            return result

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    def scan_workflows(self, diffs) -> list[RemediationTarget]:
        """Scan GitPython diff objects for mutable `uses:` references."""
        targets = []
        for d in diffs:
            if d.change_type not in ('A', 'M'):
                continue
            path = d.b_path or d.a_path or ''
            if not isinstance(path, str) or not _WORKFLOW_PATH_RE.search(path):
                continue
            try:
                content = d.b_blob.data_stream.read().decode('utf-8', errors='replace')
            except Exception:
                continue
            targets.extend(self._extract_mutable_refs(path, content))
        return targets

    def _extract_mutable_refs(self, path: str, content: str) -> list[RemediationTarget]:
        """Find all mutable `uses:` values in a single workflow file."""
        targets: list[RemediationTarget] = []
        seen: set[str] = set()
        current_step_name = ''

        for line in content.splitlines():
            name_m = re.match(r'\s+(?:-\s+)?name:\s+(.+)', line)
            if name_m:
                current_step_name = name_m.group(1).strip()

            uses_m = re.match(r'\s+(?:-\s+)?uses:\s+([^\s#\n]+)', line)
            if not uses_m:
                continue
            raw = uses_m.group(1).strip()

            # Skip local path and composite references
            if raw.startswith('./') or raw.startswith('/') or '@' not in raw:
                continue

            action, ref = raw.rsplit('@', 1)

            if _SHA_RE.match(ref) or raw in seen:
                continue
            seen.add(raw)

            targets.append(RemediationTarget(
                file=path,
                step_name=current_step_name,
                action=action,
                current_ref=ref,
                resolved_sha='',
                original_uses=raw,
                is_first_party=action.startswith(_FIRST_PARTY_PREFIXES),
            ))

        return targets

    # ------------------------------------------------------------------
    # Patching
    # ------------------------------------------------------------------

    def patch_workflow(self, content: str, targets: list[RemediationTarget]) -> str:
        """
        Replace mutable uses: values with SHA-pinned versions in YAML content.
        Appends the original ref as inline comment: actions/checkout@abc123  # v4
        Skips branch refs — they remain mutable regardless of SHA pinning.
        """
        subs = {
            t.original_uses: f'{t.action}@{t.resolved_sha}  # {t.current_ref}'
            for t in targets
            if t.resolved_sha and t.ref_type == 'tag'
        }
        if not subs:
            return content

        result_lines = []
        for line in content.splitlines(keepends=True):
            stripped = line.rstrip('\n')
            uses_m = re.match(r'(\s+(?:-\s+)?uses:\s+)([^\s#\n]+)(.*)', stripped)
            if uses_m:
                indent, ref_value = uses_m.group(1), uses_m.group(2)
                if ref_value in subs:
                    line = f'{indent}{subs[ref_value]}\n'
            result_lines.append(line)

        return ''.join(result_lines)

    # ------------------------------------------------------------------
    # PR creation
    # ------------------------------------------------------------------

    def open_pr(
        self,
        repo_full_name: str,
        base_branch: str,
        patches: dict,   # {file_path: patched_content}
        pr_branch: str = 'payloadguard/pin-action-shas',
        title: str = 'chore: pin GitHub Actions to immutable commit SHAs',
        body: str = '',
    ) -> str:
        """
        Create a new branch, commit all patches, and open a PR. Returns PR URL.
        Requires pull-requests: write only — never needs contents: write.
        """
        if not body:
            body = (
                '## PayloadGuard Auto-Remediation\n\n'
                'Pins mutable GitHub Actions version tags to their verified commit SHAs. '
                'The original tag is preserved as an inline comment.\n\n'
                '**Review before merging** — verify the resolved SHAs match '
                'the expected release tags in the upstream action repositories.\n\n'
                '_Generated by PayloadGuard auto-remediation._'
            )

        owner, repo_name = repo_full_name.split('/', 1)

        # 1. Get base branch tip SHA
        base_data = self._api_get(
            f'/repos/{owner}/{repo_name}/git/ref/heads/{base_branch}'
        )
        base_sha = base_data['object']['sha']

        # 2. Create new branch off base
        self._api_post(f'/repos/{owner}/{repo_name}/git/refs', {
            'ref': f'refs/heads/{pr_branch}',
            'sha': base_sha,
        })

        # 3. Commit each patched file onto the new branch
        for file_path, new_content in patches.items():
            existing = self._api_get(
                f'/repos/{owner}/{repo_name}/contents/{file_path}'
            )
            file_sha = existing.get('sha', '')
            encoded = base64.b64encode(new_content.encode()).decode()
            self._api_put(f'/repos/{owner}/{repo_name}/contents/{file_path}', {
                'message': f'fix: pin {file_path} action refs to immutable SHAs',
                'content': encoded,
                'sha': file_sha,
                'branch': pr_branch,
            })

        # 4. Open the PR
        pr_data = self._api_post(f'/repos/{owner}/{repo_name}/pulls', {
            'title': title,
            'body': body,
            'head': pr_branch,
            'base': base_branch,
        })
        return pr_data.get('html_url', '')


if __name__ == '__main__':
    import sys

    token = os.environ.get('GITHUB_TOKEN', '')
    json_report_path = os.environ.get('JSON_REPORT_PATH', 'payloadguard-report.json')
    base_branch = os.environ.get('PR_BASE_BRANCH', 'main')
    repo_full_name = os.environ.get('REPO_FULL_NAME', '')

    if not token:
        print('::error::GITHUB_TOKEN not set — cannot run auto-remediation')
        sys.exit(1)
    if not repo_full_name:
        print('::error::REPO_FULL_NAME not set — cannot open PR')
        sys.exit(1)

    try:
        with open(json_report_path) as f:
            report = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f'::error::Cannot read JSON report at {json_report_path}: {e}')
        sys.exit(1)

    warnings = report.get('mutable_tag_warnings', [])
    if not warnings:
        print('No mutable action tags found — nothing to remediate.')
        sys.exit(0)

    remediator = WorkflowRemediator(token=token)

    # Group warnings by file
    by_file: dict = {}
    for w in warnings:
        by_file.setdefault(w['file'], []).append(w)

    # Resolve SHAs and patch each file
    patches: dict = {}
    for file_path, file_warnings in by_file.items():
        targets = []
        for w in file_warnings:
            resolved = remediator.resolve_sha(w['action'], w['ref'])
            if resolved:
                resolved.file = file_path
                targets.append(resolved)
                if resolved.error:
                    print(f'::warning::{resolved.error}')

        # Read current file content via GitHub API
        owner, repo_name = repo_full_name.split('/', 1)
        try:
            data = remediator._api_get(f'/repos/{owner}/{repo_name}/contents/{file_path}')
            content = base64.b64decode(data['content']).decode('utf-8')
        except Exception as e:
            print(f'::warning::Could not fetch {file_path}: {e}')
            continue

        pinnable = [t for t in targets if t.resolved_sha and t.ref_type == 'tag']
        if not pinnable:
            continue

        patched = remediator.patch_workflow(content, pinnable)
        if patched != content:
            patches[file_path] = patched

    if not patches:
        print('All action refs already pinned or unresolvable — no PR needed.')
        sys.exit(0)

    pr_url = remediator.open_pr(repo_full_name, base_branch, patches)
    print(f'::notice::PayloadGuard auto-remediation PR opened: {pr_url}')
    print(f'Remediation PR: {pr_url}')
